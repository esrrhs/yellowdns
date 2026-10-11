package main

import (
	"bufio"
	"context"
	"fmt"
	"net"
	"os"
	"sort"
	"strings"
	"sync"
	"time"

	gohomedns "github.com/esrrhs/gohome/dns"
)

// 按客户端的访问控制与限速，在 routingResolver.Exchange 最前面统一裁决，
// UDP/TCP/DoT 三种入站共享同一套策略（对端地址由 gohome dns.Server 与
// dotServer 通过 context 透传）。
//
// 规则语义：
//   - allow 非空时，客户端源 IP 必须命中至少一条 allow 网段，否则拒绝；
//   - deny 始终检查且优先（命中 deny 即使也命中 allow 也拒绝）；
//   - 规则可来自命令行内联 CIDR（逗号分隔）与文件（每行一个 CIDR，
//     '#' 起始为注释，文件随 SIGHUP 热重载）；
//   - 上下文中没有对端地址（内部/合成调用）一律放行，避免误伤自身组件。
//
// 限速：每客户端源 IP 独立令牌桶，突发容量与稳态 QPS 分离；桶表惰性清扫，
// 不引入需要随进程关闭的后台 goroutine。

const (
	aclReasonAllow     = ""          // 放行
	aclReasonDeny      = "acl"       // 命中访问控制
	aclReasonRateLimit = "ratelimit" // 超过每客户端 QPS

	// rateSweepInterval 限速桶表惰性清扫间隔；rateMaxClients 是桶数硬上限，
	// 防止伪造海量源 IP 把内存撑爆（UDP 源地址可伪造）。
	rateSweepInterval = 60 * time.Second
	rateIdleAfter     = 10 * time.Minute
	rateMaxClients    = 50000
)

// clientPolicy 是解析后的访问控制 + 限速策略。零值表示全部放行且不限速。
type clientPolicy struct {
	allowFiles []string
	denyFiles  []string

	// 内联网段（命令行）不随文件重载变化，文件网段热重载时必须保留它们。
	inlineAllow []*net.IPNet
	inlineDeny  []*net.IPNet

	mu        sync.RWMutex
	fileAllow []*net.IPNet
	fileDeny  []*net.IPNet

	limiter *ipRateLimiter
}

// parseCIDRToken 解析单个条目：支持 CIDR（10.0.0.0/8）与裸 IP
// （裸 IP 按 /32 或 /128 主机路由处理）。空串返回 nil。
func parseCIDRToken(token string) (*net.IPNet, error) {
	token = strings.TrimSpace(token)
	if token == "" {
		return nil, nil
	}
	if _, ipnet, err := net.ParseCIDR(token); err == nil {
		return ipnet, nil
	}
	ip := net.ParseIP(token)
	if ip == nil {
		return nil, fmt.Errorf("invalid cidr or ip %q", token)
	}
	if v4 := ip.To4(); v4 != nil {
		return &net.IPNet{IP: v4, Mask: net.CIDRMask(32, 32)}, nil
	}
	return &net.IPNet{IP: ip, Mask: net.CIDRMask(128, 128)}, nil
}

// parseCIDRList 解析逗号分隔的内联 CIDR 列表（flag 用）。
func parseCIDRList(spec string) ([]*net.IPNet, error) {
	var nets []*net.IPNet
	for _, part := range strings.Split(spec, ",") {
		n, err := parseCIDRToken(part)
		if err != nil {
			return nil, err
		}
		if n != nil {
			nets = append(nets, n)
		}
	}
	return nets, nil
}

// parseCIDRFile 解析规则文件：每行一个 CIDR/裸 IP，'#' 后为注释，
// 允许空行与行内首尾空白。
func parseCIDRFile(path string) ([]*net.IPNet, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	var nets []*net.IPNet
	sc := bufio.NewScanner(f)
	lineNo := 0
	for sc.Scan() {
		lineNo++
		line := strings.TrimSpace(sc.Text())
		if i := strings.IndexByte(line, '#'); i >= 0 {
			line = strings.TrimSpace(line[:i])
		}
		if line == "" {
			continue
		}
		// 一行内也允许逗号分隔多个，方便手工合并文件。
		for _, tok := range strings.Split(line, ",") {
			n, err := parseCIDRToken(tok)
			if err != nil {
				return nil, fmt.Errorf("%s:%d: %w", path, lineNo, err)
			}
			if n != nil {
				nets = append(nets, n)
			}
		}
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	return nets, nil
}

// newClientPolicy 汇总内联网段与规则文件构造策略。启动时调用，
// 文件读不到/内容非法直接返回错误（fail fast）。rate<=0 关闭限速。
func newClientPolicy(allowSpec, denySpec string, allowFiles, denyFiles []string, rate float64, burst int) (*clientPolicy, error) {
	p := &clientPolicy{allowFiles: allowFiles, denyFiles: denyFiles}
	inlineAllow, err := parseCIDRList(allowSpec)
	if err != nil {
		return nil, fmt.Errorf("-allow: %w", err)
	}
	inlineDeny, err := parseCIDRList(denySpec)
	if err != nil {
		return nil, fmt.Errorf("-deny: %w", err)
	}
	p.inlineAllow = inlineAllow
	p.inlineDeny = inlineDeny
	var fileAllow, fileDeny []*net.IPNet
	for _, path := range allowFiles {
		ns, err := parseCIDRFile(path)
		if err != nil {
			return nil, fmt.Errorf("allow file: %w", err)
		}
		fileAllow = append(fileAllow, ns...)
	}
	for _, path := range denyFiles {
		ns, err := parseCIDRFile(path)
		if err != nil {
			return nil, fmt.Errorf("deny file: %w", err)
		}
		fileDeny = append(fileDeny, ns...)
	}
	p.fileAllow = fileAllow
	p.fileDeny = fileDeny

	if rate < 0 {
		return nil, fmt.Errorf("-rate-limit must not be negative")
	}
	if rate > 0 {
		if burst <= 0 {
			// 未显式给突发时默认 2 秒稳态容量，至少 1 个令牌，
			// 覆盖正常的浏览器/系统启动时并发查询突发。
			b := int(rate * 2)
			if b < 1 {
				b = 1
			}
			burst = b
		}
		p.limiter = newIPRateLimiter(rate, burst)
	}
	return p, nil
}

// reloadFiles 重新读取规则文件（SIGHUP 调用），命令行内联网段保持不变。
// 坏文件返回错误且保留旧规则，语义与其他热重载一致。
func (p *clientPolicy) reloadFiles() error {
	if p == nil {
		return nil
	}
	var allow, deny []*net.IPNet
	for _, path := range p.allowFiles {
		ns, err := parseCIDRFile(path)
		if err != nil {
			return fmt.Errorf("reload allow file, keeping old rules: %w", err)
		}
		allow = append(allow, ns...)
	}
	for _, path := range p.denyFiles {
		ns, err := parseCIDRFile(path)
		if err != nil {
			return fmt.Errorf("reload deny file, keeping old rules: %w", err)
		}
		deny = append(deny, ns...)
	}
	p.mu.Lock()
	p.fileAllow = allow
	p.fileDeny = deny
	p.mu.Unlock()
	return nil
}

// rulesLocked 返回内联+文件合并后的 allow/deny，调用方须持有读锁。
func (p *clientPolicy) rulesLocked() (allow, deny []*net.IPNet, hasAllow bool) {
	allow = append(append([]*net.IPNet{}, p.inlineAllow...), p.fileAllow...)
	deny = append(append([]*net.IPNet{}, p.inlineDeny...), p.fileDeny...)
	return allow, deny, len(allow) > 0
}

// check 裁决一个对端地址是否放行，返回拒绝原因（aclReasonAllow 表示放行）。
func (p *clientPolicy) check(addr net.Addr) string {
	if p == nil || addr == nil {
		return aclReasonAllow
	}
	ip := ipFromAddr(addr)
	if ip == nil {
		// 无法解析源 IP 时放行，避免把解析 bug 变成全站拒绝；
		// 真实 UDP/TCP/DoT 连接的地址都可解析。
		return aclReasonAllow
	}

	p.mu.RLock()
	allow, deny, hasAllow := p.rulesLocked()
	p.mu.RUnlock()

	for _, n := range deny {
		if n.Contains(ip) {
			return aclReasonDeny
		}
	}
	if hasAllow {
		matched := false
		for _, n := range allow {
			if n.Contains(ip) {
				matched = true
				break
			}
		}
		if !matched {
			return aclReasonDeny
		}
	}

	if p.limiter != nil && !p.limiter.allow(ip.String()) {
		return aclReasonRateLimit
	}
	return aclReasonAllow
}

// entryCounts 返回当前 allow/deny 规则条数，供 /stats 暴露。
func (p *clientPolicy) entryCounts() (allow, deny int) {
	if p == nil {
		return 0, 0
	}
	p.mu.RLock()
	defer p.mu.RUnlock()
	a, d, _ := p.rulesLocked()
	return len(a), len(d)
}

// rateClients 返回当前限速桶数量（近似活动客户端数）。
func (p *clientPolicy) rateClients() int {
	if p == nil || p.limiter == nil {
		return 0
	}
	return p.limiter.size()
}

// limiterBurst 返回配置的每客户端突发容量；未启用限速时为 0。
func (p *clientPolicy) limiterBurst() int {
	if p == nil || p.limiter == nil {
		return 0
	}
	return int(p.limiter.burst)
}

// ipFromAddr 从 net.Addr 提取源 IP，兼容 UDP/TCP/TLS 地址与 host:port 形式。
func ipFromAddr(addr net.Addr) net.IP {
	switch a := addr.(type) {
	case *net.UDPAddr:
		return a.IP
	case *net.TCPAddr:
		return a.IP
	}
	host, _, err := net.SplitHostPort(addr.String())
	if err != nil {
		host = addr.String()
	}
	return net.ParseIP(strings.Trim(host, "[]"))
}

// clientAddrFromContext 从 ctx 取出 gohome 透传的对端地址。
func clientAddrFromContext(ctx context.Context) net.Addr {
	return gohomedns.ClientAddrFromContext(ctx)
}

// ---- 每客户端令牌桶 ----

type tokenBucket struct {
	tokens float64
	last   time.Time
}

type ipRateLimiter struct {
	mu        sync.Mutex
	rate      float64 // 每秒补充的令牌数（稳态 QPS）
	burst     float64 // 桶容量（突发上限）
	clients   map[string]*tokenBucket
	lastSweep time.Time
}

func newIPRateLimiter(rate float64, burst int) *ipRateLimiter {
	return &ipRateLimiter{
		rate:      rate,
		burst:     float64(burst),
		clients:   make(map[string]*tokenBucket),
		lastSweep: time.Now(),
	}
}

// allow 判断 key（客户端 IP）此刻能否取走 1 个令牌。
func (l *ipRateLimiter) allow(key string) bool {
	now := time.Now()
	l.mu.Lock()
	defer l.mu.Unlock()

	if len(l.clients) >= rateMaxClients {
		l.sweepLocked(now, true)
	}
	b, ok := l.clients[key]
	if !ok {
		// 新客户端给满桶：正常用户的第一批并发查询不应被误伤，
		// 真正的持续滥用会在 burst 耗尽后被挡住。
		b = &tokenBucket{tokens: l.burst, last: now}
		l.clients[key] = b
	} else {
		elapsed := now.Sub(b.last).Seconds()
		if elapsed > 0 {
			b.tokens += elapsed * l.rate
			if b.tokens > l.burst {
				b.tokens = l.burst
			}
			b.last = now
		}
	}
	if b.tokens >= 1 {
		b.tokens--
		return true
	}
	return false
}

func (l *ipRateLimiter) size() int {
	l.mu.Lock()
	defer l.mu.Unlock()
	return len(l.clients)
}

// sweepLocked 清理空闲桶。force 用于桶数触顶时：先删长期空闲的，
// 仍超限则按最久未使用继续删，给新源地址腾出位置。
func (l *ipRateLimiter) sweepLocked(now time.Time, force bool) {
	if !force && now.Sub(l.lastSweep) < rateSweepInterval {
		return
	}
	l.lastSweep = now
	for k, b := range l.clients {
		if now.Sub(b.last) > rateIdleAfter {
			delete(l.clients, k)
		}
	}
	if len(l.clients) < rateMaxClients {
		return
	}
	// 极端流量下仍超限：按最久未活动排序，一次删到 90% 水位。
	// 5 万条目排序是 O(n log n)，避免逐个扫描删除的 O(n^2) 开销。
	keys := make([]string, 0, len(l.clients))
	for k := range l.clients {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool {
		return l.clients[keys[i]].last.Before(l.clients[keys[j]].last)
	})
	target := rateMaxClients * 9 / 10
	remove := len(l.clients) - target
	for _, k := range keys[:remove] {
		delete(l.clients, k)
	}
}
