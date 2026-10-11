package main

import (
	"context"
	"net"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	gohomedns "github.com/esrrhs/gohome/dns"
	"github.com/miekg/dns"
)

func udpAddr(ip string) net.Addr {
	return &net.UDPAddr{IP: net.ParseIP(ip), Port: 40000}
}

func TestParseCIDRToken(t *testing.T) {
	n, err := parseCIDRToken("10.0.0.0/8")
	if err != nil || n.String() != "10.0.0.0/8" {
		t.Fatalf("cidr: %v %v", n, err)
	}
	// 裸 IPv4 → /32。
	n, err = parseCIDRToken("192.168.1.5")
	if err != nil || n.String() != "192.168.1.5/32" {
		t.Fatalf("bare v4: %v %v", n, err)
	}
	if !n.Contains(net.ParseIP("192.168.1.5")) || n.Contains(net.ParseIP("192.168.1.6")) {
		t.Fatal("bare v4 must behave as /32")
	}
	// 裸 IPv6 → /128。
	n, err = parseCIDRToken("::1")
	if err != nil || n.String() != "::1/128" {
		t.Fatalf("bare v6: %v %v", n, err)
	}
	if n, err := parseCIDRToken("   "); err != nil || n != nil {
		t.Fatalf("blank: %v %v", n, err)
	}
	if _, err := parseCIDRToken("not-an-ip/99"); err == nil {
		t.Fatal("garbage must be rejected")
	}

	list, err := parseCIDRList("10.0.0.0/8, 192.168.1.5,")
	if err != nil || len(list) != 2 {
		t.Fatalf("list: %v %v", list, err)
	}
}

func TestParseCIDRFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "acl.txt")
	content := strings.Join([]string{
		"# comment line",
		"  10.0.0.0/8  ",
		"",
		"192.168.0.0/16 # inline comment is NOT supported inside token",
		"1.2.3.4,5.6.7.8", // 一行多个
	}, "\n")
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	// 注意：'#' 之后会被整体截掉，第三行解析为 192.168.0.0/16。
	nets, err := parseCIDRFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(nets) != 4 {
		t.Fatalf("parsed %d nets: %v", len(nets), nets)
	}

	// 非法行必须报错并带行号。
	bad := filepath.Join(dir, "bad.txt")
	if err := os.WriteFile(bad, []byte("10.0.0.0/8\n999.1.1.1\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := parseCIDRFile(bad); err == nil || !strings.Contains(err.Error(), "bad.txt:2") {
		t.Fatalf("bad line error = %v", err)
	}
}

func TestNewClientPolicyValidation(t *testing.T) {
	if _, err := newClientPolicy("garbage", "", nil, nil, 0, 0); err == nil {
		t.Fatal("invalid inline cidr must fail")
	}
	if _, err := newClientPolicy("", "garbage", nil, nil, 0, 0); err == nil {
		t.Fatal("invalid deny cidr must fail")
	}
	if _, err := newClientPolicy("", "", []string{"/no/such/file"}, nil, 0, 0); err == nil {
		t.Fatal("missing allow file must fail")
	}
	if _, err := newClientPolicy("", "", nil, nil, -1, 0); err == nil {
		t.Fatal("negative rate must fail")
	}

	// 默认突发 = 2 倍 QPS（至少 1）。
	p, err := newClientPolicy("", "", nil, nil, 50, 0)
	if err != nil || p.limiterBurst() != 100 {
		t.Fatalf("default burst: %v burst=%d", err, p.limiterBurst())
	}
	p2, err := newClientPolicy("", "", nil, nil, 0.4, 0)
	if err != nil || p2.limiterBurst() != 1 {
		t.Fatalf("small rate burst: %v burst=%d", err, p2.limiterBurst())
	}
	// 关闭限速时无桶表。
	p3, _ := newClientPolicy("", "", nil, nil, 0, 0)
	if p3.limiter != nil {
		t.Fatal("rate=0 must not build a limiter")
	}
}

func TestClientPolicyCheck(t *testing.T) {
	// 白名单模式：allow=10/8 与 192.168.1.5 主机位。
	p, err := newClientPolicy("10.0.0.0/8,192.168.1.5", "10.1.0.0/16", nil, nil, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		ip   string
		want string
	}{
		{"10.2.3.4", aclReasonAllow},    // 命中 allow，且不在 deny 子网
		{"10.1.2.3", aclReasonDeny},     // 同时命中 allow/deny：deny 优先
		{"192.168.1.5", aclReasonAllow}, // 裸 IP 主机位
		{"192.168.1.6", aclReasonDeny},  // 白名单外
		{"8.8.8.8", aclReasonDeny},      // 白名单外
	}
	for _, c := range cases {
		if got := p.check(udpAddr(c.ip)); got != c.want {
			t.Errorf("ip %s: reason=%q want %q", c.ip, got, c.want)
		}
	}

	// 纯黑名单：allow 为空时，未命中 deny 全部放行。
	pd, _ := newClientPolicy("", "8.8.8.8/32", nil, nil, 0, 0)
	if got := pd.check(udpAddr("1.1.1.1")); got != aclReasonAllow {
		t.Fatalf("non-denied ip: %q", got)
	}
	if got := pd.check(udpAddr("8.8.8.8")); got != aclReasonDeny {
		t.Fatalf("denied ip: %q", got)
	}

	// nil 策略与 nil/无法解析地址：一律放行。
	var nilPolicy *clientPolicy
	if got := nilPolicy.check(udpAddr("8.8.8.8")); got != aclReasonAllow {
		t.Fatal("nil policy must allow")
	}
	if got := p.check(nil); got != aclReasonAllow {
		t.Fatal("nil addr must be allowed")
	}
}

func TestClientPolicyReloadFiles(t *testing.T) {
	dir := t.TempDir()
	allowPath := filepath.Join(dir, "allow.txt")
	denyPath := filepath.Join(dir, "deny.txt")
	if err := os.WriteFile(allowPath, []byte("10.0.0.0/8\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(denyPath, []byte("10.1.0.0/16\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	// 内联 allow 192.168/16 必须在文件重载后仍然生效。
	p, err := newClientPolicy("192.168.0.0/16", "", []string{allowPath}, []string{denyPath}, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	if got := p.check(udpAddr("192.168.5.5")); got != aclReasonAllow {
		t.Fatal("inline allow must work initially")
	}

	// 文件更新：allow 改为 172.16/12 与 10.1/16，deny 清空。
	if err := os.WriteFile(allowPath, []byte("172.16.0.0/12,10.1.0.0/16\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(denyPath, []byte("\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := p.reloadFiles(); err != nil {
		t.Fatal(err)
	}
	if got := p.check(udpAddr("10.0.0.1")); got != aclReasonDeny {
		t.Fatal("old file entry must be gone after reload")
	}
	if got := p.check(udpAddr("172.16.0.1")); got != aclReasonAllow {
		t.Fatal("new file entry must take effect")
	}
	if got := p.check(udpAddr("10.1.0.1")); got != aclReasonAllow {
		t.Fatal("cleared deny must no longer reject")
	}
	if got := p.check(udpAddr("192.168.5.5")); got != aclReasonAllow {
		t.Fatal("inline allow must survive file reload")
	}

	// 坏文件：报错且旧规则继续有效。
	if err := os.WriteFile(allowPath, []byte("not-a-cidr\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := p.reloadFiles(); err == nil {
		t.Fatal("bad file reload must error")
	}
	if got := p.check(udpAddr("172.16.0.1")); got != aclReasonAllow {
		t.Fatal("old file rules must remain after failed reload")
	}
}

func TestIPRateLimiter(t *testing.T) {
	l := newIPRateLimiter(50, 5)
	// 新客户端满桶：突发 5 次放行，第 6 次拒绝。
	for i := 0; i < 5; i++ {
		if !l.allow("c1") {
			t.Fatalf("burst query %d should pass", i+1)
		}
	}
	if l.allow("c1") {
		t.Fatal("6th query over burst must be limited")
	}
	// 不同客户端独立计数。
	if !l.allow("c2") {
		t.Fatal("fresh client must get its own bucket")
	}
	// 约 100ms 后补充 ~5 个令牌，重新放行。
	time.Sleep(120 * time.Millisecond)
	if !l.allow("c1") {
		t.Fatal("tokens must refill over time")
	}
}

func TestIPRateLimiterSweepAndCap(t *testing.T) {
	l := newIPRateLimiter(1, 10)
	now := time.Now()
	l.mu.Lock()
	// 造一个长期空闲桶，强制清扫应删除。
	l.clients["idle"] = &tokenBucket{tokens: 10, last: now.Add(-rateIdleAfter - time.Minute)}
	l.clients["active"] = &tokenBucket{tokens: 10, last: now}
	l.sweepLocked(now, true)
	l.mu.Unlock()
	if _, ok := l.clients["idle"]; ok {
		t.Fatal("idle bucket must be swept")
	}
	if _, ok := l.clients["active"]; !ok {
		t.Fatal("recent bucket must survive sweep")
	}

	// 桶数触顶后仍可为新源腾位（LRU 淘汰到 90% 水位再插入），限速不失灵。
	big := newIPRateLimiter(1, 1)
	for i := 0; i < rateMaxClients; i++ {
		big.allow("old-" + strconv.Itoa(i))
	}
	if !big.allow("brand-new-client") {
		t.Fatal("eviction must make room for a new source at cap")
	}
	wantSize := rateMaxClients*9/10 + 1
	if got := big.size(); got != wantSize {
		t.Fatalf("size after eviction=%d want %d", got, wantSize)
	}
	if _, ok := big.clients["brand-new-client"]; !ok {
		t.Fatal("new client bucket missing after eviction")
	}
}

// TestACLExchangeEndToEnd 经 routingResolver 验证：黑名单源 REFUSED，
// 白名单外 REFUSED，放行源拿到真实应答，拒绝计入计数器与查询路由。
func TestACLExchangeEndToEnd(t *testing.T) {
	if _, _, err := loadDomainLists(nil, nil); err != nil {
		t.Fatal(err)
	}
	metrics.reset()
	t.Cleanup(metrics.reset)

	addr, _ := startECSCaptureDNS(t)
	p, err := newClientPolicy("10.0.0.0/8", "10.6.6.6/32", nil, nil, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	r := &routingResolver{
		local:   []exchangeClient{newSocketClient(addr, time.Second)},
		timeout: time.Second,
		policy:  p,
	}

	exchangeAs := func(ip string, qtype uint16) *dns.Msg {
		ctx := gohomedns.ContextWithClientAddr(context.Background(), udpAddr(ip))
		req := new(dns.Msg)
		req.SetQuestion("www.baidu.com.", qtype)
		resp, err := r.Exchange(ctx, req)
		if err != nil {
			t.Fatalf("exchange as %s: %v", ip, err)
		}
		return resp
	}

	// 白名单外 → REFUSED。
	if resp := exchangeAs("8.8.8.8", dns.TypeA); resp.Rcode != dns.RcodeRefused {
		t.Fatalf("outsider rcode=%s, want REFUSED", dns.RcodeToString[resp.Rcode])
	}
	// 命中 deny（即使也在 allow 段）→ REFUSED。
	if resp := exchangeAs("10.6.6.6", dns.TypeA); resp.Rcode != dns.RcodeRefused {
		t.Fatalf("deny-listed rcode=%s", dns.RcodeToString[resp.Rcode])
	}
	// 白名单内 → 上游真实应答。
	if resp := exchangeAs("10.2.3.4", dns.TypeA); resp.Rcode != dns.RcodeSuccess || len(resp.Answer) != 1 {
		t.Fatalf("allowed client rcode=%s answers=%d", dns.RcodeToString[resp.Rcode], len(resp.Answer))
	}
	// 无对端地址（内部调用）→ 放行。
	req := new(dns.Msg)
	req.SetQuestion("www.baidu.com.", dns.TypeA)
	resp, err := r.Exchange(context.Background(), req)
	if err != nil || resp.Rcode != dns.RcodeSuccess {
		t.Fatalf("no-addr exchange: %v rcode=%v", err, resp)
	}

	if n := metrics.aclDenied.Load(); n != 2 {
		t.Fatalf("aclDenied=%d want 2", n)
	}
	if n := metrics.rcRefused.Load(); n != 2 {
		t.Fatalf("rcRefused=%d want 2", n)
	}
}

// TestACLRateLimitEndToEnd 突发耗尽后该客户端收 REFUSED，另一客户端不受影响。
func TestACLRateLimitEndToEnd(t *testing.T) {
	if _, _, err := loadDomainLists(nil, nil); err != nil {
		t.Fatal(err)
	}
	metrics.reset()
	t.Cleanup(metrics.reset)

	addr, _ := startECSCaptureDNS(t)
	// 稳态 1 QPS：真实 UDP 往返耗时（亚毫秒级）补不回令牌，
	// 突发 3 次之后第 4 次必须被拒。
	p, _ := newClientPolicy("", "", nil, nil, 1, 3)
	r := &routingResolver{
		local:   []exchangeClient{newSocketClient(addr, time.Second)},
		timeout: time.Second,
		policy:  p,
	}
	ctx := gohomedns.ContextWithClientAddr(context.Background(), udpAddr("10.0.0.9"))
	ask := func() int {
		req := new(dns.Msg)
		req.SetQuestion("www.baidu.com.", dns.TypeA)
		resp, err := r.Exchange(ctx, req)
		if err != nil {
			t.Fatal(err)
		}
		return resp.Rcode
	}
	for i := 0; i < 3; i++ {
		if ask() != dns.RcodeSuccess {
			t.Fatalf("burst %d should succeed", i+1)
		}
	}
	if ask() != dns.RcodeRefused {
		t.Fatal("4th query must be REFUSED by rate limiter")
	}
	if metrics.rateLimited.Load() != 1 {
		t.Fatalf("rateLimited=%d want 1", metrics.rateLimited.Load())
	}
	// 另一客户端不受影响。
	ctx2 := gohomedns.ContextWithClientAddr(context.Background(), udpAddr("10.0.0.10"))
	req2 := new(dns.Msg)
	req2.SetQuestion("www.baidu.com.", dns.TypeA)
	resp2, err := r.Exchange(ctx2, req2)
	if err != nil || resp2.Rcode != dns.RcodeSuccess {
		t.Fatalf("other client must not be limited: %v %v", err, resp2)
	}
}

func TestACLObservability(t *testing.T) {
	old := aclStatusInfo
	aclStatusInfo = func() (int, int, float64, float64, int) {
		return 2, 1, 100, 200, 7
	}
	t.Cleanup(func() { aclStatusInfo = old })
	metrics.reset()
	t.Cleanup(metrics.reset)
	metrics.aclDenied.Store(3)
	metrics.rateLimited.Store(5)

	s := &statsServer{}
	rec := httptest.NewRecorder()
	s.statsHandler(rec, httptest.NewRequest("GET", "/stats", nil))
	body := rec.Body.String()
	for _, want := range []string{
		`"allow_entries": 2`, `"deny_entries": 1`,
		`"rate_limit_qps": 100`, `"rate_burst": 200`,
		`"active_clients": 7`, `"denied_acl": 3`, `"denied_ratelimit": 5`,
	} {
		if !strings.Contains(body, want) {
			t.Errorf("stats body missing %s\n%s", want, body)
		}
	}

	recM := httptest.NewRecorder()
	s.metricsHandler(recM, httptest.NewRequest("GET", "/metrics", nil))
	mb := recM.Body.String()
	for _, want := range []string{
		`yellowdns_acl_entries{kind="allow"} 2`,
		`yellowdns_acl_entries{kind="deny"} 1`,
		`yellowdns_acl_rate_limit_qps 100`,
		`yellowdns_acl_rate_burst 200`,
		`yellowdns_acl_active_clients 7`,
		`yellowdns_acl_denied_total{reason="acl"} 3`,
		`yellowdns_acl_denied_total{reason="ratelimit"} 5`,
	} {
		if !strings.Contains(mb, want) {
			t.Errorf("metrics body missing %s\n%s", want, mb)
		}
	}
}
