package main

import (
	"context"
	"errors"
	"flag"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/esrrhs/gohome/common"
	gohomedns "github.com/esrrhs/gohome/dns"
	"github.com/esrrhs/gohome/dns/cache"
	"github.com/esrrhs/gohome/dns/upstream"
	"github.com/esrrhs/gohome/loggo"
	"github.com/miekg/dns"
)

// version 由发布构建通过 -ldflags "-X main.version=<tag>" 注入；
// 本地 go build 无注入时显示 dev。
var version = "dev"

// defaultExternalUpstreams 境外上游默认走 DoH：
// 明文 UDP 查询本身就会被中间设备注入伪造应答，加密查询从源头避免。
const defaultExternalUpstreams = "https://1.1.1.1/dns-query,https://8.8.8.8/dns-query"

// exchangeClient 是绕行/兜底路径使用的最小上游接口，统一 UDP/TCP 与 DoH 上游。
type exchangeClient interface {
	Exchange(ctx context.Context, req *dns.Msg) (*dns.Msg, error)
}

// socketClient 传统 UDP/TCP 上游，UDP 失败时按 DNS 惯例回退 TCP。
type socketClient struct {
	addr    string
	network string // "udp" or "tcp"
	timeout time.Duration
}

func newSocketClient(spec string, timeout time.Duration) *socketClient {
	network := "udp"
	addr := spec
	if rest, ok := strings.CutPrefix(spec, "tcp://"); ok {
		network = "tcp"
		addr = rest
	} else if rest, ok := strings.CutPrefix(spec, "udp://"); ok {
		addr = rest
	}
	return &socketClient{addr: withPort(addr), network: network, timeout: timeout}
}

func (c *socketClient) Exchange(ctx context.Context, req *dns.Msg) (*dns.Msg, error) {
	client := &dns.Client{Net: c.network, Timeout: c.timeout}
	resp, _, err := client.Exchange(req, c.addr)
	if err != nil && c.network == "udp" {
		tcpClient := &dns.Client{Net: "tcp", Timeout: c.timeout}
		resp, _, err = tcpClient.Exchange(req, c.addr)
	}
	return resp, err
}

// upstreamFor 按地址形式构造兜底路径的上游：http(s) 走 DoH，其余走 UDP/TCP。
func upstreamFor(spec string, timeout time.Duration) (exchangeClient, error) {
	if strings.HasPrefix(spec, "https://") || strings.HasPrefix(spec, "http://") {
		return upstream.NewDoHUpstream(spec, "")
	}
	return newSocketClient(spec, timeout), nil
}

// splitUpstreams 解析逗号分隔的上游列表，跳过空项。
func splitUpstreams(spec string) []string {
	var list []string
	for _, addr := range strings.Split(spec, ",") {
		if addr = strings.TrimSpace(addr); addr != "" {
			list = append(list, addr)
		}
	}
	return list
}

// namedUpstream 给兜底/绕行路径的上游绑定组名（local/extern）与配置地址，
// 使分上游指标能按配置项归因；同名组合下地址相同的项共享同一组计数器。
type namedUpstream struct {
	name  string
	group string
	stats *perUpstreamCounters
	exchangeClient
}

// buildUpstreams 构造兜底路径的上游列表，非法地址跳过并告警，全部非法时报错。
// group 为 "local" 或 "extern"，仅用于指标归因。
func buildUpstreams(group, spec string, timeout time.Duration) ([]exchangeClient, error) {
	addrs := splitUpstreams(spec)
	if len(addrs) == 0 {
		return nil, errors.New("empty upstream list")
	}
	var list []exchangeClient
	for _, addr := range addrs {
		u, err := upstreamFor(addr, timeout)
		if err != nil {
			loggo.Warn("skip invalid upstream %q: %v", addr, err)
			continue
		}
		name := addr
		if c, ok := u.(*socketClient); ok {
			name = c.addr // socket 上游用补全端口后的实际地址
		}
		list = append(list, &namedUpstream{
			name:           name,
			group:          group,
			stats:          registerUpstream(group, name),
			exchangeClient: u,
		})
	}
	if len(list) == 0 {
		return nil, errors.New("no valid upstream in " + spec)
	}
	return list, nil
}

// observe 记录一次该上游的兜底查询结果（成功/失败、耗时、错误摘要）。
func (u *namedUpstream) observe(ok bool, d time.Duration, err error) {
	u.stats.record(ok, d, err)
}

// withPort 为缺省端口的上游地址补 ":53"，与 gohome 上游的宽容解析保持一致。
func withPort(addr string) string {
	if _, _, err := net.SplitHostPort(addr); err != nil {
		return net.JoinHostPort(addr, "53")
	}
	return addr
}

// routingResolver 在 gohome resolver 之上补充两层路由：
//   - 被 gohome 直连域名树遮蔽的 gfw 域名（父域命中直连规则，如 china 列表的
//     recaptcha.net 遮蔽 gfw 的 api.recaptcha.net）强制走境外上游；
//   - gohome resolver 初始化失败或查询失败时，按域名分类直接查境内/境外上游兜底。
//
// 内嵌 gohomedns.Resolver 以透传其余接口方法；Server 只会调用 Exchange。
type routingResolver struct {
	gohomedns.Resolver

	inner    gohomedns.Resolver
	local    []exchangeClient
	external []exchangeClient
	timeout  time.Duration

	// stale 是独立于 gohome 内置缓存的"最后一份好应答"备份；staleTTL 为 0
	// （功能关闭）时不写入也不读取。minTTL/maxTTL 对上游应答做 TTL 收敛，
	// 即使不启用 serve-stale 也生效。
	stale    *staleStore
	staleTTL time.Duration
	minTTL   time.Duration
	maxTTL   time.Duration

	// qlog 为可选的结构化查询日志；nil 表示关闭，recordQueryLog 直接跳过。
	qlog *queryLogger

	// ecs 为可选的 EDNS Client Subnet 策略（固定附加/剥离）；
	// nil 表示不干预，客户端自带 ECS 随上游请求原样转发。
	ecs *ecsPolicy

	// policy 为可选的客户端访问控制/限速策略；nil 表示全部放行。
	policy *clientPolicy
}

func (r *routingResolver) Exchange(ctx context.Context, req *dns.Msg) (resp *dns.Msg, err error) {
	metrics.inFlight.Add(1)
	defer metrics.inFlight.Add(-1)
	start := time.Now()
	// routeLabel 记录最终走的路由，供端到端延迟直方图归因。
	routeLabel := routeAutoLabel
	servedStale := false
	defer func() {
		metrics.observeLatency(routeLabel, time.Since(start))
		metrics.observeResult(resp, err)
		r.recordQueryLog(ctx, req, servedStale, routeLabel, start, resp, err)
	}()
	if len(req.Question) == 0 {
		return nil, errors.New("empty dns question")
	}
	q := req.Question[0]
	metrics.observeQuery(q.Qtype)

	// 客户端访问控制/限速先于一切解析动作：被拒的请求既不命中 hosts/缓存，
	// 也不会消耗任何上游资源。统一回 REFUSED（而非静默丢包），便于客户端
	// 立即故障转移，也让拒绝在查询日志/响应码统计中可见。
	if reason := r.policy.check(clientAddrFromContext(ctx)); reason != aclReasonAllow {
		routeLabel = routeDenyLabel
		metrics.observeACLReject(reason)
		loggo.Info("client denied by %s: %s (%s %s)", reason,
			clientAddrFromContext(ctx), dns.TypeToString[q.Qtype], q.Name)
		reply := new(dns.Msg)
		reply.SetRcode(req, dns.RcodeRefused)
		return reply, nil
	}

	// 静态 hosts 规则优先级最高，命中即合成应答，不查任何上游。
	if hit, ok := hostsAnswer(req); ok {
		metrics.hostsHits.Add(1)
		routeLabel = routeHostsLabel
		loggo.Info("route hosts %s", q.Name)
		return hit, nil
	}

	// ECS 只影响发往上游的报文（gohome/绕行/兜底三条路径共用同一个 req），
	// hosts 合成应答不需要；放在所有上游分支之前统一改写一次。
	if applyECS(req, r.ecs) {
		metrics.ecsApplied.Add(1)
	}

	mode := classifyName(q.Name)
	routeLabel = routeLabelOf(mode)
	if mode == routeExtern && externShadowedHit(q.Name) {
		loggo.Info("route %s %s", routeName(routeExtern), q.Name)
		metrics.observeRoute(routeExtern, true)
		resp, err = exchangeList(ctx, r.external, req, r.timeout)
		if err == nil && resp != nil {
			return r.rememberAnswer(req, resp), nil
		}
		if stale, ok := r.serveStale(req); ok {
			servedStale = true
			return stale, nil
		}
		return nil, err
	}

	if r.inner != nil {
		resp, err = r.inner.Exchange(ctx, req)
		if err == nil && resp != nil {
			metrics.observeRoute(mode, false)
			return r.rememberAnswer(req, resp), nil
		}
		loggo.Warn("gohome resolver Exchange fail %v, fallback to direct upstream", err)
	}

	list := r.local
	if mode == routeExtern {
		list = r.external
	}
	loggo.Info("route %s %s", routeName(mode), q.Name)
	metrics.fallback.Add(1)
	metrics.observeRoute(mode, false)
	resp, err = exchangeList(ctx, list, req, r.timeout)
	if err == nil && resp != nil {
		return r.rememberAnswer(req, resp), nil
	}
	// 所有上游都失败：若最近成功解析过该名字，在允许窗口内返回旧应答，
	// 让断网/上游抖动期间的业务至少拿到一个大概率仍可用的地址。
	if stale, ok := r.serveStale(req); ok {
		servedStale = true
		return stale, nil
	}
	return nil, err
}

// staleKey 与 gohome 内置缓存使用同一套 key 规则（小写、去尾点）。
func staleKey(q dns.Question) string {
	return cache.KeyForMsg(q.Name, q.Qtype, q.Qclass)
}

// rememberAnswer 对成功应答套用 min/max TTL 收敛，并登记到 serve-stale 备份。
// 只备份带 Answer 的正向应答（与 gohome 内置缓存的落盘口径一致）；
// NODATA/NXDOMAIN 等否定应答不备份。
func (r *routingResolver) rememberAnswer(req *dns.Msg, resp *dns.Msg) *dns.Msg {
	if resp == nil || len(resp.Answer) == 0 {
		return resp
	}
	effective := clampResponseTTL(resp, r.minTTL, r.maxTTL)
	if r.stale != nil && r.staleTTL > 0 && effective > 0 {
		r.stale.put(staleKey(req.Question[0]), resp, time.Now().Add(effective))
	}
	return resp
}

// serveStale 在全部上游失败后尝试返回备份应答。新鲜期内的备份按剩余 TTL
// 衰减返回；已过期但在 staleTTL 窗口内的备份以固定小 TTL 返回。
func (r *routingResolver) serveStale(req *dns.Msg) (*dns.Msg, bool) {
	if r.stale == nil || r.staleTTL <= 0 {
		return nil, false
	}
	entry, expired, ok := r.stale.get(staleKey(req.Question[0]), r.staleTTL)
	if !ok {
		return nil, false
	}
	entry.Id = req.Id
	entry.Question = req.Question
	metrics.staleServed.Add(1)
	q := req.Question[0]
	if expired {
		loggo.Warn("serve stale answer for %s type %d, all upstreams failed", q.Name, q.Qtype)
	} else {
		loggo.Info("serve backup answer for %s type %d while all upstreams are unavailable", q.Name, q.Qtype)
	}
	return entry, true
}

// exchangeList 依次尝试上游列表，任一成功即返回（failover）。
func exchangeList(ctx context.Context, list []exchangeClient, req *dns.Msg, timeout time.Duration) (*dns.Msg, error) {
	var lastErr error
	for _, u := range list {
		metrics.upAttempts.Add(1)
		start := time.Now()
		resp, err := exchangeOne(ctx, u, req, timeout)
		elapsed := time.Since(start)
		if named, ok := u.(*namedUpstream); ok {
			named.observe(err == nil && resp != nil, elapsed, err)
		}
		if err == nil && resp != nil {
			return resp, nil
		}
		metrics.upErrors.Add(1)
		lastErr = err
	}
	if lastErr == nil {
		lastErr = errors.New("no upstream configured")
	}
	return nil, lastErr
}

func exchangeOne(ctx context.Context, u exchangeClient, req *dns.Msg, timeout time.Duration) (*dns.Msg, error) {
	if _, ok := ctx.Deadline(); ok || timeout <= 0 {
		return u.Exchange(ctx, req)
	}
	callCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	return u.Exchange(callCtx, req)
}

// cacheLen 返回 gohome 响应缓存当前条目数；resolver 不可用时为 0。
func (r *routingResolver) cacheLen() int {
	if r.inner == nil {
		return 0
	}
	return r.inner.CacheLen()
}

// cacheStats 返回 gohome 响应缓存条目数与累计命中/未命中；resolver 不可用时全为 0。
func (r *routingResolver) cacheStats() (int, int64, int64) {
	if r.inner == nil {
		return 0, 0, 0
	}
	return r.inner.CacheLen(), r.inner.CacheHits(), r.inner.CacheMisses()
}

// staleLen 返回 serve-stale 备份条目数；功能未初始化时为 0。
func (r *routingResolver) staleLen() int {
	if r.stale == nil {
		return 0
	}
	return r.stale.len()
}

// flushCache 清空 gohome 响应缓存与 serve-stale 备份，返回清空前的条目总数
// （供运维确认效果）。
func (r *routingResolver) flushCache() int {
	n := 0
	if r.inner != nil {
		n = r.inner.CacheLen()
		r.inner.ClearCache()
	}
	if r.stale != nil {
		n += r.stale.len()
		r.stale.clear()
	}
	return n
}

// reload 重新加载内置、远端与用户附加的域名列表及 hosts 规则，热替换 resolver
// 的分流树与 GeoIP 库，并清空响应缓存，使新规则对下一次查询立即生效。
// 任一文件读取失败时整体放弃并保留旧状态。
func (r *routingResolver) reload(chinaFiles, gfwFiles, hostsFiles []string, geoFile string) (chinaN, gfwN, hostsN int, err error) {
	// 两份规则都先解析成功再依次替换快照：任一失败，旧状态完整保留。
	hostsSnap, err := parseHostsFiles(hostsFiles)
	if err != nil {
		return 0, 0, 0, err
	}
	chinaN, gfwN, err = loadDomainLists(chinaFiles, gfwFiles)
	if err != nil {
		return 0, 0, 0, err
	}
	hostsState.Store(hostsSnap)
	hostsN = len(hostsSnap.exact) + len(hostsSnap.wildcard)
	d := currentDomains()
	if r.inner != nil {
		r.inner.UpdateDirectDomains(domainKeys(d.china))
		r.inner.UpdateProxyDomains(domainKeys(d.gfw))
		if e := r.inner.ReloadGeoIPDatabase(geoFile); e != nil {
			loggo.Warn("reload geoip database fail %v", e)
		}
		// 已缓存的应答不会重新经过分流判定，清掉以免旧路由残留到 TTL 到期。
		r.inner.ClearCache()
	}
	// 备份应答同样不经过分流判定，规则变更后一并清空，避免把改名/换路由的
	// 旧地址在故障窗口里重新发给客户端。
	if r.stale != nil {
		r.stale.clear()
	}
	return chinaN, gfwN, hostsN, nil
}

func main() {
	defer common.CrashLog()

	listen := flag.String("l", ":53", "listen addr (udp and tcp)")
	tlsListen := flag.String("tls", "", "DNS-over-TLS (RFC 7858) listen addr (e.g. :853 or 127.0.0.1:853); empty disables. Reuses the same resolver as -l")
	tlsCert := flag.String("tls-cert", "", "TLS certificate file (PEM) for -tls; required when -tls is set")
	tlsKey := flag.String("tls-key", "", "TLS private key file (PEM, unencrypted) for -tls; required when -tls is set. Reloaded together with rules on SIGHUP for cert renewal")
	localserer := flag.String("los", "114.114.114.114:53", "local dns servers, comma-separated; host:port=UDP, tcp://host:port=TCP, https://host/dns-query=DoH")
	externalserver := flag.String("exs", defaultExternalUpstreams, "external dns servers, comma-separated; same formats as -los")
	localregion := flag.String("lor", "CN", "local region")
	localregionfile := flag.String("lof", "GeoLite2-Country.mmdb", "local region file")
	timeout := flag.Int("timeout", 5000, "wait response timeout in ms")
	chinaFile := flag.String("china", "", "extra china domain list")
	gfwFile := flag.String("gfw", "", "extra blocked domain list")
	hostsFile := flag.String("hosts", "", "static hosts file (standard hosts format or dnsmasq address=/name/ip lines)")
	updateEvery := flag.Duration("update", 0, "auto-update remote china/gfw lists and GeoIP database at this interval (e.g. 24h); 0 disables")
	updateDir := flag.String("update-dir", ".", "directory to store downloaded remote lists and GeoIP database")
	shutdownDelay := flag.Duration("shutdown-delay", 0, "delay between /readyz turning 503 and closing DNS listeners on SIGTERM/SIGINT, giving load balancers time to drain (e.g. 2s); 0 disables")
	cacheSize := flag.Int("cache-size", 2000, "response cache capacity in entries (gohome cache and serve-stale backup share this limit)")
	cacheMinTTL := flag.Duration("cache-min-ttl", 0, "floor TTL applied to every upstream answer before caching and replying (e.g. 60s); 0 disables")
	cacheMaxTTL := flag.Duration("cache-max-ttl", 0, "ceiling TTL applied to every upstream answer before caching and replying (e.g. 24h); 0 disables")
	serveStale := flag.Duration("serve-stale", 0, "when all upstreams fail, keep replying with the last good answer for this long past its TTL (e.g. 24h); stale replies carry a 5s TTL. 0 disables")
	queryLogFile := flag.String("query-log", "", "write one JSON line per query to this file (e.g. query.log); '-' writes to stdout; empty disables. Rotated by size and reopened on SIGHUP")
	queryLogMaxMB := flag.Int("query-log-max-mb", 100, "rotate the query log after it reaches this size in MiB; 0 disables size rotation")
	queryLogMaxFiles := flag.Int("query-log-max-files", 5, "number of rotated query log files to keep (query.log.1 .. query.log.N)")
	ecsCIDR := flag.String("ecs", "", "EDNS Client Subnet CIDR to add/override on upstream A/AAAA queries (e.g. -ecs 1.2.3.0/24), so CDN-savvy upstreams answer for that region; empty leaves client ECS untouched")
	ecsStrip := flag.Bool("ecs-strip", false, "remove any EDNS Client Subnet option before forwarding to upstreams (privacy mode); mutually exclusive with -ecs")
	allowCIDR := flag.String("allow", "", "comma-separated client CIDRs/IPs allowed to query (whitelist mode); empty allows everyone except -deny entries, e.g. -allow 10.0.0.0/8,192.168.1.5")
	denyCIDR := flag.String("deny", "", "comma-separated client CIDRs/IPs refused service; deny always wins over allow")
	allowFile := flag.String("allow-file", "", "file of allowed client CIDRs/IPs (one per line, '#' comments); reloaded on SIGHUP")
	denyFile := flag.String("deny-file", "", "file of denied client CIDRs/IPs (one per line, '#' comments); reloaded on SIGHUP")
	rateLimit := flag.Float64("rate-limit", 0, "per-client sustained query rate limit in QPS (e.g. 100); 0 disables. New clients start with a full burst bucket")
	rateBurst := flag.Int("rate-burst", 0, "per-client burst capacity in queries; 0 defaults to twice -rate-limit (minimum 1)")
	statsAddr := flag.String("stats", "", "HTTP listen addr for /stats JSON (e.g. 127.0.0.1:8053); empty disables")
	pprofEnabled := flag.Bool("pprof", false, "expose Go pprof profilers at /debug/pprof/ on the -stats HTTP server (same bearer token as /stats); do not enable without a token on a non-loopback address")
	statsToken := flag.String("stats-token", "", "bearer token required for /stats; defaults to YELLOWDNS_STATS_TOKEN env. Prefer the env var so the token is not visible via ps")
	nolog := flag.Int("nolog", 0, "write log file")
	noprint := flag.Int("noprint", 0, "print stdout")
	loglevel := flag.String("loglevel", "info", "log level")
	showVersion := flag.Bool("version", false, "show version and exit")

	flag.Parse()

	if *showVersion {
		println("yellowdns version " + version)
		return
	}

	if *listen == "" || *localserer == "" ||
		*externalserver == "" || *localregion == "" ||
		*localregionfile == "" {
		flag.Usage()
		return
	}

	level := loggo.LEVEL_INFO
	if loggo.NameToLevel(*loglevel) >= 0 {
		level = loggo.NameToLevel(*loglevel)
	}
	loggo.Ini(loggo.Config{
		Level:     level,
		Prefix:    "yellowdns",
		MaxDay:    3,
		NoLogFile: *nolog > 0,
		NoPrint:   *noprint > 0,
	})
	loggo.Info("start yellowdns %s", version)

	timeoutD := time.Duration(*timeout) * time.Millisecond

	if *cacheSize <= 0 {
		loggo.Error("-cache-size must be positive, got %d", *cacheSize)
		return
	}
	if *cacheMinTTL > 0 && *cacheMaxTTL > 0 && *cacheMinTTL > *cacheMaxTTL {
		loggo.Error("-cache-min-ttl %v must not be greater than -cache-max-ttl %v", *cacheMinTTL, *cacheMaxTTL)
		return
	}
	if *queryLogMaxMB < 0 || *queryLogMaxFiles < 0 {
		loggo.Error("-query-log-max-mb and -query-log-max-files must not be negative")
		return
	}
	ecsPolicy, err := parseECSPolicy(*ecsCIDR, *ecsStrip)
	if err != nil {
		loggo.Error("%v", err)
		return
	}
	if err := validateTLSConfig(*tlsListen, *tlsCert, *tlsKey); err != nil {
		loggo.Error("%v", err)
		return
	}
	var allowFiles, denyFiles []string
	if *allowFile != "" {
		allowFiles = []string{*allowFile}
	}
	if *denyFile != "" {
		denyFiles = []string{*denyFile}
	}
	clientPolicyRule, err := newClientPolicy(*allowCIDR, *denyCIDR, allowFiles, denyFiles, *rateLimit, *rateBurst)
	if err != nil {
		loggo.Error("%v", err)
		return
	}
	if ecsPolicy != nil && ecsPolicy.isPrivateScope() {
		loggo.Warn("-ecs %s is a private/local range: it leaks no real topology but gives upstreams no useful geo hint", ecsPolicy.net)
	}

	if *updateEvery > 0 {
		if err := os.MkdirAll(*updateDir, 0o755); err != nil {
			loggo.Error("create update dir %v", err)
			return
		}
	}

	// 探针服务最先上线：此时规则与 DNS 监听尚未就绪，/readyz 如实返回 503，
	// 避免启动窗口内的实例被负载均衡提前放入。
	var stats *statsServer
	if *statsAddr != "" {
		// flag 优先，环境变量兜底，避免 token 出现在进程参数中被 ps 看到。
		token := *statsToken
		if token == "" {
			token = os.Getenv("YELLOWDNS_STATS_TOKEN")
		}
		if token == "" && !isLoopbackAddr(*statsAddr) {
			loggo.Warn("stats endpoint on %s has no token and is not loopback-only; set -stats-token or YELLOWDNS_STATS_TOKEN", *statsAddr)
		}
		if *pprofEnabled && token == "" && !isLoopbackAddr(*statsAddr) {
			loggo.Error("refusing to expose /debug/pprof/ on non-loopback %s without a token; set -stats-token or YELLOWDNS_STATS_TOKEN, or bind 127.0.0.1", *statsAddr)
			return
		}
		stats = startStatsServer(*statsAddr, token, *pprofEnabled)
	} else if *pprofEnabled {
		loggo.Warn("-pprof has no effect without -stats; /debug/pprof/ is served by the stats HTTP server")
	}

	// 远端列表/GeoIP 库（若已存在）+ 用户附加文件，二者都合并进内置集合。
	remoteChinaPath := filepath.Join(*updateDir, remoteChinaFile)
	remoteGfwPath := filepath.Join(*updateDir, remoteGfwFile)
	remoteGeoPath := filepath.Join(*updateDir, remoteGeoFile)
	userChinaFiles := []string{*chinaFile}
	userGfwFiles := []string{*gfwFile}
	userHostsFiles := []string{*hostsFile}
	// 已落盘的远端 GeoIP 库优先于 -lof 内置库；不存在时回退内置库。
	geoFile := *localregionfile
	if p := remoteIfExist(remoteGeoPath); len(p) > 0 {
		geoFile = p[0]
		loggo.Info("using downloaded geoip database %s", geoFile)
	}

	hostsN, err := loadHosts(userHostsFiles)
	if err != nil {
		loggo.Error("load hosts file %v", err)
		return
	}
	loggo.Info("hosts rules %d", hostsN)

	chinaN, gfwN, err := loadDomainLists(
		append(remoteIfExist(remoteChinaPath), userChinaFiles...),
		append(remoteIfExist(remoteGfwPath), userGfwFiles...))
	if err != nil {
		loggo.Error("load domain list %v", err)
		return
	}
	doms := currentDomains()
	loggo.Info("domain list china %d gfw %d, shadowed extern %d", chinaN, gfwN, len(doms.shadowed))

	localAddrs := splitUpstreams(*localserer)
	externalAddrs := splitUpstreams(*externalserver)
	if len(localAddrs) == 0 || len(externalAddrs) == 0 {
		loggo.Error("empty upstream list: los %q exs %q", *localserer, *externalserver)
		return
	}
	loggo.Info("local upstreams %v, external upstreams %v", localAddrs, externalAddrs)

	cfg := gohomedns.DefaultConfig()
	cfg.EnableFakeIP = false
	cfg.DirectUpstreams = localAddrs
	cfg.RemoteUpstreams = externalAddrs
	cfg.GeoIPFile = geoFile
	cfg.RegionCode = *localregion
	cfg.DirectDomains = domainKeys(doms.china)
	cfg.ProxyDomains = domainKeys(doms.gfw)
	cfg.Timeout = timeoutD
	cfg.CacheCapacity = *cacheSize

	localUpstreams, err := buildUpstreams("local", *localserer, timeoutD)
	if err != nil {
		loggo.Error("local upstream %v", err)
		return
	}
	externalUpstreams, err := buildUpstreams("extern", *externalserver, timeoutD)
	if err != nil {
		loggo.Error("external upstream %v", err)
		return
	}

	res, err := gohomedns.NewResolver(cfg)
	if err != nil {
		loggo.Warn("new gohome resolver error %v, classify fallback only", err)
	}

	// 查询日志为可选组件：文件打不开只影响审计，不应阻止 DNS 服务启动，
	// 因此失败时告警并按关闭处理。
	var qlog *queryLogger
	if *queryLogFile != "" {
		ql, err := newQueryLoggerWithLimit(
			queryLogAbs(*queryLogFile),
			int64(*queryLogMaxMB)*1024*1024,
			*queryLogMaxFiles,
		)
		if err != nil {
			loggo.Error("open query log %q fail: %v; query logging disabled", *queryLogFile, err)
		} else {
			qlog = ql
			loggo.Info("query log enabled: %s (max %d MiB x %d files)", *queryLogFile, *queryLogMaxMB, *queryLogMaxFiles)
		}
	}

	rr := &routingResolver{
		inner:    res,
		local:    localUpstreams,
		external: externalUpstreams,
		timeout:  timeoutD,
		stale:    newStaleStore(*cacheSize),
		staleTTL: *serveStale,
		minTTL:   *cacheMinTTL,
		maxTTL:   *cacheMaxTTL,
		qlog:     qlog,
		ecs:      ecsPolicy,
		policy:   clientPolicyRule,
	}
	// 探针服务先于 resolver 启动，回调在 resolver 就绪后补注入。
	cacheStats = rr.cacheStats
	staleStats = rr.staleLen
	if qlog != nil {
		queryLogStatus = func() (enabled bool, written, dropped int64) {
			w, d := qlog.stats()
			return true, w, d
		}
	}
	if *serveStale > 0 {
		loggo.Info("serve-stale enabled: last good answer kept for %v past expiry", *serveStale)
	}
	if *cacheMinTTL > 0 || *cacheMaxTTL > 0 {
		loggo.Info("cache ttl clamp: min=%v max=%v", *cacheMinTTL, *cacheMaxTTL)
	}
	if ecsPolicy != nil {
		ecsModeLabel.Store(ecsPolicy.ecsLabel())
		loggo.Info("EDNS client subnet policy: %s", ecsPolicy.ecsLabel())
	}
	aclAllowN, aclDenyN := clientPolicyRule.entryCounts()
	if aclAllowN > 0 || aclDenyN > 0 || *rateLimit > 0 {
		aclStatusInfo = func() (int, int, float64, float64, int) {
			a, d := clientPolicyRule.entryCounts()
			return a, d, *rateLimit, float64(clientPolicyRule.limiterBurst()), clientPolicyRule.rateClients()
		}
		loggo.Info("client access control: allow %d entries, deny %d entries, per-client rate %v qps (burst %d)",
			aclAllowN, aclDenyN, *rateLimit, clientPolicyRule.limiterBurst())
	}
	if stats != nil {
		stats.flushCache = rr.flushCache
	}

	srv := gohomedns.NewServer(*listen, rr)
	if err := srv.Start(); err != nil {
		loggo.Error("dns server start fail %v", err)
		return
	}
	loggo.Info("listening on %s (udp+tcp)", srv.Addr())

	// 可选的 DoT 监听器：明文监听已 bind 成功后再启动 TLS，失败则把明文
	// 监听一并停掉后退出，避免"只有一半入站"的实例进入就绪。
	var dot *dotServer
	if *tlsListen != "" {
		dot, err = newDoTServer(*tlsListen, *tlsCert, *tlsKey, rr)
		if err != nil {
			loggo.Error("dns-over-tls server start fail %v", err)
			_ = srv.Stop()
			return
		}
		dotStatus = func() bool { return true }
		loggo.Info("listening on %s (dns-over-tls)", *tlsListen)
	}

	// currentGeoFile 在每次重载时重新选择：自动更新落盘新库后，HUP/更新触发的
	// 重载都应立即切到远端库；远端库被移除时回退 -lof 内置库。
	currentGeoFile := func() string {
		if p := remoteIfExist(remoteGeoPath); len(p) > 0 {
			return p[0]
		}
		return *localregionfile
	}
	// 采集当前在役库的新鲜度元信息供 /stats 暴露；无库或损坏时保持 loaded=false，
	// 不影响服务启动（后续成功更新会再次采集）。
	if err := refreshGeoMeta(currentGeoFile()); err != nil {
		loggo.Debug("capture geoip metadata fail: %v", err)
	}
	apply := func(chinaFiles, gfwFiles []string, gf string) (int, int, int, error) {
		return rr.reload(chinaFiles, gfwFiles, userHostsFiles, gf)
	}

	u := &updater{
		chinaURL:     defaultChinaListURL,
		gfwURL:       defaultGFWListURL,
		dir:          *updateDir,
		interval:     *updateEvery,
		apply:        apply,
		localGeoFile: *localregionfile,
		extraChina:   userChinaFiles,
		extraGfw:     userGfwFiles,
	}
	updateStatusInfo = func() (bool, time.Duration) {
		return *updateEvery > 0, *updateEvery
	}
	if *updateEvery > 0 {
		// 带缓冲的 trigger：HTTP 请求在 run 循环忙时等待执行，不丢请求。
		u.trigger = make(chan updateRequest, 1)
		if stats != nil {
			stats.triggerUpdate = u.requestRun
		}
		go u.run()
		loggo.Info("auto update enabled, interval %v, dir %s", *updateEvery, *updateDir)
	}

	// DNS 监听、规则加载、上游与探针服务均已就位，对就绪探针放行。
	ready.Store(true)

	done := make(chan struct{})
	// HUP 重载的范围与启动一致：已落盘的远端列表/GeoIP 库 + 用户附加文件，
	// 否则 HUP 会把自动更新已生效的规则悄悄回退。
	reloadAll := func() (int, int, int, error) {
		return apply(
			append(remoteIfExist(remoteChinaPath), userChinaFiles...),
			append(remoteIfExist(remoteGfwPath), userGfwFiles...),
			currentGeoFile())
	}
	setupSignalHandler(
		func() {
			cn, gfw, hostsN, e := reloadAll()
			if e != nil {
				loggo.Error("reload fail, keep old rules: %v", e)
			} else {
				// 规则重载成功才重新打开查询日志，避免把半次重载写进日志。
				qlog.reopen()
				loggo.Info("reload ok china %d gfw %d hosts %d shadowed %d", cn, gfw, hostsN, len(currentDomains().shadowed))
			}
			// 证书重载与规则相互独立：即使规则重载失败也要处理续期；
			// 坏证书保留旧证书继续服务。
			if dot != nil {
				if err := dot.reloadCert(); err != nil {
					loggo.Warn("tls cert reload fail: %v", err)
				} else {
					loggo.Info("tls cert reloaded")
				}
			}
			// ACL 规则文件同样独立热重载，坏文件保留旧规则；
			// 未配置 -allow-file/-deny-file 时为空操作。
			if len(allowFiles)+len(denyFiles) > 0 {
				if err := clientPolicyRule.reloadFiles(); err != nil {
					loggo.Warn("client acl reload fail: %v", err)
				} else {
					a, d := clientPolicyRule.entryCounts()
					loggo.Info("client acl reloaded allow %d deny %d", a, d)
				}
			}
		},
		func() {
			loggo.Info("stopping...")
			// 先摘就绪，探针 HTTP 服务在延迟窗口内继续返回 503，DNS 继续处理存量请求，
			// 给负载均衡一个观察到未就绪并摘除实例的窗口，然后再关监听。
			ready.Store(false)
			if *shutdownDelay > 0 {
				loggo.Info("draining for %v before closing listeners", *shutdownDelay)
				time.Sleep(*shutdownDelay)
			}
			_ = srv.Stop()
			_ = dot.stop()
			// 监听器停止后不会再有新查询，排空查询日志队列再退出。
			qlog.close(2 * time.Second)
			if stats != nil {
				stats.close()
			}
			close(done)
		},
	)
	<-done
}
