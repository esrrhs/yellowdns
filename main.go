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

// buildUpstreams 构造兜底路径的上游列表，非法地址跳过并告警，全部非法时报错。
func buildUpstreams(spec string, timeout time.Duration) ([]exchangeClient, error) {
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
		list = append(list, u)
	}
	if len(list) == 0 {
		return nil, errors.New("no valid upstream in " + spec)
	}
	return list, nil
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
}

func (r *routingResolver) Exchange(ctx context.Context, req *dns.Msg) (*dns.Msg, error) {
	if len(req.Question) == 0 {
		return nil, errors.New("empty dns question")
	}
	q := req.Question[0]
	metrics.observeQuery(q.Qtype)

	// 静态 hosts 规则优先级最高，命中即合成应答，不查任何上游。
	if resp, ok := hostsAnswer(req); ok {
		metrics.hostsHits.Add(1)
		loggo.Info("route hosts %s", q.Name)
		return resp, nil
	}

	mode := classifyName(q.Name)
	if mode == routeExtern && externShadowedHit(q.Name) {
		loggo.Info("route %s %s", routeName(routeExtern), q.Name)
		metrics.observeRoute(routeExtern, true)
		return exchangeList(ctx, r.external, req, r.timeout)
	}

	if r.inner != nil {
		resp, err := r.inner.Exchange(ctx, req)
		if err == nil && resp != nil {
			metrics.observeRoute(mode, false)
			return resp, nil
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
	return exchangeList(ctx, list, req, r.timeout)
}

// exchangeList 依次尝试上游列表，任一成功即返回（failover）。
func exchangeList(ctx context.Context, list []exchangeClient, req *dns.Msg, timeout time.Duration) (*dns.Msg, error) {
	var lastErr error
	for _, u := range list {
		metrics.upAttempts.Add(1)
		resp, err := exchangeOne(ctx, u, req, timeout)
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
	return chinaN, gfwN, hostsN, nil
}

func main() {
	defer common.CrashLog()

	listen := flag.String("l", ":53", "listen addr (udp and tcp)")
	localserer := flag.String("los", "114.114.114.114:53", "local dns servers, comma-separated; host:port=UDP, tcp://host:port=TCP, https://host/dns-query=DoH")
	externalserver := flag.String("exs", defaultExternalUpstreams, "external dns servers, comma-separated; same formats as -los")
	localregion := flag.String("lor", "CN", "local region")
	localregionfile := flag.String("lof", "GeoLite2-Country.mmdb", "local region file")
	timeout := flag.Int("timeout", 5000, "wait response timeout in ms")
	chinaFile := flag.String("china", "", "extra china domain list")
	gfwFile := flag.String("gfw", "", "extra blocked domain list")
	hostsFile := flag.String("hosts", "", "static hosts file (standard hosts format or dnsmasq address=/name/ip lines)")
	updateEvery := flag.Duration("update", 0, "auto-update remote china/gfw lists at this interval (e.g. 24h); 0 disables")
	updateDir := flag.String("update-dir", ".", "directory to store downloaded remote lists")
	statsAddr := flag.String("stats", "", "HTTP listen addr for /stats JSON (e.g. 127.0.0.1:8053); empty disables")
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

	if *updateEvery > 0 {
		if err := os.MkdirAll(*updateDir, 0o755); err != nil {
			loggo.Error("create update dir %v", err)
			return
		}
	}
	// 远端列表（若已存在）+ 用户附加文件，二者都合并进内置集合。
	remoteChinaPath := filepath.Join(*updateDir, remoteChinaFile)
	remoteGfwPath := filepath.Join(*updateDir, remoteGfwFile)
	userChinaFiles := []string{*chinaFile}
	userGfwFiles := []string{*gfwFile}
	userHostsFiles := []string{*hostsFile}

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
	cfg.GeoIPFile = *localregionfile
	cfg.RegionCode = *localregion
	cfg.DirectDomains = domainKeys(doms.china)
	cfg.ProxyDomains = domainKeys(doms.gfw)
	cfg.Timeout = timeoutD

	localUpstreams, err := buildUpstreams(*localserer, timeoutD)
	if err != nil {
		loggo.Error("local upstream %v", err)
		return
	}
	externalUpstreams, err := buildUpstreams(*externalserver, timeoutD)
	if err != nil {
		loggo.Error("external upstream %v", err)
		return
	}

	res, err := gohomedns.NewResolver(cfg)
	if err != nil {
		loggo.Warn("new gohome resolver error %v, classify fallback only", err)
	}

	rr := &routingResolver{
		inner:    res,
		local:    localUpstreams,
		external: externalUpstreams,
		timeout:  timeoutD,
	}

	srv := gohomedns.NewServer(*listen, rr)
	if err := srv.Start(); err != nil {
		loggo.Error("dns server start fail %v", err)
		return
	}
	loggo.Info("listening on %s (udp+tcp)", srv.Addr())

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
		stats = startStatsServer(*statsAddr, token)
	}

	apply := func(chinaFiles, gfwFiles []string) (int, int, int, error) {
		return rr.reload(chinaFiles, gfwFiles, userHostsFiles, *localregionfile)
	}

	if *updateEvery > 0 {
		u := &updater{
			chinaURL:   defaultChinaListURL,
			gfwURL:     defaultGFWListURL,
			dir:        *updateDir,
			interval:   *updateEvery,
			apply:      apply,
			extraChina: userChinaFiles,
			extraGfw:   userGfwFiles,
		}
		go u.run()
		loggo.Info("auto update enabled, interval %v, dir %s", *updateEvery, *updateDir)
	}

	done := make(chan struct{})
	// HUP 重载的范围与启动一致：已落盘的远端列表 + 用户附加文件，
	// 否则 HUP 会把自动更新已生效的规则悄悄回退。
	reloadAll := func() (int, int, int, error) {
		return apply(
			append(remoteIfExist(remoteChinaPath), userChinaFiles...),
			append(remoteIfExist(remoteGfwPath), userGfwFiles...))
	}
	setupSignalHandler(
		func() {
			cn, gfw, hostsN, e := reloadAll()
			if e != nil {
				loggo.Error("reload fail, keep old rules: %v", e)
				return
			}
			loggo.Info("reload ok china %d gfw %d hosts %d shadowed %d", cn, gfw, hostsN, len(currentDomains().shadowed))
		},
		func() {
			loggo.Info("stopping...")
			if stats != nil {
				stats.close()
			}
			_ = srv.Stop()
			close(done)
		},
	)
	<-done
}
