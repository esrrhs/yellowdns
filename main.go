package main

import (
	"context"
	"errors"
	"flag"
	"net"
	"strings"
	"time"

	"github.com/esrrhs/gohome/common"
	gohomedns "github.com/esrrhs/gohome/dns"
	"github.com/esrrhs/gohome/dns/upstream"
	"github.com/esrrhs/gohome/loggo"
	"github.com/miekg/dns"
)

var yellowdnsVersion = "0.5.0"

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

	mode := classifyName(q.Name)
	if mode == routeExtern && externShadowedHit(q.Name) {
		loggo.Info("route %s %s", routeName(routeExtern), q.Name)
		return exchangeList(ctx, r.external, req, r.timeout)
	}

	if r.inner != nil {
		resp, err := r.inner.Exchange(ctx, req)
		if err == nil && resp != nil {
			return resp, nil
		}
		loggo.Warn("gohome resolver Exchange fail %v, fallback to direct upstream", err)
	}

	list := r.local
	if mode == routeExtern {
		list = r.external
	}
	loggo.Info("route %s %s", routeName(mode), q.Name)
	return exchangeList(ctx, list, req, r.timeout)
}

// exchangeList 依次尝试上游列表，任一成功即返回（failover）。
func exchangeList(ctx context.Context, list []exchangeClient, req *dns.Msg, timeout time.Duration) (*dns.Msg, error) {
	var lastErr error
	for _, u := range list {
		resp, err := exchangeOne(ctx, u, req, timeout)
		if err == nil && resp != nil {
			return resp, nil
		}
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

// reload 重新加载内置与外部域名列表、热替换 resolver 的分流树与 GeoIP 库，
// 并清空响应缓存，使新规则对下一次查询立即生效。列表文件读取失败时保留旧状态。
func (r *routingResolver) reload(chinaFile, gfwFile, geoFile string) (chinaN, gfwN int, err error) {
	chinaN, gfwN, err = loadDomainLists(chinaFile, gfwFile)
	if err != nil {
		return 0, 0, err
	}
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
	return chinaN, gfwN, nil
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
	nolog := flag.Int("nolog", 0, "write log file")
	noprint := flag.Int("noprint", 0, "print stdout")
	loglevel := flag.String("loglevel", "info", "log level")
	showVersion := flag.Bool("version", false, "show version and exit")

	flag.Parse()

	if *showVersion {
		println("yellowdns version " + yellowdnsVersion)
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
	loggo.Info("start yellowdns %s", yellowdnsVersion)

	timeoutD := time.Duration(*timeout) * time.Millisecond

	chinaN, gfwN, err := loadDomainLists(*chinaFile, *gfwFile)
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
	if *chinaFile != "" {
		cfg.DirectDomainFiles = []string{*chinaFile}
	}
	if *gfwFile != "" {
		cfg.ProxyDomainFiles = []string{*gfwFile}
	}
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

	done := make(chan struct{})
	setupSignalHandler(
		func() {
			cn, gfw, e := rr.reload(*chinaFile, *gfwFile, *localregionfile)
			if e != nil {
				loggo.Error("reload fail, keep old rules: %v", e)
				return
			}
			loggo.Info("reload ok china %d gfw %d shadowed %d", cn, gfw, len(currentDomains().shadowed))
		},
		func() {
			loggo.Info("stopping...")
			_ = srv.Stop()
			close(done)
		},
	)
	<-done
}
