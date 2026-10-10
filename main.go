package main

import (
	"context"
	"errors"
	"flag"
	"net"
	"time"

	"github.com/esrrhs/gohome/common"
	gohomedns "github.com/esrrhs/gohome/dns"
	"github.com/esrrhs/gohome/loggo"
	"github.com/miekg/dns"
)

var yellowdnsVersion = "0.5.0"

// routingResolver 在 gohome resolver 之上补充两层路由：
//   - 被 gohome 直连域名树遮蔽的 gfw 域名（父域命中直连规则，如 china 列表的
//     recaptcha.net 遮蔽 gfw 的 api.recaptcha.net）强制走境外上游；
//   - gohome resolver 初始化失败或查询失败时，按域名分类直接查境内/境外上游兜底。
//
// 内嵌 gohomedns.Resolver 以透传其余接口方法；Server 只会调用 Exchange。
type routingResolver struct {
	gohomedns.Resolver

	inner        gohomedns.Resolver
	localAddr    string
	externalAddr string
	timeout      time.Duration
}

func (r *routingResolver) Exchange(ctx context.Context, req *dns.Msg) (*dns.Msg, error) {
	if len(req.Question) == 0 {
		return nil, errors.New("empty dns question")
	}
	q := req.Question[0]

	mode := classifyName(q.Name)
	if mode == routeExtern && externShadowedHit(q.Name) {
		loggo.Info("route %s %s", routeName(routeExtern), q.Name)
		return r.exchangeUpstream(r.externalAddr, req)
	}

	if r.inner != nil {
		resp, err := r.inner.Exchange(ctx, req)
		if err == nil && resp != nil {
			return resp, nil
		}
		loggo.Warn("gohome resolver Exchange fail %v, fallback to direct upstream", err)
	}

	addr := r.localAddr
	if mode == routeExtern {
		addr = r.externalAddr
	}
	loggo.Info("route %s %s", routeName(mode), q.Name)
	return r.exchangeUpstream(addr, req)
}

// exchangeUpstream 直接向指定上游查询，UDP 失败时按 DNS 惯例回退 TCP。
func (r *routingResolver) exchangeUpstream(addr string, req *dns.Msg) (*dns.Msg, error) {
	client := &dns.Client{Net: "udp", Timeout: r.timeout}
	resp, _, err := client.Exchange(req, addr)
	if err != nil {
		tcpClient := &dns.Client{Net: "tcp", Timeout: r.timeout}
		resp, _, err = tcpClient.Exchange(req, addr)
	}
	return resp, err
}

// withPort 为缺省端口的上游地址补 ":53"，与 gohome 上游的宽容解析保持一致。
func withPort(addr string) string {
	if _, _, err := net.SplitHostPort(addr); err != nil {
		return net.JoinHostPort(addr, "53")
	}
	return addr
}

func main() {
	defer common.CrashLog()

	listen := flag.String("l", ":53", "listen addr (udp and tcp)")
	localserer := flag.String("los", "114.114.114.114:53", "local dns server")
	externalserver := flag.String("exs", "8.8.8.8:53", "external dns server")
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

	chinaN, gfwN, err := loadDomainLists(*chinaFile, *gfwFile)
	if err != nil {
		loggo.Error("load domain list %v", err)
		return
	}
	loggo.Info("domain list china %d gfw %d, shadowed extern %d", chinaN, gfwN, len(externShadowed))

	cfg := gohomedns.DefaultConfig()
	cfg.EnableFakeIP = false
	cfg.DirectUpstreams = []string{*localserer}
	cfg.RemoteUpstreams = []string{*externalserver}
	cfg.GeoIPFile = *localregionfile
	cfg.RegionCode = *localregion
	cfg.DirectDomains = domainKeys(chinaDomains)
	cfg.ProxyDomains = domainKeys(gfwDomains)
	if *chinaFile != "" {
		cfg.DirectDomainFiles = []string{*chinaFile}
	}
	if *gfwFile != "" {
		cfg.ProxyDomainFiles = []string{*gfwFile}
	}
	cfg.Timeout = time.Duration(*timeout) * time.Millisecond

	res, err := gohomedns.NewResolver(cfg)
	if err != nil {
		loggo.Warn("new gohome resolver error %v, classify fallback only", err)
	}

	rr := &routingResolver{
		inner:        res,
		localAddr:    withPort(*localserer),
		externalAddr: withPort(*externalserver),
		timeout:      time.Duration(*timeout) * time.Millisecond,
	}

	srv := gohomedns.NewServer(*listen, rr)
	if err := srv.Start(); err != nil {
		loggo.Error("dns server start fail %v", err)
		return
	}
	loggo.Info("listening on %s (udp+tcp)", srv.Addr())

	select {}
}
