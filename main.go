package main

import (
	"context"
	"flag"
	"net"
	"sync"
	"time"

	"github.com/esrrhs/gohome/common"
	gohomedns "github.com/esrrhs/gohome/dns"
	"github.com/esrrhs/gohome/loggo"
	"github.com/esrrhs/gohome/thirdparty"
	"github.com/miekg/dns"
)

type dnscache struct {
	mu         sync.Mutex
	host       string
	ip         string
	externip   string
	extern     bool
	fromextern bool
	time       time.Time
}

type dnscachestatus struct {
	LocalDNS     int
	Local_local  int
	Local_extern int
	ExternDNS    int
	Extern_same  int
	Extern_diff  int
}

type dnsserverstatus struct {
	Reqnum        int
	ResNum        int
	Packerror     int
	Anum          int
	ARetnum       int
	ACachenum     int
	Localnum      int
	Externnum     int
	ExternFailnum int
	LocalFailnum  int
	LocalRetnum   int
	ExternRetnum  int
}

type dnsserver struct {
	listener    *net.UDPConn
	localregion string
	timeout     int
	expire      int
	statusMu    sync.Mutex
	status      dnsserverstatus

	cache              sync.Map
	localsereraddr     *net.UDPAddr
	externalserveraddr *net.UDPAddr
	resolver           gohomedns.Resolver
}

var gds dnsserver

func (s *dnsserver) incr(n *int) {
	s.statusMu.Lock()
	*n++
	s.statusMu.Unlock()
}

var yellowdnsVersion = "0.4.0"

func main() {
	defer common.CrashLog()

	listen := flag.String("l", ":53", "listen addr")
	localserer := flag.String("los", "114.114.114.114:53", "local dns server")
	externalserver := flag.String("exs", "8.8.8.8:53", "external dns server")
	localregion := flag.String("lor", "CN", "local region")
	localregionfile := flag.String("lof", "GeoLite2-Country.mmdb", "local region file")
	timeout := flag.Int("timeout", 5000, "wait response timeout in ms")
	expire := flag.Int("expire", 24, "host region cache expire time in hour")
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
	loggo.Info("start...")

	gds.timeout = *timeout
	gds.expire = *expire

	listenaddr, err := net.ResolveUDPAddr("udp", *listen)
	if err != nil {
		loggo.Error("listen addr fail %v", err)
		return
	}
	loggo.Info("listen addr %v", listenaddr)

	listener, err := net.ListenUDP("udp", listenaddr)
	if err != nil {
		loggo.Error("listening fail %v", err)
		return
	}
	gds.listener = listener
	loggo.Info("listen ok %v", listener.LocalAddr())

	localsereraddr, err := net.ResolveUDPAddr("udp", *localserer)
	if err != nil {
		loggo.Error("local dns server fail %v", err)
		return
	}
	gds.localsereraddr = localsereraddr
	loggo.Info("local dns server is %v", localsereraddr)

	externalserveraddr, err := net.ResolveUDPAddr("udp", *externalserver)
	if err != nil {
		loggo.Error("external dns server fail %v", err)
		return
	}
	gds.externalserveraddr = externalserveraddr
	loggo.Info("external dns server is %v", externalserveraddr)

	err = thirdparty.LoadGeoip2(*localregionfile)
	if err != nil {
		loggo.Error("load local region ip file ERROR: %v", err)
		return
	}

	chinaN, gfwN, err := loadDomainLists(*chinaFile, *gfwFile)
	if err != nil {
		loggo.Error("load domain list %v", err)
	}
	loggo.Info("domain list china %d gfw %d", chinaN, gfwN)

	cfg := gohomedns.DefaultConfig()
	cfg.EnableFakeIP = false
	if *localserer != "" {
		cfg.DirectUpstreams = []string{*localserer}
	}
	if *externalserver != "" {
		cfg.RemoteUpstreams = []string{*externalserver}
	}
	cfg.GeoIPFile = *localregionfile
	if *chinaFile != "" {
		cfg.DirectDomainFiles = []string{*chinaFile}
	}
	if *gfwFile != "" {
		cfg.ProxyDomainFiles = []string{*gfwFile}
	}
	cfg.Timeout = time.Duration(*timeout) * time.Millisecond
	res, err := gohomedns.NewResolver(cfg)
	if err == nil {
		gds.resolver = res
	} else {
		loggo.Warn("New gohome resolver error: %v, using default forwarder", err)
	}

	gds.localregion = *localregion

	go updateCache()

	buf := make([]byte, 4096)
	for {
		loggo.Info("wait for udp in")
		n, srcaddr, err := gds.listener.ReadFromUDP(buf)
		if err != nil || n <= 0 {
			continue
		}

		req := make([]byte, n)
		copy(req, buf[:n])

		loggo.Info("recv udp %v from %v", n, srcaddr)

		gds.incr(&gds.status.Reqnum)

		go forward(srcaddr, req)
	}
}

func updateCache() {
	defer common.CrashLog()

	for {
		dcs := dnscachestatus{}

		tmpdelete := make([]string, 0)

		gds.cache.Range(func(key, value interface{}) bool {
			host := key.(string)
			dc := value.(*dnscache)

			dc.mu.Lock()
			fromextern := dc.fromextern
			externip := dc.externip
			ip := dc.ip
			isExtern := dc.extern
			expired := time.Since(dc.time) > time.Hour*time.Duration(gds.expire)
			dc.mu.Unlock()

			if fromextern {
				dcs.ExternDNS++
				if externip != ip {
					dcs.Extern_diff++
				} else {
					dcs.Extern_same++
				}
			} else {
				if isExtern {
					dcs.Local_extern++
				} else {
					dcs.Local_local++
				}
				dcs.LocalDNS++
			}

			if expired {
				tmpdelete = append(tmpdelete, host)
			}

			return true
		})

		gds.statusMu.Lock()
		status := gds.status
		gds.status = dnsserverstatus{}
		gds.statusMu.Unlock()

		loggo.Warn("\n%s%s", common.StructToTable(&dcs),
			common.StructToTable(&status))

		for _, host := range tmpdelete {
			gds.cache.Delete(host)
			loggo.Warn("delete expire cache %s", host)
		}

		time.Sleep(time.Minute)
	}

}

func forward(srcaddr *net.UDPAddr, srcreq []byte) {
	defer common.CrashLog()

	msg := dns.Msg{}
	err := msg.Unpack(srcreq)
	if err != nil {
		gds.incr(&gds.status.Packerror)
		loggo.Error("dns Msg Unpack fail %v", err)
		return
	}
	loggo.Info("dns Msg: \n%v", msg.String())

	if gds.resolver != nil {
		resp, err := gds.resolver.Exchange(context.Background(), &msg)
		if err == nil && resp != nil {
			respBytes, packErr := resp.Pack()
			if packErr == nil {
				_, writeErr := gds.listener.WriteToUDP(respBytes, srcaddr)
				if writeErr == nil {
					gds.incr(&gds.status.ResNum)
					return
				}
			}
		}
		loggo.Warn("gohome resolver Exchange failed: %v, falling back to legacy router", err)
	}

	mode := routeAuto
	for _, q := range msg.Question {
		if q.Qtype == dns.TypeA {
			gds.incr(&gds.status.Anum)
		}
		switch classifyName(q.Name) {
		case routeExtern:
			mode = routeExtern
		case routeLocal:
			if mode != routeExtern {
				mode = routeLocal
			}
		}
	}
	if mode == routeAuto {
		for _, q := range msg.Question {
			if q.Qtype != dns.TypeA && q.Qtype != dns.TypeAAAA {
				continue
			}
			v, ok := gds.cache.Load(q.Name)
			if !ok {
				continue
			}
			gds.incr(&gds.status.ACachenum)
			dc := v.(*dnscache)
			dc.mu.Lock()
			isExtern := dc.extern
			dc.mu.Unlock()
			if isExtern {
				mode = routeExtern
				break
			}
		}
	}

	loggo.Info("route %s", routeName(mode))

	if mode == routeExtern {
		go forwardextern(srcaddr, srcreq, mode)
	} else {
		go forwardlocal(srcaddr, srcreq, mode)
	}
}

func forwardlocal(srcaddr *net.UDPAddr, srcreq []byte, mode int) {
	defer common.CrashLog()

	gds.incr(&gds.status.Localnum)

	loggo.Info("forward local start %v %v", srcaddr, gds.localsereraddr)
	c, err := net.DialUDP("udp", nil, gds.localsereraddr)
	if err != nil {
		gds.incr(&gds.status.LocalFailnum)
		loggo.Error("DialUDP local fail %v", err)
		return
	}
	defer c.Close()
	loggo.Info("forward local dail ok %v %v", srcaddr, gds.localsereraddr)

	_, err = c.Write(srcreq)
	if err != nil {
		gds.incr(&gds.status.LocalFailnum)
		loggo.Error("Write local fail %v", err)
		return
	}
	loggo.Info("forward local write ok, wait ret %v %v", srcaddr, gds.localsereraddr)

	bytes := make([]byte, 4096)
	c.SetReadDeadline(time.Now().Add(time.Millisecond * time.Duration(gds.timeout)))
	n, err := c.Read(bytes)
	if err != nil {
		gds.incr(&gds.status.LocalFailnum)
		loggo.Info("ReadFromUDP local fail %v", err)
		return
	}

	loggo.Info("forward local ret %v %v", srcaddr, gds.localsereraddr)

	gds.incr(&gds.status.LocalRetnum)

	go processret(false, mode, srcaddr, srcreq, bytes[0:n])
}

func forwardextern(srcaddr *net.UDPAddr, srcreq []byte, mode int) {
	defer common.CrashLog()

	gds.incr(&gds.status.Externnum)

	loggo.Info("forward extern start %v %v", srcaddr, gds.externalserveraddr)
	c, err := net.DialUDP("udp", nil, gds.externalserveraddr)
	if err != nil {
		gds.incr(&gds.status.ExternFailnum)
		loggo.Error("DialUDP extern fail %v", err)
		return
	}
	defer c.Close()
	loggo.Info("forward extern dail ok %v %v", srcaddr, gds.externalserveraddr)

	_, err = c.Write(srcreq)
	if err != nil {
		gds.incr(&gds.status.ExternFailnum)
		loggo.Error("Write extern fail %v", err)
		return
	}
	loggo.Info("forward extern write ok, wait ret %v %v", srcaddr, gds.externalserveraddr)

	bytes := make([]byte, 4096)
	c.SetReadDeadline(time.Now().Add(time.Millisecond * time.Duration(gds.timeout)))
	n, err := c.Read(bytes)
	if err != nil {
		gds.incr(&gds.status.ExternFailnum)
		loggo.Info("ReadFromUDP extern fail %v", err)
		return
	}

	loggo.Info("forward extern ret %v %v", srcaddr, gds.externalserveraddr)

	gds.incr(&gds.status.ExternRetnum)

	go processret(true, mode, srcaddr, srcreq, bytes[0:n])
}

func processret(extern bool, mode int, srcaddr *net.UDPAddr, srcreq []byte, retdata []byte) {
	defer common.CrashLog()

	name := ""
	if extern {
		name = "extern"
	} else {
		name = "local"
	}

	loggo.Info("%v %v process ret start", name, srcaddr)

	msg := dns.Msg{}
	err := msg.Unpack(retdata)
	if err != nil {
		loggo.Error("%v %v Msg Unpack fail %v", name, srcaddr, err)
		return
	}
	loggo.Info("%v %v return dns Msg: \n%v", name, srcaddr, msg.String())

	hasextern := false
	if msg.Rcode == dns.RcodeSuccess {
		for _, a := range msg.Answer {
			host, ip, ok := answerIP(a)
			if !ok {
				continue
			}
			if a.Header().Rrtype == dns.TypeA {
				gds.incr(&gds.status.ARetnum)
			}

			region, _ := thirdparty.GetGeoipCountryIsoCode(ip)
			isExtern := len(region) > 0 && gds.localregion != region
			switch mode {
			case routeLocal:
				isExtern = false
			case routeExtern:
				isExtern = true
			}
			if isExtern {
				hasextern = true
			}
			remember(host, ip, extern, isExtern)

			if isExtern {
				loggo.Info("%v %v save extern dns cache: %v %v", name, srcaddr, host, ip)
			} else {
				loggo.Info("%v %v save local dns cache: %v %v", name, srcaddr, host, ip)
			}
		}
	}

	if mode == routeAuto && hasextern {
		req := dns.Msg{}
		if err := req.Unpack(srcreq); err == nil {
			for _, q := range req.Question {
				remember(q.Name, "", extern, true)
			}
		}
	}

	if mode == routeAuto && !extern && hasextern {
		loggo.Info("%v %v retry forward extern", name, srcaddr)
		go forwardextern(srcaddr, srcreq, routeAuto)
		return
	}

	_, err = gds.listener.WriteToUDP(retdata, srcaddr)
	if err != nil {
		loggo.Error("%v %v WriteToUDP fail %v", name, srcaddr, err)
		return
	}

	loggo.Info("%v %v process ret ok", name, srcaddr)

	gds.incr(&gds.status.ResNum)
}

func answerIP(rr dns.RR) (string, string, bool) {
	switch a := rr.(type) {
	case *dns.A:
		if a.A == nil {
			return "", "", false
		}
		return a.Hdr.Name, a.A.String(), true
	case *dns.AAAA:
		if a.AAAA == nil {
			return "", "", false
		}
		return a.Hdr.Name, a.AAAA.String(), true
	default:
		return "", "", false
	}
}

func remember(host, ip string, fromextern, isExtern bool) {
	if host == "" {
		return
	}
	v, _ := gds.cache.LoadOrStore(host, &dnscache{})
	dc := v.(*dnscache)
	dc.mu.Lock()
	dc.host = host
	if ip != "" {
		if fromextern {
			dc.externip = ip
		} else {
			dc.ip = ip
		}
	}
	dc.time = time.Now()
	dc.fromextern = fromextern
	dc.extern = isExtern
	dc.mu.Unlock()
}
