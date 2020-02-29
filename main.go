package main

import (
	"flag"
	"github.com/esrrhs/go-engine/src/common"
	"github.com/esrrhs/go-engine/src/geoip"
	"github.com/esrrhs/go-engine/src/loggo"
	"github.com/miekg/dns"
	"net"
	"sync"
	"time"
)

type dnscache struct {
	host   string
	ip     string
	extern bool
	time   time.Time
}

type dnsserver struct {
	listener    *net.UDPConn
	localregion string
	timeout     int
	expire      int

	cache              sync.Map
	localsereraddr     *net.UDPAddr
	externalserveraddr *net.UDPAddr
}

var gds dnsserver

func main() {
	defer common.CrashLog()

	listen := flag.String("l", ":53", "listen addr")
	localserer := flag.String("los", "114.114.114.114:53", "local dns server")
	externalserver := flag.String("exs", "8.8.8.8:53", "external dns server")
	localregion := flag.String("lor", "CN", "local region")
	localregionfile := flag.String("lof", "GeoLite2-Country.mmdb", "local region file")
	timeout := flag.Int("timeout", 5000, "wait timeout in ms")
	expire := flag.Int("expire", 24, "host region cache expire time in hour")
	nolog := flag.Int("nolog", 0, "write log file")
	noprint := flag.Int("noprint", 0, "print stdout")
	loglevel := flag.String("loglevel", "info", "log level")

	flag.Parse()

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

	err = geoip.Load(*localregionfile)
	if err != nil {
		loggo.Error("load local region ip file ERROR: %v", err)
		return
	}

	gds.localregion = *localregion

	go updateCache()

	for {
		bytes := make([]byte, 4096)

		loggo.Info("wait for udp in")
		n, srcaddr, err := gds.listener.ReadFromUDP(bytes)
		if err != nil {
			continue
		}
		if n <= 0 {
			continue
		}

		loggo.Info("recv udp %v from %v", n, srcaddr)

		go forward(srcaddr, bytes[0:n])
	}
}

func updateCache() {
	defer common.CrashLog()

	for {
		local := 0
		extern := 0
		tmpdelete := make([]string, 0)

		gds.cache.Range(func(key, value interface{}) bool {
			host := key.(string)
			dc := value.(*dnscache)

			if dc.extern {
				extern++
			} else {
				local++
			}

			if time.Now().Sub(dc.time) > time.Hour*time.Duration(gds.expire) {
				tmpdelete = append(tmpdelete, host)
			}

			return true
		})

		loggo.Warn("local %d, extern %d, total %d", local, extern, local+extern)

		for _, host := range tmpdelete {
			gds.cache.Delete(host)
			loggo.Warn("delete expire cache %s", host)
		}

		time.Sleep(time.Second)
	}

}

func forward(srcaddr *net.UDPAddr, srcreq []byte) {
	defer common.CrashLog()

	msg := dns.Msg{}
	err := msg.Unpack(srcreq)
	if err != nil {
		loggo.Error("dns Msg Unpack fail %v", err)
		return
	}
	loggo.Info("dns Msg: \n%v", msg.String())

	extern := false
	for _, q := range msg.Question {
		if q.Qtype == dns.TypeA {
			v, ok := gds.cache.Load(q.Name)
			if !ok {
				continue
			}
			dc := v.(*dnscache)
			if dc.extern {
				extern = true
				break
			}
		}
	}

	if extern {
		go forwardextern(srcaddr, srcreq)
	} else {
		go forwardlocal(srcaddr, srcreq)
	}
}

func forwardlocal(srcaddr *net.UDPAddr, srcreq []byte) {
	defer common.CrashLog()

	loggo.Info("forward local start %v %v", srcaddr, gds.localsereraddr)
	c, err := net.DialUDP("udp", nil, gds.localsereraddr)
	if err != nil {
		loggo.Error("DialUDP local fail %v", err)
		return
	}
	loggo.Info("forward local dail ok %v %v", srcaddr, gds.localsereraddr)

	_, err = c.Write(srcreq)
	if err != nil {
		loggo.Error("Write local fail %v", err)
		return
	}
	loggo.Info("forward local write ok, wait ret %v %v", srcaddr, gds.localsereraddr)

	bytes := make([]byte, 4096)
	c.SetReadDeadline(time.Now().Add(time.Millisecond * time.Duration(gds.timeout)))
	n, err := c.Read(bytes)
	if err != nil {
		loggo.Info("ReadFromUDP local fail %v", err)
		return
	}

	loggo.Info("forward local ret %v %v", srcaddr, gds.externalserveraddr)

	go processret(false, srcaddr, srcreq, bytes[0:n])
}

func forwardextern(srcaddr *net.UDPAddr, srcreq []byte) {
	defer common.CrashLog()

	loggo.Info("forward extern start %v %v", srcaddr, gds.externalserveraddr)
	c, err := net.DialUDP("udp", nil, gds.externalserveraddr)
	if err != nil {
		loggo.Error("DialUDP extern fail %v", err)
		return
	}
	loggo.Info("forward extern dail ok %v %v", srcaddr, gds.externalserveraddr)

	_, err = c.Write(srcreq)
	if err != nil {
		loggo.Error("Write extern fail %v", err)
		return
	}
	loggo.Info("forward extern write ok, wait ret %v %v", srcaddr, gds.externalserveraddr)

	bytes := make([]byte, 4096)
	c.SetReadDeadline(time.Now().Add(time.Millisecond * time.Duration(gds.timeout)))
	n, err := c.Read(bytes)
	if err != nil {
		loggo.Info("ReadFromUDP extern fail %v", err)
		return
	}

	loggo.Info("forward extern ret %v %v", srcaddr, gds.externalserveraddr)

	go processret(true, srcaddr, srcreq, bytes[0:n])
}

func processret(extern bool, srcaddr *net.UDPAddr, srcreq []byte, retdata []byte) {
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
			if a.Header().Rrtype == dns.TypeA {
				aa := a.(*dns.A)
				ip := aa.A.String()
				host := aa.Hdr.Name

				v, _ := gds.cache.LoadOrStore(host, &dnscache{})
				dc := v.(*dnscache)
				dc.host = host
				dc.ip = ip
				dc.time = time.Now()

				region, _ := geoip.GetCountryIsoCode(ip)
				if len(region) <= 0 {
					dc.extern = false
				} else if gds.localregion == region {
					dc.extern = false
				} else {
					dc.extern = true
					hasextern = true
				}

				if dc.extern {
					loggo.Info("%v %v save extern dns cache: %v %v", name, srcaddr, host, ip)
				} else {
					loggo.Info("%v %v save local dns cache: %v %v", name, srcaddr, host, ip)
				}
			}
		}
	}

	if !extern && hasextern {
		loggo.Info("%v %v retry forward extern", name, srcaddr)
		go forwardextern(srcaddr, srcreq)
		return
	}

	_, err = gds.listener.WriteToUDP(retdata, srcaddr)
	if err != nil {
		loggo.Error("%v %v WriteToUDP fail %v", name, srcaddr, err)
		return
	}

	loggo.Info("%v %v process ret ok", name, srcaddr)
}
