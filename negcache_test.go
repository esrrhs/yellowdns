package main

import (
	"context"
	"net"
	"sync/atomic"
	"testing"
	"time"

	"github.com/miekg/dns"
)

// nxdomainMsg 构造一条带 SOA 的 NXDOMAIN 应答（无 Question，存储侧不关心）。
func nxdomainMsg(name string, soaTTL, soaMin uint32) *dns.Msg {
	m := new(dns.Msg)
	m.Rcode = dns.RcodeNameError
	m.Ns = append(m.Ns, &dns.SOA{
		Hdr:     dns.RR_Header{Name: dns.Fqdn(name), Rrtype: dns.TypeSOA, Class: dns.ClassINET, Ttl: soaTTL},
		Ns:      "ns1." + name + ".",
		Mbox:    "hostmaster." + name + ".",
		Serial:  1,
		Refresh: 7200,
		Retry:   3600,
		Expire:  86400,
		Minttl:  soaMin,
	})
	return m
}

// nodataMsg 构造一条 NODATA 应答（NOERROR、无 Answer、authority 带 SOA）。
func nodataMsg(name string, soaTTL, soaMin uint32) *dns.Msg {
	m := nxdomainMsg(name, soaTTL, soaMin)
	m.Rcode = dns.RcodeSuccess
	return m
}

func negQuestionKey(name string, qtype uint16) string {
	req := new(dns.Msg)
	req.SetQuestion(dns.Fqdn(name), qtype)
	return negKey(req.Question[0])
}

// TestNegativeCacheFreshAndExpired 验证否定缓存的新鲜命中（TTL 按剩余时间
// 衰减）、过期淘汰与 hits/misses 计数。
func TestNegativeCacheFreshAndExpired(t *testing.T) {
	c := newNegativeCache(10)
	key := negQuestionKey("a.test", dns.TypeA)

	if _, ok := c.get(key); ok {
		t.Fatal("empty cache must miss")
	}

	c.put(key, nxdomainMsg("a.test", 300, 300), time.Now().Add(300*time.Second))
	resp, ok := c.get(key)
	if !ok {
		t.Fatal("fresh entry must hit")
	}
	if got := resp.Ns[0].Header().Ttl; got < 299 || got > 300 {
		t.Fatalf("fresh TTL = %d, want 299~300", got)
	}
	if _, h, m := c.stats(); h != 1 || m != 1 {
		t.Fatalf("stats = %d/%d, want hits 1 misses 1", h, m)
	}

	// 过期条目：miss 且被懒清理。
	c.put(key, nxdomainMsg("a.test", 300, 300), time.Now().Add(-time.Second))
	if _, ok := c.get(key); ok {
		t.Fatal("expired entry must miss")
	}
	if c.len() != 0 {
		t.Fatalf("expired entry should be evicted, len = %d", c.len())
	}
	if _, h, m := c.stats(); h != 1 || m != 2 {
		t.Fatalf("stats = %d/%d, want hits 1 misses 2", h, m)
	}
}

// TestNegativeCacheCapacityAndClear 满容时同名刷新不增长；新 key 插入触发
// 淘汰；clear 清空全部。
func TestNegativeCacheCapacityAndClear(t *testing.T) {
	c := newNegativeCache(2)
	c.put(negQuestionKey("a.test", dns.TypeA), nxdomainMsg("a.test", 60, 60), time.Now().Add(time.Minute))
	c.put(negQuestionKey("a.test", dns.TypeA), nxdomainMsg("a.test", 60, 60), time.Now().Add(time.Minute))
	if c.len() != 1 {
		t.Fatalf("same-key refresh len = %d, want 1", c.len())
	}
	c.put(negQuestionKey("b.test", dns.TypeA), nxdomainMsg("b.test", 60, 60), time.Now().Add(time.Minute))
	c.put(negQuestionKey("c.test", dns.TypeA), nxdomainMsg("c.test", 60, 60), time.Now().Add(time.Minute))
	if c.len() != 2 {
		t.Fatalf("capacity eviction len = %d, want 2", c.len())
	}
	c.clear()
	if c.len() != 0 {
		t.Fatalf("len after clear = %d, want 0", c.len())
	}
}

// TestNegativeCacheNilSafe 功能关闭（neg 为 nil）时所有方法安全可用。
func TestNegativeCacheNilSafe(t *testing.T) {
	var c *negativeCache
	if _, ok := c.get("k"); ok {
		t.Fatal("nil cache must miss")
	}
	c.put("k", nxdomainMsg("a.test", 60, 60), time.Now().Add(time.Minute)) // 不 panic
	if c.len() != 0 {
		t.Fatal("nil cache len must be 0")
	}
	c.clear()
	if n, h, m := c.stats(); n != 0 || h != 0 || m != 0 {
		t.Fatalf("nil cache stats = %d/%d/%d, want zeros", n, h, m)
	}
}

// TestNegativeResponseTTL 表驱动验证 RFC 2308 TTL 推导：SOA TTL 与 MINIMUM
// 取小、-negcache-ttl 封顶、min/max TTL 收敛，以及无 SOA 时不缓存。
func TestNegativeResponseTTL(t *testing.T) {
	cases := []struct {
		name          string
		msg           *dns.Msg
		cap, min, max time.Duration
		want          time.Duration
	}{
		{
			name: "soa min below ttl",
			msg:  nxdomainMsg("a.test", 3600, 600),
			want: 600 * time.Second,
		},
		{
			name: "soa ttl below minimum",
			msg:  nxdomainMsg("a.test", 60, 86400),
			want: 60 * time.Second,
		},
		{
			name: "no soa",
			msg:  &dns.Msg{Rcode: dns.RcodeNameError},
			want: 0,
		},
		{
			name: "negcache cap",
			msg:  nxdomainMsg("a.test", 86400, 86400),
			cap:  5 * time.Minute,
			want: 5 * time.Minute,
		},
		{
			name: "min ttl floor",
			msg:  nxdomainMsg("a.test", 30, 30),
			min:  2 * time.Minute,
			want: 2 * time.Minute,
		},
		{
			name: "max ttl ceiling",
			msg:  nxdomainMsg("a.test", 7200, 7200),
			max:  time.Hour,
			want: time.Hour,
		},
		{
			name: "cap then ceiling",
			msg:  nxdomainMsg("a.test", 86400, 86400),
			cap:  2 * time.Hour,
			max:  time.Hour,
			want: time.Hour,
		},
		{
			name: "min above cap keeps min",
			msg:  nxdomainMsg("a.test", 10, 10),
			cap:  time.Second,
			min:  time.Minute,
			want: time.Minute,
		},
	}
	for _, c := range cases {
		if got := negativeResponseTTL(c.msg, c.cap, c.min, c.max); got != c.want {
			t.Errorf("%s: ttl = %v, want %v", c.name, got, c.want)
		}
	}
}

// TestIsCacheableNegative 只有 NXDOMAIN 与 NODATA 可缓存；SERVFAIL/REFUSED、
// 正向应答与 TC 截断应答都不缓存。
func TestIsCacheableNegative(t *testing.T) {
	positive := new(dns.Msg)
	positive.SetReply(&dns.Msg{Question: []dns.Question{{Name: "a.test.", Qtype: dns.TypeA, Qclass: dns.ClassINET}}})
	positive.Answer = append(positive.Answer, &dns.A{
		Hdr: dns.RR_Header{Name: "a.test.", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 30},
		A:   net.ParseIP("1.2.3.4"),
	})

	cases := []struct {
		name string
		msg  *dns.Msg
		want bool
	}{
		{"nxdomain", nxdomainMsg("a.test", 60, 60), true},
		{"nodata", nodataMsg("a.test", 60, 60), true},
		{"positive", positive, false},
		{"servfail", &dns.Msg{Rcode: dns.RcodeServerFailure}, false},
		{"refused", &dns.Msg{Rcode: dns.RcodeRefused}, false},
		{"notimp", &dns.Msg{Rcode: dns.RcodeNotImplemented}, false},
		{"nil", nil, false},
		{"truncated nodata", func() *dns.Msg {
			m := nodataMsg("a.test", 60, 60)
			m.Truncated = true
			return m
		}(), false},
	}
	for _, c := range cases {
		if got := isCacheableNegative(c.msg); got != c.want {
			t.Errorf("%s: cacheable = %v, want %v", c.name, got, c.want)
		}
	}
}

// startCountingNXDNS 启动一个计数假 DNS：A 查询回 NXDOMAIN（带 SOA），
// AAAA 查询回 NODATA，其余回 A 记录；返回地址与查询计数器。
func startCountingNXDNS(t *testing.T, ip string) (string, *atomic.Int64) {
	t.Helper()
	var count atomic.Int64
	mux := dns.NewServeMux()
	mux.HandleFunc(".", func(w dns.ResponseWriter, m *dns.Msg) {
		count.Add(1)
		reply := new(dns.Msg)
		reply.SetReply(m)
		for _, q := range m.Question {
			switch q.Qtype {
			case dns.TypeA:
				reply.Rcode = dns.RcodeNameError
				reply.Ns = append(reply.Ns, &dns.SOA{
					Hdr:     dns.RR_Header{Name: q.Name, Rrtype: dns.TypeSOA, Class: dns.ClassINET, Ttl: 600},
					Ns:      "ns1." + q.Name,
					Mbox:    "hostmaster." + q.Name,
					Serial:  1,
					Refresh: 7200,
					Retry:   3600,
					Expire:  86400,
					Minttl:  300,
				})
			case dns.TypeAAAA:
				// NODATA：NOERROR、无 Answer、authority 带 SOA。
				reply.Ns = append(reply.Ns, &dns.SOA{
					Hdr:     dns.RR_Header{Name: q.Name, Rrtype: dns.TypeSOA, Class: dns.ClassINET, Ttl: 120},
					Ns:      "ns1." + q.Name,
					Mbox:    "hostmaster." + q.Name,
					Serial:  1,
					Refresh: 7200,
					Retry:   3600,
					Expire:  86400,
					Minttl:  120,
				})
			default:
				reply.Answer = append(reply.Answer, &dns.A{
					Hdr: dns.RR_Header{Name: q.Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 30},
					A:   net.ParseIP(ip).To4(),
				})
			}
		}
		_ = w.WriteMsg(reply)
	})
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	srv := &dns.Server{PacketConn: pc, Handler: mux}
	go func() { _ = srv.ActivateAndServe() }()
	t.Cleanup(func() { _ = srv.Shutdown() })
	return pc.LocalAddr().String(), &count
}

func exchange(t *testing.T, r *routingResolver, name string, qtype uint16) *dns.Msg {
	t.Helper()
	req := new(dns.Msg)
	req.SetQuestion(dns.Fqdn(name), qtype)
	resp, err := r.Exchange(context.Background(), req)
	if err != nil {
		t.Fatalf("exchange %s: %v", name, err)
	}
	return resp
}

// TestRoutingNegativeCacheHit 端到端：NXDOMAIN/NODATA 首次经上游后写入否定
// 缓存，第二次命中缓存不再打上游；应答的 Id/Question 对到新请求，路由标签
// 为 negcache，统计命中数递增。
func TestRoutingNegativeCacheHit(t *testing.T) {
	if _, _, err := loadDomainLists(nil, nil); err != nil {
		t.Fatal(err)
	}
	metrics.reset()
	t.Cleanup(metrics.reset)

	addr, upstreamCount := startCountingNXDNS(t, "10.50.0.5")
	r := &routingResolver{
		inner:    nil,
		local:    []exchangeClient{newSocketClient(addr, time.Second)},
		external: []exchangeClient{newSocketClient(addr, time.Second)},
		timeout:  time.Second,
		neg:      newNegativeCache(100),
		negTTL:   time.Hour,
	}

	// 第一次：NXDOMAIN 经上游，SOA TTL 600/MINIMUM 300 -> 缓存 300s。
	resp := exchange(t, r, "nx.test", dns.TypeA)
	if resp.Rcode != dns.RcodeNameError {
		t.Fatalf("first rcode = %s, want NXDOMAIN", dns.RcodeToString[resp.Rcode])
	}
	if got := upstreamCount.Load(); got != 1 {
		t.Fatalf("upstream queries after first = %d, want 1", got)
	}
	if got := resp.Ns[0].Header().Ttl; got != 300 {
		t.Fatalf("served SOA TTL = %d, want 300 (clamped by SOA MINIMUM)", got)
	}

	// 第二次：命中否定缓存，不再打上游；Id/Question 对到新请求。
	req := new(dns.Msg)
	req.SetQuestion("nx.test.", dns.TypeA)
	req.Id = 0x1234
	resp2, err := r.Exchange(context.Background(), req)
	if err != nil {
		t.Fatalf("second exchange: %v", err)
	}
	if got := upstreamCount.Load(); got != 1 {
		t.Fatalf("upstream queries after cache hit = %d, want 1", got)
	}
	if resp2.Id != 0x1234 || len(resp2.Question) != 1 || resp2.Question[0].Name != "nx.test." {
		t.Fatalf("cached reply not rebound to request: id=%d question=%v", resp2.Id, resp2.Question)
	}
	if resp2.Rcode != dns.RcodeNameError {
		t.Fatalf("cached rcode = %s, want NXDOMAIN", dns.RcodeToString[resp2.Rcode])
	}
	// 否定缓存自身的条目/命中计数，以及 negcache 路由的延迟样本
	// （命中应答端到端应为亚毫秒级，但样本存在即证明路由标签生效）。
	if n, h, m := r.neg.stats(); n != 1 || h != 1 || m != 1 {
		t.Fatalf("negative cache stats = entries %d hits %d misses %d, want 1/1/1", n, h, m)
	}
	if got := metrics.snapshot().Queries.Latency[routeNegcacheLabel].Count; got != 1 {
		t.Fatalf("negcache latency samples = %d, want 1", got)
	}

	// NODATA（AAAA）同样被缓存。
	exchange(t, r, "v6.test", dns.TypeAAAA)
	exchange(t, r, "v6.test", dns.TypeAAAA)
	if got := upstreamCount.Load(); got != 2 {
		t.Fatalf("upstream queries after nodata pair = %d, want 2 (one upstream + one cached)", got)
	}

	// 不同 qtype 是不同 key：A 的 NXDOMAIN 不遮蔽 AAAA 的查询。
	resp3 := exchange(t, r, "nx.test", dns.TypeAAAA)
	if resp3.Rcode != dns.RcodeSuccess || len(resp3.Answer) != 0 {
		t.Fatalf("aaaa on nx name rcode = %s answers %d, want NOERROR/0", dns.RcodeToString[resp3.Rcode], len(resp3.Answer))
	}
}

// TestRoutingNegativeCacheFlushAndReload 验证 flush 与规则重载都会清空否定
// 缓存，清空后下一次查询重新回源。
func TestRoutingNegativeCacheFlushAndReload(t *testing.T) {
	if _, _, err := loadDomainLists(nil, nil); err != nil {
		t.Fatal(err)
	}
	addr, upstreamCount := startCountingNXDNS(t, "10.50.0.6")
	r := &routingResolver{
		local:   []exchangeClient{newSocketClient(addr, time.Second)},
		timeout: time.Second,
		neg:     newNegativeCache(100),
		negTTL:  time.Hour,
	}

	exchange(t, r, "nx.test", dns.TypeA)
	exchange(t, r, "nx.test", dns.TypeA)
	if got := upstreamCount.Load(); got != 1 {
		t.Fatalf("upstream queries = %d, want 1 (second from cache)", got)
	}

	// flush 清掉否定缓存，计数也一并上报。
	if n := r.flushCache(); n != 1 {
		t.Fatalf("flush cleared %d entries, want 1", n)
	}
	exchange(t, r, "nx.test", dns.TypeA)
	if got := upstreamCount.Load(); got != 2 {
		t.Fatalf("upstream queries after flush = %d, want 2", got)
	}

	// 重新回源后条目再次入缓存：紧随其后的查询仍走缓存。
	exchange(t, r, "nx.test", dns.TypeA)
	if got := upstreamCount.Load(); got != 2 {
		t.Fatalf("upstream queries after re-cache = %d, want 2", got)
	}
	// reload（SIGHUP/自动更新路径）同样清空否定缓存。
	if _, _, _, err := r.reload(nil, nil, nil, ""); err != nil {
		t.Fatal(err)
	}
	exchange(t, r, "nx.test", dns.TypeA)
	if got := upstreamCount.Load(); got != 3 {
		t.Fatalf("upstream queries after reload = %d, want 3", got)
	}
}

// TestRoutingNegativeCacheDisabled negTTL 为 0 时不写入也不读取否定缓存。
func TestRoutingNegativeCacheDisabled(t *testing.T) {
	if _, _, err := loadDomainLists(nil, nil); err != nil {
		t.Fatal(err)
	}
	addr, upstreamCount := startCountingNXDNS(t, "10.50.0.7")
	r := &routingResolver{
		local:   []exchangeClient{newSocketClient(addr, time.Second)},
		timeout: time.Second,
		// neg 为 nil、negTTL 为 0：-negcache-ttl 0 的关闭形态。
	}

	exchange(t, r, "nx.test", dns.TypeA)
	exchange(t, r, "nx.test", dns.TypeA)
	if got := upstreamCount.Load(); got != 2 {
		t.Fatalf("upstream queries with negcache disabled = %d, want 2", got)
	}
	if n := r.flushCache(); n != 0 {
		t.Fatalf("flush with negcache disabled cleared %d, want 0", n)
	}
}
