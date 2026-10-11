package main

import (
	"context"
	"encoding/json"
	"net"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/miekg/dns"
)

// findECS 从消息的 OPT 记录中提取 ECS option，不存在返回 nil。
func findECS(m *dns.Msg) *dns.EDNS0_SUBNET {
	opt := m.IsEdns0()
	if opt == nil {
		return nil
	}
	for _, o := range opt.Option {
		if ecs, ok := o.(*dns.EDNS0_SUBNET); ok {
			return ecs
		}
	}
	return nil
}

func TestParseECSPolicy(t *testing.T) {
	// 默认关闭。
	p, err := parseECSPolicy("", false)
	if err != nil || p != nil {
		t.Fatalf("empty policy = %v, %v, want nil", p, err)
	}

	// IPv4：主机位被掩码收敛，family=1，地址为 4 字节。
	p, err = parseECSPolicy("1.2.3.4/24", false)
	if err != nil {
		t.Fatal(err)
	}
	if p.mode != ecsCIDR || p.family != 1 || p.mask != 24 || p.net != "1.2.3.0/24" {
		t.Fatalf("v4 policy = %+v", p)
	}
	if got := p.addr.String(); got != "1.2.3.0" || len(p.addr) != 4 {
		t.Fatalf("normalized v4 addr = %s (len %d)", got, len(p.addr))
	}

	// IPv6：family=2，地址 16 字节。
	p6, err := parseECSPolicy("2001:db8:1234::1/48", false)
	if err != nil {
		t.Fatal(err)
	}
	if p6.family != 2 || p6.mask != 48 || p6.net != "2001:db8:1234::/48" || len(p6.addr) != 16 {
		t.Fatalf("v6 policy = %+v", p6)
	}

	// 剥离模式。
	ps, err := parseECSPolicy("", true)
	if err != nil || ps.mode != ecsStrip || ps.ecsLabel() != "strip" {
		t.Fatalf("strip policy = %v, %v", ps, err)
	}

	// 互斥。
	if _, err := parseECSPolicy("1.2.3.0/24", true); err == nil {
		t.Fatal("cidr + strip must be rejected")
	}
	// 非法 CIDR 与 /0。
	for _, bad := range []string{"not-a-cidr", "1.2.3.0", "1.2.3.0/33", "0.0.0.0/0", "::/0"} {
		if _, err := parseECSPolicy(bad, false); err == nil {
			t.Fatalf("bad cidr %q must be rejected", bad)
		}
	}

	// 私网检测（仅告警用，不影响策略构造）。
	priv, _ := parseECSPolicy("10.0.0.0/8", false)
	if !priv.isPrivateScope() {
		t.Fatal("10.0.0.0/8 must be detected as private scope")
	}
	pub, _ := parseECSPolicy("1.2.3.0/24", false)
	if pub.isPrivateScope() {
		t.Fatal("1.2.3.0/24 is public scope")
	}
}

// TestApplyECSAdd 无 EDNS0 与已有 EDNS0 两种情况下都能正确附加固定子网。
func TestApplyECSAdd(t *testing.T) {
	p, err := parseECSPolicy("8.8.4.0/24", false)
	if err != nil {
		t.Fatal(err)
	}

	// 客户端无 OPT：新建并附加。
	req := new(dns.Msg)
	req.SetQuestion("example.com.", dns.TypeA)
	if !applyECS(req, p) {
		t.Fatal("applyECS should report a change")
	}
	ecs := findECS(req)
	if ecs == nil {
		t.Fatal("ECS option missing")
	}
	if ecs.Family != 1 || ecs.SourceNetmask != 24 || ecs.SourceScope != 0 ||
		ecs.Address.String() != "8.8.4.0" {
		t.Fatalf("ecs = family %d mask %d scope %d addr %s", ecs.Family, ecs.SourceNetmask, ecs.SourceScope, ecs.Address)
	}
	if req.IsEdns0().UDPSize() != 4096 {
		t.Fatalf("udp size = %d, want 4096", req.IsEdns0().UDPSize())
	}

	// 客户端自带不同 ECS：被固定子网覆盖而不是并存两个。
	req2 := new(dns.Msg)
	req2.SetQuestion("example.com.", dns.TypeAAAA)
	req2.SetEdns0(1232, false)
	old := req2.IsEdns0()
	old.Option = append(old.Option, &dns.EDNS0_SUBNET{
		Code: dns.EDNS0SUBNET, Family: 1, SourceNetmask: 24, Address: net.ParseIP("192.168.1.0"),
	})
	applyECS(req2, p)
	var count int
	for _, o := range req2.IsEdns0().Option {
		if o.Option() == dns.EDNS0SUBNET {
			count++
		}
	}
	if count != 1 {
		t.Fatalf("ECS option count = %d, want 1", count)
	}
	if got := findECS(req2).Address.String(); got != "8.8.4.0" {
		t.Fatalf("overridden ECS addr = %s, want 8.8.4.0", got)
	}
	if req2.IsEdns0().UDPSize() != 1232 {
		t.Fatal("existing OPT attributes must be preserved, including UDP size")
	}
}

// TestApplyECSStrip 剥离必须只删 ECS：DO 位、版本、其他 option 全部保留。
func TestApplyECSStrip(t *testing.T) {
	p, _ := parseECSPolicy("", true)

	req := new(dns.Msg)
	req.SetQuestion("example.com.", dns.TypeA)
	req.SetEdns0(1232, true) // DO=true
	opt := req.IsEdns0()
	opt.Option = append(opt.Option,
		&dns.EDNS0_SUBNET{Code: dns.EDNS0SUBNET, Family: 1, SourceNetmask: 24, Address: net.ParseIP("10.1.2.0")},
		&dns.EDNS0_COOKIE{Code: dns.EDNS0COOKIE, Cookie: "deadbeefdeadbeef"},
	)
	if !applyECS(req, p) {
		t.Fatal("strip should report a change when ECS existed")
	}
	if findECS(req) != nil {
		t.Fatal("ECS must be removed")
	}
	if !req.IsEdns0().Do() {
		t.Fatal("DNSSEC DO bit must survive ECS stripping")
	}
	if req.IsEdns0().UDPSize() != 1232 {
		t.Fatal("UDP size must survive")
	}
	var cookies int
	for _, o := range req.IsEdns0().Option {
		if o.Option() == dns.EDNS0COOKIE {
			cookies++
		}
	}
	if cookies != 1 {
		t.Fatal("non-ECS EDNS options (cookie) must survive")
	}

	// 无 OPT / 有 OPT 但无 ECS：返回 false，不制造空 OPT。
	plain := new(dns.Msg)
	plain.SetQuestion("example.com.", dns.TypeA)
	if applyECS(plain, p) {
		t.Fatal("strip on plain request must be no-op without creating OPT")
	}
	if plain.IsEdns0() != nil {
		t.Fatal("strip must not synthesize an OPT record")
	}
	optOnly := new(dns.Msg)
	optOnly.SetQuestion("example.com.", dns.TypeA)
	optOnly.SetEdns0(1232, true)
	if applyECS(optOnly, p) {
		t.Fatal("strip without an ECS option must report no change")
	}
}

// TestApplyECSOnlyAddressTypes 非 A/AAAA 与空问题/空策略一律不改写。
func TestApplyECSOnlyAddressTypes(t *testing.T) {
	p, _ := parseECSPolicy("8.8.4.0/24", false)
	for _, qtype := range []uint16{dns.TypeTXT, dns.TypePTR, dns.TypeMX, dns.TypeNS, dns.TypeSOA} {
		req := new(dns.Msg)
		req.SetQuestion("example.com.", qtype)
		if applyECS(req, p) {
			t.Fatalf("qtype %d must not carry ECS", qtype)
		}
		if req.IsEdns0() != nil {
			t.Fatalf("qtype %d must not get a synthesized OPT", qtype)
		}
	}
	// AAAA 必须附加（IPv6 策略）。
	p6, _ := parseECSPolicy("2001:db8::/48", false)
	req6 := new(dns.Msg)
	req6.SetQuestion("example.com.", dns.TypeAAAA)
	if !applyECS(req6, p6) || findECS(req6) == nil {
		t.Fatal("AAAA must carry ECS under v6 policy")
	}
	// nil 策略与空问题。
	empty := new(dns.Msg)
	if applyECS(empty, nil) {
		t.Fatal("nil policy must be no-op")
	}
}

// startECSCaptureDNS 启动一个记录最后收到的 ECS option 的假上游。
func startECSCaptureDNS(t *testing.T) (string, func() *dns.EDNS0_SUBNET) {
	t.Helper()
	var mu sync.Mutex
	var last *dns.EDNS0_SUBNET
	mux := dns.NewServeMux()
	mux.HandleFunc(".", func(w dns.ResponseWriter, m *dns.Msg) {
		mu.Lock()
		last = findECS(m)
		mu.Unlock()
		reply := new(dns.Msg)
		reply.SetReply(m)
		for _, q := range m.Question {
			if q.Qtype == dns.TypeA {
				reply.Answer = append(reply.Answer, &dns.A{
					Hdr: dns.RR_Header{Name: q.Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 30},
					A:   net.ParseIP("10.70.0.1").To4(),
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
	return pc.LocalAddr().String(), func() *dns.EDNS0_SUBNET {
		mu.Lock()
		defer mu.Unlock()
		return last
	}
}

// TestECSEndToEnd 固定子网模式：上游真正收到 8.8.4.0/24；
// 剥离模式：客户端带私网 ECS 时上游收不到任何 ECS。
func TestECSEndToEnd(t *testing.T) {
	if _, _, err := loadDomainLists(nil, nil); err != nil {
		t.Fatal(err)
	}
	metrics.reset()
	t.Cleanup(metrics.reset)

	addr, seen := startECSCaptureDNS(t)
	p, _ := parseECSPolicy("8.8.4.0/24", false)
	r := &routingResolver{
		local:   []exchangeClient{newSocketClient(addr, time.Second)},
		timeout: time.Second,
		ecs:     p,
	}
	if got := queryA(t, r, "www.baidu.com"); got != "10.70.0.1" {
		t.Fatalf("answer = %s", got)
	}
	got := seen()
	if got == nil || got.Family != 1 || got.SourceNetmask != 24 || got.Address.String() != "8.8.4.0" {
		t.Fatalf("upstream saw ECS = %+v, want 8.8.4.0/24", got)
	}
	if n := metrics.ecsApplied.Load(); n != 1 {
		t.Fatalf("ecsApplied = %d, want 1", n)
	}

	// 同一上游切到剥离策略，客户端请求携带私网 ECS。
	r.ecs, _ = parseECSPolicy("", true)
	req := new(dns.Msg)
	req.SetQuestion("www.baidu.com.", dns.TypeA)
	req.SetEdns0(1232, false)
	req.IsEdns0().Option = append(req.IsEdns0().Option, &dns.EDNS0_SUBNET{
		Code: dns.EDNS0SUBNET, Family: 1, SourceNetmask: 24, Address: net.ParseIP("192.168.9.0"),
	})
	resp, err := r.Exchange(context.Background(), req)
	if err != nil || resp == nil {
		t.Fatalf("strip exchange fail: %v", err)
	}
	if ecs := seen(); ecs != nil {
		t.Fatalf("upstream must not see ECS after strip, got %+v", ecs)
	}
}

// TestECSObservability 验证模式标签与计数进入 /stats 与 /metrics。
func TestECSObservability(t *testing.T) {
	old := ecsModeLabel.Load()
	ecsModeLabel.Store("cidr:8.8.4.0/24")
	t.Cleanup(func() { ecsModeLabel.Store(old) })
	metrics.reset()
	t.Cleanup(metrics.reset)
	metrics.ecsApplied.Add(7)

	s := &statsServer{}
	rec := httptest.NewRecorder()
	s.statsHandler(rec, httptest.NewRequest("GET", "/stats", nil))
	var snap statsSnapshot
	if err := json.Unmarshal(rec.Body.Bytes(), &snap); err != nil {
		t.Fatal(err)
	}
	if snap.ECS.Mode != "cidr:8.8.4.0/24" || snap.ECS.Applied != 7 {
		t.Fatalf("ecs snapshot = %+v", snap.ECS)
	}

	recM := httptest.NewRecorder()
	s.metricsHandler(recM, httptest.NewRequest("GET", "/metrics", nil))
	body := recM.Body.String()
	for _, want := range []string{
		`# TYPE yellowdns_ecs_info gauge`,
		`yellowdns_ecs_info{mode="cidr:8.8.4.0/24"} 1`,
		"# TYPE yellowdns_ecs_applied_total counter",
		"yellowdns_ecs_applied_total 7",
	} {
		if !strings.Contains(body, want) {
			t.Errorf("metrics body missing %q\n%s", want, body)
		}
	}
}
