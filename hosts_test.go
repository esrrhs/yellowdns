package main

import (
	"net"
	"os"
	"testing"
	"time"

	"github.com/miekg/dns"
)

func TestAddHostsLine(t *testing.T) {
	h := &hostsData{exact: map[string][]net.IP{}, wildcard: map[string][]net.IP{}}
	addHostsLine(h, "127.0.0.1 localhost")
	addHostsLine(h, "::1 localhost ip6-localhost # comment")
	addHostsLine(h, "  10.0.0.1  a.test  b.test ")
	addHostsLine(h, "# 1.2.3.4 commented.test")
	addHostsLine(h, "not-an-ip x.test")
	addHostsLine(h, "address=/wild.test/10.1.2.3")
	addHostsLine(h, "address=/v6.wild.test/::1,2606:4700::1")

	if got := h.exact["localhost"]; len(got) != 2 {
		t.Fatalf("localhost exact = %v, want 2 IPs", got)
	}
	if got := h.exact["a.test"]; len(got) != 1 || got[0].String() != "10.0.0.1" {
		t.Fatalf("a.test = %v", got)
	}
	if _, ok := h.exact["commented.test"]; ok {
		t.Error("commented line must be ignored")
	}
	if _, ok := h.exact["x.test"]; ok {
		t.Error("invalid IP must be ignored")
	}
	if got := h.wildcard["wild.test"]; len(got) != 1 || !got[0].Equal(net.ParseIP("10.1.2.3")) {
		t.Fatalf("wild.test = %v", got)
	}
	if got := h.wildcard["v6.wild.test"]; len(got) != 2 {
		t.Fatalf("v6.wild.test = %v, want 2 IPs", got)
	}
}

func TestLookupHosts(t *testing.T) {
	h := &hostsData{
		exact: map[string][]net.IP{
			"exact.test": {net.ParseIP("10.0.0.9")},
		},
		wildcard: map[string][]net.IP{
			"wild.test": {net.ParseIP("10.1.0.9")},
		},
	}
	hostsState.Store(h)
	t.Cleanup(func() { hostsState.Store(nil) })

	// 精确条目不匹配子域
	if ips := lookupHosts("sub.exact.test"); ips != nil {
		t.Errorf("exact entry must not match subdomain, got %v", ips)
	}
	if ips := lookupHosts("exact.test."); len(ips) != 1 || ips[0].String() != "10.0.0.9" {
		t.Errorf("exact.test = %v", ips)
	}
	// 通配条目匹配自身与任意深度子域
	if ips := lookupHosts("wild.test"); len(ips) != 1 {
		t.Errorf("wild.test self = %v", ips)
	}
	if ips := lookupHosts("a.b.wild.test."); len(ips) != 1 || ips[0].String() != "10.1.0.9" {
		t.Errorf("a.b.wild.test = %v", ips)
	}
	if ips := lookupHosts("other.test"); ips != nil {
		t.Errorf("unrelated name = %v", ips)
	}
}

func TestHostsAnswer(t *testing.T) {
	h := &hostsData{
		wildcard: map[string][]net.IP{
			"mix.test": {
				net.ParseIP("10.2.3.4"),
				net.ParseIP("2606:4700::1"),
			},
		},
	}
	hostsState.Store(h)
	t.Cleanup(func() { hostsState.Store(nil) })

	reqA := new(dns.Msg)
	reqA.SetQuestion("sub.mix.test.", dns.TypeA)
	resp, ok := hostsAnswer(reqA)
	if !ok || len(resp.Answer) != 1 {
		t.Fatalf("A answer ok=%v answers=%d", ok, len(resp.Answer))
	}
	a, isA := resp.Answer[0].(*dns.A)
	if !isA || a.A.String() != "10.2.3.4" || !resp.Authoritative || a.Hdr.Ttl != hostsTTL {
		t.Fatalf("bad A answer: %+v", resp.Answer)
	}

	req6 := new(dns.Msg)
	req6.SetQuestion("mix.test.", dns.TypeAAAA)
	resp, ok = hostsAnswer(req6)
	if !ok || len(resp.Answer) != 1 {
		t.Fatalf("AAAA answer ok=%v answers=%d", ok, len(resp.Answer))
	}
	if _, isAAAA := resp.Answer[0].(*dns.AAAA); !isAAAA {
		t.Fatalf("want AAAA record, got %T", resp.Answer[0])
	}

	// 有规则但族不匹配：NOERROR 空应答而非 NXDOMAIN/上游
	req6v4only := new(dns.Msg)
	h2 := &hostsData{exact: map[string][]net.IP{"v4.test": {net.ParseIP("10.9.9.9")}}}
	hostsState.Store(h2)
	req6v4only.SetQuestion("v4.test.", dns.TypeAAAA)
	resp, ok = hostsAnswer(req6v4only)
	if !ok || resp.Rcode != dns.RcodeSuccess || len(resp.Answer) != 0 {
		t.Fatalf("family mismatch should give empty NOERROR, ok=%v rcode=%d answers=%d", ok, resp.Rcode, len(resp.Answer))
	}

	// 无规则与其他 qtype 放行给上游
	reqMiss := new(dns.Msg)
	reqMiss.SetQuestion("nope.test.", dns.TypeA)
	if _, ok := hostsAnswer(reqMiss); ok {
		t.Error("missing rule must not synthesize")
	}
	reqMX := new(dns.Msg)
	reqMX.SetQuestion("mix.test.", dns.TypeMX)
	if _, ok := hostsAnswer(reqMX); ok {
		t.Error("non-A/AAAA qtype must fall through")
	}
}

// TestHostsExchangeAndReload 验证 hosts 规则在完整 Exchange 路径上优先于分流，
// 且坏 hosts 文件不会破坏既有快照。
func TestHostsExchangeAndReload(t *testing.T) {
	if _, _, err := loadDomainLists(nil, nil); err != nil {
		t.Fatal(err)
	}
	hostsState.Store(nil)
	t.Cleanup(func() { hostsState.Store(nil) })

	localAddr := startFakeUDPDNS(t, "10.50.0.1")
	r := &routingResolver{
		local:   []exchangeClient{newSocketClient(localAddr, 0)},
		timeout: time.Second,
	}

	f, err := os.CreateTemp("", "hosts-*.txt")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(f.Name())
	if _, err := f.WriteString("10.60.0.66 static.local\naddress=/wild.local/10.60.0.67\n"); err != nil {
		t.Fatal(err)
	}
	f.Close()
	if _, _, err := r.reload(nil, nil, []string{f.Name()}, ""); err != nil {
		t.Fatal(err)
	}

	if got := queryA(t, r, "static.local"); got != "10.60.0.66" {
		t.Fatalf("exact hosts answer %s", got)
	}
	if got := queryA(t, r, "x.wild.local"); got != "10.60.0.67" {
		t.Fatalf("wildcard hosts answer %s", got)
	}

	// 无 hosts 规则的名字仍走上游兜底（假上游回 10.50.0.1）
	if got := queryA(t, r, "www.baidu.com"); got != "10.50.0.1" {
		t.Fatalf("non-hosts query should hit upstream, got %s", got)
	}

	// 坏 hosts 文件：reload 失败且 hosts 与域名快照都保留
	beforeHosts := currentHosts()
	if _, _, err := r.reload(nil, nil, []string{"/no/such/hosts"}, ""); err == nil {
		t.Fatal("missing hosts file should fail reload")
	}
	if currentHosts() != beforeHosts {
		t.Fatal("failed reload must keep the previous hosts snapshot")
	}
	if got := queryA(t, r, "static.local"); got != "10.60.0.66" {
		t.Fatalf("old hosts rule lost after failed reload, got %s", got)
	}
}
