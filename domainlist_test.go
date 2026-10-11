package main

import (
	"os"
	"testing"
	"time"

	"github.com/esrrhs/gohome/thirdparty"
	"github.com/oschwald/maxminddb-golang"
)

func TestClassifyEmbedded(t *testing.T) {
	if _, _, err := loadDomainLists(nil, nil); err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		name string
		want int
	}{
		{"www.baidu.com.", routeLocal},
		{"QQ.com", routeLocal},
		{"a1.mzstatic.com.", routeLocal},
		{"adservice.google.com.", routeLocal},
		{"www.google.com.", routeExtern},
		{"github.com.", routeExtern},
		{"example.cn.", routeLocal},
		{"www.example.中国.", routeLocal},
		{"example.com.", routeAuto},
	}
	for _, c := range cases {
		if got := classifyName(c.name); got != c.want {
			t.Errorf("%s got %s want %s", c.name, routeName(got), routeName(c.want))
		}
	}
}

func TestClassifySpecificChinaWins(t *testing.T) {
	china := domainSet{}
	gfw := domainSet{}
	addDomain(gfw, "google.com")
	addDomain(china, "adservice.google.com")
	domainState.Store(&domainData{
		china:    china,
		gfw:      gfw,
		shadowed: buildExternShadowed(china, gfw),
	})
	if got := classifyName("adservice.google.com."); got != routeLocal {
		t.Fatalf("specific china domain got %s", routeName(got))
	}
	if got := classifyName("www.google.com."); got != routeExtern {
		t.Fatalf("parent gfw domain got %s", routeName(got))
	}
	if _, _, err := loadDomainLists(nil, nil); err != nil {
		t.Fatal(err)
	}
}

func TestReloadPicksUpExtraFile(t *testing.T) {
	if _, _, err := loadDomainLists(nil, nil); err != nil {
		t.Fatal(err)
	}
	name := "reload-test-domain.example"
	if got := classifyName(name); got != routeAuto {
		t.Fatalf("%s before reload got %s, want auto", name, routeName(got))
	}

	f, err := os.CreateTemp("", "china-*.txt")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(f.Name())
	if _, err := f.WriteString(name + "\n"); err != nil {
		t.Fatal(err)
	}
	f.Close()

	r := &routingResolver{} // inner 为 nil：只验证规则快照热替换
	cn, _, _, err := r.reload([]string{f.Name()}, nil, nil, "GeoLite2-Country.mmdb")
	if err != nil {
		t.Fatal(err)
	}
	if cn == 0 {
		t.Fatal("reloaded china count should include embedded list")
	}
	if got := classifyName(name + "."); got != routeLocal {
		t.Fatalf("%s after reload got %s, want local", name, routeName(got))
	}

	// 坏文件不能破坏现有快照
	before := currentDomains()
	if _, _, _, err := r.reload([]string{"/no/such/file"}, nil, nil, ""); err == nil {
		t.Fatal("missing file should fail reload")
	}
	if currentDomains() != before {
		t.Fatal("failed reload must keep the previous snapshot")
	}

	if _, _, err := loadDomainLists(nil, nil); err != nil {
		t.Fatal(err)
	}
}

func TestExternShadowed(t *testing.T) {
	if _, _, err := loadDomainLists(nil, nil); err != nil {
		t.Fatal(err)
	}
	// tiktokcdn.com 同时出现在 gfw 列表与 gohome 内置主干域名中
	if !externShadowedHit("tiktokcdn.com.") {
		t.Error("tiktokcdn.com should be shadowed by builtin direct domain")
	}
	// c.mi.com 是 gfw 域名，但 mi.com 是 gohome 内置直连主干域名
	if !externShadowedHit("c.mi.com.") {
		t.Error("c.mi.com should be shadowed by builtin mi.com")
	}
	// 遮蔽规则对子域同样生效
	if !externShadowedHit("x.c.mi.com.") {
		t.Error("x.c.mi.com should inherit the shadow of c.mi.com")
	}
	// admin.recaptcha.net 是 gfw 域名，recaptcha.net 在 china 列表中
	if !externShadowedHit("admin.recaptcha.net.") {
		t.Error("admin.recaptcha.net should be shadowed by china parent recaptcha.net")
	}
	// 普通 gfw 域名不被遮蔽，正常交给 gohome resolver
	if externShadowedHit("www.google.com.") {
		t.Error("www.google.com must not be shadowed")
	}
	// 被遮蔽的名字分类结果仍为境外
	if got := classifyName("c.mi.com."); got != routeExtern {
		t.Fatalf("c.mi.com got %s want extern", routeName(got))
	}
}

func TestLoadDomainListsMissingFile(t *testing.T) {
	if _, _, err := loadDomainLists(nil, nil); err != nil {
		t.Fatal(err)
	}
	if _, _, err := loadDomainLists([]string{"/no/such/china/file"}, nil); err == nil {
		t.Fatal("missing china file should return error")
	}
	if _, _, err := loadDomainLists(nil, []string{"/no/such/gfw/file"}); err == nil {
		t.Fatal("missing gfw file should return error")
	}
}

func TestWithPort(t *testing.T) {
	cases := []struct{ in, want string }{
		{"114.114.114.114", "114.114.114.114:53"},
		{"114.114.114.114:53", "114.114.114.114:53"},
		{"::1", "[::1]:53"},
		{"[::1]:5353", "[::1]:5353"},
	}
	for _, c := range cases {
		if got := withPort(c.in); got != c.want {
			t.Errorf("withPort(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

func TestSplitUpstreams(t *testing.T) {
	cases := []struct {
		in   string
		want []string
	}{
		{"8.8.8.8:53", []string{"8.8.8.8:53"}},
		{"https://1.1.1.1/dns-query, https://8.8.8.8/dns-query", []string{"https://1.1.1.1/dns-query", "https://8.8.8.8/dns-query"}},
		{" , a:53 ,, ", []string{"a:53"}},
		{" , , ", nil},
	}
	for _, c := range cases {
		got := splitUpstreams(c.in)
		if len(got) != len(c.want) {
			t.Fatalf("splitUpstreams(%q) = %v, want %v", c.in, got, c.want)
		}
		for i := range got {
			if got[i] != c.want[i] {
				t.Fatalf("splitUpstreams(%q) = %v, want %v", c.in, got, c.want)
			}
		}
	}
}

func TestUpstreamFor(t *testing.T) {
	u, err := upstreamFor("https://1.1.1.1/dns-query", time.Second)
	if err != nil || u == nil {
		t.Fatalf("DoH upstream: %v", err)
	}
	s := newSocketClient("114.114.114.114", time.Second)
	if s.addr != "114.114.114.114:53" || s.network != "udp" {
		t.Fatalf("socket client: %+v", s)
	}
	s2 := newSocketClient("tcp://1.2.3.4", time.Second)
	if s2.addr != "1.2.3.4:53" || s2.network != "tcp" {
		t.Fatalf("tcp client: %+v", s2)
	}
	if _, err := buildUpstreams(" , ", time.Second); err == nil {
		t.Error("empty list should error")
	}
	if _, err := buildUpstreams("8.8.8.8,https://1.1.1.1/dns-query", time.Second); err != nil {
		t.Fatalf("mixed list: %v", err)
	}
}

func TestCountryDB(t *testing.T) {
	db, err := maxminddb.Open("GeoLite2-Country.mmdb")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if int64(db.Metadata.BuildEpoch) < time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC).Unix() {
		t.Fatalf("country db too old: %s", time.Unix(int64(db.Metadata.BuildEpoch), 0).UTC())
	}
	if err := thirdparty.LoadGeoip2("GeoLite2-Country.mmdb"); err != nil {
		t.Fatal(err)
	}
	cn, err := thirdparty.GetGeoipCountryIsoCode("114.114.114.114")
	if err != nil || cn != "CN" {
		t.Fatalf("114.114.114.114 %q %v", cn, err)
	}
	us, err := thirdparty.GetGeoipCountryIsoCode("8.8.8.8")
	if err != nil || us != "US" {
		t.Fatalf("8.8.8.8 %q %v", us, err)
	}
}
