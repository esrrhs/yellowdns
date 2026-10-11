package main

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/miekg/dns"
)

func TestStatsHandlerJSON(t *testing.T) {
	if _, _, err := loadDomainLists(nil, nil); err != nil {
		t.Fatal(err)
	}
	metrics.reset()
	t.Cleanup(metrics.reset)
	metrics.total.Add(7)
	metrics.routeLocal.Add(3)
	metrics.routeExtern.Add(2)
	metrics.routeAuto.Add(2)
	metrics.shadowed.Add(1)
	metrics.fallback.Add(4)
	metrics.upAttempts.Add(9)
	metrics.upErrors.Add(2)
	metrics.qtypeA.Add(5)
	metrics.qtypeAAAA.Add(2)

	s := &statsServer{}
	rec := httptest.NewRecorder()
	s.statsHandler(rec, httptest.NewRequest(http.MethodGet, "/stats", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d", rec.Code)
	}
	if ct := rec.Header().Get("Content-Type"); ct != "application/json" {
		t.Fatalf("content-type = %q", ct)
	}
	var snap statsSnapshot
	if err := json.Unmarshal(rec.Body.Bytes(), &snap); err != nil {
		t.Fatal(err)
	}
	if snap.Queries.Total != 7 || snap.Queries.Local != 3 || snap.Queries.Extern != 2 ||
		snap.Queries.Auto != 2 || snap.Queries.Shadowed != 1 || snap.Queries.Fallback != 4 {
		t.Errorf("query counters mismatch: %+v", snap.Queries)
	}
	if snap.Upstreams.Attempts != 9 || snap.Upstreams.Errors != 2 {
		t.Errorf("upstream counters mismatch: %+v", snap.Upstreams)
	}
	if snap.Qtypes.A != 5 || snap.Qtypes.AAAA != 2 {
		t.Errorf("qtype counters mismatch: %+v", snap.Qtypes)
	}
	if snap.Domains.China == 0 {
		t.Error("domain counts should reflect the embedded snapshot")
	}
	if snap.UptimeSeconds < 0 {
		t.Error("uptime must be non-negative")
	}

	// 非 GET 拒绝
	rec2 := httptest.NewRecorder()
	s.statsHandler(rec2, httptest.NewRequest(http.MethodPost, "/stats", nil))
	if rec2.Code != http.StatusMethodNotAllowed {
		t.Fatalf("POST status = %d, want 405", rec2.Code)
	}
}

func TestStatsAuth(t *testing.T) {
	s := &statsServer{token: "s3cret-token"}
	authedReq := func(auth string) *http.Request {
		r := httptest.NewRequest(http.MethodGet, "/stats", nil)
		if auth != "" {
			r.Header.Set("Authorization", auth)
		}
		return r
	}

	// 无 token 头 -> 401 且带 WWW-Authenticate
	rec := httptest.NewRecorder()
	s.statsHandler(rec, authedReq(""))
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("no header status = %d, want 401", rec.Code)
	}
	if rec.Header().Get("WWW-Authenticate") == "" {
		t.Error("401 should carry WWW-Authenticate")
	}

	cases := []struct {
		name string
		auth string
		want int
	}{
		{"wrong token", "Bearer wrong", http.StatusUnauthorized},
		{"bad scheme", "Basic s3cret-token", http.StatusUnauthorized},
		{"token without scheme", "s3cret-token", http.StatusUnauthorized},
		{"empty bearer", "Bearer ", http.StatusUnauthorized},
		{"correct", "Bearer s3cret-token", http.StatusOK},
		{"scheme case-insensitive", "bearer s3cret-token", http.StatusOK},
	}
	for _, c := range cases {
		rec := httptest.NewRecorder()
		s.statsHandler(rec, authedReq(c.auth))
		if rec.Code != c.want {
			t.Errorf("%s: status = %d, want %d", c.name, rec.Code, c.want)
		}
	}

	// 未配置 token 时放行（兼容默认行为）
	open := &statsServer{}
	rec = httptest.NewRecorder()
	open.statsHandler(rec, authedReq(""))
	if rec.Code != http.StatusOK {
		t.Fatalf("no-token server status = %d, want 200", rec.Code)
	}
}

func TestIsLoopbackAddr(t *testing.T) {
	cases := map[string]bool{
		"127.0.0.1:8053": true,
		"[::1]:8053":     true,
		"localhost:8053": true,
		":8053":          false,
		"0.0.0.0:8053":   false,
		"[::]:8053":      false,
		"192.168.1.2:80": false,
	}
	for addr, want := range cases {
		if got := isLoopbackAddr(addr); got != want {
			t.Errorf("isLoopbackAddr(%q) = %v, want %v", addr, got, want)
		}
	}
}

func TestMetricsHandler(t *testing.T) {
	if _, _, err := loadDomainLists(nil, nil); err != nil {
		t.Fatal(err)
	}
	metrics.reset()
	t.Cleanup(metrics.reset)
	metrics.total.Add(11)
	metrics.routeLocal.Add(5)
	metrics.hostsHits.Add(2)
	metrics.upAttempts.Add(8)
	metrics.upErrors.Add(3)
	metrics.qtypeOther.Add(1)

	s := &statsServer{}
	rec := httptest.NewRecorder()
	s.metricsHandler(rec, httptest.NewRequest(http.MethodGet, "/metrics", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d", rec.Code)
	}
	body := rec.Body.String()
	if ct := rec.Header().Get("Content-Type"); !strings.HasPrefix(ct, "text/plain") {
		t.Fatalf("content-type = %q", ct)
	}
	for _, want := range []string{
		"# TYPE yellowdns_queries_total counter",
		`yellowdns_queries_total{route="local"} 5`,
		"yellowdns_queries_hosts_total 2",
		"yellowdns_queries_total_all 11",
		"yellowdns_upstream_attempts_total 8",
		"yellowdns_upstream_errors_total 3",
		`yellowdns_queries_qtype_total{type="other"} 1`,
		"# TYPE yellowdns_domains gauge",
		"# TYPE yellowdns_uptime_seconds gauge",
	} {
		if !strings.Contains(body, want) {
			t.Errorf("metrics body missing %q\n%s", want, body)
		}
	}

	// 鉴权与 /stats 相同
	protected := &statsServer{token: "tk"}
	rec2 := httptest.NewRecorder()
	protected.metricsHandler(rec2, httptest.NewRequest(http.MethodGet, "/metrics", nil))
	if rec2.Code != http.StatusUnauthorized {
		t.Fatalf("no token status = %d, want 401", rec2.Code)
	}
	rec3 := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/metrics", nil)
	req.Header.Set("Authorization", "Bearer tk")
	protected.metricsHandler(rec3, req)
	if rec3.Code != http.StatusOK {
		t.Fatalf("with token status = %d, want 200", rec3.Code)
	}

	// POST 拒绝
	rec4 := httptest.NewRecorder()
	s.metricsHandler(rec4, httptest.NewRequest(http.MethodPost, "/metrics", nil))
	if rec4.Code != http.StatusMethodNotAllowed {
		t.Fatalf("POST status = %d, want 405", rec4.Code)
	}
}

func TestHealthzHandler(t *testing.T) {
	// 健康探针不鉴权，即使配置了 token
	protected := &statsServer{token: "tk"}
	rec := httptest.NewRecorder()
	protected.statsHandler(rec, httptest.NewRequest(http.MethodGet, "/stats", nil))
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("sanity: /stats should be 401, got %d", rec.Code)
	}
	hrec := httptest.NewRecorder()
	healthzHandler(hrec, httptest.NewRequest(http.MethodGet, "/healthz", nil))
	if hrec.Code != http.StatusOK || strings.TrimSpace(hrec.Body.String()) != "ok" {
		t.Fatalf("healthz = %d %q", hrec.Code, hrec.Body.String())
	}
	hrec2 := httptest.NewRecorder()
	healthzHandler(hrec2, httptest.NewRequest(http.MethodPost, "/healthz", nil))
	if hrec2.Code != http.StatusMethodNotAllowed {
		t.Fatalf("POST healthz = %d, want 405", hrec2.Code)
	}
}

// TestStatsRoutingCounters 走完整 Exchange 路径验证计数器：本地/境外分类、
// 兜底次数、qtype、上游尝试与失败。
func TestStatsRoutingCounters(t *testing.T) {
	if _, _, err := loadDomainLists(nil, nil); err != nil {
		t.Fatal(err)
	}
	metrics.reset()
	t.Cleanup(metrics.reset)

	localAddr := startFakeUDPDNS(t, "10.40.0.1")
	externalAddr := startFakeUDPDNS(t, "10.40.0.2")
	r := &routingResolver{
		local:    []exchangeClient{newSocketClient(localAddr, time.Second)},
		external: []exchangeClient{newSocketClient(externalAddr, time.Second)},
		timeout:  time.Second,
	}

	if got := queryA(t, r, "www.baidu.com"); got != "10.40.0.1" {
		t.Fatalf("baidu via %s", got)
	}
	if got := queryA(t, r, "www.google.com"); got != "10.40.0.2" {
		t.Fatalf("google via %s", got)
	}

	// AAAA 查询计入其他 qtype（假上游只回 A，无 answer 不算错误）
	req6 := new(dns.Msg)
	req6.SetQuestion("www.baidu.com.", dns.TypeAAAA)
	if _, err := r.Exchange(context.Background(), req6); err != nil {
		t.Fatal(err)
	}

	// 全部上游失败：attempts/errors 各加 1
	r2 := &routingResolver{
		local:   []exchangeClient{newSocketClient("127.0.0.1:9", 100*time.Millisecond)},
		timeout: 200 * time.Millisecond,
	}
	req := new(dns.Msg)
	req.SetQuestion("zzz-no-rule.invalid.", dns.TypeA)
	if _, err := r2.Exchange(context.Background(), req); err == nil {
		t.Fatal("dead upstream should return error")
	}

	snap := metrics.snapshot()
	if snap.Queries.Total != 4 {
		t.Errorf("total = %d, want 4", snap.Queries.Total)
	}
	if snap.Queries.Local != 2 || snap.Queries.Extern != 1 || snap.Queries.Auto != 1 {
		t.Errorf("route counters = %+v, want local 2 extern 1 auto 1", snap.Queries)
	}
	if snap.Queries.Fallback != 4 {
		t.Errorf("fallback = %d, want 4", snap.Queries.Fallback)
	}
	if snap.Qtypes.A != 3 || snap.Qtypes.AAAA != 1 {
		t.Errorf("qtypes = %+v, want A 3 AAAA 1", snap.Qtypes)
	}
	// 2 次成功 + 1 次无 answer 的 AAAA + 1 次死上游失败 = 4 次尝试，1 次错误
	if snap.Upstreams.Attempts != 4 || snap.Upstreams.Errors != 1 {
		t.Errorf("upstreams = %+v, want attempts 4 errors 1", snap.Upstreams)
	}
}
