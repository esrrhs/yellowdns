package main

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	gohomedns "github.com/esrrhs/gohome/dns"
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

func TestReadyzHandler(t *testing.T) {
	// 就绪探针不鉴权，即使配置了 token 也要能被 K8s 探针访问。
	ready.Store(false)
	t.Cleanup(func() { ready.Store(false) })

	rec := httptest.NewRecorder()
	readyzHandler(rec, httptest.NewRequest(http.MethodGet, "/readyz", nil))
	if rec.Code != http.StatusServiceUnavailable || strings.TrimSpace(rec.Body.String()) != "not ready" {
		t.Fatalf("before ready = %d %q, want 503 not ready", rec.Code, rec.Body.String())
	}
	if ct := rec.Header().Get("Content-Type"); !strings.HasPrefix(ct, "text/plain") {
		t.Fatalf("content-type = %q", ct)
	}

	// HEAD 在未就绪时同样返回 503
	recHead := httptest.NewRecorder()
	readyzHandler(recHead, httptest.NewRequest(http.MethodHead, "/readyz", nil))
	if recHead.Code != http.StatusServiceUnavailable {
		t.Fatalf("HEAD before ready = %d, want 503", recHead.Code)
	}

	ready.Store(true)
	rec2 := httptest.NewRecorder()
	readyzHandler(rec2, httptest.NewRequest(http.MethodGet, "/readyz", nil))
	if rec2.Code != http.StatusOK || strings.TrimSpace(rec2.Body.String()) != "ready" {
		t.Fatalf("after ready = %d %q, want 200 ready", rec2.Code, rec2.Body.String())
	}

	// POST 拒绝
	rec3 := httptest.NewRecorder()
	readyzHandler(rec3, httptest.NewRequest(http.MethodPost, "/readyz", nil))
	if rec3.Code != http.StatusMethodNotAllowed {
		t.Fatalf("POST readyz = %d, want 405", rec3.Code)
	}

	// 经真实 HTTP 服务验证：即使配置了 token，探针不带鉴权头也返回 200。
	mux := http.NewServeMux()
	mux.HandleFunc("/readyz", readyzHandler)
	ts := httptest.NewServer(mux)
	defer ts.Close()
	httpReq, err := http.Get(ts.URL + "/readyz")
	if err != nil {
		t.Fatal(err)
	}
	defer httpReq.Body.Close()
	if httpReq.StatusCode != http.StatusOK {
		t.Fatalf("http readyz = %d, want 200", httpReq.StatusCode)
	}
}

// stubCacheResolver 只覆盖缓存相关方法，其余接口方法由内嵌 nil 接口提升
// （这些路径在本测试中不会被调用）。
type stubCacheResolver struct {
	gohomedns.Resolver
	n            int
	hits, misses int64
}

func (s *stubCacheResolver) CacheLen() int      { return s.n }
func (s *stubCacheResolver) ClearCache()        { s.n = 0 }
func (s *stubCacheResolver) CacheHits() int64   { return s.hits }
func (s *stubCacheResolver) CacheMisses() int64 { return s.misses }

func TestRoutingResolverCache(t *testing.T) {
	// inner 为 nil（gohome 初始化失败的兜底模式）时不 panic，按 0 处理。
	rr := &routingResolver{}
	if rr.cacheLen() != 0 || rr.flushCache() != 0 {
		t.Fatal("nil inner should report zero cache and flush nothing")
	}
	if n, hits, misses := rr.cacheStats(); n != 0 || hits != 0 || misses != 0 {
		t.Fatalf("nil inner cacheStats = %d/%d/%d, want all zero", n, hits, misses)
	}

	stub := &stubCacheResolver{n: 5, hits: 8, misses: 2}
	rr = &routingResolver{inner: stub}
	if got := rr.cacheLen(); got != 5 {
		t.Fatalf("cacheLen = %d, want 5", got)
	}
	if n, hits, misses := rr.cacheStats(); n != 5 || hits != 8 || misses != 2 {
		t.Fatalf("cacheStats = %d/%d/%d, want 5/8/2", n, hits, misses)
	}
	if got := rr.flushCache(); got != 5 {
		t.Fatalf("flushCache returned %d, want 5", got)
	}
	if got := rr.cacheLen(); got != 0 {
		t.Fatalf("cacheLen after flush = %d, want 0", got)
	}
}

func TestCacheFlushHandler(t *testing.T) {
	metrics.reset()
	t.Cleanup(metrics.reset)

	s := &statsServer{token: "tk", flushCache: func() int { return 7 }}

	// 无鉴权 -> 401 且带 WWW-Authenticate
	rec := httptest.NewRecorder()
	s.cacheFlushHandler(rec, httptest.NewRequest(http.MethodPost, "/cache/flush", nil))
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("no token status = %d, want 401", rec.Code)
	}
	if rec.Header().Get("WWW-Authenticate") == "" {
		t.Error("401 should carry WWW-Authenticate")
	}

	// 带 token 但用 GET -> 405（写操作只接受 POST）
	recGet := httptest.NewRecorder()
	getReq := httptest.NewRequest(http.MethodGet, "/cache/flush", nil)
	getReq.Header.Set("Authorization", "Bearer tk")
	s.cacheFlushHandler(recGet, getReq)
	if recGet.Code != http.StatusMethodNotAllowed {
		t.Fatalf("GET status = %d, want 405", recGet.Code)
	}

	// 带 token POST -> 200，返回清空前条目数，并累计 flush 计数
	recPost := httptest.NewRecorder()
	postReq := httptest.NewRequest(http.MethodPost, "/cache/flush", nil)
	postReq.Header.Set("Authorization", "Bearer tk")
	s.cacheFlushHandler(recPost, postReq)
	if recPost.Code != http.StatusOK {
		t.Fatalf("POST status = %d, want 200", recPost.Code)
	}
	var body map[string]int
	if err := json.Unmarshal(recPost.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if body["cleared_entries"] != 7 {
		t.Fatalf("cleared_entries = %d, want 7", body["cleared_entries"])
	}
	if got := metrics.cacheFlushes.Load(); got != 1 {
		t.Fatalf("cacheFlushes = %d, want 1", got)
	}

	// 未配置 token 时 POST 放行（兼容默认回环部署）
	open := &statsServer{flushCache: func() int { return 0 }}
	recOpen := httptest.NewRecorder()
	open.cacheFlushHandler(recOpen, httptest.NewRequest(http.MethodPost, "/cache/flush", nil))
	if recOpen.Code != http.StatusOK {
		t.Fatalf("open POST status = %d, want 200", recOpen.Code)
	}
}

func TestCacheObservability(t *testing.T) {
	old := cacheStats
	cacheStats = func() (int, int64, int64) { return 42, 30, 10 } // 75% 命中率
	t.Cleanup(func() { cacheStats = old })
	metrics.reset()
	t.Cleanup(metrics.reset)
	metrics.cacheFlushes.Add(3)

	s := &statsServer{}
	rec := httptest.NewRecorder()
	s.statsHandler(rec, httptest.NewRequest(http.MethodGet, "/stats", nil))
	var snap statsSnapshot
	if err := json.Unmarshal(rec.Body.Bytes(), &snap); err != nil {
		t.Fatal(err)
	}
	if snap.Cache.Entries != 42 || snap.Cache.Flushes != 3 ||
		snap.Cache.Hits != 30 || snap.Cache.Misses != 10 {
		t.Fatalf("cache snapshot = %+v, want entries 42 flushes 3 hits 30 misses 10", snap.Cache)
	}
	if snap.Cache.HitRatio != 0.75 {
		t.Fatalf("hit_ratio = %v, want 0.75", snap.Cache.HitRatio)
	}

	recM := httptest.NewRecorder()
	s.metricsHandler(recM, httptest.NewRequest(http.MethodGet, "/metrics", nil))
	body := recM.Body.String()
	for _, want := range []string{
		"# TYPE yellowdns_cache_entries gauge",
		"yellowdns_cache_entries 42",
		"# TYPE yellowdns_cache_hits_total counter",
		"yellowdns_cache_hits_total 30",
		"# TYPE yellowdns_cache_misses_total counter",
		"yellowdns_cache_misses_total 10",
		"# TYPE yellowdns_cache_flushes_total counter",
		"yellowdns_cache_flushes_total 3",
	} {
		if !strings.Contains(body, want) {
			t.Errorf("metrics body missing %q\n%s", want, body)
		}
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
	// 假上游对 A/AAAA 都回 NOERROR（AAAA 仅无 answer），死上游返回错误无应答。
	if snap.Queries.Rcodes.NoError != 3 || snap.Queries.Errors != 1 {
		t.Errorf("results = noerror %d errors %d, want 3/1", snap.Queries.Rcodes.NoError, snap.Queries.Errors)
	}
}

// TestObserveResult 直接验证应答结果分类：各 rcode、错误/无应答、TC 截断。
func TestObserveResult(t *testing.T) {
	metrics.reset()
	t.Cleanup(metrics.reset)
	msg := func(rcode int, truncated bool) *dns.Msg {
		m := new(dns.Msg)
		m.Rcode = rcode
		m.Truncated = truncated
		return m
	}
	metrics.observeResult(msg(dns.RcodeSuccess, false), nil)
	metrics.observeResult(msg(dns.RcodeSuccess, true), nil) // 截断的成功应答同时计 truncated
	metrics.observeResult(msg(dns.RcodeNameError, false), nil)
	metrics.observeResult(msg(dns.RcodeServerFailure, false), nil)
	metrics.observeResult(msg(dns.RcodeRefused, false), nil)
	metrics.observeResult(msg(dns.RcodeFormatError, false), nil) // 其他 rcode
	metrics.observeResult(nil, errors.New("boom"))
	metrics.observeResult(msg(dns.RcodeSuccess, false), errors.New("late error")) // 有错误优先计 error

	snap := metrics.snapshot()
	r := snap.Queries.Rcodes
	if r.NoError != 2 || r.NXDomain != 1 || r.ServFail != 1 || r.Refused != 1 || r.Other != 1 {
		t.Fatalf("rcode counts = %+v", r)
	}
	if snap.Queries.Truncated != 1 {
		t.Fatalf("truncated = %d, want 1", snap.Queries.Truncated)
	}
	if snap.Queries.Errors != 2 {
		t.Fatalf("errors = %d, want 2", snap.Queries.Errors)
	}

	// Prometheus 输出包含各 rcode 序列与错误/截断指标。
	s := &statsServer{}
	rec := httptest.NewRecorder()
	s.metricsHandler(rec, httptest.NewRequest(http.MethodGet, "/metrics", nil))
	body := rec.Body.String()
	for _, want := range []string{
		`yellowdns_responses_total{rcode="noerror"} 2`,
		`yellowdns_responses_total{rcode="nxdomain"} 1`,
		`yellowdns_responses_total{rcode="servfail"} 1`,
		`yellowdns_responses_total{rcode="refused"} 1`,
		`yellowdns_responses_total{rcode="other"} 1`,
		`yellowdns_query_errors_total 2`,
		`yellowdns_response_truncated_total 1`,
	} {
		if !strings.Contains(body, want) {
			t.Errorf("metrics body missing %q", want)
		}
	}
}

func TestUpdateRefreshHandler(t *testing.T) {
	// 未配置触发回调（-update 关闭）：401 → 405 → 503 的判定顺序
	open := &statsServer{}
	rec := httptest.NewRecorder()
	open.updateRefreshHandler(rec, httptest.NewRequest(http.MethodPost, "/update/refresh", nil))
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("disabled POST status = %d, want 503", rec.Code)
	}

	authed := &statsServer{token: "tk", triggerUpdate: func(ctx context.Context) (updateResult, error) {
		return updateResult{}, nil
	}}
	// 无鉴权 -> 401
	rec401 := httptest.NewRecorder()
	authed.updateRefreshHandler(rec401, httptest.NewRequest(http.MethodPost, "/update/refresh", nil))
	if rec401.Code != http.StatusUnauthorized {
		t.Fatalf("no token status = %d, want 401", rec401.Code)
	}
	// GET -> 405
	recGet := httptest.NewRecorder()
	getReq := httptest.NewRequest(http.MethodGet, "/update/refresh", nil)
	getReq.Header.Set("Authorization", "Bearer tk")
	authed.updateRefreshHandler(recGet, getReq)
	if recGet.Code != http.StatusMethodNotAllowed {
		t.Fatalf("GET status = %d, want 405", recGet.Code)
	}
	// 全部成功：200，返回结构化结果
	ok := &statsServer{token: "tk", triggerUpdate: func(ctx context.Context) (updateResult, error) {
		return updateResult{
			China:    sourceResult{Changed: true},
			Reloaded: true,
		}, nil
	}}
	recOK := httptest.NewRecorder()
	postReq := httptest.NewRequest(http.MethodPost, "/update/refresh", nil)
	postReq.Header.Set("Authorization", "Bearer tk")
	ok.updateRefreshHandler(recOK, postReq)
	if recOK.Code != http.StatusOK {
		t.Fatalf("all-ok status = %d, want 200", recOK.Code)
	}
	var res updateResult
	if err := json.Unmarshal(recOK.Body.Bytes(), &res); err != nil {
		t.Fatal(err)
	}
	if !res.China.Changed || !res.Reloaded {
		t.Fatalf("body = %+v", res)
	}

	// 部分源失败仍 200（旧规则继续服务）
	partial := &statsServer{token: "tk", triggerUpdate: func(ctx context.Context) (updateResult, error) {
		return updateResult{GeoIP: sourceResult{Error: "http 404"}}, nil
	}}
	recPartial := httptest.NewRecorder()
	partialReq := httptest.NewRequest(http.MethodPost, "/update/refresh", nil)
	partialReq.Header.Set("Authorization", "Bearer tk")
	partial.updateRefreshHandler(recPartial, partialReq)
	if recPartial.Code != http.StatusOK {
		t.Fatalf("partial failure status = %d, want 200", recPartial.Code)
	}

	// 三个源全失败：502
	allFail := &statsServer{token: "tk", triggerUpdate: func(ctx context.Context) (updateResult, error) {
		return updateResult{
			China: sourceResult{Error: "x"},
			Gfw:   sourceResult{Error: "y"},
			GeoIP: sourceResult{Error: "z"},
		}, nil
	}}
	recFail := httptest.NewRecorder()
	failReq := httptest.NewRequest(http.MethodPost, "/update/refresh", nil)
	failReq.Header.Set("Authorization", "Bearer tk")
	allFail.updateRefreshHandler(recFail, failReq)
	if recFail.Code != http.StatusBadGateway {
		t.Fatalf("all-failed status = %d, want 502", recFail.Code)
	}

	// 触发超时：504
	timedOut := &statsServer{token: "tk", triggerUpdate: func(ctx context.Context) (updateResult, error) {
		return updateResult{}, context.DeadlineExceeded
	}}
	recTO := httptest.NewRecorder()
	toReq := httptest.NewRequest(http.MethodPost, "/update/refresh", nil)
	toReq.Header.Set("Authorization", "Bearer tk")
	timedOut.updateRefreshHandler(recTO, toReq)
	if recTO.Code != http.StatusGatewayTimeout {
		t.Fatalf("timeout status = %d, want 504", recTO.Code)
	}
}

func TestUpdateObservability(t *testing.T) {
	oldInfo := updateStatusInfo
	updateStatusInfo = func() (bool, time.Duration) { return true, time.Hour }
	t.Cleanup(func() { updateStatusInfo = oldInfo })
	updateMetrics.reset()
	t.Cleanup(updateMetrics.reset)
	updateMetrics.china.record(true)
	updateMetrics.gfw.record(false)

	s := &statsServer{}
	rec := httptest.NewRecorder()
	s.statsHandler(rec, httptest.NewRequest(http.MethodGet, "/stats", nil))
	var snap statsSnapshot
	if err := json.Unmarshal(rec.Body.Bytes(), &snap); err != nil {
		t.Fatal(err)
	}
	if !snap.Updates.Enabled || snap.Updates.IntervalSeconds != 3600 {
		t.Fatalf("updates meta = %+v", snap.Updates)
	}
	if snap.Updates.Sources["china"].Successes != 1 || snap.Updates.Sources["gfw"].ConsecutiveFailures != 1 {
		t.Fatalf("sources = %+v", snap.Updates.Sources)
	}

	recM := httptest.NewRecorder()
	s.metricsHandler(recM, httptest.NewRequest(http.MethodGet, "/metrics", nil))
	body := recM.Body.String()
	for _, want := range []string{
		`yellowdns_update_last_success_timestamp_seconds{source="china"}`,
		`yellowdns_update_failures_total{source="gfw"} 1`,
		`yellowdns_update_consecutive_failures{source="gfw"} 1`,
		`yellowdns_update_success_total{source="china"} 1`,
	} {
		if !strings.Contains(body, want) {
			t.Errorf("metrics body missing %q", want)
		}
	}
}

// TestLatencyHistogram 验证延迟样本归入正确的桶且累计计数/sum 正确。
func TestLatencyHistogram(t *testing.T) {
	h := &latencyHistogram{}
	// 0ms 与 1ms 都落 le=1 桶；7ms 落 le=10；6000ms 落 +Inf。
	for _, ms := range []int64{0, 1, 7, 6000} {
		h.observe(ms)
	}
	snap := h.snapshot()
	if snap.Count != 4 || snap.SumMs != 6008 {
		t.Fatalf("count/sum = %d/%d, want 4/6008", snap.Count, snap.SumMs)
	}
	find := func(le int64) int64 {
		for _, b := range snap.Buckets {
			if !b.Inf && b.LeMs == le {
				return b.Count
			}
		}
		return -1
	}
	if got := find(1); got != 2 {
		t.Errorf("le=1 bucket = %d, want 2", got)
	}
	if got := find(10); got != 1 {
		t.Errorf("le=10 bucket = %d, want 1", got)
	}
	var infCount int64
	for _, b := range snap.Buckets {
		if b.Inf {
			infCount = b.Count
		}
	}
	if infCount != 1 {
		t.Errorf("+Inf bucket = %d, want 1", infCount)
	}
}

// TestPerUpstreamCountersRecord 验证单上游成功/失败计数、最近错误与延迟汇总。
func TestPerUpstreamCountersRecord(t *testing.T) {
	c := &perUpstreamCounters{name: "1.2.3.4:53", group: "local"}
	c.record(false, 7*time.Millisecond, errors.New("boom"))
	c.record(true, 3*time.Millisecond, nil)
	c.record(true, 12*time.Millisecond, nil)

	if c.attempts.Load() != 3 || c.failures.Load() != 1 {
		t.Fatalf("attempts/failures = %d/%d", c.attempts.Load(), c.failures.Load())
	}
	if c.lastSuccess.Load() == 0 || c.lastAttempt.Load() < c.lastSuccess.Load() {
		t.Fatalf("timestamps wrong: attempt=%d success=%d", c.lastAttempt.Load(), c.lastSuccess.Load())
	}
	if c.lastErrorText() != "boom" {
		t.Fatalf("last error = %q", c.lastErrorText())
	}
	if c.latency.count.Load() != 3 || c.latency.sumMs.Load() != 22 ||
		c.latency.minMs.Load() != 3 || c.latency.maxMs.Load() != 12 {
		t.Fatalf("latency agg = count=%d sum=%d min=%d max=%d",
			c.latency.count.Load(), c.latency.sumMs.Load(), c.latency.minMs.Load(), c.latency.maxMs.Load())
	}

	// 超长错误被截断，避免 /stats 被异常长文本刷屏。
	long := strings.Repeat("x", maxUpstreamErrorLen+50)
	c.record(false, time.Millisecond, errors.New(long))
	if got := c.lastErrorText(); len(got) != maxUpstreamErrorLen {
		t.Fatalf("truncated error len = %d, want %d", len(got), maxUpstreamErrorLen)
	}
}

// TestUpstreamAndLatencyObservability 验证分上游指标与路由延迟直方图在
// /stats JSON 与 /metrics 文本中均正确暴露。
func TestUpstreamAndLatencyObservability(t *testing.T) {
	metrics.reset()
	t.Cleanup(metrics.reset)
	bad := registerUpstream("local", "127.0.0.1:9")
	bad.record(false, 2*time.Millisecond, errors.New("dial refused"))
	good := registerUpstream("extern", "https://1.1.1.1/dns-query")
	good.record(true, 25*time.Millisecond, nil)
	metrics.observeLatency(routeLocalLabel, 3*time.Millisecond)
	metrics.observeLatency(routeExternLabel, 30*time.Millisecond)

	s := &statsServer{}
	rec := httptest.NewRecorder()
	s.statsHandler(rec, httptest.NewRequest(http.MethodGet, "/stats", nil))
	var snap statsSnapshot
	if err := json.Unmarshal(rec.Body.Bytes(), &snap); err != nil {
		t.Fatal(err)
	}
	byName := map[string]upstreamServerSnapshot{}
	for _, srv := range snap.Upstreams.Servers {
		byName[srv.Name] = srv
	}
	badSnap, ok := byName["127.0.0.1:9"]
	if !ok || badSnap.Group != "local" || badSnap.Attempts != 1 || badSnap.Errors != 1 ||
		badSnap.LastError != "dial refused" || badSnap.LastSuccess != 0 || badSnap.Latency.Count != 1 {
		t.Fatalf("bad upstream snapshot = %+v (found=%v)", badSnap, ok)
	}
	goodSnap := byName["https://1.1.1.1/dns-query"]
	if goodSnap.Group != "extern" || goodSnap.Errors != 0 || goodSnap.LastSuccess == 0 ||
		goodSnap.Latency.MinMs != 25 || goodSnap.Latency.MaxMs != 25 {
		t.Fatalf("good upstream snapshot = %+v", goodSnap)
	}
	if snap.Queries.Latency["local"].Count != 1 || snap.Queries.Latency["extern"].Count != 1 {
		t.Fatalf("route latency = local:%+v extern:%+v", snap.Queries.Latency["local"], snap.Queries.Latency["extern"])
	}

	recM := httptest.NewRecorder()
	s.metricsHandler(recM, httptest.NewRequest(http.MethodGet, "/metrics", nil))
	body := recM.Body.String()
	for _, want := range []string{
		`yellowdns_upstream_server_errors_total{group="local",upstream="127.0.0.1:9"} 1`,
		`yellowdns_upstream_server_attempts_total{group="extern",upstream="https://1.1.1.1/dns-query"} 1`,
		`yellowdns_upstream_server_response_seconds_count{group="extern",upstream="https://1.1.1.1/dns-query"} 1`,
		`yellowdns_query_duration_seconds_bucket{route="local",le="0.005"} 1`,
		`yellowdns_query_duration_seconds_bucket{route="local",le="+Inf"} 1`,
		`yellowdns_query_duration_seconds_count{route="extern"} 1`,
		`# TYPE yellowdns_query_duration_seconds histogram`,
	} {
		if !strings.Contains(body, want) {
			t.Errorf("metrics body missing %q", want)
		}
	}
}
