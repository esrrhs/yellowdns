package main

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// doPprof 对测试 mux 发起一次请求，返回状态码与响应体。
func doPprof(t *testing.T, h http.Handler, target, auth string) (int, string) {
	t.Helper()
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, target, nil)
	if auth != "" {
		req.Header.Set("Authorization", auth)
	}
	h.ServeHTTP(rec, req)
	body, _ := io.ReadAll(rec.Body)
	return rec.Code, string(body)
}

// TestPprofDisabledByDefault 未开启 -pprof 时所有 profiling 路由必须是 404，
// 避免"导入即暴露"。
func TestPprofDisabledByDefault(t *testing.T) {
	h := newStatsMux("", false)
	for _, target := range []string{
		"/debug/pprof/", "/debug/pprof/goroutine", "/debug/pprof/heap",
		"/debug/pprof/profile?seconds=1", "/debug/pprof/cmdline",
		"/debug/pprof/symbol", "/debug/pprof/trace?seconds=1",
	} {
		if code, _ := doPprof(t, h, target, ""); code != http.StatusNotFound {
			t.Fatalf("%s with pprof disabled: code = %d, want 404", target, code)
		}
	}
}

// TestPprofAuth 开启后：无 token 时放行（配合回环绑定的使用方式）；
// 配置 token 时无凭据/错误凭据 401，正确 Bearer 200。
func TestPprofAuth(t *testing.T) {
	hNoToken := newStatsMux("", true)
	if code, body := doPprof(t, hNoToken, "/debug/pprof/", ""); code != http.StatusOK ||
		!strings.Contains(body, "Types of profiles available") {
		t.Fatalf("pprof index no-token: code %d body %q", code, body)
	}

	h := newStatsMux("s3cret", true)
	cases := []struct {
		name string
		auth string
		want int
	}{
		{"missing", "", http.StatusUnauthorized},
		{"wrong scheme", "Basic s3cret", http.StatusUnauthorized},
		{"wrong token", "Bearer nope", http.StatusUnauthorized},
		{"empty bearer", "Bearer ", http.StatusUnauthorized},
		{"correct", "Bearer s3cret", http.StatusOK},
	}
	for _, c := range cases {
		code, _ := doPprof(t, h, "/debug/pprof/", c.auth)
		if code != c.want {
			t.Errorf("%s: code = %d, want %d", c.name, code, c.want)
		}
	}

	// 401 必须带 WWW-Authenticate 质询头。
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/debug/pprof/goroutine", nil)
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized ||
		rec.Header().Get("WWW-Authenticate") == "" {
		t.Fatalf("unauthenticated pprof: code %d challenge %q", rec.Code, rec.Header().Get("WWW-Authenticate"))
	}
}

// TestPprofSubEndpoints 鉴权通过后各子端点能真正工作（非空 profile 数据）。
func TestPprofSubEndpoints(t *testing.T) {
	// 真实 httptest server：/debug/pprof/profile 内部按 query 参数采集，
	// httptest.NewRecorder 也能跑，但用真 server 更贴近线上。
	ts := httptest.NewServer(newStatsMux("tk", true))
	t.Cleanup(ts.Close)

	get := func(target string) (int, []byte) {
		req, _ := http.NewRequest(http.MethodGet, ts.URL+target, nil)
		req.Header.Set("Authorization", "Bearer tk")
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		b, _ := io.ReadAll(resp.Body)
		return resp.StatusCode, b
	}

	// 堆快照是 gzip 或 protobuf，只校验 200 且非空。
	if code, b := get("/debug/pprof/heap"); code != http.StatusOK || len(b) == 0 {
		t.Fatalf("heap: code %d bytes %d", code, len(b))
	}
	// cmdline 返回当前进程参数，至少应包含测试二进制名。
	if code, b := get("/debug/pprof/cmdline"); code != http.StatusOK || len(b) == 0 {
		t.Fatalf("cmdline: code %d body %q", code, b)
	}
	// CPU profile 采集 1 秒，返回非空 protobuf。
	if code, b := get("/debug/pprof/profile?seconds=1"); code != http.StatusOK || len(b) == 0 {
		t.Fatalf("cpu profile: code %d bytes %d", code, len(b))
	}
}

// TestPprofDoesNotGateProbes 启用 token 后，免鉴权探针仍必须公开，
// 证明鉴权包装只作用于 pprof，没有误伤健康检查。readyz 的 200/503 取决于
// 进程就绪状态（其他测试可能改写），这里只断言不会被 401 拦住。
func TestPprofDoesNotGateProbes(t *testing.T) {
	h := newStatsMux("tk", true)
	if code, _ := doPprof(t, h, "/healthz", ""); code != http.StatusOK {
		t.Fatalf("healthz with token configured: code %d, want 200", code)
	}
	if code, _ := doPprof(t, h, "/readyz", ""); code == http.StatusUnauthorized {
		t.Fatalf("readyz must not require bearer auth, got 401")
	}
}
