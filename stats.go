package main

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"strings"
	"sync/atomic"
	"time"

	"github.com/esrrhs/gohome/loggo"
	"github.com/miekg/dns"
)

// procStart 近似进程启动时间，用于 /stats 的 uptime。
var procStart = time.Now()

// ready 表示服务是否完成启动、可对外应答；供 /readyz 就绪探针使用。
// 启动过程中为 false，DNS 服务监听成功后置 true；进程退出时随进程失效。
var ready = atomic.Bool{}

func isReady() bool { return ready.Load() }

// statsCounters 是全进程查询统计，全部用原子计数，查询路径无锁累加。
type statsCounters struct {
	total        atomic.Int64 // 收到的查询总数
	routeLocal   atomic.Int64 // 最终判定走境内（含 resolver 与兜底路径）
	routeExtern  atomic.Int64 // 最终判定走境外
	routeAuto    atomic.Int64 // 交给 gohome resolver 双栈竞速
	shadowed     atomic.Int64 // 被直连树遮蔽、强制绕行境外的 gfw 域名
	fallback     atomic.Int64 // gohome resolver 不可用/失败，直查上游兜底
	qtypeA       atomic.Int64
	qtypeAAAA    atomic.Int64
	qtypeOther   atomic.Int64
	hostsHits    atomic.Int64 // 命中静态 hosts 规则的查询数
	upAttempts   atomic.Int64 // 上游尝试次数（含 failover 重试）
	upErrors     atomic.Int64 // 上游单次尝试失败次数
	cacheFlushes atomic.Int64 // 通过 POST /cache/flush 主动清缓存的次数
}

var metrics = &statsCounters{}

// cacheStatus 由 main 注入，返回 resolver 当前响应缓存条目数；未注入时按 0 输出。
var cacheStatus func() int

// updateStatusInfo 由 main 注入，返回自动更新是否启用与检查间隔；未注入时按禁用输出。
var updateStatusInfo func() (enabled bool, interval time.Duration)

func (s *statsCounters) reset() {
	*s = statsCounters{}
}

// observeQuery 记录一次入站查询的总数与 qtype 分布。
func (s *statsCounters) observeQuery(qtype uint16) {
	s.total.Add(1)
	switch qtype {
	case dns.TypeA:
		s.qtypeA.Add(1)
	case dns.TypeAAAA:
		s.qtypeAAAA.Add(1)
	default:
		s.qtypeOther.Add(1)
	}
}

// observeRoute 记录由分类结果决定的路由；shadowed 为 true 时同时累计遮蔽绕行。
func (s *statsCounters) observeRoute(mode int, shadowed bool) {
	switch mode {
	case routeLocal:
		s.routeLocal.Add(1)
	case routeExtern:
		s.routeExtern.Add(1)
	default:
		s.routeAuto.Add(1)
	}
	if shadowed {
		s.shadowed.Add(1)
	}
}

// statsSnapshot 是 /stats 输出的 JSON 结构。
type statsSnapshot struct {
	Version       string  `json:"version"`
	UptimeSeconds float64 `json:"uptime_seconds"`
	Domains       struct {
		China    int `json:"china"`
		Gfw      int `json:"gfw"`
		Shadowed int `json:"shadowed"`
		Hosts    int `json:"hosts"`
	} `json:"domains"`
	Queries struct {
		Total    int64 `json:"total"`
		Local    int64 `json:"local"`
		Extern   int64 `json:"extern"`
		Auto     int64 `json:"auto"`
		Shadowed int64 `json:"shadowed"`
		Fallback int64 `json:"fallback"`
		Hosts    int64 `json:"hosts"`
	} `json:"queries"`
	Upstreams struct {
		Attempts int64 `json:"attempts"`
		Errors   int64 `json:"errors"`
	} `json:"upstreams"`
	Cache struct {
		Entries int   `json:"entries"` // resolver 响应缓存当前条目（含未懒清理的过期项）
		Flushes int64 `json:"flushes"` // 主动 flush 次数
	} `json:"cache"`
	Qtypes struct {
		A     int64 `json:"A"`
		AAAA  int64 `json:"AAAA"`
		Other int64 `json:"other"`
	} `json:"qtypes"`
	Updates struct {
		Enabled         bool                            `json:"enabled"`
		IntervalSeconds int64                           `json:"interval_seconds"`
		Sources         map[string]updateSourceSnapshot `json:"sources"`
	} `json:"updates"`
}

func (s *statsCounters) snapshot() statsSnapshot {
	var snap statsSnapshot
	snap.Version = version
	snap.UptimeSeconds = time.Since(procStart).Round(time.Millisecond).Seconds()
	d := currentDomains()
	snap.Domains.China = len(d.china)
	snap.Domains.Gfw = len(d.gfw)
	snap.Domains.Shadowed = len(d.shadowed)
	h := currentHosts()
	snap.Domains.Hosts = len(h.exact) + len(h.wildcard)
	snap.Queries.Total = s.total.Load()
	snap.Queries.Local = s.routeLocal.Load()
	snap.Queries.Extern = s.routeExtern.Load()
	snap.Queries.Auto = s.routeAuto.Load()
	snap.Queries.Shadowed = s.shadowed.Load()
	snap.Queries.Fallback = s.fallback.Load()
	snap.Queries.Hosts = s.hostsHits.Load()
	snap.Upstreams.Attempts = s.upAttempts.Load()
	snap.Upstreams.Errors = s.upErrors.Load()
	if cacheStatus != nil {
		snap.Cache.Entries = cacheStatus()
	}
	snap.Cache.Flushes = s.cacheFlushes.Load()
	snap.Qtypes.A = s.qtypeA.Load()
	snap.Qtypes.AAAA = s.qtypeAAAA.Load()
	snap.Qtypes.Other = s.qtypeOther.Load()

	if updateStatusInfo != nil {
		enabled, interval := updateStatusInfo()
		snap.Updates.Enabled = enabled
		snap.Updates.IntervalSeconds = int64(interval.Seconds())
	}
	chinaH, gfwH, geoH := updateMetrics.snapshot()
	snap.Updates.Sources = map[string]updateSourceSnapshot{
		"china": chinaH,
		"gfw":   gfwH,
		"geoip": geoH,
	}
	return snap
}

// metricsHandler 输出 Prometheus 文本格式指标，鉴权与 /stats 一致。
func (s *statsServer) metricsHandler(w http.ResponseWriter, r *http.Request) {
	if !s.authorized(r) {
		w.Header().Set("WWW-Authenticate", `Bearer realm="yellowdns-stats"`)
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	snap := metrics.snapshot()
	var b strings.Builder
	writeMetric := func(line string) { b.WriteString(line); b.WriteByte('\n') }
	writeHelp := func(name, typ, help string) {
		writeMetric("# HELP " + name + " " + help)
		writeMetric("# TYPE " + name + " " + typ)
	}

	writeHelp("yellowdns_uptime_seconds", "gauge", "Process uptime in seconds.")
	fmt.Fprintf(&b, "yellowdns_uptime_seconds %g\n", snap.UptimeSeconds)

	writeHelp("yellowdns_domains", "gauge", "Domain rules currently loaded.")
	fmt.Fprintf(&b, "yellowdns_domains{list=\"china\"} %d\n", snap.Domains.China)
	fmt.Fprintf(&b, "yellowdns_domains{list=\"gfw\"} %d\n", snap.Domains.Gfw)
	fmt.Fprintf(&b, "yellowdns_domains{list=\"shadowed\"} %d\n", snap.Domains.Shadowed)
	fmt.Fprintf(&b, "yellowdns_domains{list=\"hosts\"} %d\n", snap.Domains.Hosts)

	writeHelp("yellowdns_queries_total", "counter", "Queries handled by final route.")
	fmt.Fprintf(&b, "yellowdns_queries_total{route=\"local\"} %d\n", snap.Queries.Local)
	fmt.Fprintf(&b, "yellowdns_queries_total{route=\"extern\"} %d\n", snap.Queries.Extern)
	fmt.Fprintf(&b, "yellowdns_queries_total{route=\"auto\"} %d\n", snap.Queries.Auto)

	writeHelp("yellowdns_queries_shadowed_total", "counter", "External queries forced to bypass the gohome direct trie.")
	fmt.Fprintf(&b, "yellowdns_queries_shadowed_total %d\n", snap.Queries.Shadowed)
	writeHelp("yellowdns_queries_fallback_total", "counter", "Queries answered via direct upstream fallback.")
	fmt.Fprintf(&b, "yellowdns_queries_fallback_total %d\n", snap.Queries.Fallback)
	writeHelp("yellowdns_queries_hosts_total", "counter", "Queries answered from static hosts rules.")
	fmt.Fprintf(&b, "yellowdns_queries_hosts_total %d\n", snap.Queries.Hosts)
	writeHelp("yellowdns_queries_total_all", "counter", "Total inbound queries.")
	fmt.Fprintf(&b, "yellowdns_queries_total_all %d\n", snap.Queries.Total)

	writeHelp("yellowdns_queries_qtype_total", "counter", "Inbound queries by question type.")
	fmt.Fprintf(&b, "yellowdns_queries_qtype_total{type=\"A\"} %d\n", snap.Qtypes.A)
	fmt.Fprintf(&b, "yellowdns_queries_qtype_total{type=\"AAAA\"} %d\n", snap.Qtypes.AAAA)
	fmt.Fprintf(&b, "yellowdns_queries_qtype_total{type=\"other\"} %d\n", snap.Qtypes.Other)

	writeHelp("yellowdns_upstream_attempts_total", "counter", "Upstream exchange attempts, including failover retries.")
	fmt.Fprintf(&b, "yellowdns_upstream_attempts_total %d\n", snap.Upstreams.Attempts)
	writeHelp("yellowdns_upstream_errors_total", "counter", "Failed upstream exchange attempts.")
	fmt.Fprintf(&b, "yellowdns_upstream_errors_total %d\n", snap.Upstreams.Errors)

	writeHelp("yellowdns_cache_entries", "gauge", "DNS response cache entries currently held by the resolver.")
	fmt.Fprintf(&b, "yellowdns_cache_entries %d\n", snap.Cache.Entries)
	writeHelp("yellowdns_cache_flushes_total", "counter", "Explicit cache flushes triggered via POST /cache/flush.")
	fmt.Fprintf(&b, "yellowdns_cache_flushes_total %d\n", snap.Cache.Flushes)

	writeHelp("yellowdns_update_last_attempt_timestamp_seconds", "gauge", "Unix timestamp of the last auto-update attempt per source; 0 means never attempted.")
	writeHelp("yellowdns_update_last_success_timestamp_seconds", "gauge", "Unix timestamp of the last reachable auto-update source (content unchanged counts as success); 0 means never succeeded.")
	writeHelp("yellowdns_update_success_total", "counter", "Successful auto-update source checks.")
	writeHelp("yellowdns_update_failures_total", "counter", "Failed auto-update source checks (download, size, health validation or disk).")
	writeHelp("yellowdns_update_consecutive_failures", "gauge", "Consecutive failed checks per source; reset to 0 on success.")
	for _, src := range []string{"china", "gfw", "geoip"} {
		h := snap.Updates.Sources[src]
		fmt.Fprintf(&b, "yellowdns_update_last_attempt_timestamp_seconds{source=%q} %d\n", src, h.LastAttempt)
		fmt.Fprintf(&b, "yellowdns_update_last_success_timestamp_seconds{source=%q} %d\n", src, h.LastSuccess)
		fmt.Fprintf(&b, "yellowdns_update_success_total{source=%q} %d\n", src, h.Successes)
		fmt.Fprintf(&b, "yellowdns_update_failures_total{source=%q} %d\n", src, h.Failures)
		fmt.Fprintf(&b, "yellowdns_update_consecutive_failures{source=%q} %d\n", src, h.ConsecutiveFailures)
	}

	w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
	if _, err := w.Write([]byte(b.String())); err != nil {
		loggo.Warn("write metrics fail: %v", err)
	}
}

// readyzHandler 是就绪探针：服务启动完成前返回 503，启动后 200。
// 不鉴权（K8s readinessProbe 不便带认证头），且不泄露数据。
func readyzHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	if !isReady() {
		w.WriteHeader(http.StatusServiceUnavailable)
		_, _ = w.Write([]byte("not ready\n"))
		return
	}
	_, _ = w.Write([]byte("ready\n"))
}

// healthzHandler 是无鉴权存活探针（只暴露存活状态，不泄露任何规则/统计信息）。
func healthzHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	_, _ = w.Write([]byte("ok\n"))
}

// statsHandler 以 JSON 输出当前统计快照。
func (s *statsServer) statsHandler(w http.ResponseWriter, r *http.Request) {
	if !s.authorized(r) {
		w.Header().Set("WWW-Authenticate", `Bearer realm="yellowdns-stats"`)
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	if err := enc.Encode(metrics.snapshot()); err != nil {
		loggo.Warn("write stats fail: %v", err)
	}
}

// cacheFlushHandler 主动清空 resolver 响应缓存。写操作，鉴权与 /stats 一致，
// 且只接受 POST；返回清空前的条目数。
func (s *statsServer) cacheFlushHandler(w http.ResponseWriter, r *http.Request) {
	if !s.authorized(r) {
		w.Header().Set("WWW-Authenticate", `Bearer realm="yellowdns-stats"`)
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	n := 0
	if s.flushCache != nil {
		n = s.flushCache()
	}
	metrics.cacheFlushes.Add(1)
	loggo.Info("cache flushed %d entries via http", n)
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(map[string]int{"cleared_entries": n}); err != nil {
		loggo.Warn("write flush result fail: %v", err)
	}
}

// updateRefreshHandler 立即触发一次 china/gfw/GeoIP 全量刷新（与周期检查串行，
// 不会并发重载）。鉴权同 /stats，只接受 POST；返回各源结果。部分源失败仍返回
// 200（旧规则继续生效，细节在 body）；三个源全部失败返回 502；刷新超时返回 504。
func (s *statsServer) updateRefreshHandler(w http.ResponseWriter, r *http.Request) {
	if !s.authorized(r) {
		w.Header().Set("WWW-Authenticate", `Bearer realm="yellowdns-stats"`)
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if s.triggerUpdate == nil {
		http.Error(w, "auto-update disabled", http.StatusServiceUnavailable)
		return
	}
	// 三个源串行下载，最坏情况接近各自 60s 超时之和，给到 150s。
	ctx, cancel := context.WithTimeout(r.Context(), 150*time.Second)
	defer cancel()
	res, err := s.triggerUpdate(ctx)
	if err != nil {
		if errors.Is(err, context.DeadlineExceeded) {
			http.Error(w, "refresh timed out", http.StatusGatewayTimeout)
			return
		}
		http.Error(w, "refresh not available", http.StatusServiceUnavailable)
		return
	}
	code := http.StatusOK
	if res.China.Error != "" && res.Gfw.Error != "" && res.GeoIP.Error != "" {
		code = http.StatusBadGateway
	}
	loggo.Info("manual update refresh: china{changed=%v err=%q} gfw{changed=%v err=%q} geoip{changed=%v err=%q} reloaded=%v",
		res.China.Changed, res.China.Error, res.Gfw.Changed, res.Gfw.Error,
		res.GeoIP.Changed, res.GeoIP.Error, res.Reloaded)
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	if err := json.NewEncoder(w).Encode(res); err != nil {
		loggo.Warn("write refresh result fail: %v", err)
	}
}

// authorized 校验 Bearer token；未配置 token 时不做限制（默认仅建议绑回环）。
// 比较走常量时间，避免计时侧信道。
func (s *statsServer) authorized(r *http.Request) bool {
	if s.token == "" {
		return true
	}
	h := r.Header.Get("Authorization")
	const scheme = "Bearer "
	if len(h) <= len(scheme) || !strings.EqualFold(h[:len(scheme)], scheme) {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(h[len(scheme):]), []byte(s.token)) == 1
}

// statsServer 是可选的统计 HTTP 服务，-stats 指定监听地址时启用。
type statsServer struct {
	srv   *http.Server
	token string
	// flushCache / triggerUpdate 在 resolver/updater 就绪后由 main 注入。
	flushCache    func() int
	triggerUpdate func(ctx context.Context) (updateResult, error)
}

func startStatsServer(addr, token string) *statsServer {
	mux := http.NewServeMux()
	s := &statsServer{
		token: token,
		srv: &http.Server{
			Addr:              addr,
			Handler:           mux,
			ReadHeaderTimeout: 5 * time.Second,
		},
	}
	mux.HandleFunc("/stats", s.statsHandler)
	mux.HandleFunc("/metrics", s.metricsHandler)
	mux.HandleFunc("/cache/flush", s.cacheFlushHandler)
	mux.HandleFunc("/update/refresh", s.updateRefreshHandler)
	mux.HandleFunc("/readyz", readyzHandler)
	mux.HandleFunc("/healthz", healthzHandler)
	go func() {
		if err := s.srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			loggo.Error("stats server fail: %v", err)
		}
	}()
	if token == "" {
		loggo.Info("stats endpoint on http://%s/stats (no auth token configured)", addr)
	} else {
		loggo.Info("stats endpoint on http://%s/stats (bearer token required)", addr)
	}
	return s
}

// isLoopbackAddr 粗略判断监听地址是否只绑回环，用于无 token 时告警。
func isLoopbackAddr(addr string) bool {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		host = addr
	}
	switch host {
	case "", "0.0.0.0", "::":
		return false
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback() || host == "localhost"
}

func (s *statsServer) close() {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	_ = s.srv.Shutdown(ctx)
}
