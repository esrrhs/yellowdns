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
	"sync"
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

	// 应答结果维度：Exchange 返回错误（或无应答）计 qErrors；
	// 有应答时按 Rcode 归类，并统计 TC 截断（UDP 超限需走 TCP 的信号）。
	qErrors    atomic.Int64
	truncated  atomic.Int64
	rcNoerror  atomic.Int64
	rcNxdomain atomic.Int64
	rcServfail atomic.Int64
	rcRefused  atomic.Int64
	rcOther    atomic.Int64
}

var metrics = &statsCounters{}

// cacheStats 由 main 注入，返回 resolver 响应缓存的当前条目数与累计命中/未命中次数；
// 未注入时全部按 0 输出。
var cacheStats func() (entries int, hits, misses int64)

// updateStatusInfo 由 main 注入，返回自动更新是否启用与检查间隔；未注入时按禁用输出。
var updateStatusInfo func() (enabled bool, interval time.Duration)

func (s *statsCounters) reset() {
	*s = statsCounters{}
	routeLatencies.reset()
	upstreamRegistry.reset()
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

// observeLatency 记录一次端到端查询耗时，按最终路由归入对应直方图。
func (s *statsCounters) observeLatency(route string, d time.Duration) {
	routeLatencies.observe(route, d)
}

// observeResult 记录一次查询的最终结果：错误（无应答）或应答 Rcode/TC 位。
func (s *statsCounters) observeResult(resp *dns.Msg, err error) {
	if err != nil || resp == nil {
		s.qErrors.Add(1)
		return
	}
	if resp.Truncated {
		s.truncated.Add(1)
	}
	switch resp.Rcode {
	case dns.RcodeSuccess:
		s.rcNoerror.Add(1)
	case dns.RcodeNameError:
		s.rcNxdomain.Add(1)
	case dns.RcodeServerFailure:
		s.rcServfail.Add(1)
	case dns.RcodeRefused:
		s.rcRefused.Add(1)
	default:
		s.rcOther.Add(1)
	}
}

// 路由标签：与 domainlist 的 route* 常量及 hosts 合成应答路径对应。
const (
	routeHostsLabel  = "hosts"
	routeLocalLabel  = "local"
	routeExternLabel = "extern"
	routeAutoLabel   = "auto"
)

func routeLabelOf(mode int) string {
	switch mode {
	case routeLocal:
		return routeLocalLabel
	case routeExtern:
		return routeExternLabel
	default:
		return routeAutoLabel
	}
}

// latencyBucketBoundsMs 是端到端查询延迟直方图的桶上界（毫秒），其后是隐式 +Inf 桶。
var latencyBucketBoundsMs = [11]int64{1, 5, 10, 25, 50, 100, 250, 500, 1000, 2500, 5000}

// latencyHistogram 固定桶直方图，查询热路径仅做原子加法。
type latencyHistogram struct {
	count   atomic.Int64
	sumMs   atomic.Int64
	buckets [len(latencyBucketBoundsMs) + 1]atomic.Int64
}

func (h *latencyHistogram) observe(ms int64) {
	h.count.Add(1)
	h.sumMs.Add(ms)
	for i, bound := range latencyBucketBoundsMs {
		if ms <= bound {
			h.buckets[i].Add(1)
			return
		}
	}
	h.buckets[len(latencyBucketBoundsMs)].Add(1)
}

func (h *latencyHistogram) reset() {
	h.count.Store(0)
	h.sumMs.Store(0)
	for i := range h.buckets {
		h.buckets[i].Store(0)
	}
}

// latencyBucketSnapshot 是单个桶的计数；Inf 为 true 时 LeMs 无意义，表示 +Inf 桶。
type latencyBucketSnapshot struct {
	LeMs  int64 `json:"le_ms"`
	Inf   bool  `json:"inf,omitempty"`
	Count int64 `json:"count"`
}

type latencySnapshot struct {
	Count   int64                   `json:"count"`
	SumMs   int64                   `json:"sum_ms"`
	Buckets []latencyBucketSnapshot `json:"buckets"`
}

func (h *latencyHistogram) snapshot() latencySnapshot {
	snap := latencySnapshot{
		Count:   h.count.Load(),
		SumMs:   h.sumMs.Load(),
		Buckets: make([]latencyBucketSnapshot, 0, len(latencyBucketBoundsMs)+1),
	}
	for i, bound := range latencyBucketBoundsMs {
		snap.Buckets = append(snap.Buckets, latencyBucketSnapshot{LeMs: bound, Count: h.buckets[i].Load()})
	}
	snap.Buckets = append(snap.Buckets, latencyBucketSnapshot{
		Inf:   true,
		Count: h.buckets[len(latencyBucketBoundsMs)].Load(),
	})
	return snap
}

// routeLatencySet 持有各最终路由的延迟直方图，集合初始化后不再变更。
type routeLatencySet struct {
	order []string
	m     map[string]*latencyHistogram
}

func newRouteLatencySet() *routeLatencySet {
	order := []string{routeHostsLabel, routeLocalLabel, routeExternLabel, routeAutoLabel}
	m := make(map[string]*latencyHistogram, len(order))
	for _, r := range order {
		m[r] = &latencyHistogram{}
	}
	return &routeLatencySet{order: order, m: m}
}

var routeLatencies = newRouteLatencySet()

func (s *routeLatencySet) observe(route string, d time.Duration) {
	h := s.m[route]
	if h == nil {
		h = s.m[routeAutoLabel]
	}
	h.observe(d.Milliseconds())
}

func (s *routeLatencySet) reset() {
	for _, h := range s.m {
		h.reset()
	}
}

// latencyAgg 是单上游的简单延迟汇总（count/sum/min/max，毫秒）；min 为 0 表示无样本。
type latencyAgg struct {
	count atomic.Int64
	sumMs atomic.Int64
	minMs atomic.Int64
	maxMs atomic.Int64
}

func (a *latencyAgg) observe(ms int64) {
	a.count.Add(1)
	a.sumMs.Add(ms)
	for {
		cur := a.minMs.Load()
		if cur != 0 && cur <= ms {
			break
		}
		if a.minMs.CompareAndSwap(cur, ms) {
			break
		}
	}
	for {
		cur := a.maxMs.Load()
		if cur >= ms {
			break
		}
		if a.maxMs.CompareAndSwap(cur, ms) {
			break
		}
	}
}

func (a *latencyAgg) reset() {
	a.count.Store(0)
	a.sumMs.Store(0)
	a.minMs.Store(0)
	a.maxMs.Store(0)
}

type latencyAggSnapshot struct {
	Count int64 `json:"count"`
	SumMs int64 `json:"sum_ms"`
	MinMs int64 `json:"min_ms"`
	MaxMs int64 `json:"max_ms"`
}

// perUpstreamCounters 是单个配置上游（local/extern 组内按地址区分）的健康计数。
type perUpstreamCounters struct {
	name        string
	group       string
	attempts    atomic.Int64
	failures    atomic.Int64
	lastAttempt atomic.Int64
	lastSuccess atomic.Int64
	lastError   atomic.Value // 存放 string，未记录时为 nil
	latency     latencyAgg
}

func (c *perUpstreamCounters) lastErrorText() string {
	if v := c.lastError.Load(); v != nil {
		return v.(string)
	}
	return ""
}

// maxUpstreamErrorLen 限制最近错误文本长度，避免异常长错误刷屏 /stats。
const maxUpstreamErrorLen = 200

func (c *perUpstreamCounters) record(ok bool, d time.Duration, err error) {
	now := time.Now().Unix()
	c.attempts.Add(1)
	c.lastAttempt.Store(now)
	c.latency.observe(d.Milliseconds())
	if ok {
		c.lastSuccess.Store(now)
		return
	}
	c.failures.Add(1)
	if err != nil {
		msg := err.Error()
		if len(msg) > maxUpstreamErrorLen {
			msg = msg[:maxUpstreamErrorLen]
		}
		c.lastError.Store(msg)
	}
}

type upstreamServerSnapshot struct {
	Name        string             `json:"name"`
	Group       string             `json:"group"`
	Attempts    int64              `json:"attempts"`
	Errors      int64              `json:"errors"`
	LastAttempt int64              `json:"last_attempt_unixtime"`
	LastSuccess int64              `json:"last_success_unixtime"`
	LastError   string             `json:"last_error"`
	Latency     latencyAggSnapshot `json:"latency_ms"`
}

// upstreamStatsRegistry 收集所有已配置上游的计数器；register 在启动期完成，
// 之后热路径直接持有返回的指针记录，无需加锁。
type upstreamStatsRegistry struct {
	mu    sync.Mutex
	order []string
	items map[string]*perUpstreamCounters
}

func newUpstreamStatsRegistry() *upstreamStatsRegistry {
	return &upstreamStatsRegistry{items: map[string]*perUpstreamCounters{}}
}

var upstreamRegistry = newUpstreamStatsRegistry()

func upstreamKey(group, name string) string { return group + "|" + name }

// registerUpstream 返回该组/地址对应的计数器；重复注册同一组合返回同一项。
func registerUpstream(group, name string) *perUpstreamCounters {
	key := upstreamKey(group, name)
	upstreamRegistry.mu.Lock()
	defer upstreamRegistry.mu.Unlock()
	if c, ok := upstreamRegistry.items[key]; ok {
		return c
	}
	c := &perUpstreamCounters{name: name, group: group}
	upstreamRegistry.items[key] = c
	upstreamRegistry.order = append(upstreamRegistry.order, key)
	return c
}

func (r *upstreamStatsRegistry) snapshot() []upstreamServerSnapshot {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]upstreamServerSnapshot, 0, len(r.order))
	for _, key := range r.order {
		c := r.items[key]
		out = append(out, upstreamServerSnapshot{
			Name:        c.name,
			Group:       c.group,
			Attempts:    c.attempts.Load(),
			Errors:      c.failures.Load(),
			LastAttempt: c.lastAttempt.Load(),
			LastSuccess: c.lastSuccess.Load(),
			LastError:   c.lastErrorText(),
			Latency: latencyAggSnapshot{
				Count: c.latency.count.Load(),
				SumMs: c.latency.sumMs.Load(),
				MinMs: c.latency.minMs.Load(),
				MaxMs: c.latency.maxMs.Load(),
			},
		})
	}
	return out
}

// reset 清空注册项（测试用）；已分发到 namedUpstream 的旧指针不影响新注册。
func (r *upstreamStatsRegistry) reset() {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.order = nil
	r.items = map[string]*perUpstreamCounters{}
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
		Total     int64 `json:"total"`
		Local     int64 `json:"local"`
		Extern    int64 `json:"extern"`
		Auto      int64 `json:"auto"`
		Shadowed  int64 `json:"shadowed"`
		Fallback  int64 `json:"fallback"`
		Hosts     int64 `json:"hosts"`
		Errors    int64 `json:"errors"`    // Exchange 返回错误/无应答的查询数
		Truncated int64 `json:"truncated"` // TC 位置位的应答数（提示需走 TCP）
		Rcodes    struct {
			NoError  int64 `json:"noerror"`
			NXDomain int64 `json:"nxdomain"`
			ServFail int64 `json:"servfail"`
			Refused  int64 `json:"refused"`
			Other    int64 `json:"other"`
		} `json:"responses_by_rcode"`
		Latency map[string]latencySnapshot `json:"latency_ms"`
	} `json:"queries"`
	Upstreams struct {
		Attempts int64                    `json:"attempts"`
		Errors   int64                    `json:"errors"`
		Servers  []upstreamServerSnapshot `json:"servers"`
	} `json:"upstreams"`
	Cache struct {
		Entries  int     `json:"entries"`   // resolver 响应缓存当前条目（含未懒清理的过期项）
		Hits     int64   `json:"hits"`      // 累计缓存命中
		Misses   int64   `json:"misses"`    // 累计缓存未命中（含过期）
		HitRatio float64 `json:"hit_ratio"` // hits/(hits+misses)，无查找时为 0
		Flushes  int64   `json:"flushes"`   // 主动 flush 次数
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
	snap.Queries.Errors = s.qErrors.Load()
	snap.Queries.Truncated = s.truncated.Load()
	snap.Queries.Rcodes.NoError = s.rcNoerror.Load()
	snap.Queries.Rcodes.NXDomain = s.rcNxdomain.Load()
	snap.Queries.Rcodes.ServFail = s.rcServfail.Load()
	snap.Queries.Rcodes.Refused = s.rcRefused.Load()
	snap.Queries.Rcodes.Other = s.rcOther.Load()
	snap.Upstreams.Attempts = s.upAttempts.Load()
	snap.Upstreams.Errors = s.upErrors.Load()
	snap.Upstreams.Servers = upstreamRegistry.snapshot()
	snap.Queries.Latency = make(map[string]latencySnapshot, len(routeLatencies.order))
	for _, route := range routeLatencies.order {
		snap.Queries.Latency[route] = routeLatencies.m[route].snapshot()
	}
	if cacheStats != nil {
		snap.Cache.Entries, snap.Cache.Hits, snap.Cache.Misses = cacheStats()
		if lookups := snap.Cache.Hits + snap.Cache.Misses; lookups > 0 {
			snap.Cache.HitRatio = float64(snap.Cache.Hits) / float64(lookups)
		}
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

	writeHelp("yellowdns_responses_total", "counter", "Queries answered, by DNS response code.")
	fmt.Fprintf(&b, "yellowdns_responses_total{rcode=\"noerror\"} %d\n", snap.Queries.Rcodes.NoError)
	fmt.Fprintf(&b, "yellowdns_responses_total{rcode=\"nxdomain\"} %d\n", snap.Queries.Rcodes.NXDomain)
	fmt.Fprintf(&b, "yellowdns_responses_total{rcode=\"servfail\"} %d\n", snap.Queries.Rcodes.ServFail)
	fmt.Fprintf(&b, "yellowdns_responses_total{rcode=\"refused\"} %d\n", snap.Queries.Rcodes.Refused)
	fmt.Fprintf(&b, "yellowdns_responses_total{rcode=\"other\"} %d\n", snap.Queries.Rcodes.Other)
	writeHelp("yellowdns_query_errors_total", "counter", "Queries that ended with an error or no DNS response.")
	fmt.Fprintf(&b, "yellowdns_query_errors_total %d\n", snap.Queries.Errors)
	writeHelp("yellowdns_response_truncated_total", "counter", "Responses with the TC bit set (client should retry over TCP).")
	fmt.Fprintf(&b, "yellowdns_response_truncated_total %d\n", snap.Queries.Truncated)

	writeHelp("yellowdns_upstream_attempts_total", "counter", "Upstream exchange attempts, including failover retries.")
	fmt.Fprintf(&b, "yellowdns_upstream_attempts_total %d\n", snap.Upstreams.Attempts)
	writeHelp("yellowdns_upstream_errors_total", "counter", "Failed upstream exchange attempts.")
	fmt.Fprintf(&b, "yellowdns_upstream_errors_total %d\n", snap.Upstreams.Errors)

	writeHelp("yellowdns_upstream_server_attempts_total", "counter", "Exchange attempts per configured fallback upstream.")
	writeHelp("yellowdns_upstream_server_errors_total", "counter", "Failed exchange attempts per configured fallback upstream.")
	writeHelp("yellowdns_upstream_server_last_attempt_timestamp_seconds", "gauge", "Unix timestamp of the last attempt per fallback upstream; 0 means never attempted.")
	writeHelp("yellowdns_upstream_server_last_success_timestamp_seconds", "gauge", "Unix timestamp of the last success per fallback upstream; 0 means never succeeded.")
	writeHelp("yellowdns_upstream_server_response_seconds", "summary", "Fallback upstream response time (sum/count), including failed attempts.")
	for _, srv := range snap.Upstreams.Servers {
		fmt.Fprintf(&b, "yellowdns_upstream_server_attempts_total{group=%q,upstream=%q} %d\n", srv.Group, srv.Name, srv.Attempts)
		fmt.Fprintf(&b, "yellowdns_upstream_server_errors_total{group=%q,upstream=%q} %d\n", srv.Group, srv.Name, srv.Errors)
		fmt.Fprintf(&b, "yellowdns_upstream_server_last_attempt_timestamp_seconds{group=%q,upstream=%q} %d\n", srv.Group, srv.Name, srv.LastAttempt)
		fmt.Fprintf(&b, "yellowdns_upstream_server_last_success_timestamp_seconds{group=%q,upstream=%q} %d\n", srv.Group, srv.Name, srv.LastSuccess)
		fmt.Fprintf(&b, "yellowdns_upstream_server_response_seconds_sum{group=%q,upstream=%q} %g\n", srv.Group, srv.Name, float64(srv.Latency.SumMs)/1000)
		fmt.Fprintf(&b, "yellowdns_upstream_server_response_seconds_count{group=%q,upstream=%q} %d\n", srv.Group, srv.Name, srv.Latency.Count)
	}

	writeHelp("yellowdns_query_duration_seconds", "histogram", "End-to-end query handling time by final route (hosts/local/extern/auto).")
	for _, route := range routeLatencies.order {
		h := snap.Queries.Latency[route]
		var cumulative int64
		for _, bk := range h.Buckets {
			if !bk.Inf {
				cumulative += bk.Count
				fmt.Fprintf(&b, "yellowdns_query_duration_seconds_bucket{route=%q,le=%q} %d\n", route, fmt.Sprintf("%g", float64(bk.LeMs)/1000), cumulative)
			}
		}
		// +Inf 桶累计值等于总样本数。
		fmt.Fprintf(&b, "yellowdns_query_duration_seconds_bucket{route=%q,le=\"+Inf\"} %d\n", route, h.Count)
		fmt.Fprintf(&b, "yellowdns_query_duration_seconds_sum{route=%q} %g\n", route, float64(h.SumMs)/1000)
		fmt.Fprintf(&b, "yellowdns_query_duration_seconds_count{route=%q} %d\n", route, h.Count)
	}

	writeHelp("yellowdns_cache_entries", "gauge", "DNS response cache entries currently held by the resolver.")
	fmt.Fprintf(&b, "yellowdns_cache_entries %d\n", snap.Cache.Entries)
	writeHelp("yellowdns_cache_hits_total", "counter", "Resolver cache lookups that hit a live entry.")
	fmt.Fprintf(&b, "yellowdns_cache_hits_total %d\n", snap.Cache.Hits)
	writeHelp("yellowdns_cache_misses_total", "counter", "Resolver cache lookups that missed (including expired entries).")
	fmt.Fprintf(&b, "yellowdns_cache_misses_total %d\n", snap.Cache.Misses)
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
