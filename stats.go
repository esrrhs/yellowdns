package main

import (
	"context"
	"crypto/subtle"
	"encoding/json"
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

// statsCounters 是全进程查询统计，全部用原子计数，查询路径无锁累加。
type statsCounters struct {
	total       atomic.Int64 // 收到的查询总数
	routeLocal  atomic.Int64 // 最终判定走境内（含 resolver 与兜底路径）
	routeExtern atomic.Int64 // 最终判定走境外
	routeAuto   atomic.Int64 // 交给 gohome resolver 双栈竞速
	shadowed    atomic.Int64 // 被直连树遮蔽、强制绕行境外的 gfw 域名
	fallback    atomic.Int64 // gohome resolver 不可用/失败，直查上游兜底
	qtypeA      atomic.Int64
	qtypeAAAA   atomic.Int64
	qtypeOther  atomic.Int64
	upAttempts  atomic.Int64 // 上游尝试次数（含 failover 重试）
	upErrors    atomic.Int64 // 上游单次尝试失败次数
}

var metrics = &statsCounters{}

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
	} `json:"domains"`
	Queries struct {
		Total    int64 `json:"total"`
		Local    int64 `json:"local"`
		Extern   int64 `json:"extern"`
		Auto     int64 `json:"auto"`
		Shadowed int64 `json:"shadowed"`
		Fallback int64 `json:"fallback"`
	} `json:"queries"`
	Upstreams struct {
		Attempts int64 `json:"attempts"`
		Errors   int64 `json:"errors"`
	} `json:"upstreams"`
	Qtypes struct {
		A     int64 `json:"A"`
		AAAA  int64 `json:"AAAA"`
		Other int64 `json:"other"`
	} `json:"qtypes"`
}

func (s *statsCounters) snapshot() statsSnapshot {
	var snap statsSnapshot
	snap.Version = version
	snap.UptimeSeconds = time.Since(procStart).Round(time.Millisecond).Seconds()
	d := currentDomains()
	snap.Domains.China = len(d.china)
	snap.Domains.Gfw = len(d.gfw)
	snap.Domains.Shadowed = len(d.shadowed)
	snap.Queries.Total = s.total.Load()
	snap.Queries.Local = s.routeLocal.Load()
	snap.Queries.Extern = s.routeExtern.Load()
	snap.Queries.Auto = s.routeAuto.Load()
	snap.Queries.Shadowed = s.shadowed.Load()
	snap.Queries.Fallback = s.fallback.Load()
	snap.Upstreams.Attempts = s.upAttempts.Load()
	snap.Upstreams.Errors = s.upErrors.Load()
	snap.Qtypes.A = s.qtypeA.Load()
	snap.Qtypes.AAAA = s.qtypeAAAA.Load()
	snap.Qtypes.Other = s.qtypeOther.Load()
	return snap
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
