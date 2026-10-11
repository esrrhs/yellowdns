package main

import (
	"context"
	"encoding/json"
	"net"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/miekg/dns"
)

// aAnswerMsg 构造一条只含单个 A 记录的应答（无 Question，存储侧不关心）。
func aAnswerMsg(name, ip string, ttl uint32) *dns.Msg {
	m := new(dns.Msg)
	m.Answer = append(m.Answer, &dns.A{
		Hdr: dns.RR_Header{Name: dns.Fqdn(name), Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: ttl},
		A:   net.ParseIP(ip).To4(),
	})
	return m
}

func questionKey(name string) string {
	req := new(dns.Msg)
	req.SetQuestion(dns.Fqdn(name), dns.TypeA)
	return staleKey(req.Question[0])
}

// TestStaleStoreFreshAndExpired 验证备份存储在新鲜期/过期窗口内/越界三种情况下的行为，
// 以及同名刷新不占新容量。
func TestStaleStoreFreshAndExpired(t *testing.T) {
	s := newStaleStore(10)
	key := questionKey("a.test")

	// 不存在 -> miss
	if _, _, ok := s.get(key, time.Hour); ok {
		t.Fatal("empty store must miss")
	}

	// 新鲜期内：TTL 按剩余时间衰减（30s 余量，结果应在 29~30s）。
	s.put(key, aAnswerMsg("a.test", "1.1.1.1", 30), time.Now().Add(30*time.Second))
	if s.len() != 1 {
		t.Fatalf("len = %d, want 1", s.len())
	}
	resp, stale, ok := s.get(key, time.Hour)
	if !ok || stale {
		t.Fatalf("fresh entry: ok=%v stale=%v, want true/false", ok, stale)
	}
	if got := resp.Answer[0].Header().Ttl; got < 29 || got > 30 {
		t.Fatalf("fresh TTL = %d, want 29~30", got)
	}

	// 过期 10 分钟但在 1h 窗口内：返回固定 5s TTL 的过期应答。
	s.put(key, aAnswerMsg("a.test", "1.1.1.1", 30), time.Now().Add(-10*time.Minute))
	resp, stale, ok = s.get(key, time.Hour)
	if !ok || !stale {
		t.Fatalf("expired-in-window: ok=%v stale=%v, want true/true", ok, stale)
	}
	if got := resp.Answer[0].Header().Ttl; got != staleReplyTTLSeconds {
		t.Fatalf("stale TTL = %d, want %d", got, staleReplyTTLSeconds)
	}

	// 过期超过窗口：miss 且条目被懒清理。
	if _, _, ok := s.get(key, time.Minute); ok {
		t.Fatal("entry past stale window must miss")
	}
	if s.len() != 0 {
		t.Fatalf("out-of-window entry should be evicted, len = %d", s.len())
	}
}

// TestStaleStoreCapacity 满容时同名刷新不增长；新 key 插入触发淘汰。
func TestStaleStoreCapacity(t *testing.T) {
	s := newStaleStore(2)
	m := aAnswerMsg("a.test", "1.1.1.1", 30)
	s.put(questionKey("a.test"), m, time.Now().Add(30*time.Second))
	s.put(questionKey("a.test"), m, time.Now().Add(30*time.Second))
	if s.len() != 1 {
		t.Fatalf("same-key refresh len = %d, want 1", s.len())
	}
	s.put(questionKey("b.test"), m, time.Now().Add(30*time.Second))
	s.put(questionKey("c.test"), m, time.Now().Add(30*time.Second))
	if s.len() != 2 {
		t.Fatalf("capacity eviction len = %d, want 2", s.len())
	}
}

// TestStaleStoreClear 清空后所有条目消失。
func TestStaleStoreClear(t *testing.T) {
	s := newStaleStore(10)
	s.put(questionKey("a.test"), aAnswerMsg("a.test", "1.1.1.1", 30), time.Now().Add(30*time.Second))
	s.clear()
	if s.len() != 0 {
		t.Fatalf("len after clear = %d, want 0", s.len())
	}
}

// TestClampResponseTTL 验证 TTL 下限/上限收敛、生效时长返回值与 OPT 记录不被改写。
func TestClampResponseTTL(t *testing.T) {
	// 下限：30s 被抬到 60s，effective 同步为 60s。
	m := aAnswerMsg("a.test", "1.1.1.1", 30)
	if eff := clampResponseTTL(m, 60*time.Second, 0); eff != 60*time.Second {
		t.Fatalf("min clamp effective = %v, want 60s", eff)
	}
	if got := m.Answer[0].Header().Ttl; got != 60 {
		t.Fatalf("min clamped TTL = %d, want 60", got)
	}

	// 上限：7200s 被压到 3600s。
	m = aAnswerMsg("b.test", "2.2.2.2", 7200)
	if eff := clampResponseTTL(m, 0, time.Hour); eff != time.Hour {
		t.Fatalf("max clamp effective = %v, want 1h", eff)
	}
	if got := m.Answer[0].Header().Ttl; got != 3600 {
		t.Fatalf("max clamped TTL = %d, want 3600", got)
	}

	// 上下限同时存在时落在区间内；min>max 的非法组合由 main 启动校验拦截。
	m = aAnswerMsg("c.test", "3.3.3.3", 500)
	clampResponseTTL(m, 60*time.Second, time.Hour)
	if got := m.Answer[0].Header().Ttl; got != 500 {
		t.Fatalf("in-range TTL = %d, want 500", got)
	}

	// OPT 的 Ttl 编码 EDNS 标志，绝不能被收敛改写。
	m = aAnswerMsg("d.test", "4.4.4.4", 30)
	opt := &dns.OPT{Hdr: dns.RR_Header{Name: ".", Rrtype: dns.TypeOPT, Ttl: 0x8000}}
	m.Extra = append(m.Extra, opt)
	clampResponseTTL(m, 60*time.Second, time.Hour)
	if got := m.Extra[0].Header().Ttl; got != 0x8000 {
		t.Fatalf("OPT Ttl = %#x, want 0x8000", got)
	}

	// 无 Answer 的应答不产生缓存时长。
	if eff := clampResponseTTL(new(dns.Msg), time.Minute, time.Hour); eff != 0 {
		t.Fatalf("empty answer effective = %v, want 0", eff)
	}
}

// TestServeStaleEndToEnd 走完整 Exchange：先经假上游成功一次，再把上游换成死地址，
// 验证新鲜备份与过期备份都能兜底；关闭开关时仍然返回错误。
func TestServeStaleEndToEnd(t *testing.T) {
	if _, _, err := loadDomainLists(nil, nil); err != nil {
		t.Fatal(err)
	}
	metrics.reset()
	t.Cleanup(metrics.reset)

	ip := "10.50.0.1"
	good := startFakeUDPDNS(t, ip)
	dead := func() []exchangeClient {
		return []exchangeClient{newSocketClient("127.0.0.1:9", 200*time.Millisecond)}
	}

	r := &routingResolver{
		local:    []exchangeClient{newSocketClient(good, time.Second)},
		timeout:  500 * time.Millisecond,
		stale:    newStaleStore(100),
		staleTTL: time.Hour,
	}

	// 第一次：上游正常，应答（TTL 30）登记为备份。
	if got := queryA(t, r, "www.baidu.com"); got != ip {
		t.Fatalf("first answer = %s, want %s", got, ip)
	}

	// 上游全挂：备份仍在 30s 新鲜期内，按剩余 TTL 返回。
	r.local = dead()
	req := new(dns.Msg)
	req.SetQuestion("www.baidu.com.", dns.TypeA)
	resp, err := r.Exchange(context.Background(), req)
	if err != nil {
		t.Fatalf("fresh backup should be served: %v", err)
	}
	if got := resp.Answer[0].(*dns.A).A.String(); got != ip {
		t.Fatalf("fresh backup answer = %s, want %s", got, ip)
	}
	if ttl := resp.Answer[0].Header().Ttl; ttl < 29 || ttl > 30 {
		t.Fatalf("fresh backup TTL = %d, want 29~30", ttl)
	}

	// 把备份改成 10 分钟前过期：在 1h stale 窗口内返回固定 5s TTL。
	r.stale.put(questionKey("www.baidu.com"), aAnswerMsg("www.baidu.com", ip, 30), time.Now().Add(-10*time.Minute))
	req2 := new(dns.Msg)
	req2.SetQuestion("www.baidu.com.", dns.TypeA)
	resp, err = r.Exchange(context.Background(), req2)
	if err != nil {
		t.Fatalf("stale backup should be served: %v", err)
	}
	if got := resp.Answer[0].(*dns.A).A.String(); got != ip {
		t.Fatalf("stale backup answer = %s, want %s", got, ip)
	}
	if ttl := resp.Answer[0].Header().Ttl; ttl != staleReplyTTLSeconds {
		t.Fatalf("stale TTL = %d, want %d", ttl, staleReplyTTLSeconds)
	}
	if got := metrics.staleServed.Load(); got != 2 {
		t.Fatalf("staleServed = %d, want 2", got)
	}

	// 关闭开关（staleTTL=0）：即使备份存在且上游全挂，也必须返回错误。
	r.staleTTL = 0
	req3 := new(dns.Msg)
	req3.SetQuestion("www.baidu.com.", dns.TypeA)
	if _, err := r.Exchange(context.Background(), req3); err == nil {
		t.Fatal("serve-stale disabled must propagate the upstream error")
	}
	if got := metrics.staleServed.Load(); got != 2 {
		t.Fatalf("staleServed after disabled query = %d, want 2", got)
	}
}

// TestServeStaleMinTTLClamp 启用 -cache-min-ttl 后，外发 TTL 被抬高，
// 且 gohome 内置缓存已过期而本地备份仍在保鲜地板内时仍可兜底。
func TestServeStaleMinTTLClamp(t *testing.T) {
	if _, _, err := loadDomainLists(nil, nil); err != nil {
		t.Fatal(err)
	}
	metrics.reset()
	t.Cleanup(metrics.reset)

	ip := "10.50.0.2"
	good := startFakeUDPDNS(t, ip)
	r := &routingResolver{
		local:    []exchangeClient{newSocketClient(good, time.Second)},
		timeout:  500 * time.Millisecond,
		stale:    newStaleStore(100),
		staleTTL: 2 * time.Hour,
		minTTL:   5 * time.Minute,
	}
	req := new(dns.Msg)
	req.SetQuestion("www.baidu.com.", dns.TypeA)
	resp, err := r.Exchange(context.Background(), req)
	if err != nil {
		t.Fatal(err)
	}
	if got := resp.Answer[0].Header().Ttl; got != 300 {
		t.Fatalf("min-ttl clamped outgoing TTL = %d, want 300", got)
	}
	if got := r.stale.len(); got != 1 {
		t.Fatalf("stale store len = %d, want 1", got)
	}

	// 备份的过期时间是 5 分钟后；把当前时间拨到"已过期但在窗口内"验证上限边界：
	// 超过 staleTTL 窗口则不再兜底。
	r.local = []exchangeClient{newSocketClient("127.0.0.1:9", 200*time.Millisecond)}
	r.stale.put(questionKey("www.baidu.com"), aAnswerMsg("www.baidu.com", ip, 30), time.Now().Add(-3*time.Hour))
	req2 := new(dns.Msg)
	req2.SetQuestion("www.baidu.com.", dns.TypeA)
	if _, err := r.Exchange(context.Background(), req2); err == nil {
		t.Fatal("entry older than stale window must not be served")
	}
	if got := metrics.staleServed.Load(); got != 0 {
		t.Fatalf("staleServed = %d, want 0", got)
	}
}

// TestStaleFlushAndReload flush 与 reload 都必须清空备份存储。
func TestStaleFlushAndReload(t *testing.T) {
	s := newStaleStore(10)
	s.put(questionKey("a.test"), aAnswerMsg("a.test", "1.1.1.1", 30), time.Now().Add(30*time.Second))
	r := &routingResolver{stale: s}
	if n := r.flushCache(); n != 1 {
		t.Fatalf("flushCache returned %d, want 1", n)
	}
	if r.staleLen() != 0 {
		t.Fatalf("staleLen after flush = %d, want 0", r.staleLen())
	}

	s.put(questionKey("b.test"), aAnswerMsg("b.test", "2.2.2.2", 30), time.Now().Add(30*time.Second))
	if _, _, _, err := r.reload(nil, nil, nil, ""); err != nil {
		t.Fatal(err)
	}
	if r.staleLen() != 0 {
		t.Fatalf("staleLen after reload = %d, want 0", r.staleLen())
	}
}

// TestStaleObservability 验证备份条目数与兜底次数进入 /stats JSON 与 /metrics。
func TestStaleObservability(t *testing.T) {
	old := staleStats
	staleStats = func() int { return 17 }
	t.Cleanup(func() { staleStats = old })
	metrics.reset()
	t.Cleanup(metrics.reset)
	metrics.staleServed.Add(4)

	s := &statsServer{}
	rec := httptest.NewRecorder()
	s.statsHandler(rec, httptest.NewRequest("GET", "/stats", nil))
	var snap statsSnapshot
	if err := json.Unmarshal(rec.Body.Bytes(), &snap); err != nil {
		t.Fatal(err)
	}
	if snap.Cache.StaleEntries != 17 || snap.Cache.StaleServed != 4 {
		t.Fatalf("stale snapshot = %+v, want entries 17 served 4", snap.Cache)
	}

	recM := httptest.NewRecorder()
	s.metricsHandler(recM, httptest.NewRequest("GET", "/metrics", nil))
	body := recM.Body.String()
	for _, want := range []string{
		"# TYPE yellowdns_cache_stale_entries gauge",
		"yellowdns_cache_stale_entries 17",
		"# TYPE yellowdns_cache_stale_served_total counter",
		"yellowdns_cache_stale_served_total 4",
	} {
		if !strings.Contains(body, want) {
			t.Errorf("metrics body missing %q\n%s", want, body)
		}
	}
}
