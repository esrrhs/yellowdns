package main

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/miekg/dns"
)

// startFakeUDPDNS 在随机端口启动一个只回 A 记录的假 DNS，返回监听地址。
// 收到的每个 A 查询都以固定 IPv4 应答，用于离线验证分流路径。
func startFakeUDPDNS(t *testing.T, ip string) string {
	t.Helper()
	mux := dns.NewServeMux()
	mux.HandleFunc(".", func(w dns.ResponseWriter, m *dns.Msg) {
		reply := new(dns.Msg)
		reply.SetReply(m)
		for _, q := range m.Question {
			if q.Qtype == dns.TypeA {
				reply.Answer = append(reply.Answer, &dns.A{
					Hdr: dns.RR_Header{Name: q.Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 30},
					A:   net.ParseIP(ip).To4(),
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
	return pc.LocalAddr().String()
}

func queryA(t *testing.T, r *routingResolver, name string) string {
	t.Helper()
	req := new(dns.Msg)
	req.SetQuestion(dns.Fqdn(name), dns.TypeA)
	resp, err := r.Exchange(context.Background(), req)
	if err != nil {
		t.Fatalf("exchange %s: %v", name, err)
	}
	if len(resp.Answer) == 0 {
		t.Fatalf("exchange %s: no answer", name)
	}
	a, ok := resp.Answer[0].(*dns.A)
	if !ok {
		t.Fatalf("exchange %s: first answer is %T", name, resp.Answer[0])
	}
	return a.A.String()
}

// TestRoutingResolverClassifyFallback 使用 nil inner（gohome 初始化失败的形态），
// 验证分类结果决定查询走境内还是境外假上游。
func TestRoutingResolverClassifyFallback(t *testing.T) {
	if _, _, err := loadDomainLists(nil, nil); err != nil {
		t.Fatal(err)
	}
	localIP, externalIP := "10.10.0.1", "10.20.0.2"
	localAddr := startFakeUDPDNS(t, localIP)
	externalAddr := startFakeUDPDNS(t, externalIP)

	r := &routingResolver{
		inner:    nil,
		local:    []exchangeClient{newSocketClient(localAddr, time.Second)},
		external: []exchangeClient{newSocketClient(externalAddr, time.Second)},
		timeout:  time.Second,
	}

	cases := []struct {
		name string
		want string
	}{
		{"www.baidu.com", localIP},        // 内置 china -> 境内
		{"www.taobao.com", localIP},       // 内置 china -> 境内
		{"www.google.com", externalIP},    // 内置 gfw -> 境外
		{"api.recaptcha.net", externalIP}, // china 父域遮蔽的 gfw 子域 -> 境外
		{"c.mi.com", externalIP},          // gohome 内置 mi.com 遮蔽的 gfw 域名 -> 境外
		{"zzz-no-rule.invalid", localIP},  // 无规则 auto，inner 为 nil -> 境内兜底
	}
	for _, c := range cases {
		if got := queryA(t, r, c.name); got != c.want {
			t.Errorf("%s resolved via %s, want %s", c.name, got, c.want)
		}
	}
}

// TestRoutingResolverUpstreamFailover 第一个上游拒绝连接时应顺序尝试第二个。
func TestRoutingResolverUpstreamFailover(t *testing.T) {
	if _, _, err := loadDomainLists(nil, nil); err != nil {
		t.Fatal(err)
	}
	ip := "10.30.0.3"
	good := startFakeUDPDNS(t, ip)

	r := &routingResolver{
		local: []exchangeClient{
			newSocketClient("127.0.0.1:9", 300*time.Millisecond), // 本机 discard 端口，立即拒绝
			newSocketClient(good, time.Second),
		},
		external: []exchangeClient{
			newSocketClient("127.0.0.1:9", 300*time.Millisecond),
		},
		timeout: time.Second,
	}
	start := time.Now()
	got := queryA(t, r, "www.baidu.com")
	if time.Since(start) > 3*time.Second {
		t.Fatalf("failover took too long: %v", time.Since(start))
	}
	if got != ip {
		t.Fatalf("failover answer %s, want %s", got, ip)
	}
}

// TestRoutingResolverAllLocalUpstreamsFail 全部境内上游失败时返回错误而非挂起。
func TestRoutingResolverAllLocalUpstreamsFail(t *testing.T) {
	if _, _, err := loadDomainLists(nil, nil); err != nil {
		t.Fatal(err)
	}
	r := &routingResolver{
		local:   []exchangeClient{newSocketClient("127.0.0.1:9", 200*time.Millisecond)},
		timeout: time.Second,
	}
	req := new(dns.Msg)
	req.SetQuestion("www.baidu.com.", dns.TypeA)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if _, err := r.Exchange(ctx, req); err == nil {
		t.Fatal("all upstreams failing must return an error")
	}
}

// TestRoutingPerServerMetrics 端到端验证：经 Exchange 兜底后，分上游计数器按
// group/name 记录成功、失败与延迟，路由延迟直方图也产生样本。
func TestRoutingPerServerMetrics(t *testing.T) {
	if _, _, err := loadDomainLists(nil, nil); err != nil {
		t.Fatal(err)
	}
	metrics.reset()
	t.Cleanup(metrics.reset)

	ip := "10.40.0.4"
	goodAddr := startFakeUDPDNS(t, ip)
	r := &routingResolver{
		local: []exchangeClient{
			&namedUpstream{
				name:           "127.0.0.1:9",
				group:          "local",
				stats:          registerUpstream("local", "127.0.0.1:9"),
				exchangeClient: newSocketClient("127.0.0.1:9", 200*time.Millisecond),
			},
			&namedUpstream{
				name:           goodAddr,
				group:          "local",
				stats:          registerUpstream("local", goodAddr),
				exchangeClient: newSocketClient(goodAddr, time.Second),
			},
		},
		external: []exchangeClient{
			&namedUpstream{
				name:           "127.0.0.1:10",
				group:          "extern",
				stats:          registerUpstream("extern", "127.0.0.1:10"),
				exchangeClient: newSocketClient("127.0.0.1:10", 200*time.Millisecond),
			},
		},
		timeout: time.Second,
	}

	// baidu -> local 兜底：首个上游失败、第二个成功；google -> extern 失败一次。
	if got := queryA(t, r, "www.baidu.com"); got != ip {
		t.Fatalf("answer = %s, want %s", got, ip)
	}
	req := new(dns.Msg)
	req.SetQuestion("www.google.com.", dns.TypeA)
	_, _ = r.Exchange(context.Background(), req)

	snap := metrics.snapshot()
	byName := map[string]upstreamServerSnapshot{}
	for _, srv := range snap.Upstreams.Servers {
		byName[srv.Name] = srv
	}
	bad := byName["127.0.0.1:9"]
	if bad.Attempts != 1 || bad.Errors != 1 || bad.LastSuccess != 0 || bad.LastError == "" {
		t.Fatalf("failing local upstream stats = %+v", bad)
	}
	good := byName[goodAddr]
	if good.Attempts != 1 || good.Errors != 0 || good.LastSuccess == 0 || good.Latency.Count != 1 {
		t.Fatalf("successful local upstream stats = %+v", good)
	}
	ext := byName["127.0.0.1:10"]
	if ext.Attempts != 1 || ext.Errors != 1 || ext.Group != "extern" {
		t.Fatalf("extern upstream stats = %+v", ext)
	}
	if snap.Upstreams.Attempts != 3 || snap.Upstreams.Errors != 2 {
		t.Fatalf("aggregate attempts/errors = %d/%d, want 3/2", snap.Upstreams.Attempts, snap.Upstreams.Errors)
	}
	// baidu 归 local，google 归 extern；每次 Exchange 无论成败都产生一个延迟样本。
	if snap.Queries.Latency["local"].Count < 1 || snap.Queries.Latency["extern"].Count < 1 {
		t.Fatalf("route latency counts missing: %+v", snap.Queries.Latency)
	}
}
