package main

import (
	"bufio"
	"context"
	"encoding/json"
	"net"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	gohomedns "github.com/esrrhs/gohome/dns"
	"github.com/miekg/dns"
)

// waitWritten 轮询等待 worker 落盘够 want 条，超时则 t.Fatal。
func waitWritten(t *testing.T, l *queryLogger, want int64) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if w, _ := l.stats(); w >= want {
			return
		}
		time.Sleep(time.Millisecond)
	}
	w, d := l.stats()
	t.Fatalf("query log written = %d (dropped %d), want %d", w, d, want)
}

// readQueryLogLines 读取日志文件（含所有轮转分片），返回全部 JSON 行。
func readQueryLogLines(t *testing.T, path string, maxFiles int) []string {
	t.Helper()
	var lines []string
	paths := []string{path}
	for i := 1; i <= maxFiles; i++ {
		paths = append(paths, numberedQueryLogPath(path, i))
	}
	for _, p := range paths {
		f, err := os.Open(p)
		if os.IsNotExist(err) {
			continue
		}
		if err != nil {
			t.Fatal(err)
		}
		sc := bufio.NewScanner(f)
		sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
		for sc.Scan() {
			lines = append(lines, sc.Text())
		}
		if err := sc.Err(); err != nil {
			t.Fatalf("scan %s: %v", p, err)
		}
		_ = f.Close()
	}
	return lines
}

// makeRotateEntry 构造一条约 200 字节的日志记录。
func makeRotateEntry() *queryLogEntry {
	return &queryLogEntry{
		TS:    time.Now().UTC().Format("2006-01-02T15:04:05.000Z07:00"),
		QName: "rotate-test.example.",
		QType: "A",
		Route: routeAutoLabel,
		Rcode: "NOERROR",
		Answers: []string{
			"10.0.0.1", "10.0.0.2", "10.0.0.3", "10.0.0.4",
		},
		DurationMs: 1.234,
	}
}

// TestQueryLoggerWriteRotate 保留份数足够大时：出现编号分片，所有记录
// 都在（主文件+.1..N），每行都是合法 JSON。
func TestQueryLoggerWriteRotate(t *testing.T) {
	path := filepath.Join(t.TempDir(), "query.log")
	// 每条 JSON 约 150~250 字节；300 字节阈值保证写几条就轮转。
	// 20 个分片上限 > 20 条记录实际产生的分片数，因此不会因保留窗口丢记录。
	l, err := newQueryLoggerWithLimit(path, 300, 20)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { l.close(time.Second) })

	const n = 20
	for i := 0; i < n; i++ {
		l.log(makeRotateEntry())
	}
	waitWritten(t, l, n)
	l.close(time.Second) // 显式落盘，避免 cleanup 重复关闭的竞态

	if _, err := os.Stat(numberedQueryLogPath(path, 1)); err != nil {
		t.Fatalf("rotated file .1 missing: %v", err)
	}
	lines := readQueryLogLines(t, path, 20)
	if len(lines) != n {
		t.Fatalf("total lines across files = %d, want %d", len(lines), n)
	}
	for _, line := range lines {
		var e queryLogEntry
		if err := json.Unmarshal([]byte(line), &e); err != nil {
			t.Fatalf("invalid JSON line %q: %v", line, err)
		}
		if e.QName != "rotate-test.example." || e.Answers[0] != "10.0.0.1" {
			t.Fatalf("line content mismatch: %+v", e)
		}
	}
}

// TestQueryLoggerRotationRetention 保留份数为 1 时，磁盘上只应有当前文件
// 和 .1，绝不能出现 .2，且最老分片已被淘汰（总行数受限而非全量保留）。
func TestQueryLoggerRotationRetention(t *testing.T) {
	path := filepath.Join(t.TempDir(), "query.log")
	l, err := newQueryLoggerWithLimit(path, 300, 1)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { l.close(time.Second) })

	const n = 8
	for i := 0; i < n; i++ {
		l.log(makeRotateEntry())
	}
	waitWritten(t, l, n)
	l.close(time.Second)

	if _, err := os.Stat(numberedQueryLogPath(path, 2)); !os.IsNotExist(err) {
		t.Fatalf(".2 must never exist with maxFiles=1, stat err=%v", err)
	}
	lines := readQueryLogLines(t, path, 1)
	if len(lines) == 0 || len(lines) >= n {
		t.Fatalf("retention should keep a bounded subset, got %d/%d", len(lines), n)
	}
	for _, line := range lines {
		var e queryLogEntry
		if err := json.Unmarshal([]byte(line), &e); err != nil {
			t.Fatalf("invalid JSON line %q: %v", line, err)
		}
	}
}

// TestQueryLoggerReopen 模拟外部 logrotate rename 后 SIGHUP 重开：
// 旧记录留在被改名的文件，新记录进入新建的同名文件。
func TestQueryLoggerReopen(t *testing.T) {
	path := filepath.Join(t.TempDir(), "query.log")
	l, err := newQueryLoggerWithLimit(path, 0, 5) // 关闭大小轮转，避免干扰
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { l.close(time.Second) })

	l.log(&queryLogEntry{QName: "old.example.", QType: "A", Route: "auto"})
	waitWritten(t, l, 1)

	// 外部 rename（不发信号前 worker 仍持有旧 inode）。
	moved := path + ".moved"
	if err := os.Rename(path, moved); err != nil {
		t.Fatal(err)
	}
	l.reopen()
	// reopen 是异步通知，轮询直到新文件出现后再写，避免新行落到旧 inode。
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if _, err := os.Stat(path); err == nil {
			break
		}
		time.Sleep(time.Millisecond)
	}
	l.log(&queryLogEntry{QName: "new.example.", QType: "AAAA", Route: "extern"})
	waitWritten(t, l, 2)
	l.close(time.Second)

	oldData, err := os.ReadFile(moved)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(oldData), "old.example.") {
		t.Fatalf("renamed file should keep old line: %s", oldData)
	}
	newData, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(newData), "new.example.") ||
		strings.Contains(string(newData), "old.example.") {
		t.Fatalf("reopened file content mismatch: %s", newData)
	}
}

// TestAnswerSummaries 覆盖常见记录类型的摘要与数量上限。
func TestAnswerSummaries(t *testing.T) {
	m := new(dns.Msg)
	m.Answer = append(m.Answer,
		&dns.A{Hdr: dns.RR_Header{Name: "a.test.", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60}, A: net.ParseIP("1.2.3.4")},
		&dns.AAAA{Hdr: dns.RR_Header{Name: "a.test.", Rrtype: dns.TypeAAAA, Class: dns.ClassINET, Ttl: 60}, AAAA: net.ParseIP("2001:db8::1")},
		&dns.CNAME{Hdr: dns.RR_Header{Name: "a.test.", Rrtype: dns.TypeCNAME, Class: dns.ClassINET, Ttl: 60}, Target: "target.test."},
		&dns.PTR{Hdr: dns.RR_Header{Name: "x.in-addr.arpa.", Rrtype: dns.TypePTR, Class: dns.ClassINET, Ttl: 60}, Ptr: "host.test."},
		&dns.MX{Hdr: dns.RR_Header{Name: "test.", Rrtype: dns.TypeMX, Class: dns.ClassINET, Ttl: 60}, Preference: 10, Mx: "mx.test."},
		&dns.TXT{Hdr: dns.RR_Header{Name: "test.", Rrtype: dns.TypeTXT, Class: dns.ClassINET, Ttl: 60}, Txt: []string{"hello", "world"}},
	)
	got := answerSummaries(m)
	want := []string{"1.2.3.4", "2001:db8::1", "target.test.", "host.test.", "10 mx.test.", "hello world"}
	if strings.Join(got, "|") != strings.Join(want, "|") {
		t.Fatalf("summaries = %v, want %v", got, want)
	}
	if answerSummaries(new(dns.Msg)) != nil {
		t.Fatal("empty answer must return nil")
	}

	// 超过上限截断到 maxQueryLogAnswers。
	big := new(dns.Msg)
	for i := 0; i < maxQueryLogAnswers+10; i++ {
		big.Answer = append(big.Answer, &dns.A{
			Hdr: dns.RR_Header{Name: "big.test.", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60},
			A:   net.IPv4(10, 0, 0, byte(i)),
		})
	}
	if n := len(answerSummaries(big)); n != maxQueryLogAnswers {
		t.Fatalf("capped summaries = %d, want %d", n, maxQueryLogAnswers)
	}
}

// TestRecordQueryLogDirect 直接验证记录组装：client 取自 context、
// qtype/class/route/answers 齐全；失败时 rcode 为 SERVFAIL 且带错误文本。
func TestRecordQueryLogDirect(t *testing.T) {
	path := filepath.Join(t.TempDir(), "query.log")
	l, err := newQueryLoggerWithLimit(path, 0, 5)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { l.close(time.Second) })
	rr := &routingResolver{qlog: l}
	start := time.Now()

	req := new(dns.Msg)
	req.SetQuestion("WWW.Example.COM.", dns.TypeA)
	resp := aAnswerMsg("www.example.com", "9.9.9.9", 120)
	ctx := gohomedns.ContextWithClientAddr(context.Background(), &net.UDPAddr{IP: net.ParseIP("192.0.2.7"), Port: 43210})
	rr.recordQueryLog(ctx, req, false, routeLocalLabel, start, resp, nil)

	failReq := new(dns.Msg)
	failReq.SetQuestion("dead.test.", dns.TypeAAAA)
	rr.recordQueryLog(context.Background(), failReq, true, routeExternLabel, start, nil, errSentinelForLog())
	waitWritten(t, l, 2)
	l.close(time.Second)

	lines := readQueryLogLines(t, path, 5)
	if len(lines) != 2 {
		t.Fatalf("lines = %d, want 2", len(lines))
	}
	var ok1 queryLogEntry
	if err := json.Unmarshal([]byte(lines[0]), &ok1); err != nil {
		t.Fatal(err)
	}
	if ok1.Client != "192.0.2.7:43210" || ok1.QName != "WWW.Example.COM." ||
		ok1.QType != "A" || ok1.QClass != "IN" || ok1.Route != "local" ||
		ok1.Rcode != "NOERROR" || ok1.Stale || len(ok1.Answers) != 1 ||
		ok1.Answers[0] != "9.9.9.9" || ok1.DurationMs < 0 || ok1.TS == "" {
		t.Fatalf("success entry mismatch: %+v", ok1)
	}
	var failEntry queryLogEntry
	if err := json.Unmarshal([]byte(lines[1]), &failEntry); err != nil {
		t.Fatal(err)
	}
	if failEntry.Rcode != "SERVFAIL" || failEntry.Route != "extern" ||
		failEntry.QType != "AAAA" || !failEntry.Stale || failEntry.Error == "" {
		t.Fatalf("failure entry mismatch: %+v", failEntry)
	}

	// 空问题与未配置 qlog 的 resolver 都是安全空操作，不 panic、不写入。
	before, _ := l.stats()
	rr.recordQueryLog(ctx, new(dns.Msg), false, routeAutoLabel, start, resp, nil)
	(&routingResolver{}).recordQueryLog(ctx, req, false, routeAutoLabel, start, resp, nil)
	time.Sleep(20 * time.Millisecond)
	if after, _ := l.stats(); after != before {
		t.Fatalf("no-op records must not be written: before %d after %d", before, after)
	}
}

// errSentinelForLog 返回一个带固定文本的错误，避免引入额外测试依赖。
func errSentinelForLog() error {
	return &logTestErr{"all upstreams failed: dial udp 127.0.0.1:9: connect: connection refused"}
}

type logTestErr struct{ s string }

func (e *logTestErr) Error() string { return e.s }

// TestRecordQueryLogServerEndToEnd 经真实 gohome UDP server 发查询，
// 验证对端地址通过 context 透传（gohome 侧改动）并完整出现在 JSONL 中。
func TestRecordQueryLogServerEndToEnd(t *testing.T) {
	if _, _, err := loadDomainLists(nil, nil); err != nil {
		t.Fatal(err)
	}
	metrics.reset()
	t.Cleanup(metrics.reset)

	ip := "10.60.0.1"
	fakeAddr := startFakeUDPDNS(t, ip)
	path := filepath.Join(t.TempDir(), "query.log")
	l, err := newQueryLoggerWithLimit(path, 0, 5)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { l.close(time.Second) })

	rr := &routingResolver{
		local:   []exchangeClient{newSocketClient(fakeAddr, time.Second)},
		timeout: time.Second,
		qlog:    l,
	}
	// gohome Server.Addr() 返回配置值，:0 拿不到实际端口；先探测空闲端口。
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := pc.LocalAddr().String()
	_ = pc.Close()
	srv := gohomedns.NewServer(addr, rr)
	if err := srv.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = srv.Stop() })

	cli := &dns.Client{Net: "udp", Timeout: 2 * time.Second}
	req := new(dns.Msg)
	req.SetQuestion("www.baidu.com.", dns.TypeA)
	resp, _, err := cli.Exchange(req, addr)
	if err != nil || len(resp.Answer) == 0 {
		t.Fatalf("exchange fail: %v resp=%v", err, resp)
	}
	l.close(time.Second)

	lines := readQueryLogLines(t, path, 5)
	if len(lines) != 1 {
		t.Fatalf("lines = %d, want 1: %v", len(lines), lines)
	}
	var e queryLogEntry
	if err := json.Unmarshal([]byte(lines[0]), &e); err != nil {
		t.Fatal(err)
	}
	if e.Client == "" {
		t.Fatal("client addr must be propagated from the DNS server context")
	}
	if e.QName != "www.baidu.com." || e.QType != "A" || e.Route != "local" ||
		e.Rcode != "NOERROR" || len(e.Answers) != 1 || e.Answers[0] != ip {
		t.Fatalf("server entry mismatch: %+v", e)
	}
}

// TestQueryLogObservability 验证启用状态/写入/丢弃计数进入 /stats 与 /metrics。
func TestQueryLogObservability(t *testing.T) {
	old := queryLogStatus
	queryLogStatus = func() (bool, int64, int64) { return true, 123, 4 }
	t.Cleanup(func() { queryLogStatus = old })

	s := &statsServer{}
	rec := httptest.NewRecorder()
	s.statsHandler(rec, httptest.NewRequest("GET", "/stats", nil))
	var snap statsSnapshot
	if err := json.Unmarshal(rec.Body.Bytes(), &snap); err != nil {
		t.Fatal(err)
	}
	if !snap.QueryLog.Enabled || snap.QueryLog.Written != 123 || snap.QueryLog.Dropped != 4 {
		t.Fatalf("query_log snapshot = %+v", snap.QueryLog)
	}

	recM := httptest.NewRecorder()
	s.metricsHandler(recM, httptest.NewRequest("GET", "/metrics", nil))
	body := recM.Body.String()
	for _, want := range []string{
		"# TYPE yellowdns_querylog_enabled gauge",
		"yellowdns_querylog_enabled 1",
		"# TYPE yellowdns_querylog_written_total counter",
		"yellowdns_querylog_written_total 123",
		"# TYPE yellowdns_querylog_dropped_total counter",
		"yellowdns_querylog_dropped_total 4",
	} {
		if !strings.Contains(body, want) {
			t.Errorf("metrics body missing %q\n%s", want, body)
		}
	}
}
