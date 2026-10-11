package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	gohomedns "github.com/esrrhs/gohome/dns"
	"github.com/esrrhs/gohome/loggo"
	"github.com/miekg/dns"
)

// queryLogQueueLen 是异步写盘队列长度。查询热路径只做一次 json 编码和
// channel 入队；队列满时丢条并计数，绝不因磁盘慢反压 DNS 应答。
const queryLogQueueLen = 4096

// maxQueryLogAnswers 限制单条日志携带的应答记录数，防止超大应答
// （如巨型 TXT/大量 A 记录）把日志行撑爆。
const maxQueryLogAnswers = 50

// queryLogEntry 是每条查询日志的结构化记录（JSON Lines，一行一条）。
type queryLogEntry struct {
	TS         string   `json:"ts"`                // RFC3339（毫秒精度，UTC）
	Client     string   `json:"client,omitempty"`  // 对端 ip:port，无法获知时省略
	QName      string   `json:"qname"`             // 查询名（小写、保留尾点以反映线上请求原貌）
	QType      string   `json:"qtype"`             // A / AAAA / PTR ...
	QClass     string   `json:"qclass,omitempty"`  // IN 等；未知时给数字
	Route      string   `json:"route"`             // hosts / local / extern / auto
	Rcode      string   `json:"rcode,omitempty"`   // NOERROR / NXDOMAIN ...；失败时为 SERVFAIL
	Stale      bool     `json:"stale,omitempty"`   // 应答来自 serve-stale 备份
	Answers    []string `json:"answers,omitempty"` // Answer 段摘要（IP/CNAME 目标等）
	DurationMs float64  `json:"duration_ms"`       // Exchange 端到端耗时（毫秒，3 位小数）
	Error      string   `json:"error,omitempty"`   // 失败原因（截断保护）
}

// queryLogger 把查询日志异步写入文件，按大小轮转。文件所有权只属于 worker
// goroutine：reopen/rotate/close 都通过控制通道在 worker 内执行，避免
// SIGHUP、shutdown 与写盘并发操作同一个 *os.File。
type queryLogger struct {
	path     string
	maxBytes int64
	maxFiles int

	records  chan []byte
	reopenCh chan struct{}
	stopCh   chan struct{}
	doneCh   chan struct{}
	stopOnce sync.Once

	f        *os.File
	curBytes int64

	written atomic.Int64
	dropped atomic.Int64
}

// newQueryLoggerWithLimit 打开（不存在则创建）日志文件并启动写盘 worker。
// path 为 "-" 时输出到 stdout 且不轮转；maxBytes<=0 表示不按大小轮转。
func newQueryLoggerWithLimit(path string, maxBytes int64, maxFiles int) (*queryLogger, error) {
	l := &queryLogger{
		path:     path,
		maxBytes: maxBytes,
		maxFiles: maxFiles,
		records:  make(chan []byte, queryLogQueueLen),
		reopenCh: make(chan struct{}, 1),
		stopCh:   make(chan struct{}),
		doneCh:   make(chan struct{}),
	}
	if path != "-" {
		f, size, err := openQueryLogFile(path)
		if err != nil {
			return nil, err
		}
		l.f = f
		l.curBytes = size
	}
	go l.run()
	return l, nil
}

func openQueryLogFile(path string) (*os.File, int64, error) {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o644)
	if err != nil {
		return nil, 0, err
	}
	st, err := f.Stat()
	if err != nil {
		_ = f.Close()
		return nil, 0, err
	}
	return f, st.Size(), nil
}

func (l *queryLogger) run() {
	defer close(l.doneCh)
	for {
		select {
		case b := <-l.records:
			l.write(b)
		case <-l.reopenCh:
			l.doReopen()
		case <-l.stopCh:
			// 关闭前排空已入队记录，尽量不丢最后一批查询日志。
			for {
				select {
				case b := <-l.records:
					l.write(b)
				default:
					if l.f != nil {
						_ = l.f.Close()
					}
					return
				}
			}
		}
	}
}

func (l *queryLogger) write(b []byte) {
	if l.f == nil {
		// stdout 模式：轮转关闭，写失败也无法补救。
		_, _ = os.Stdout.Write(b)
		l.written.Add(1)
		return
	}
	n, err := l.f.Write(b)
	if err != nil {
		loggo.Warn("query log write fail: %v", err)
		return
	}
	l.written.Add(1)
	l.curBytes += int64(n)
	if l.maxBytes > 0 && l.curBytes >= l.maxBytes {
		l.rotate()
	}
}

// rotate 在 worker 内执行：当前文件改名为 path.1，旧 .1 顺延为 .2……
// 超过保留份数的最老文件删除，然后开一个新文件继续追加。
// maxFiles<=0 表示不保留任何旧文件：直接删当前文件后重建。
func (l *queryLogger) rotate() {
	if l.f != nil {
		_ = l.f.Close()
		l.f = nil
	}
	if l.maxFiles <= 0 {
		_ = os.Remove(l.path)
		f, size, err := openQueryLogFile(l.path)
		if err != nil {
			loggo.Error("query log reopen after truncate fail: %v", err)
			return
		}
		l.f = f
		l.curBytes = size
		return
	}
	// 保留 .1..N 共 N 个旧分片（连同当前文件磁盘上最多 N+1 个）：
	// 先删掉越界的最老 .N，再从老到新倒着顺延 .(N-1)->.N … .1->.2，
	// 最后当前文件改名为 .1。
	_ = os.Remove(numberedQueryLogPath(l.path, l.maxFiles))
	for i := l.maxFiles; i >= 2; i-- {
		old := numberedQueryLogPath(l.path, i-1)
		new := numberedQueryLogPath(l.path, i)
		if _, err := os.Stat(old); err == nil {
			// Windows 下 Rename 不允许覆盖已存在目标，先删目标。
			_ = os.Remove(new)
			if err := os.Rename(old, new); err != nil {
				loggo.Warn("query log rotate %s -> %s fail: %v", old, new, err)
			}
		}
	}
	if _, err := os.Stat(l.path); err == nil {
		_ = os.Remove(numberedQueryLogPath(l.path, 1))
		if err := os.Rename(l.path, numberedQueryLogPath(l.path, 1)); err != nil {
			loggo.Warn("query log rotate %s -> .1 fail: %v", l.path, err)
		}
	}
	f, size, err := openQueryLogFile(l.path)
	if err != nil {
		// 重新打开失败后后续写入会持续报错并跳过轮转，进程不因此退出。
		loggo.Error("query log reopen after rotate fail: %v", err)
		return
	}
	l.f = f
	l.curBytes = size
}

func numberedQueryLogPath(path string, idx int) string {
	if idx == 0 {
		return path
	}
	return fmt.Sprintf("%s.%d", path, idx)
}

// doReopen 关闭并重新打开当前文件，供外部 logrotate（rename + reopen 模式）
// 在 SIGHUP 后把写入切到新文件。
func (l *queryLogger) doReopen() {
	if l.path == "-" || l.f == nil {
		return
	}
	_ = l.f.Close()
	f, size, err := openQueryLogFile(l.path)
	if err != nil {
		loggo.Error("query log reopen fail: %v", err)
		l.f = nil
		l.curBytes = 0
		return
	}
	l.f = f
	l.curBytes = size
}

// log 非阻塞入队一条日志；队列满时丢条累加 dropped，绝不等盘。
func (l *queryLogger) log(e *queryLogEntry) {
	if l == nil {
		return
	}
	b, err := json.Marshal(e)
	if err != nil {
		return
	}
	b = append(b, '\n')
	select {
	case l.records <- b:
	default:
		l.dropped.Add(1)
	}
}

// reopen 供 SIGHUP 调用：非阻塞通知 worker 重新打开文件。
func (l *queryLogger) reopen() {
	if l == nil || l.path == "-" {
		return
	}
	select {
	case l.reopenCh <- struct{}{}:
	default:
	}
}

// close 通知 worker 排空队列后退出；最多等待 timeout 让最后一批记录落盘。
// 可重复调用（测试 cleanup 与显式关闭并存时不会 panic）。
func (l *queryLogger) close(timeout time.Duration) {
	if l == nil {
		return
	}
	l.stopOnce.Do(func() { close(l.stopCh) })
	select {
	case <-l.doneCh:
	case <-time.After(timeout):
	}
}

func (l *queryLogger) stats() (written, dropped int64) {
	return l.written.Load(), l.dropped.Load()
}

// recordQueryLog 在 Exchange 返回时组装并投递一条查询日志。
func (r *routingResolver) recordQueryLog(ctx context.Context, req *dns.Msg, servedStale bool,
	route string, start time.Time, resp *dns.Msg, err error) {
	if r.qlog == nil || req == nil || len(req.Question) == 0 {
		return
	}
	q := req.Question[0]
	e := &queryLogEntry{
		TS:         start.UTC().Format("2006-01-02T15:04:05.000Z07:00"),
		QName:      q.Name,
		QType:      dns.TypeToString[q.Qtype],
		Route:      route,
		Stale:      servedStale,
		DurationMs: float64(time.Since(start).Microseconds()) / 1000,
	}
	if e.QType == "" {
		e.QType = fmt.Sprintf("%d", q.Qtype)
	}
	if cn := dns.ClassToString[q.Qclass]; cn != "" {
		e.QClass = cn
	} else {
		e.QClass = fmt.Sprintf("%d", q.Qclass)
	}
	if addr := gohomedns.ClientAddrFromContext(ctx); addr != nil {
		e.Client = addr.String()
	}
	if err != nil {
		// gohome server 在 Exchange 失败时对客户端回 SERVFAIL，日志保持同一口径。
		e.Rcode = dns.RcodeToString[dns.RcodeServerFailure]
		msg := err.Error()
		if len(msg) > maxQueryLogErrorLen {
			msg = msg[:maxQueryLogErrorLen]
		}
		e.Error = msg
	} else if resp != nil {
		if rc := dns.RcodeToString[resp.Rcode]; rc != "" {
			e.Rcode = rc
		} else {
			e.Rcode = fmt.Sprintf("%d", resp.Rcode)
		}
		e.Answers = answerSummaries(resp)
	}
	r.qlog.log(e)
}

// maxQueryLogErrorLen 限制错误文本长度，避免异常错误信息刷出超长日志行。
const maxQueryLogErrorLen = 200

// answerSummaries 提取 Answer 段中各记录的简短摘要。
func answerSummaries(msg *dns.Msg) []string {
	if len(msg.Answer) == 0 {
		return nil
	}
	out := make([]string, 0, min(len(msg.Answer), maxQueryLogAnswers))
	for _, rr := range msg.Answer {
		var s string
		switch v := rr.(type) {
		case *dns.A:
			s = v.A.String()
		case *dns.AAAA:
			s = v.AAAA.String()
		case *dns.CNAME:
			s = v.Target
		case *dns.PTR:
			s = v.Ptr
		case *dns.NS:
			s = v.Ns
		case *dns.MX:
			s = fmt.Sprintf("%d %s", v.Preference, v.Mx)
		case *dns.TXT:
			s = strings.Join(v.Txt, " ")
		case *dns.SRV:
			s = fmt.Sprintf("%d %d %d %s", v.Priority, v.Weight, v.Port, v.Target)
		default:
			s = strings.TrimSpace(rr.String())
			if len(s) > maxQueryLogErrorLen {
				s = s[:maxQueryLogErrorLen]
			}
		}
		out = append(out, s)
		if len(out) >= maxQueryLogAnswers {
			break
		}
	}
	return out
}

// queryLogPathDefault 给 -query-log 的相对路径补全目录前缀，与 -update-dir 无关，
// 保留独立小工具以便测试构造路径。
func queryLogAbs(path string) string {
	if path == "" || path == "-" || filepath.IsAbs(path) {
		return path
	}
	abs, err := filepath.Abs(path)
	if err != nil {
		return path
	}
	return abs
}
