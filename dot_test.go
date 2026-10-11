package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"errors"
	"math/big"
	"net"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	gohomedns "github.com/esrrhs/gohome/dns"
	"github.com/miekg/dns"
)

// writeSelfSignedCert 生成一对 ECDSA P-256 自签证书并写入临时目录，
// 返回 cert/key 路径。CN/SAN 固定 dot.test。
func writeSelfSignedCert(t *testing.T, dir, cn string) (string, string) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	serial, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 62))
	tmpl := x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: cn},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     []string{cn},
	}
	der, err := x509.CreateCertificate(rand.Reader, &tmpl, &tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	certPath := filepath.Join(dir, "cert.pem")
	keyPath := filepath.Join(dir, "key.pem")
	cf, err := os.Create(certPath)
	if err != nil {
		t.Fatal(err)
	}
	if err := pem.Encode(cf, &pem.Block{Type: "CERTIFICATE", Bytes: der}); err != nil {
		t.Fatal(err)
	}
	cf.Close()
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	kf, err := os.Create(keyPath)
	if err != nil {
		t.Fatal(err)
	}
	if err := pem.Encode(kf, &pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}); err != nil {
		t.Fatal(err)
	}
	kf.Close()
	return certPath, keyPath
}

// freeTCPAddr 返回一个刚释放的回环 TCP 地址，供测试监听器 bind。
func freeTCPAddr(t *testing.T) string {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := l.Addr().String()
	l.Close()
	return addr
}

// dotStubResolver 返回固定 A 记录，并记录到达的 ctx 对端地址与请求数。
type dotStubResolver struct {
	mu       sync.Mutex
	lastAddr net.Addr
	calls    int
	fail     bool
}

func (s *dotStubResolver) Exchange(ctx context.Context, m *dns.Msg) (*dns.Msg, error) {
	s.mu.Lock()
	s.calls++
	s.lastAddr = gohomedns.ClientAddrFromContext(ctx)
	fail := s.fail
	s.mu.Unlock()
	if fail {
		return nil, errors.New("stub upstream down")
	}
	reply := new(dns.Msg)
	reply.SetReply(m)
	for _, q := range m.Question {
		if q.Qtype == dns.TypeA {
			reply.Answer = append(reply.Answer, &dns.A{
				Hdr: dns.RR_Header{Name: q.Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 30},
				A:   net.ParseIP("10.53.53.53").To4(),
			})
		}
	}
	return reply, nil
}

func (s *dotStubResolver) snapshot() (int, net.Addr) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.calls, s.lastAddr
}

func TestValidateTLSConfig(t *testing.T) {
	// 未启用 DoT：零值直接通过。
	if err := validateTLSConfig("", "", ""); err != nil {
		t.Fatalf("empty: %v", err)
	}

	dir := t.TempDir()
	certPath, keyPath := writeSelfSignedCert(t, dir, "dot.test")

	// 启用但缺证书/私钥参数。
	if err := validateTLSConfig(":853", "", keyPath); err == nil {
		t.Fatal("missing cert must be rejected")
	}
	if err := validateTLSConfig(":853", certPath, ""); err == nil {
		t.Fatal("missing key must be rejected")
	}
	// 文件不存在。
	if err := validateTLSConfig(":853", certPath, filepath.Join(dir, "nope.pem")); err == nil {
		t.Fatal("missing key file must be rejected")
	}
	// 证书与私钥不匹配：生成第二对密钥，交叉组合。
	dir2 := t.TempDir()
	_, key2 := writeSelfSignedCert(t, dir2, "other.test")
	if err := validateTLSConfig(":853", certPath, key2); err == nil {
		t.Fatal("cert/key mismatch must be rejected")
	}
	// 正常组合。
	if err := validateTLSConfig(":853", certPath, keyPath); err != nil {
		t.Fatalf("valid keypair: %v", err)
	}
}

func TestNewDoTServerRejectsBadFiles(t *testing.T) {
	dir := t.TempDir()
	// cert/key 路径存在但内容不是 PEM。
	cert := filepath.Join(dir, "cert.pem")
	key := filepath.Join(dir, "key.pem")
	if err := os.WriteFile(cert, []byte("not a cert"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(key, []byte("not a key"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := newDoTServer(freeTCPAddr(t), cert, key, &dotStubResolver{}); err == nil {
		t.Fatal("garbage keypair must fail startup")
	}
	// nil resolver 必须报错。
	cp, kp := writeSelfSignedCert(t, dir, "dot.test")
	if _, err := newDoTServer(freeTCPAddr(t), cp, kp, nil); err == nil {
		t.Fatal("nil resolver must fail startup")
	}
}

// dotQuery 用 tcp-tls 客户端发一次 A 查询。
func dotQuery(t *testing.T, addr string) (*dns.Msg, error) {
	t.Helper()
	c := &dns.Client{
		Net:       "tcp-tls",
		TLSConfig: &tls.Config{InsecureSkipVerify: true},
		Timeout:   3 * time.Second,
	}
	req := new(dns.Msg)
	req.SetQuestion("dot.example.", dns.TypeA)
	resp, _, err := c.Exchange(req, addr)
	return resp, err
}

// TestDoTEndToEnd 真实 TLS 握手 + DNS 报文往返，并验证：
// 1) 应答内容正确；2) resolver 收到透传的 TCP 对端地址（查询日志依赖）；
// 3) resolver 报错时客户端收到 SERVFAIL；4) TLS1.0/1.1 被拒绝。
func TestDoTEndToEnd(t *testing.T) {
	dir := t.TempDir()
	certPath, keyPath := writeSelfSignedCert(t, dir, "dot.test")
	stub := &dotStubResolver{}
	d, err := newDoTServer(freeTCPAddr(t), certPath, keyPath, stub)
	if err != nil {
		t.Fatalf("start: %v", err)
	}
	t.Cleanup(func() { _ = d.stop() })

	resp, err := dotQuery(t, d.addr)
	if err != nil {
		t.Fatalf("dot exchange: %v", err)
	}
	if resp.Rcode != dns.RcodeSuccess || len(resp.Answer) != 1 {
		t.Fatalf("resp rcode=%s answers=%d", dns.RcodeToString[resp.Rcode], len(resp.Answer))
	}
	if a, ok := resp.Answer[0].(*dns.A); !ok || !a.A.Equal(net.ParseIP("10.53.53.53")) {
		t.Fatalf("answer = %v", resp.Answer)
	}
	calls, addr := stub.snapshot()
	if calls != 1 {
		t.Fatalf("resolver calls = %d, want 1", calls)
	}
	if addr == nil || addr.Network() != "tcp" {
		t.Fatalf("client addr not propagated: %+v", addr)
	}

	// 上游失败路径：客户端应收到 SERVFAIL（dns.HandleFailed）。
	stub.fail = true
	resp2, err := dotQuery(t, d.addr)
	if err != nil {
		t.Fatalf("dot exchange on failure: %v", err)
	}
	if resp2.Rcode != dns.RcodeServerFailure {
		t.Fatalf("rcode = %s, want SERVFAIL", dns.RcodeToString[resp2.Rcode])
	}
	stub.fail = false

	// TLS1.0 握手必须被服务端（MinVersion 1.2）拒绝。
	c10 := &dns.Client{
		Net: "tcp-tls",
		TLSConfig: &tls.Config{
			InsecureSkipVerify: true,
			MinVersion:         tls.VersionTLS10,
			MaxVersion:         tls.VersionTLS10,
		},
		Timeout: 3 * time.Second,
	}
	req := new(dns.Msg)
	req.SetQuestion("dot.example.", dns.TypeA)
	if _, _, err := c10.Exchange(req, d.addr); err == nil {
		t.Fatal("TLS 1.0 handshake must be rejected")
	}
}

// TestDoTCertReload 覆盖：正常替换证书生效；坏文件返回错误且旧证书继续服务。
func TestDoTCertReload(t *testing.T) {
	dir := t.TempDir()
	certPath, keyPath := writeSelfSignedCert(t, dir, "first.test")
	stub := &dotStubResolver{}
	d, err := newDoTServer(freeTCPAddr(t), certPath, keyPath, stub)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = d.stop() })

	// 用一套新证书覆盖文件后 reload，新连接拿到的证书序列号应变化。
	cert2Path, key2Path := writeSelfSignedCert(t, dir, "second.test")
	cert2PEM, _ := os.ReadFile(cert2Path)
	key2PEM, _ := os.ReadFile(key2Path)
	if err := os.WriteFile(certPath, cert2PEM, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyPath, key2PEM, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := d.reloadCert(); err != nil {
		t.Fatalf("reload good cert: %v", err)
	}

	// 抓当前服务端证书：通过自定义校验回调拿到 peer leaf。
	gotLeaf := dialDoTLeaf(t, d.addr)
	wantBlock, _ := pem.Decode(cert2PEM)
	wantCert, err := x509.ParseCertificate(wantBlock.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	if gotLeaf.SerialNumber.Cmp(wantCert.SerialNumber) != 0 {
		t.Fatalf("served cert serial %s, want %s", gotLeaf.SerialNumber, wantCert.SerialNumber)
	}

	// 写入损坏的私钥：reload 报错，旧证书仍继续提供服务。
	if err := os.WriteFile(keyPath, []byte("-----BEGIN PRIVATE KEY-----\ncorrupt\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := d.reloadCert(); err == nil {
		t.Fatal("corrupt key must make reload fail")
	}
	if _, err := dotQuery(t, d.addr); err != nil {
		t.Fatalf("service must keep the old cert after failed reload: %v", err)
	}
}

// dialDoTLeaf 建立 TLS 连接并返回服务端叶子证书，不做任何查询。
func dialDoTLeaf(t *testing.T, addr string) *x509.Certificate {
	t.Helper()
	conn, err := tls.Dial("tcp", addr, &tls.Config{
		InsecureSkipVerify: true,
		MinVersion:         tls.VersionTLS12,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	state := conn.ConnectionState()
	if len(state.PeerCertificates) == 0 {
		t.Fatal("no peer certificate")
	}
	return state.PeerCertificates[0]
}

// TestDoTStop 关闭后新连接必须被拒绝。
func TestDoTStop(t *testing.T) {
	dir := t.TempDir()
	certPath, keyPath := writeSelfSignedCert(t, dir, "dot.test")
	d, err := newDoTServer(freeTCPAddr(t), certPath, keyPath, &dotStubResolver{})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := dotQuery(t, d.addr); err != nil {
		t.Fatalf("query before stop: %v", err)
	}
	if err := d.stop(); err != nil {
		t.Fatalf("stop: %v", err)
	}
	// 重复 stop 必须幂等无 panic。
	if err := d.stop(); err != nil {
		t.Fatalf("second stop: %v", err)
	}
	if _, err := net.DialTimeout("tcp", d.addr, time.Second); err == nil {
		t.Fatal("listener still accepting after stop")
	}
}

// TestDoTObservability 验证 DoT 开关进入 /stats 与 /metrics。
func TestDoTObservability(t *testing.T) {
	old := dotStatus
	dotStatus = func() bool { return true }
	t.Cleanup(func() { dotStatus = old })

	s := &statsServer{}
	rec := httptest.NewRecorder()
	s.statsHandler(rec, httptest.NewRequest("GET", "/stats", nil))
	var snap statsSnapshot
	if err := json.Unmarshal(rec.Body.Bytes(), &snap); err != nil {
		t.Fatal(err)
	}
	if !snap.DOT.Enabled {
		t.Fatal("snapshot dot.enabled = false, want true")
	}

	recM := httptest.NewRecorder()
	s.metricsHandler(recM, httptest.NewRequest("GET", "/metrics", nil))
	body := recM.Body.String()
	if !strings.Contains(body, "# TYPE yellowdns_dot_info gauge") ||
		!strings.Contains(body, "yellowdns_dot_info 1") {
		t.Fatalf("metrics missing dot info:\n%s", body)
	}

	// 未注入时按禁用输出 0。
	dotStatus = nil
	rec2 := httptest.NewRecorder()
	s.metricsHandler(rec2, httptest.NewRequest("GET", "/metrics", nil))
	if !strings.Contains(rec2.Body.String(), "yellowdns_dot_info 0") {
		t.Fatalf("default metrics should expose dot 0:\n%s", rec2.Body.String())
	}
}
