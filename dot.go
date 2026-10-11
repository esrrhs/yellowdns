package main

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"os"
	"sync"
	"time"

	gohomedns "github.com/esrrhs/gohome/dns"
	"github.com/esrrhs/gohome/loggo"
	"github.com/miekg/dns"
)

// DNS-over-TLS（RFC 7858）入站监听。
//
// gohome 的 dns.Server 只硬编码 udp+tcp，DoT 在 yellowdns 侧直接用
// miekg/dns 的 "tcp-tls" network 实现，复用同一个 routingResolver：
// 路由、缓存、serve-stale、ECS、查询日志等全部入站链路天然共享，
// DoT 客户端与明文客户端在 stats 中按同一套口径计数。

const (
	dotStartTimeout = 3 * time.Second // 等待 TLS 监听器完成 bind 的上限
	dotStopTimeout  = 5 * time.Second // 优雅关闭等待存量连接收尾的上限
)

// messageExchanger 是入站 handler 对 resolver 的唯一依赖，
// *routingResolver 天然满足；用最小接口避免与 gohome.Resolver 全量方法耦合。
type messageExchanger interface {
	Exchange(ctx context.Context, m *dns.Msg) (*dns.Msg, error)
}

// dotServer 是一个 TCP/TLS(853) DNS 监听器。
type dotServer struct {
	addr     string
	certFile string
	keyFile  string

	srv *dns.Server

	// cert 通过 TLSConfig.GetCertificate 提供给每个新连接；SIGHUP 时可在
	// 不重启监听器的情况下原子替换（证书续期场景）。加载失败保留旧证书。
	certMu sync.RWMutex
	cert   tls.Certificate
}

// validateTLSConfig 校验 -tls 相关参数：启用 DoT 必须同时给出证书与私钥，
// 且文件当前可读、密钥对匹配。
func validateTLSConfig(addr, certFile, keyFile string) error {
	if addr == "" {
		return nil
	}
	if certFile == "" || keyFile == "" {
		return errors.New("-tls requires both -tls-cert and -tls-key")
	}
	if _, err := os.Stat(certFile); err != nil {
		return fmt.Errorf("tls cert: %w", err)
	}
	if _, err := os.Stat(keyFile); err != nil {
		return fmt.Errorf("tls key: %w", err)
	}
	if _, err := tls.LoadX509KeyPair(certFile, keyFile); err != nil {
		return fmt.Errorf("load tls keypair: %w", err)
	}
	return nil
}

// newDoTServer 加载证书并启动 TCP/TLS 监听器。返回 nil error 时已完成 bind；
// bind 失败/超时会自行清理，绝不返回一个半启动的 server。
func newDoTServer(addr, certFile, keyFile string, resolver messageExchanger) (*dotServer, error) {
	if resolver == nil {
		return nil, errors.New("dot server requires a non-nil resolver")
	}
	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return nil, fmt.Errorf("load tls keypair: %w", err)
	}
	d := &dotServer{
		addr:     addr,
		certFile: certFile,
		keyFile:  keyFile,
		cert:     cert,
	}

	// 与 gohome 的明文 handler 保持同一语义：透传对端地址（查询日志依赖）、
	// resolver 失败走 dns.HandleFailed（SERVFAIL）。
	handler := dns.HandlerFunc(func(w dns.ResponseWriter, r *dns.Msg) {
		ctx := gohomedns.ContextWithClientAddr(context.Background(), w.RemoteAddr())
		resp, err := resolver.Exchange(ctx, r)
		if err != nil || resp == nil {
			dns.HandleFailed(w, r)
			return
		}
		resp.Id = r.Id
		_ = w.WriteMsg(resp)
	})

	started := make(chan struct{})
	var startOnce sync.Once
	d.srv = &dns.Server{
		Addr:    addr,
		Net:     "tcp-tls",
		Handler: handler,
		// RFC 8996 已禁止 TLS1.0/1.1；强制 1.2 起步，跟随 Go 安全默认的密码套件。
		TLSConfig: &tls.Config{
			MinVersion: tls.VersionTLS12,
			GetCertificate: func(*tls.ClientHelloInfo) (*tls.Certificate, error) {
				d.certMu.RLock()
				defer d.certMu.RUnlock()
				c := d.cert
				return &c, nil
			},
		},
		NotifyStartedFunc: func() { startOnce.Do(func() { close(started) }) },
	}

	// 容量 1：启动成功后无人再收，ListenAndServe 退出（含优雅关闭）写 channel
	// 也不会泄漏 goroutine；当前 vendored miekg/dns 版本关闭时返回 nil。
	errCh := make(chan error, 1)
	go func() {
		errCh <- d.srv.ListenAndServe()
	}()

	timer := time.NewTimer(dotStartTimeout)
	defer timer.Stop()
	select {
	case <-started:
		return d, nil
	case err := <-errCh:
		if err != nil {
			return nil, fmt.Errorf("dot listen on %s: %w", addr, err)
		}
		return nil, fmt.Errorf("dot server on %s exited before becoming ready", addr)
	case <-timer.C:
		_ = d.stop()
		return nil, fmt.Errorf("dot server start timed out after %v on %s", dotStartTimeout, addr)
	}
}

// reloadCert 重新加载证书与私钥（SIGHUP 调用，支撑证书续期不重启）。
// 新加载失败时保留旧证书继续服务，并把错误返回给调用方记录，
// 语义与规则文件重载一致：坏配置不踢掉在役配置。
func (d *dotServer) reloadCert() error {
	cert, err := tls.LoadX509KeyPair(d.certFile, d.keyFile)
	if err != nil {
		return fmt.Errorf("reload tls keypair, keeping current cert: %w", err)
	}
	d.certMu.Lock()
	d.cert = cert
	d.certMu.Unlock()
	return nil
}

// stop 关闭监听器并等待存量连接收尾（最多 dotStopTimeout）。
func (d *dotServer) stop() error {
	if d == nil || d.srv == nil {
		return nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), dotStopTimeout)
	defer cancel()
	if err := d.srv.ShutdownContext(ctx); err != nil {
		loggo.Debug("[DoT Server] shutdown: %v", err)
	}
	return nil
}
