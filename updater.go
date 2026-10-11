package main

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"github.com/esrrhs/gohome/loggo"
)

// 远端列表源：dnsmasq-china-list 的 dnsmasq conf 与 v2ray-rules-dat 的纯文本 gfw 列表。
// 仅在 -update 显式开启后才会访问。
const (
	defaultChinaListURL = "https://raw.githubusercontent.com/felixonmars/dnsmasq-china-list/master/accelerated-domains.china.conf"
	defaultGFWListURL   = "https://raw.githubusercontent.com/Loyalsoldier/v2ray-rules-dat/release/gfw.txt"

	// 下载体积上限：当前两份列表均在 5MB 内，留足余量防异常超大响应。
	maxListBytes = 32 << 20
	// 内容健康下限：低于该规模视为源站异常，拒绝替换。
	minChinaDomains = 1000
	minGfwDomains   = 100
)

// remoteChinaFile / remoteGfwFile 是 -update-dir 下远端列表的落盘文件名。
const (
	remoteChinaFile = "china.remote.txt"
	remoteGfwFile   = "gfw.remote.txt"
)

// updater 周期拉取远端域名列表并触发重载：
//   - 内容与上次一致（sha256）时跳过重载；
//   - 解析出的域名数低于健康下限时拒绝落盘；
//   - 下载/写盘失败只记日志，旧规则继续生效；
//   - mmdb 不在自动更新范围，随版本发布。
type updater struct {
	chinaURL string
	gfwURL   string
	dir      string
	interval time.Duration
	apply    func(chinaFiles, gfwFiles []string) (int, int, int, error)
	// extraChina/extraGfw 是 -china/-gfw 用户附加文件，随远端更新一并重载。
	extraChina []string
	extraGfw   []string

	client *http.Client
}

func (u *updater) chinaPath() string { return filepath.Join(u.dir, remoteChinaFile) }
func (u *updater) gfwPath() string   { return filepath.Join(u.dir, remoteGfwFile) }

func (u *updater) httpClient() *http.Client {
	if u.client != nil {
		return u.client
	}
	return &http.Client{Timeout: 90 * time.Second}
}

// run 启动即检查一次，之后按 interval 周期检查，直到进程退出。
func (u *updater) run() {
	u.runOnce()
	t := time.NewTicker(u.interval)
	defer t.Stop()
	for range t.C {
		u.runOnce()
	}
}

func (u *updater) runOnce() {
	chinaChanged, chinaErr := u.updateOne("china", u.chinaURL, u.chinaPath(), minChinaDomains)
	if chinaErr != nil {
		loggo.Warn("update china list fail: %v", chinaErr)
	}
	gfwChanged, gfwErr := u.updateOne("gfw", u.gfwURL, u.gfwPath(), minGfwDomains)
	if gfwErr != nil {
		loggo.Warn("update gfw list fail: %v", gfwErr)
	}
	if !chinaChanged && !gfwChanged && chinaErr == nil && gfwErr == nil {
		loggo.Info("remote lists unchanged")
		return
	}
	if chinaErr != nil || gfwErr != nil {
		// 任一失败仍按现有远端文件（旧内容或新内容）重载，保持与磁盘一致。
		loggo.Info("partial update, reloading with available remote files")
	}
	u.applyRemote()
}

// applyRemote 按当前存在的远端文件（优先）+ 用户附加文件触发重载。
func (u *updater) applyRemote() {
	chinaFiles := append(remoteIfExist(u.chinaPath()), u.extraChina...)
	gfwFiles := append(remoteIfExist(u.gfwPath()), u.extraGfw...)
	cn, gfw, hostsN, err := u.apply(chinaFiles, gfwFiles)
	if err != nil {
		loggo.Error("apply remote lists fail, keep old rules: %v", err)
		return
	}
	loggo.Info("remote lists applied china %d gfw %d hosts %d shadowed %d", cn, gfw, hostsN, len(currentDomains().shadowed))
}

// updateOne 下载并校验单个列表；内容与现有文件一致时不重写。
func (u *updater) updateOne(name, url, dst string, minDomains int) (bool, error) {
	body, err := u.fetch(url)
	if err != nil {
		return false, err
	}
	n := countDomains(body)
	if n < minDomains {
		return false, fmt.Errorf("list %s from %s has %d domains, below healthy minimum %d", name, url, n, minDomains)
	}
	if cur, err := os.ReadFile(dst); err == nil && sha256.Sum256(cur) == sha256.Sum256(body) {
		loggo.Info("%s list unchanged (%d domains)", name, n)
		return false, nil
	}
	tmp := dst + ".tmp"
	if err := os.WriteFile(tmp, body, 0o644); err != nil {
		return false, err
	}
	if err := os.Rename(tmp, dst); err != nil {
		_ = os.Remove(tmp)
		return false, err
	}
	loggo.Info("%s list updated from %s (%d domains)", name, url, n)
	return true, nil
}

func (u *updater) fetch(url string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	resp, err := u.httpClient().Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("http %d for %s", resp.StatusCode, url)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxListBytes+1))
	if err != nil {
		return nil, err
	}
	if len(body) > maxListBytes {
		return nil, errors.New("list exceeds size limit")
	}
	return body, nil
}

func countDomains(body []byte) int {
	set := domainSet{}
	for _, line := range splitLines(body) {
		addDomain(set, line)
	}
	return len(set)
}

func splitLines(body []byte) []string {
	var lines []string
	start := 0
	for i, b := range body {
		if b == '\n' {
			lines = append(lines, string(body[start:i]))
			start = i + 1
		}
	}
	lines = append(lines, string(body[start:]))
	return lines
}

// remoteIfExist 返回已存在的远端列表路径，不存在（首次运行、未开启更新）时为空。
func remoteIfExist(path string) []string {
	if st, err := os.Stat(path); err == nil && !st.IsDir() {
		return []string{path}
	}
	return nil
}
