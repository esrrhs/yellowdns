package main

import (
	"bytes"
	"compress/gzip"
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
	"github.com/oschwald/geoip2-golang"
)

// 远端列表源：dnsmasq-china-list 的 dnsmasq conf 与 v2ray-rules-dat 的纯文本 gfw 列表。
// 仅在 -update 显式开启后才会访问。
const (
	defaultChinaListURL = "https://raw.githubusercontent.com/felixonmars/dnsmasq-china-list/master/accelerated-domains.china.conf"
	defaultGFWListURL   = "https://raw.githubusercontent.com/Loyalsoldier/v2ray-rules-dat/release/gfw.txt"
	// defaultGeoURLTemplate 是 DB-IP 免费 Country Lite 库（mmdb.gz，按月发布，
	// 与内置 GeoLite2/DBIP-Country 格式兼容），%s 由 2006-01 格式的年月填充。
	defaultGeoURLTemplate = "https://download.db-ip.com/free/dbip-country-lite-%s.mmdb.gz"

	// 下载体积上限：当前两份列表均在 5MB 内，留足余量防异常超大响应。
	maxListBytes = 32 << 20
	// GeoIP 压缩包约 4MB、解压后约 10MB 量级，上限留足余量防异常响应。
	maxGeoGzBytes   = 64 << 20
	maxGeoMMDBBytes = 256 << 20
	// 内容健康下限：低于该规模视为源站异常，拒绝替换。
	minChinaDomains = 1000
	minGfwDomains   = 100
	// 解压后小于 1MB 的 mmdb 不可能是完整国家库。
	minGeoMMDBBytes = 1 << 20
)

// remoteChinaFile / remoteGfwFile / remoteGeoFile 是 -update-dir 下远端数据的落盘文件名。
const (
	remoteChinaFile = "china.remote.txt"
	remoteGfwFile   = "gfw.remote.txt"
	remoteGeoFile   = "geoip.country.mmdb"
)

// updater 周期拉取远端域名列表与 GeoIP 库并触发重载：
//   - 内容与上次一致（sha256）时跳过重载；
//   - 域名数/mmdb 健康校验不通过时拒绝落盘；
//   - 下载/写盘失败只记日志，旧规则继续生效。
type updater struct {
	chinaURL string
	gfwURL   string
	// geoURLs 为空时按 DB-IP 当月/上月地址依次尝试；测试可注入本地地址。
	geoURLs  []string
	dir      string
	interval time.Duration
	apply    func(chinaFiles, gfwFiles []string, geoFile string) (int, int, int, error)
	// localGeoFile 是 -lof 指定的内置库；远端库不存在时回退它。
	localGeoFile string
	// extraChina/extraGfw 是 -china/-gfw 用户附加文件，随远端更新一并重载。
	extraChina []string
	extraGfw   []string

	client *http.Client
	// now 可在测试中注入，决定默认 GeoIP 库的月份。
	now func() time.Time
}

func (u *updater) chinaPath() string { return filepath.Join(u.dir, remoteChinaFile) }
func (u *updater) gfwPath() string   { return filepath.Join(u.dir, remoteGfwFile) }
func (u *updater) geoPath() string   { return filepath.Join(u.dir, remoteGeoFile) }

// geoCandidates 返回本次尝试的 GeoIP 下载地址：显式配置优先，否则当月失败回退上月。
func geoCandidates(now time.Time) []string {
	return []string{
		fmt.Sprintf(defaultGeoURLTemplate, now.Format("2006-01")),
		fmt.Sprintf(defaultGeoURLTemplate, now.AddDate(0, -1, 0).Format("2006-01")),
	}
}

// activeGeoFile 返回当前应使用的 GeoIP 库路径：已下载的远端库优先，否则回退内置库。
func (u *updater) activeGeoFile() string {
	if st, err := os.Stat(u.geoPath()); err == nil && !st.IsDir() {
		return u.geoPath()
	}
	return u.localGeoFile
}

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
	geoChanged, geoErr := u.updateGeo()
	if geoErr != nil {
		loggo.Warn("update geoip database fail: %v", geoErr)
	}
	if !chinaChanged && !gfwChanged && !geoChanged && chinaErr == nil && gfwErr == nil && geoErr == nil {
		loggo.Info("remote lists unchanged")
		return
	}
	if chinaErr != nil || gfwErr != nil || geoErr != nil {
		// 任一失败仍按现有远端文件（旧内容或新内容）重载，保持与磁盘一致。
		loggo.Info("partial update, reloading with available remote files")
	}
	u.applyRemote()
}

// applyRemote 按当前存在的远端文件（优先）+ 用户附加文件触发重载。
func (u *updater) applyRemote() {
	chinaFiles := append(remoteIfExist(u.chinaPath()), u.extraChina...)
	gfwFiles := append(remoteIfExist(u.gfwPath()), u.extraGfw...)
	cn, gfw, hostsN, err := u.apply(chinaFiles, gfwFiles, u.activeGeoFile())
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

// updateGeo 下载（当月失败回退上月）、解压并校验 mmdb，原子替换落盘文件；
// 内容与现有文件一致时不重写。任一环节失败都保留旧库。
func (u *updater) updateGeo() (bool, error) {
	urls := u.geoURLs
	if len(urls) == 0 {
		now := time.Now
		if u.now != nil {
			now = u.now
		}
		urls = geoCandidates(now())
	}

	var gzBody []byte
	var lastErr error
	for _, url := range urls {
		body, err := u.fetchLimited(url, maxGeoGzBytes)
		if err == nil {
			gzBody = body
			lastErr = nil
			break
		}
		lastErr = err
		loggo.Warn("fetch geoip from %s fail: %v", url, err)
	}
	if lastErr != nil {
		return false, fmt.Errorf("all geoip sources failed: %w", lastErr)
	}

	zr, err := gzip.NewReader(bytes.NewReader(gzBody))
	if err != nil {
		return false, fmt.Errorf("gunzip geoip: %w", err)
	}
	mmdb, err := io.ReadAll(io.LimitReader(zr, maxGeoMMDBBytes+1))
	if err != nil {
		return false, fmt.Errorf("read gunzipped geoip: %w", err)
	}
	if len(mmdb) > maxGeoMMDBBytes {
		return false, errors.New("geoip database exceeds decompressed size limit")
	}
	if len(mmdb) < minGeoMMDBBytes {
		return false, fmt.Errorf("geoip database only %d bytes, below healthy minimum %d", len(mmdb), minGeoMMDBBytes)
	}
	if err := validateMMDB(mmdb); err != nil {
		return false, fmt.Errorf("invalid geoip database: %w", err)
	}

	dst := u.geoPath()
	if cur, err := os.ReadFile(dst); err == nil && sha256.Sum256(cur) == sha256.Sum256(mmdb) {
		loggo.Info("geoip database unchanged (%d bytes)", len(mmdb))
		return false, nil
	}
	tmp := dst + ".tmp"
	if err := os.WriteFile(tmp, mmdb, 0o644); err != nil {
		return false, err
	}
	if err := os.Rename(tmp, dst); err != nil {
		_ = os.Remove(tmp)
		return false, err
	}
	loggo.Info("geoip database updated (%d bytes)", len(mmdb))
	return true, nil
}

// validateMMDB 用 geoip2 打开内存数据，确认是可读的 MaxMind 国家库
// （DBIP-Country-Lite / GeoLite2-Country / GeoIP2-Country 等，City 库也兼容）。
func validateMMDB(data []byte) error {
	r, err := geoip2.FromBytes(data)
	if err != nil {
		return err
	}
	return r.Close()
}

func (u *updater) fetch(url string) ([]byte, error) {
	return u.fetchLimited(url, maxListBytes)
}

func (u *updater) fetchLimited(url string, maxBytes int64) ([]byte, error) {
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
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxBytes+1))
	if err != nil {
		return nil, err
	}
	if int64(len(body)) > maxBytes {
		return nil, errors.New("download exceeds size limit")
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
