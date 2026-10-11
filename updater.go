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
	"sync/atomic"
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
	// trigger 由 POST /update/refresh 投递刷新请求，run 循环在同一 goroutine
	// 串行消费，保证周期检查与手动刷新不会并发执行 runOnce。
	trigger chan updateRequest
}

// updateRequest 是手动刷新请求；run 循环执行完一次 runOnce 后把结果投回 reply。
type updateRequest struct {
	reply chan updateResult
}

// sourceResult 是单个数据源本次检查的结果。
type sourceResult struct {
	Changed bool   `json:"changed"`         // 是否有新内容落盘
	Error   string `json:"error,omitempty"` // 失败原因；空表示源可达且检查通过（含内容未变）
}

// updateResult 是一次完整刷新周期（china/gfw/geoip + 是否触发重载）的结果。
type updateResult struct {
	China    sourceResult `json:"china"`
	Gfw      sourceResult `json:"gfw"`
	GeoIP    sourceResult `json:"geoip"`
	Reloaded bool         `json:"reloaded"` // 是否因内容变化执行了热重载
}

// errUpdateDisabled 表示未开启 -update，手动刷新不可用。
var errUpdateDisabled = errors.New("auto-update is disabled (set -update to enable)")

// updateSourceHealth 用原子计数跟踪单个数据源（china/gfw/geoip）的更新健康，
// 供 /stats 与 Prometheus 暴露；快照读取路径完全无锁。
type updateSourceHealth struct {
	lastAttempt atomic.Int64 // unix 秒，最近一次尝试时间
	lastSuccess atomic.Int64 // unix 秒，最近一次源可达（含内容未变）；0 表示从未成功
	successes   atomic.Int64
	failures    atomic.Int64
	consecutive atomic.Int64 // 连续失败次数，任意一次成功即清零
}

// record 记录一次源检查结果。ok 为 true 表示源可达（无论内容是否变化）。
func (h *updateSourceHealth) record(ok bool) {
	now := time.Now().Unix()
	h.lastAttempt.Store(now)
	if ok {
		h.lastSuccess.Store(now)
		h.successes.Add(1)
		h.consecutive.Store(0)
	} else {
		h.failures.Add(1)
		h.consecutive.Add(1)
	}
}

// updateSourceSnapshot 是单个数据源的健康快照。
type updateSourceSnapshot struct {
	LastSuccess         int64 `json:"last_success_unixtime"` // 0 表示从未成功
	LastAttempt         int64 `json:"last_attempt_unixtime"` // 0 表示从未尝试
	Successes           int64 `json:"successes"`
	Failures            int64 `json:"failures"`
	ConsecutiveFailures int64 `json:"consecutive_failures"`
}

// updateHealth 汇总三个数据源的健康状态。
type updateHealth struct {
	china updateSourceHealth
	gfw   updateSourceHealth
	geoip updateSourceHealth
}

func (h *updateHealth) snapshot() (china, gfw, geoip updateSourceSnapshot) {
	snap := func(x *updateSourceHealth) updateSourceSnapshot {
		return updateSourceSnapshot{
			LastSuccess:         x.lastSuccess.Load(),
			LastAttempt:         x.lastAttempt.Load(),
			Successes:           x.successes.Load(),
			Failures:            x.failures.Load(),
			ConsecutiveFailures: x.consecutive.Load(),
		}
	}
	return snap(&h.china), snap(&h.gfw), snap(&h.geoip)
}

// updateMetrics 是全局更新健康指标；-update 未开启时保持零值。
var updateMetrics = &updateHealth{}

// reset 清空全部源的健康记录，供测试隔离全局状态。
func (h *updateHealth) reset() { *h = updateHealth{} }

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

// run 启动即检查一次，之后按 interval 周期检查，并串行消费手动刷新请求，直到进程退出。
func (u *updater) run() {
	u.runOnce()
	t := time.NewTicker(u.interval)
	defer t.Stop()
	for {
		select {
		case <-t.C:
			u.runOnce()
		case req := <-u.trigger:
			req.reply <- u.runOnce()
		}
	}
}

// requestRun 通过 trigger 通道请求一次立即刷新，阻塞到 run 循环执行完毕或 ctx 超时。
// 未开启自动更新（没有 run 循环）时返回 errUpdateDisabled。
func (u *updater) requestRun(ctx context.Context) (updateResult, error) {
	if u.trigger == nil {
		return updateResult{}, errUpdateDisabled
	}
	reply := make(chan updateResult, 1)
	select {
	case u.trigger <- updateRequest{reply: reply}:
	case <-ctx.Done():
		return updateResult{}, ctx.Err()
	}
	select {
	case res := <-reply:
		return res, nil
	case <-ctx.Done():
		return updateResult{}, ctx.Err()
	}
}

func (u *updater) runOnce() updateResult {
	var res updateResult

	chinaChanged, chinaErr := u.updateOne("china", u.chinaURL, u.chinaPath(), minChinaDomains)
	if chinaErr != nil {
		loggo.Warn("update china list fail: %v", chinaErr)
		res.China.Error = chinaErr.Error()
	}
	updateMetrics.china.record(chinaErr == nil)
	res.China.Changed = chinaChanged

	gfwChanged, gfwErr := u.updateOne("gfw", u.gfwURL, u.gfwPath(), minGfwDomains)
	if gfwErr != nil {
		loggo.Warn("update gfw list fail: %v", gfwErr)
		res.Gfw.Error = gfwErr.Error()
	}
	updateMetrics.gfw.record(gfwErr == nil)
	res.Gfw.Changed = gfwChanged

	geoChanged, geoErr := u.updateGeo()
	if geoErr != nil {
		loggo.Warn("update geoip database fail: %v", geoErr)
		res.GeoIP.Error = geoErr.Error()
	}
	updateMetrics.geoip.record(geoErr == nil)
	res.GeoIP.Changed = geoChanged

	if !chinaChanged && !gfwChanged && !geoChanged && chinaErr == nil && gfwErr == nil && geoErr == nil {
		loggo.Info("remote lists unchanged")
		return res
	}
	if chinaErr != nil || gfwErr != nil || geoErr != nil {
		// 任一失败仍按现有远端文件（旧内容或新内容）重载，保持与磁盘一致。
		loggo.Info("partial update, reloading with available remote files")
	}
	u.applyRemote()
	res.Reloaded = true
	return res
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

	// 与磁盘现有文件 hash 一致即视为 unchanged：该文件是此前校验通过后原子写入的，
	// 内容相同必然同样有效，直接跳过昂贵的整库解析（8MB mmdb 的 FromBytes）。
	dst := u.geoPath()
	if cur, err := os.ReadFile(dst); err == nil && sha256.Sum256(cur) == sha256.Sum256(mmdb) {
		loggo.Info("geoip database unchanged (%d bytes)", len(mmdb))
		return false, nil
	}
	if err := validateMMDB(mmdb); err != nil {
		return false, fmt.Errorf("invalid geoip database: %w", err)
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
