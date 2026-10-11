package main

import (
	"bytes"
	"compress/gzip"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func genUpdateChina(n int) []byte {
	var b bytes.Buffer
	for i := 0; i < n; i++ {
		fmt.Fprintf(&b, "server=/d%d.update-china.test/114.114.114.114\n", i)
	}
	return b.Bytes()
}

func genUpdateGfw(n int) []byte {
	var b bytes.Buffer
	for i := 0; i < n; i++ {
		fmt.Fprintf(&b, "d%d.update-gfw.test\n", i)
	}
	return b.Bytes()
}

func TestCountDomains(t *testing.T) {
	body := []byte("# comment\nserver=/a.china.conf/114.114.114.114\nb.example.com\nc.example.com\nd.example.com")
	if got := countDomains(body); got != 4 {
		t.Fatalf("countDomains = %d, want 4", got)
	}
}

// TestUpdaterRunOnce 覆盖完整更新链路：下载落盘并生效、内容未变跳过重载、
// 坏内容（低于健康下限）与下载失败均保留旧规则。
func TestUpdaterRunOnce(t *testing.T) {
	t.Cleanup(func() { _, _, _ = loadDomainLists(nil, nil) })

	var chinaBody, gfwBody []byte
	chinaStatus := http.StatusOK
	mmdbBytes, err := os.ReadFile("GeoLite2-Country.mmdb")
	if err != nil {
		t.Fatal(err)
	}
	mmdbGz := gzipBytes(t, mmdbBytes)
	mux := http.NewServeMux()
	mux.HandleFunc("/china", func(w http.ResponseWriter, r *http.Request) {
		if chinaStatus != http.StatusOK {
			http.Error(w, "boom", chinaStatus)
			return
		}
		w.Write(chinaBody)
	})
	mux.HandleFunc("/gfw", func(w http.ResponseWriter, r *http.Request) {
		w.Write(gfwBody)
	})
	mux.HandleFunc("/geo", func(w http.ResponseWriter, r *http.Request) {
		w.Write(mmdbGz)
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	chinaBody = genUpdateChina(minChinaDomains)
	gfwBody = genUpdateGfw(minGfwDomains)

	dir := t.TempDir()
	userChina := filepath.Join(dir, "user-china.txt")
	if err := os.WriteFile(userChina, []byte("user-extra-china.test\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	var applied int
	var lastChina, lastGfw []string
	var lastGeo string
	apply := func(chinaFiles, gfwFiles []string, geoFile string) (int, int, int, error) {
		applied++
		lastChina, lastGfw, lastGeo = chinaFiles, gfwFiles, geoFile
		cn, gfw, err := loadDomainLists(chinaFiles, gfwFiles)
		return cn, gfw, 0, err
	}
	u := &updater{
		chinaURL:     srv.URL + "/china",
		gfwURL:       srv.URL + "/gfw",
		geoURLs:      []string{srv.URL + "/geo"},
		dir:          dir,
		interval:     time.Hour,
		apply:        apply,
		localGeoFile: "builtin.mmdb",
		extraChina:   []string{userChina},
		client:       srv.Client(),
	}

	// 首次更新：下载、落盘、重载
	u.runOnce()
	if applied != 1 {
		t.Fatalf("first runOnce applied %d times, want 1", applied)
	}
	chinaDisk, err := os.ReadFile(filepath.Join(dir, remoteChinaFile))
	if err != nil || !bytes.Equal(chinaDisk, chinaBody) {
		t.Fatalf("china remote file mismatch: %v", err)
	}
	if got := classifyName("d0.update-china.test."); got != routeLocal {
		t.Errorf("remote china rule got %s, want local", routeName(got))
	}
	if got := classifyName("d0.update-gfw.test."); got != routeExtern {
		t.Errorf("remote gfw rule got %s, want extern", routeName(got))
	}
	if got := classifyName("user-extra-china.test."); got != routeLocal {
		t.Errorf("extra user rule got %s, want local", routeName(got))
	}
	// apply 收到 远端文件 + 用户附加文件
	if len(lastChina) != 2 {
		t.Fatalf("apply chinaFiles = %v, want [remote, user]", lastChina)
	}
	if filepath.Base(lastChina[0]) != remoteChinaFile || lastChina[1] != userChina {
		t.Errorf("apply chinaFiles = %v, want remote file + %s", lastChina, userChina)
	}
	if len(lastGfw) != 1 || lastGfw[0] != filepath.Join(dir, remoteGfwFile) {
		t.Errorf("apply gfwFiles = %v, want only remote file", lastGfw)
	}
	// 远端 GeoIP 库下载落盘后，apply 使用它而非内置库
	if lastGeo != filepath.Join(dir, remoteGeoFile) {
		t.Errorf("apply geoFile = %q, want downloaded %s", lastGeo, remoteGeoFile)
	}
	geoDisk, err := os.ReadFile(filepath.Join(dir, remoteGeoFile))
	if err != nil || !bytes.Equal(geoDisk, mmdbBytes) {
		t.Fatalf("geoip remote file mismatch: %v", err)
	}

	// 内容未变：跳过重载
	u.runOnce()
	if applied != 1 {
		t.Fatalf("unchanged content should skip apply, applied %d", applied)
	}

	// 坏内容（低于健康下限）：拒绝落盘，旧规则继续生效
	chinaBody = genUpdateChina(3)
	gfwBody = genUpdateGfw(3)
	u.runOnce()
	chinaDisk2, err := os.ReadFile(filepath.Join(dir, remoteChinaFile))
	if err != nil || !bytes.Equal(chinaDisk2, genUpdateChina(minChinaDomains)) {
		t.Fatalf("bad content must not replace old file: %v", err)
	}
	if got := classifyName("d0.update-china.test."); got != routeLocal {
		t.Errorf("old china rule lost after bad update, got %s", routeName(got))
	}

	// 下载失败（非 200）：同样保留旧文件与旧规则
	chinaBody = genUpdateChina(minChinaDomains)
	chinaStatus = http.StatusInternalServerError
	u.runOnce()
	chinaDisk3, err := os.ReadFile(filepath.Join(dir, remoteChinaFile))
	if err != nil || !bytes.Equal(chinaDisk3, genUpdateChina(minChinaDomains)) {
		t.Fatalf("failed download must not replace old file: %v", err)
	}
	if got := classifyName("d0.update-gfw.test."); got != routeExtern {
		t.Errorf("old gfw rule lost after failed update, got %s", routeName(got))
	}
}

func gzipBytes(t testing.TB, b []byte) []byte {
	t.Helper()
	var buf bytes.Buffer
	zw := gzip.NewWriter(&buf)
	if _, err := zw.Write(b); err != nil {
		t.Fatal(err)
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func TestGeoCandidates(t *testing.T) {
	// 普通月份：当月优先，上月回退
	got := geoCandidates(time.Date(2026, 10, 5, 0, 0, 0, 0, time.UTC))
	want := []string{
		"https://download.db-ip.com/free/dbip-country-lite-2026-10.mmdb.gz",
		"https://download.db-ip.com/free/dbip-country-lite-2026-09.mmdb.gz",
	}
	if len(got) != 2 || got[0] != want[0] || got[1] != want[1] {
		t.Fatalf("geoCandidates = %v, want %v", got, want)
	}
	// 1 月的上月要正确翻到上一年的 12 月
	jan := geoCandidates(time.Date(2027, 1, 1, 0, 0, 0, 0, time.UTC))
	if jan[1] != "https://download.db-ip.com/free/dbip-country-lite-2026-12.mmdb.gz" {
		t.Fatalf("january fallback = %q, want 2026-12", jan[1])
	}
}

func TestValidateMMDB(t *testing.T) {
	if err := validateMMDB([]byte("not an mmdb")); err == nil {
		t.Fatal("garbage bytes must fail validation")
	}
	b, err := os.ReadFile("GeoLite2-Country.mmdb")
	if err != nil {
		t.Fatal(err)
	}
	if err := validateMMDB(b); err != nil {
		t.Fatalf("real country mmdb must pass validation: %v", err)
	}
}

// TestUpdateGeo 覆盖 GeoIP 更新主链路与各类失败回退。
func TestUpdateGeo(t *testing.T) {
	mmdbBytes, err := os.ReadFile("GeoLite2-Country.mmdb")
	if err != nil {
		t.Fatal(err)
	}
	mmdbGz := gzipBytes(t, mmdbBytes)
	badMmdbGz := gzipBytes(t, make([]byte, minGeoMMDBBytes+1024))

	mux := http.NewServeMux()
	mux.HandleFunc("/ok", func(w http.ResponseWriter, r *http.Request) {
		w.Write(mmdbGz)
	})
	mux.HandleFunc("/badgz", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("this is not gzip"))
	})
	mux.HandleFunc("/badmmdb", func(w http.ResponseWriter, r *http.Request) {
		// 超过 1MB 的零字节，绕过体积下限但不是合法 mmdb
		w.Write(badMmdbGz)
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	t.Run("download and unchanged", func(t *testing.T) {
		dir := t.TempDir()
		u := &updater{dir: dir, geoURLs: []string{srv.URL + "/ok"}, client: srv.Client()}

		if u.activeGeoFile() != "" {
			t.Fatal("activeGeoFile with no local fallback and no download should be empty")
		}
		u.localGeoFile = "builtin.mmdb"
		if got := u.activeGeoFile(); got != "builtin.mmdb" {
			t.Fatalf("before download activeGeoFile = %q, want builtin", got)
		}

		changed, err := u.updateGeo()
		if err != nil || !changed {
			t.Fatalf("first updateGeo changed=%v err=%v", changed, err)
		}
		dst := filepath.Join(dir, remoteGeoFile)
		got, err := os.ReadFile(dst)
		if err != nil || !bytes.Equal(got, mmdbBytes) {
			t.Fatalf("downloaded mmdb mismatch: %v", err)
		}
		if got := u.activeGeoFile(); got != dst {
			t.Fatalf("after download activeGeoFile = %q, want %s", got, dst)
		}

		// 内容一致：不重写
		changed, err = u.updateGeo()
		if err != nil || changed {
			t.Fatalf("unchanged updateGeo changed=%v err=%v", changed, err)
		}
	})

	t.Run("invalid gzip keeps old database", func(t *testing.T) {
		dir := t.TempDir()
		u := &updater{
			dir:          dir,
			geoURLs:      []string{srv.URL + "/ok"},
			localGeoFile: "builtin.mmdb",
			client:       srv.Client(),
		}
		// 先写入一份好库
		if _, err := u.updateGeo(); err != nil {
			t.Fatal(err)
		}
		old, err := os.ReadFile(filepath.Join(dir, remoteGeoFile))
		if err != nil {
			t.Fatal(err)
		}
		// 再喂坏 gzip：必须失败且旧库保留
		u.geoURLs = []string{srv.URL + "/badgz"}
		if _, err := u.updateGeo(); err == nil {
			t.Fatal("invalid gzip must return error")
		}
		cur, err := os.ReadFile(filepath.Join(dir, remoteGeoFile))
		if err != nil || !bytes.Equal(cur, old) {
			t.Fatalf("old database must survive invalid gzip: %v", err)
		}
		if got := u.activeGeoFile(); got != filepath.Join(dir, remoteGeoFile) {
			t.Fatalf("activeGeoFile = %q, want old remote db", got)
		}
	})

	t.Run("invalid mmdb payload rejected", func(t *testing.T) {
		dir := t.TempDir()
		u := &updater{dir: dir, geoURLs: []string{srv.URL + "/badmmdb"}, client: srv.Client()}
		if changed, err := u.updateGeo(); err == nil || changed {
			t.Fatalf("invalid mmdb changed=%v err=%v", changed, err)
		}
		if _, err := os.Stat(filepath.Join(dir, remoteGeoFile)); !os.IsNotExist(err) {
			t.Fatalf("no database file should be written, stat err=%v", err)
		}
	})

	t.Run("month fallback and all sources fail", func(t *testing.T) {
		dir := t.TempDir()
		// 第一个地址 404，回退到第二个地址成功
		u := &updater{
			dir:     dir,
			geoURLs: []string{srv.URL + "/missing", srv.URL + "/ok"},
			client:  srv.Client(),
		}
		if changed, err := u.updateGeo(); err != nil || !changed {
			t.Fatalf("fallback update changed=%v err=%v", changed, err)
		}

		// 全部失败：返回错误且不落盘
		dir2 := t.TempDir()
		bad := &updater{dir: dir2, geoURLs: []string{srv.URL + "/missing"}, client: srv.Client()}
		if _, err := bad.updateGeo(); err == nil {
			t.Fatal("all sources failing must return error")
		}
	})
}
