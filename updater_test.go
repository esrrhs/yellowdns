package main

import (
	"bytes"
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
	apply := func(chinaFiles, gfwFiles []string) (int, int, error) {
		applied++
		lastChina, lastGfw = chinaFiles, gfwFiles
		return loadDomainLists(chinaFiles, gfwFiles)
	}
	u := &updater{
		chinaURL:   srv.URL + "/china",
		gfwURL:     srv.URL + "/gfw",
		dir:        dir,
		interval:   time.Hour,
		apply:      apply,
		extraChina: []string{userChina},
		client:     srv.Client(),
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
		t.Errorf("old gfw rule lost after failed download, got %s", routeName(got))
	}
}
