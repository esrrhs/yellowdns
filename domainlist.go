package main

import (
	"bufio"
	"embed"
	"io"
	"os"
	"strings"
	"sync/atomic"

	gohomedns "github.com/esrrhs/gohome/dns"
	"golang.org/x/net/idna"
)

const (
	routeAuto = iota
	routeLocal
	routeExtern
)

//go:embed data/china.txt data/gfw.txt
var domainFiles embed.FS

var cnSuffixes = []string{
	"cn",
	"xn--fiqs8s", // 中国
	"xn--55qx5d", // 公司
	"xn--io0a7i", // 网络
}

type domainSet map[string]struct{}

// domainData 是域名规则某一时刻的不可变快照。
// 热重载整体替换快照（atomic.Pointer），查询路径无锁读取，避免数据竞争。
type domainData struct {
	china domainSet
	gfw   domainSet
	// shadowed 中的 gfw 域名（或其父域）同时存在于直连规则中，
	// gohome resolver 直连优先的 trie 语义会把它们错误放行，必须绕开 resolver。
	shadowed domainSet
}

// 启动前为空快照，保证未加载列表时 currentDomains 也不返回 nil。
var domainState = atomic.Pointer[domainData]{}

func currentDomains() *domainData {
	d := domainState.Load()
	if d == nil {
		return &domainData{china: domainSet{}, gfw: domainSet{}, shadowed: domainSet{}}
	}
	return d
}

func loadDomainLists(chinaFile, gfwFile string) (int, int, error) {
	china := domainSet{}
	gfw := domainSet{}
	if err := loadEmbed(china, "data/china.txt"); err != nil {
		return 0, 0, err
	}
	if err := loadEmbed(gfw, "data/gfw.txt"); err != nil {
		return len(china), 0, err
	}
	var err error
	if chinaFile != "" {
		err = loadFile(china, chinaFile)
	}
	if gfwFile != "" && err == nil {
		err = loadFile(gfw, gfwFile)
	}
	if err != nil {
		// 文件加载失败时保留旧快照，调用方按错误处理（启动退出/重载放弃）。
		return len(china), len(gfw), err
	}
	for name := range gfw {
		delete(china, name)
	}
	domainState.Store(&domainData{
		china:    china,
		gfw:      gfw,
		shadowed: buildExternShadowed(china, gfw),
	})
	return len(china), len(gfw), nil
}

// buildExternShadowed 计算会被 gohome 直连域名树遮蔽的 gfw 域名。
// 遮蔽来源包括内置 china 列表以及 gohome 强制内置的默认 TLD 与主干域名。
func buildExternShadowed(china, gfw domainSet) domainSet {
	shadowed := domainSet{}
	direct := domainSet{}
	for _, tld := range gohomedns.DefaultDirectTLDs {
		direct[normalizeName(tld)] = struct{}{}
	}
	for _, d := range gohomedns.DefaultChinaMainDomains {
		direct[normalizeName(d)] = struct{}{}
	}
	for d := range china {
		direct[d] = struct{}{}
	}
	for g := range gfw {
		cur := g
		for {
			if _, ok := direct[cur]; ok {
				shadowed[g] = struct{}{}
				break
			}
			parent, ok := parentDomain(cur)
			if !ok {
				break
			}
			cur = parent
		}
	}
	return shadowed
}

// externShadowedHit 判断 name 自身或其父域是否为被遮蔽的 gfw 域名
func externShadowedHit(name string) bool {
	shadowed := currentDomains().shadowed
	cur := normalizeName(name)
	for cur != "" {
		if _, ok := shadowed[cur]; ok {
			return true
		}
		parent, ok := parentDomain(cur)
		if !ok {
			return false
		}
		cur = parent
	}
	return false
}

func domainKeys(set domainSet) []string {
	keys := make([]string, 0, len(set))
	for name := range set {
		keys = append(keys, name)
	}
	return keys
}

func loadEmbed(set domainSet, name string) error {
	f, err := domainFiles.Open(name)
	if err != nil {
		return err
	}
	defer f.Close()
	return loadReader(set, f)
}

func loadFile(set domainSet, path string) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	return loadReader(set, f)
}

func loadReader(set domainSet, r io.Reader) error {
	s := bufio.NewScanner(r)
	for s.Scan() {
		addDomain(set, s.Text())
	}
	return s.Err()
}

func addDomain(set domainSet, line string) {
	line = strings.TrimSpace(line)
	if line == "" || strings.HasPrefix(line, "#") {
		return
	}
	if rest, ok := strings.CutPrefix(line, "server=/"); ok {
		domain, _, found := strings.Cut(rest, "/")
		if !found {
			return
		}
		line = domain
	}
	line = normalizeName(line)
	if strings.Count(line, ".") < 1 || strings.ContainsAny(line, " \t/@*") {
		return
	}
	set[line] = struct{}{}
}

func classifyName(name string) int {
	name = normalizeName(name)
	if name == "" {
		return routeAuto
	}
	d := currentDomains()
	cur := name
	for {
		if _, ok := d.gfw[cur]; ok {
			return routeExtern
		}
		if _, ok := d.china[cur]; ok {
			return routeLocal
		}
		parent, ok := parentDomain(cur)
		if !ok {
			break
		}
		cur = parent
	}
	if isChinaSuffix(name) {
		return routeLocal
	}
	return routeAuto
}

func isChinaSuffix(name string) bool {
	name = normalizeName(name)
	for _, suffix := range cnSuffixes {
		if name == suffix || strings.HasSuffix(name, "."+suffix) {
			return true
		}
	}
	return false
}

func parentDomain(name string) (string, bool) {
	_, rest, ok := strings.Cut(name, ".")
	if !ok || rest == "" {
		return "", false
	}
	return rest, true
}

func normalizeName(name string) string {
	name = strings.TrimSuffix(strings.TrimSpace(strings.ToLower(name)), ".")
	if name == "" {
		return ""
	}
	ascii, err := idna.Lookup.ToASCII(name)
	if err != nil || ascii == "" {
		return name
	}
	return strings.ToLower(ascii)
}

func routeName(mode int) string {
	switch mode {
	case routeLocal:
		return "local"
	case routeExtern:
		return "extern"
	default:
		return "auto"
	}
}
