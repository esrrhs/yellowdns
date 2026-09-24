package main

import (
	"bufio"
	"embed"
	"io"
	"os"
	"strings"

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

var (
	chinaDomains domainSet
	gfwDomains   domainSet
)

func loadDomainLists(chinaFile, gfwFile string) (int, int, error) {
	chinaDomains = domainSet{}
	gfwDomains = domainSet{}
	if err := loadEmbed(chinaDomains, "data/china.txt"); err != nil {
		return 0, 0, err
	}
	if err := loadEmbed(gfwDomains, "data/gfw.txt"); err != nil {
		return len(chinaDomains), 0, err
	}
	var err error
	if chinaFile != "" {
		err = loadFile(chinaDomains, chinaFile)
	}
	if gfwFile != "" {
		if e := loadFile(gfwDomains, gfwFile); err == nil {
			err = e
		}
	}
	for name := range gfwDomains {
		delete(chinaDomains, name)
	}
	return len(chinaDomains), len(gfwDomains), err
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
	cur := name
	for {
		if _, ok := gfwDomains[cur]; ok {
			return routeExtern
		}
		if _, ok := chinaDomains[cur]; ok {
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
