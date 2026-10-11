package main

import (
	"bufio"
	"io"
	"net"
	"os"
	"strings"
	"sync/atomic"

	"github.com/miekg/dns"
)

// hostsTTL 是静态应答的 TTL：规则只在重载时变化，给短 TTL 保证变更尽快生效。
const hostsTTL = 60

// hostsData 是静态解析规则某一时刻的不可变快照。
//   - exact：标准 hosts 条目，仅精确匹配名字；
//   - wildcard：dnsmasq address=/name/ip 条目，匹配名字自身及其全部子域。
type hostsData struct {
	exact    map[string][]net.IP
	wildcard map[string][]net.IP
}

var hostsState = atomic.Pointer[hostsData]{}

func currentHosts() *hostsData {
	h := hostsState.Load()
	if h == nil {
		return &hostsData{exact: map[string][]net.IP{}, wildcard: map[string][]net.IP{}}
	}
	return h
}

// loadHosts 解析全部 hosts 文件（后者追加到前者同名条目），任一文件失败则保留旧快照。
func loadHosts(files []string) (int, error) {
	h, err := parseHostsFiles(files)
	if err != nil {
		return 0, err
	}
	hostsState.Store(h)
	return len(h.exact) + len(h.wildcard), nil
}

// parseHostsFiles 只解析不落盘，供 reload 与域名快照一起原子替换。
func parseHostsFiles(files []string) (*hostsData, error) {
	h := &hostsData{exact: map[string][]net.IP{}, wildcard: map[string][]net.IP{}}
	for _, f := range files {
		if f == "" {
			continue
		}
		if err := loadHostsFile(h, f); err != nil {
			return nil, err
		}
	}
	return h, nil
}

func loadHostsFile(h *hostsData, path string) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	return parseHosts(h, f)
}

func parseHosts(h *hostsData, r io.Reader) error {
	s := bufio.NewScanner(r)
	for s.Scan() {
		addHostsLine(h, s.Text())
	}
	return s.Err()
}

// addHostsLine 接受两种格式：
//   - 标准 hosts："1.2.3.4 a.example b.example" / "::1 name"
//   - dnsmasq："address=/example.com/1.2.3.4"（含子域通配）
func addHostsLine(h *hostsData, line string) {
	if i := strings.IndexByte(line, '#'); i >= 0 {
		line = line[:i]
	}
	line = strings.TrimSpace(line)
	if line == "" {
		return
	}
	if rest, ok := strings.CutPrefix(line, "address=/"); ok {
		// rest: domain/ip[;ip] 或 domain/ip/
		domain, ips, found := strings.Cut(rest, "/")
		if !found {
			return
		}
		domain = normalizeName(domain)
		for _, raw := range strings.FieldsFunc(ips, func(r rune) bool { return r == '/' || r == ',' || r == ';' }) {
			if ip := net.ParseIP(strings.TrimSpace(raw)); ip != nil && domain != "" {
				h.wildcard[domain] = append(h.wildcard[domain], ip)
			}
		}
		return
	}
	fields := strings.Fields(line)
	if len(fields) < 2 {
		return
	}
	ip := net.ParseIP(fields[0])
	if ip == nil {
		return
	}
	for _, name := range fields[1:] {
		name = normalizeName(name)
		if name == "" {
			continue
		}
		h.exact[name] = append(h.exact[name], ip)
	}
}

// lookupHosts 返回名字对应的静态 IP：精确条目优先，再按父域回溯通配条目。
func lookupHosts(name string) []net.IP {
	name = normalizeName(name)
	if name == "" {
		return nil
	}
	h := currentHosts()
	var ips []net.IP
	if v, ok := h.exact[name]; ok {
		ips = append(ips, v...)
	}
	cur := name
	for {
		if v, ok := h.wildcard[cur]; ok {
			ips = append(ips, v...)
			break
		}
		parent, ok := parentDomain(cur)
		if !ok {
			break
		}
		cur = parent
	}
	return ips
}

// hostsAnswer 用静态 IP 合成应答；qtype 与 IP 族不匹配时返回无 answer 的 NOERROR
// （与 dnsmasq address=/ 行为一致），ok 为 false 表示没有静态规则。
func hostsAnswer(req *dns.Msg) (*dns.Msg, bool) {
	q := req.Question[0]
	ips := lookupHosts(q.Name)
	if ips == nil {
		return nil, false
	}
	reply := new(dns.Msg)
	reply.SetReply(req)
	reply.Authoritative = true
	for _, ip := range ips {
		switch q.Qtype {
		case dns.TypeA:
			if v4 := ip.To4(); v4 != nil {
				reply.Answer = append(reply.Answer, &dns.A{
					Hdr: dns.RR_Header{Name: q.Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: hostsTTL},
					A:   v4,
				})
			}
		case dns.TypeAAAA:
			if ip.To4() == nil {
				reply.Answer = append(reply.Answer, &dns.AAAA{
					Hdr:  dns.RR_Header{Name: q.Name, Rrtype: dns.TypeAAAA, Class: dns.ClassINET, Ttl: hostsTTL},
					AAAA: ip,
				})
			}
		default:
			// 其他类型没有静态合成数据，直接交给上游。
			return nil, false
		}
	}
	return reply, true
}
