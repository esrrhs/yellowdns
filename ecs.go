package main

import (
	"errors"
	"fmt"
	"net"

	"github.com/miekg/dns"
)

// EDNS Client Subnet（RFC 7871）处理策略。
//
// yellowdns 只支持"固定子网附加"与"剥离"两种管理模式，不做按客户端源 IP
// 透传生成：gohome 响应缓存的 key 只含 qname/qtype/qclass，不包含 ECS，
// 透传各客户端不同子网会让 A 客户端的 CDN 结果命中给 B 客户端（缓存串味）。
// 固定子网对所有客户端恒定，与该缓存模型天然兼容。
// 未配置策略时保持报文原貌（客户端自带 ECS 会随上游请求原样转发）。

type ecsMode uint8

const (
	ecsOff   ecsMode = iota // 不干预
	ecsCIDR                 // 用配置的固定子网覆盖/附加 ECS
	ecsStrip                // 删除请求中的 ECS option
)

// ecsPolicy 是解析后的 ECS 策略（cidr 模式下携带规范化后的网络地址）。
type ecsPolicy struct {
	mode   ecsMode
	net    string // 原始配置文本，供 /stats 展示
	family uint16 // 1=IPv4, 2=IPv6（RFC 7871 Address Family Number）
	mask   uint8  // Source Netmask（前缀长度）
	addr   net.IP // 已掩码的网络地址；IPv4 固定 4 字节表示
}

// parseECSPolicy 校验并构造 ECS 策略。cidr 非空时为固定子网模式，
// strip 为 true 时为剥离模式，二者互斥；都缺省返回 nil（不干预）。
func parseECSPolicy(cidr string, strip bool) (*ecsPolicy, error) {
	if cidr != "" && strip {
		return nil, errors.New("-ecs and -ecs-strip are mutually exclusive")
	}
	if strip {
		return &ecsPolicy{mode: ecsStrip, net: "strip"}, nil
	}
	if cidr == "" {
		return nil, nil
	}
	_, ipnet, err := net.ParseCIDR(cidr)
	if err != nil {
		return nil, fmt.Errorf("parse -ecs %q: %w", cidr, err)
	}
	ones, bits := ipnet.Mask.Size()
	p := &ecsPolicy{
		mode: ecsCIDR,
		net:  ipnet.String(),
		mask: uint8(ones),
		addr: ipnet.IP, // ParseCIDR 返回的网络地址已按掩码收敛
	}
	if bits == 32 {
		p.family = 1
		p.addr = p.addr.To4()
	} else {
		p.family = 2
	}
	// /0 没有任何地理含义且会让部分上游直接拒绝，显式报错。
	if ones == 0 {
		return nil, fmt.Errorf("parse -ecs %q: prefix length must be greater than 0", cidr)
	}
	return p, nil
}

// isPrivateScope 判断配置子网是否为私有/本地范围。把这类子网作为 ECS
// 发给公共上游没有地理优化价值，还会泄露内网拓扑；仅用于启动告警，不阻断。
func (p *ecsPolicy) isPrivateScope() bool {
	if p == nil || p.mode != ecsCIDR {
		return false
	}
	return p.addr.IsPrivate() || p.addr.IsLoopback() ||
		p.addr.IsLinkLocalUnicast() || p.addr.IsUnspecified()
}

// applyECS 在请求发往上游前按策略改写 EDNS0 选项。
// 只对 A/AAAA 生效（RFC 7871 的 ECS 仅用于地址类递归查询）；
// 只动 ECS option，不替换 OPT 记录本身，DO 位与其他 EDNS 选项完整保留。
// 返回 true 表示报文被修改（供指标计数）。
func applyECS(req *dns.Msg, p *ecsPolicy) bool {
	if p == nil || p.mode == ecsOff || req == nil || len(req.Question) == 0 {
		return false
	}
	switch req.Question[0].Qtype {
	case dns.TypeA, dns.TypeAAAA:
	default:
		return false
	}
	opt := req.IsEdns0()
	switch p.mode {
	case ecsStrip:
		if opt == nil {
			return false
		}
		if removeECSOption(opt) {
			return true
		}
		return false
	case ecsCIDR:
		if opt == nil {
			// 客户端没带 EDNS0：新建一个，UDP payload 取常用协商值，DO=false。
			req.SetEdns0(4096, false)
			opt = req.IsEdns0()
		}
		// 客户端自带 ECS 时以管理员配置的固定子网为准，避免内网视角泄露/串味。
		removeECSOption(opt)
		opt.Option = append(opt.Option, &dns.EDNS0_SUBNET{
			Code:          dns.EDNS0SUBNET,
			Family:        p.family,
			SourceNetmask: p.mask,
			SourceScope:   0, // 请求中 scope 必须为 0（RFC 7871 §7.3）
			Address:       p.addr,
		})
		return true
	}
	return false
}

// removeECSOption 从 OPT 中删除 ECS option，返回是否删除过。
func removeECSOption(opt *dns.OPT) bool {
	kept := opt.Option[:0]
	removed := false
	for _, o := range opt.Option {
		if o.Option() == dns.EDNS0SUBNET {
			removed = true
			continue
		}
		kept = append(kept, o)
	}
	opt.Option = kept
	return removed
}

// ecsLabel 返回策略的稳定文本标签，供 /stats 与日志使用。
func (p *ecsPolicy) ecsLabel() string {
	if p == nil {
		return "off"
	}
	switch p.mode {
	case ecsCIDR:
		return "cidr:" + p.net
	case ecsStrip:
		return "strip"
	default:
		return "off"
	}
}
