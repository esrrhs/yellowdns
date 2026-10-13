package main

import (
	"sync"
	"sync/atomic"
	"time"

	"github.com/esrrhs/gohome/dns/cache"
	"github.com/miekg/dns"
)

// 否定应答缓存（negative caching，RFC 2308）。
//
// gohome 内置响应缓存的 Set 对空 Answer 直接返回：NXDOMAIN 与 NODATA
// （NOERROR 但无 Answer）在任何路径上都不会被缓存。这不是边角情况——
// 双栈网络下每个只有 IPv4 的域名都会产生 AAAA-NODATA，加上输错域名、
// 扫描噪声带来的 NXDOMAIN，否定应答在日常查询里占比很高，每次未命中
// 都要重走一遍上游 failover。
//
// 本缓存在 routingResolver.Exchange 的路由判定之前查询：命中即按剩余
// TTL 衰减后直接下发，不再触碰 hosts 之后的任何上游逻辑。与 serve-stale
// 备份的分工：那里只存正向应答、仅在上游全失败时兜底；这里存否定应答、
// 正常路径也参与命中。

// negEntry 是一条否定应答的缓存条目。
type negEntry struct {
	msg       *dns.Msg
	expiresAt time.Time
}

// negativeCache 按 RFC 2308 语义缓存否定应答。容量与淘汰策略和
// staleStore 保持一致（共享 -cache-size），满容时优先淘汰已过期条目。
type negativeCache struct {
	mu       sync.RWMutex
	items    map[string]*negEntry
	capacity int
	hits     atomic.Int64 // Get 命中次数
	misses   atomic.Int64 // Get 未命中次数（含过期淘汰）
}

// newNegativeCache 创建否定缓存；容量非法时退到默认值。
func newNegativeCache(capacity int) *negativeCache {
	if capacity <= 0 {
		capacity = 2000
	}
	return &negativeCache{
		items:    make(map[string]*negEntry),
		capacity: capacity,
	}
}

// put 登记一条否定应答。同名 key 刷新只替换条目、不占用新容量；
// 满容时优先淘汰一个已过期条目，否则随手淘汰一个（map 遍历顺序即随机）。
func (c *negativeCache) put(key string, msg *dns.Msg, expiresAt time.Time) {
	if c == nil || msg == nil {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if _, exists := c.items[key]; !exists && len(c.items) >= c.capacity {
		now := time.Now()
		deleted := false
		for k, v := range c.items {
			if now.After(v.expiresAt) {
				delete(c.items, k)
				deleted = true
				break
			}
		}
		if !deleted {
			for k := range c.items {
				delete(c.items, k)
				break
			}
		}
	}
	c.items[key] = &negEntry{msg: msg.Copy(), expiresAt: expiresAt}
}

// get 取出一条否定应答：未命中或已过期（懒清理）返回 false；
// 命中时返回副本，并把各记录 TTL 收敛到剩余存活时间，避免下游拿到
// 一个"看起来还很新鲜"的过期时间戳。
func (c *negativeCache) get(key string) (*dns.Msg, bool) {
	if c == nil {
		return nil, false
	}
	c.mu.RLock()
	e, exists := c.items[key]
	c.mu.RUnlock()
	if !exists {
		c.misses.Add(1)
		return nil, false
	}
	now := time.Now()
	if now.After(e.expiresAt) {
		c.mu.Lock()
		// 再次确认，避免与并发 put 竞争误删刚刷新的同名条目。
		if cur, ok := c.items[key]; ok && now.After(cur.expiresAt) {
			delete(c.items, key)
		}
		c.mu.Unlock()
		c.misses.Add(1)
		return nil, false
	}
	c.hits.Add(1)
	resp := e.msg.Copy()
	decayToRemaining(resp, time.Until(e.expiresAt))
	return resp, true
}

// stats 返回当前条目数与累计命中/未命中，供 /stats 与 Prometheus 暴露。
func (c *negativeCache) stats() (entries int, hits, misses int64) {
	if c == nil {
		return 0, 0, 0
	}
	c.mu.RLock()
	defer c.mu.RUnlock()
	return len(c.items), c.hits.Load(), c.misses.Load()
}

func (c *negativeCache) len() int {
	if c == nil {
		return 0
	}
	c.mu.RLock()
	defer c.mu.RUnlock()
	return len(c.items)
}

func (c *negativeCache) clear() {
	if c == nil {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.items = make(map[string]*negEntry)
}

// negKey 与 gohome 内置缓存、serve-stale 备份共用同一套 key 规则
// （小写、去尾点），三层缓存对同一个问题的口径一致。
func negKey(q dns.Question) string {
	return cache.KeyForMsg(q.Name, q.Qtype, q.Qclass)
}

// isCacheableNegative 判断一条成功应答是否属于可缓存的否定应答：
// NXDOMAIN（RcodeNameError）与 NODATA（NOERROR 且无 Answer）。
// SERVFAIL/REFUSED 等 Rcode 按 RFC 2308 明确不得缓存；TC 置位的应答
// 不完整（可能有没能放下的 Answer），同样不缓存。
func isCacheableNegative(resp *dns.Msg) bool {
	if resp == nil || resp.Truncated {
		return false
	}
	switch resp.Rcode {
	case dns.RcodeNameError:
		return true
	case dns.RcodeSuccess:
		return len(resp.Answer) == 0
	}
	return false
}

// negativeResponseTTL 计算一条否定应答的本地缓存时长（RFC 2308 §5）：
// 取 authority 段 SOA 记录 TTL 与 MINIMUM 字段的较小值，再用
// -negcache-ttl 封顶，最后与正向应答共用同一套 min/max TTL 收敛
// （min 抬升、max 压低）。没有 SOA 的畸形否定应答返回 0，调用方跳过。
func negativeResponseTTL(msg *dns.Msg, capTTL, minTTL, maxTTL time.Duration) time.Duration {
	soa := soaRecord(msg)
	if soa == nil {
		return 0
	}
	ttl := time.Duration(soa.Header().Ttl) * time.Second
	if minimum := time.Duration(soa.Minttl) * time.Second; minimum < ttl {
		ttl = minimum
	}
	if capTTL > 0 && ttl > capTTL {
		ttl = capTTL
	}
	if minTTL > 0 && ttl < minTTL {
		ttl = minTTL
	}
	if maxTTL > 0 && ttl > maxTTL {
		ttl = maxTTL
	}
	return ttl
}

// soaRecord 从 authority 段取第一条 SOA：否定应答的 TTL 语义由它承载
// （NXDOMAIN/NODATA 的 Answer 段为空，无法像正向应答那样取最小 TTL）。
func soaRecord(msg *dns.Msg) *dns.SOA {
	if msg == nil {
		return nil
	}
	for _, rr := range msg.Ns {
		if soa, ok := rr.(*dns.SOA); ok {
			return soa
		}
	}
	return nil
}
