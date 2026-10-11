package main

import (
	"sync"
	"time"

	"github.com/miekg/dns"
)

// staleReplyTTL 是过期应答重新下发时统一使用的 TTL。取值足够小，使客户端
// 在上游恢复后的下一次查询就能拿到新结果；又大于 0，避免断网窗口内每个
// 查询都重新走一遍完整的上游 failover 超时（默认 -timeout 5s）。
const staleReplyTTLSeconds uint32 = 5

// staleEntry 是一条最近成功应答的备份，独立于 gohome 内置响应缓存保存。
type staleEntry struct {
	msg       *dns.Msg
	expiresAt time.Time // 新鲜期截止时刻（已经过 min/max TTL 收敛）
}

// staleStore 保存最近的成功应答，在 gohome resolver 与直连兜底上游全部失败时
// 兜底返回（serve-stale，RFC 8767）。gohome 缓存在 TTL 到期时立即删除条目，
// 本存储把条目多保留一段可配置窗口，但只在解析失败路径读取，不参与正常命中，
// 因此不会让客户端在链路正常时拿到过期数据。
type staleStore struct {
	mu       sync.RWMutex
	items    map[string]*staleEntry
	capacity int
}

func newStaleStore(capacity int) *staleStore {
	if capacity <= 0 {
		capacity = 2000
	}
	return &staleStore{
		items:    make(map[string]*staleEntry),
		capacity: capacity,
	}
}

// put 记录一次成功应答。同名 key 刷新只替换条目、不占用新容量；
// 满容时优先淘汰一个已过新鲜期的条目，否则随手淘汰一个（map 遍历顺序即随机）。
func (s *staleStore) put(key string, msg *dns.Msg, expiresAt time.Time) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, exists := s.items[key]; !exists && len(s.items) >= s.capacity {
		now := time.Now()
		deleted := false
		for k, v := range s.items {
			if now.After(v.expiresAt) {
				delete(s.items, k)
				deleted = true
				break
			}
		}
		if !deleted {
			for k := range s.items {
				delete(s.items, k)
				break
			}
		}
	}
	s.items[key] = &staleEntry{msg: msg.Copy(), expiresAt: expiresAt}
}

// get 取出备份条目，分三种情况：
//   - 新鲜期内（now <= expiresAt）：按剩余存活时间衰减 TTL 后返回，stale=false。
//     常见于 gohome 不可用、本存储是唯一缓存，或 min-ttl 把本地保鲜期拉长到
//     gohome 内置缓存过期之后；
//   - 已过期但未超过 maxAge：把所有 TTL 改写为 staleReplyTTLSeconds 后返回，
//     stale=true；
//   - 不存在或过期超过 maxAge：ok=false，并顺带清理越界条目。
func (s *staleStore) get(key string, maxAge time.Duration) (resp *dns.Msg, stale bool, ok bool) {
	s.mu.RLock()
	e, exists := s.items[key]
	s.mu.RUnlock()
	if !exists {
		return nil, false, false
	}
	now := time.Now()
	if now.After(e.expiresAt.Add(maxAge)) {
		s.mu.Lock()
		// 再次确认，避免与并发 put 竞争误删刚刷新的同名条目。
		if cur, ok := s.items[key]; ok && now.After(cur.expiresAt.Add(maxAge)) {
			delete(s.items, key)
		}
		s.mu.Unlock()
		return nil, false, false
	}
	resp = e.msg.Copy()
	if now.After(e.expiresAt) {
		rewriteTTL(resp, staleReplyTTLSeconds)
		return resp, true, true
	}
	decayToRemaining(resp, time.Until(e.expiresAt))
	return resp, false, true
}

func (s *staleStore) len() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.items)
}

func (s *staleStore) clear() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.items = make(map[string]*staleEntry)
}

// rewriteTTL 把消息中所有资源记录的 TTL 统一改写为 secs。
// OPT（EDNS0）是元记录：其 Ttl 字段实际编码 extended rcode/版本/标志
// （如 DNSSEC DO 位），没有 TTL 语义，绝不能改写。
func rewriteTTL(msg *dns.Msg, secs uint32) {
	for _, rrs := range [][]dns.RR{msg.Answer, msg.Ns, msg.Extra} {
		for _, rr := range rrs {
			h := rr.Header()
			if h != nil && h.Rrtype != dns.TypeOPT {
				h.Ttl = secs
			}
		}
	}
}

// decayToRemaining 把消息内所有记录的 TTL 收敛到不超过剩余存活时间。
func decayToRemaining(msg *dns.Msg, remaining time.Duration) {
	secs := uint32(remaining.Seconds())
	if secs == 0 {
		secs = 1
	}
	for _, rrs := range [][]dns.RR{msg.Answer, msg.Ns, msg.Extra} {
		for _, rr := range rrs {
			h := rr.Header()
			if h != nil && h.Rrtype != dns.TypeOPT && h.Ttl > secs {
				h.Ttl = secs
			}
		}
	}
}

// clampResponseTTL 把应答内所有记录的 TTL 收敛到 [minTTL, maxTTL]，
// 并返回 Answer 段收敛后的最小 TTL（本应答在本地的有效保鲜时长）。
// minTTL/maxTTL <= 0 表示对应方向不限制；只缓存带 Answer 的正向应答。
// OPT 记录同样跳过。
func clampResponseTTL(msg *dns.Msg, minTTL, maxTTL time.Duration) time.Duration {
	if msg == nil || len(msg.Answer) == 0 {
		return 0
	}
	var minSec, maxSec uint32
	if minTTL > 0 {
		minSec = uint32(minTTL.Seconds())
	}
	if maxTTL > 0 {
		maxSec = uint32(maxTTL.Seconds())
	}
	for _, rrs := range [][]dns.RR{msg.Answer, msg.Ns, msg.Extra} {
		for _, rr := range rrs {
			h := rr.Header()
			if h == nil || h.Rrtype == dns.TypeOPT {
				continue
			}
			if minSec > 0 && h.Ttl < minSec {
				h.Ttl = minSec
			}
			if maxSec > 0 && h.Ttl > maxSec {
				h.Ttl = maxSec
			}
		}
	}
	var answerMin uint32
	for i, ans := range msg.Answer {
		if ttl := ans.Header().Ttl; i == 0 || ttl < answerMin {
			answerMin = ttl
		}
	}
	return time.Duration(answerMin) * time.Second
}
