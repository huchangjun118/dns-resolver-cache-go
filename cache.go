package dnsres

import (
	"container/list"
	"sync"
	"time"
)

// NegKind 区分负缓存条目类型。
type NegKind int

const (
	NegNone     NegKind = iota // 非负缓存
	NegNXDomain                // 域名不存在
	NegServFail                // 上游临时失败
)

func (k NegKind) String() string {
	switch k {
	case NegNXDomain:
		return "NXDOMAIN"
	case NegServFail:
		return "SERVFAIL"
	default:
		return "NONE"
	}
}

// cacheEntry 是缓存条目。
type cacheEntry struct {
	msg       *Message
	neg       NegKind
	expiresAt time.Time
}

// Cache 是有容量上限、按 TTL 过期、LRU 淘汰的解析结果缓存。
// 所有方法持有锁的时间与条目数无关的操作均为 O(1)，
// 不会阻塞正在进行的解析（解析发生在锁外）。
type Cache struct {
	mu       sync.Mutex
	capacity int
	now      func() time.Time
	items    map[string]*list.Element // key -> *list.Element(Value: *cacheItem)
	lru      *list.List               // 队首为最近使用
}

type cacheItem struct {
	key   string
	entry *cacheEntry
}

// NewCache 创建缓存；capacity<=0 表示不限制（仍受 TTL 约束）。
// now 为可注入时钟，传 nil 使用真实时间。
func NewCache(capacity int, now func() time.Time) *Cache {
	if now == nil {
		now = time.Now
	}
	return &Cache{
		capacity: capacity,
		now:      now,
		items:    make(map[string]*list.Element),
		lru:      list.New(),
	}
}

// Get 查询缓存；过期条目视为未命中并被移除。
// 命中时把条目移到 LRU 队首。
func (c *Cache) Get(key string) (*cacheEntry, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	el, ok := c.items[key]
	if !ok {
		return nil, false
	}
	item := el.Value.(*cacheItem)
	if !c.now().Before(item.entry.expiresAt) {
		c.removeElement(el)
		return nil, false
	}
	c.lru.MoveToFront(el)
	return item.entry, true
}

// Set 写入缓存条目，超出容量时按 LRU 淘汰，返回淘汰条数。
func (c *Cache) Set(key string, e *cacheEntry) (evicted int) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if el, ok := c.items[key]; ok {
		el.Value.(*cacheItem).entry = e
		c.lru.MoveToFront(el)
		return 0
	}
	el := c.lru.PushFront(&cacheItem{key: key, entry: e})
	c.items[key] = el
	for c.capacity > 0 && c.lru.Len() > c.capacity {
		back := c.lru.Back()
		if back == nil {
			break
		}
		c.removeElement(back)
		evicted++
	}
	return evicted
}

// Len 返回当前条目数（含尚未清理的过期条目）。
func (c *Cache) Len() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.lru.Len()
}

// PurgeExpired 清理全部过期条目，返回清理数量。
// 调用方应控制调用频率；持锁期间只做内存操作，不与解析互斥等待。
func (c *Cache) PurgeExpired() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	now := c.now()
	removed := 0
	for el := c.lru.Back(); el != nil; {
		prev := el.Prev()
		if !now.Before(el.Value.(*cacheItem).entry.expiresAt) {
			c.removeElement(el)
			removed++
		}
		el = prev
	}
	return removed
}

func (c *Cache) removeElement(el *list.Element) {
	c.lru.Remove(el)
	delete(c.items, el.Value.(*cacheItem).key)
}
