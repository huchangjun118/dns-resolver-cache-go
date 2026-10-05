// Package cache 提供带 TTL、容量上限与 LRU 淘汰的解析结果缓存。
package cache

import (
	"container/list"
	"sync"
	"time"
)

// Kind 缓存条目类别，正缓存与两类负缓存可区分
type Kind int

const (
	KindPositive   Kind = iota // 正常解析结果
	KindNXDomain               // 域名不存在（NXDOMAIN）
	KindServerFail             // 上游临时失败（SERVFAIL 等）
)

// Answer 缓存中的一条解析结果
type Answer struct {
	Type uint16
	Data string
}

// Entry 缓存条目
type Entry struct {
	Kind      Kind
	Answers   []Answer
	ExpiresAt time.Time
}

// Expired 判断条目是否已过期
func (e *Entry) Expired(now time.Time) bool { return !now.Before(e.ExpiresAt) }

type item struct {
	key   string
	entry Entry
}

// Cache 并发安全的 TTL 缓存，LRU 淘汰，后台协程定期清理过期条目。
// 清理在独立协程中进行，只持有短暂锁，不阻塞正在进行的解析。
type Cache struct {
	mu       sync.Mutex
	ll       *list.List // 前端为最近使用
	items    map[string]*list.Element
	capacity int
	now      func() time.Time
	stop     chan struct{}
	done     chan struct{}
	onEvict  func() // 容量淘汰回调（用于指标）
}

// New 创建缓存；capacity<=0 时按 1024 处理，保证内存有界。
func New(capacity int) *Cache {
	if capacity <= 0 {
		capacity = 1024
	}
	c := &Cache{
		ll:       list.New(),
		items:    make(map[string]*list.Element),
		capacity: capacity,
		now:      time.Now,
		stop:     make(chan struct{}),
		done:     make(chan struct{}),
	}
	go c.janitor()
	return c
}

// SetOnEvict 设置容量淘汰回调（每次淘汰调用一次）
func (c *Cache) SetOnEvict(f func()) {
	c.mu.Lock()
	c.onEvict = f
	c.mu.Unlock()
}

// Get 查询缓存；过期条目会被删除并返回未命中。
// 命中会把条目移到 LRU 前端。
func (c *Cache) Get(key string) (*Entry, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	el, ok := c.items[key]
	if !ok {
		return nil, false
	}
	it := el.Value.(*item)
	if it.entry.Expired(c.now()) {
		c.remove(el)
		return nil, false
	}
	c.ll.MoveToFront(el)
	e := it.entry
	return &e, true
}

// Set 写入缓存，ttl 为条目生存时间；ttl<=0 时不写入。
func (c *Cache) Set(key string, e Entry, ttl time.Duration) {
	if ttl <= 0 {
		return
	}
	e.ExpiresAt = c.now().Add(ttl)
	c.mu.Lock()
	defer c.mu.Unlock()
	if el, ok := c.items[key]; ok {
		el.Value.(*item).entry = e
		c.ll.MoveToFront(el)
		return
	}
	for c.ll.Len() >= c.capacity {
		c.evictBack()
	}
	el := c.ll.PushFront(&item{key: key, entry: e})
	c.items[key] = el
}

func (c *Cache) remove(el *list.Element) {
	c.ll.Remove(el)
	delete(c.items, el.Value.(*item).key)
}

func (c *Cache) evictBack() {
	back := c.ll.Back()
	if back == nil {
		return
	}
	c.remove(back)
	if c.onEvict != nil {
		c.onEvict()
	}
}

// Len 当前条目数（含未清理的过期条目）
func (c *Cache) Len() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.ll.Len()
}

// janitor 定期清理过期条目；每次只短暂持锁，不阻塞读写。
func (c *Cache) janitor() {
	t := time.NewTicker(time.Second)
	defer t.Stop()
	defer close(c.done)
	for {
		select {
		case <-c.stop:
			return
		case <-t.C:
			c.sweep()
		}
	}
}

func (c *Cache) sweep() {
	now := c.now()
	c.mu.Lock()
	defer c.mu.Unlock()
	for el := c.ll.Back(); el != nil; {
		prev := el.Prev()
		if el.Value.(*item).entry.Expired(now) {
			c.remove(el)
		}
		el = prev
	}
}

// Close 停止后台清理协程
func (c *Cache) Close() {
	select {
	case <-c.done:
	default:
		close(c.stop)
		<-c.done
	}
}
