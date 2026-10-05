package dnsres

import (
	"fmt"
	"sync"
	"testing"
	"time"
)

// fakeClock 是可手动推进的时钟，保证测试可复现。
type fakeClock struct {
	mu  sync.Mutex
	now time.Time
}

func newFakeClock() *fakeClock {
	return &fakeClock{now: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)}
}

func (c *fakeClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

func (c *fakeClock) Advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.now = c.now.Add(d)
}

func TestCacheExpiry(t *testing.T) {
	clock := newFakeClock()
	c := NewCache(0, clock.Now)
	c.Set("a", &cacheEntry{msg: &Message{ID: 1}, expiresAt: clock.Now().Add(10 * time.Second)})

	if _, ok := c.Get("a"); !ok {
		t.Fatal("expected hit before expiry")
	}
	clock.Advance(11 * time.Second)
	if _, ok := c.Get("a"); ok {
		t.Fatal("expired entry must not be returned")
	}
	if c.Len() != 0 {
		t.Fatalf("expired entry should be removed on Get, len=%d", c.Len())
	}
}

func TestCacheLRUEviction(t *testing.T) {
	clock := newFakeClock()
	c := NewCache(2, clock.Now)
	ttl := clock.Now().Add(time.Minute)
	c.Set("a", &cacheEntry{expiresAt: ttl})
	c.Set("b", &cacheEntry{expiresAt: ttl})
	// 访问 a，使 b 成为最久未使用。
	if _, ok := c.Get("a"); !ok {
		t.Fatal("expected hit for a")
	}
	evicted := c.Set("c", &cacheEntry{expiresAt: ttl})
	if evicted != 1 {
		t.Fatalf("expected 1 eviction, got %d", evicted)
	}
	if _, ok := c.Get("b"); ok {
		t.Fatal("b should have been evicted (LRU)")
	}
	if _, ok := c.Get("a"); !ok {
		t.Fatal("a should survive eviction")
	}
	if _, ok := c.Get("c"); !ok {
		t.Fatal("c should be present")
	}
}

func TestCachePurgeExpired(t *testing.T) {
	clock := newFakeClock()
	c := NewCache(0, clock.Now)
	for i := 0; i < 10; i++ {
		c.Set(fmt.Sprintf("k%d", i), &cacheEntry{expiresAt: clock.Now().Add(time.Minute)})
	}
	clock.Advance(2 * time.Minute)
	if n := c.PurgeExpired(); n != 10 {
		t.Fatalf("expected 10 purged, got %d", n)
	}
	if c.Len() != 0 {
		t.Fatalf("expected empty cache, len=%d", c.Len())
	}
}

func TestCacheBoundedMemory(t *testing.T) {
	clock := newFakeClock()
	c := NewCache(100, clock.Now)
	ttl := clock.Now().Add(time.Minute)
	totalEvicted := 0
	for i := 0; i < 100000; i++ {
		totalEvicted += c.Set(fmt.Sprintf("k%d", i), &cacheEntry{expiresAt: ttl})
	}
	if c.Len() > 100 {
		t.Fatalf("cache exceeded capacity: %d", c.Len())
	}
	if totalEvicted != 100000-100 {
		t.Fatalf("expected %d evictions, got %d", 100000-100, totalEvicted)
	}
}
