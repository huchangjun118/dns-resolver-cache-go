package cache

import (
	"fmt"
	"sync"
	"testing"
	"time"
)

func TestSetGet(t *testing.T) {
	c := New(10)
	defer c.Close()
	c.Set("a", Entry{Kind: KindPositive, Answers: []Answer{{Type: 1, Data: "1.2.3.4"}}}, time.Minute)
	e, ok := c.Get("a")
	if !ok || e.Kind != KindPositive || e.Answers[0].Data != "1.2.3.4" {
		t.Fatalf("want hit, got %+v ok=%v", e, ok)
	}
	if _, ok := c.Get("missing"); ok {
		t.Fatal("want miss")
	}
}

func TestExpiry(t *testing.T) {
	c := New(10)
	defer c.Close()
	now := time.Now()
	c.now = func() time.Time { return now }
	c.Set("a", Entry{Kind: KindPositive}, 100*time.Millisecond)
	if _, ok := c.Get("a"); !ok {
		t.Fatal("want hit before expiry")
	}
	now = now.Add(200 * time.Millisecond)
	if _, ok := c.Get("a"); ok {
		t.Fatal("expired entry must not be returned")
	}
	if c.Len() != 0 {
		t.Fatal("expired entry must be removed on access")
	}
}

func TestNegativeKindsDistinct(t *testing.T) {
	c := New(10)
	defer c.Close()
	c.Set("nx", Entry{Kind: KindNXDomain}, time.Minute)
	c.Set("sf", Entry{Kind: KindServerFail}, time.Minute)
	e1, _ := c.Get("nx")
	e2, _ := c.Get("sf")
	if e1.Kind != KindNXDomain || e2.Kind != KindServerFail {
		t.Fatalf("kinds not distinguishable: %v %v", e1.Kind, e2.Kind)
	}
}

func TestCapacityEviction(t *testing.T) {
	c := New(3)
	defer c.Close()
	evicted := 0
	c.SetOnEvict(func() { evicted++ })
	for i := 0; i < 10; i++ {
		c.Set(fmt.Sprintf("k%d", i), Entry{Kind: KindPositive}, time.Minute)
	}
	if c.Len() != 3 {
		t.Fatalf("len=%d, want 3 (bounded)", c.Len())
	}
	if evicted != 7 {
		t.Fatalf("evicted=%d, want 7", evicted)
	}
	// 最早写入的应被淘汰，最新的保留
	if _, ok := c.Get("k0"); ok {
		t.Fatal("oldest entry should be evicted")
	}
	if _, ok := c.Get("k9"); !ok {
		t.Fatal("newest entry should remain")
	}
}

func TestLRUOrder(t *testing.T) {
	c := New(2)
	defer c.Close()
	c.Set("a", Entry{Kind: KindPositive}, time.Minute)
	c.Set("b", Entry{Kind: KindPositive}, time.Minute)
	c.Get("a") // a 变为最近使用
	c.Set("c", Entry{Kind: KindPositive}, time.Minute)
	if _, ok := c.Get("b"); ok {
		t.Fatal("b should be evicted (LRU)")
	}
	if _, ok := c.Get("a"); !ok {
		t.Fatal("a should remain")
	}
}

func TestConcurrentAccess(t *testing.T) {
	c := New(64)
	defer c.Close()
	var wg sync.WaitGroup
	for i := 0; i < 32; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			for j := 0; j < 200; j++ {
				k := fmt.Sprintf("k%d", (i+j)%100)
				c.Set(k, Entry{Kind: KindPositive}, time.Minute)
				c.Get(k)
			}
		}(i)
	}
	wg.Wait()
	if c.Len() > 64 {
		t.Fatalf("len=%d exceeds capacity", c.Len())
	}
}

func TestZeroTTLNotCached(t *testing.T) {
	c := New(10)
	defer c.Close()
	c.Set("a", Entry{Kind: KindPositive}, 0)
	if _, ok := c.Get("a"); ok {
		t.Fatal("zero TTL must not be cached")
	}
}
