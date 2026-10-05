package dnsres

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"
)

func testConfig(clock *fakeClock, addrs ...string) Config {
	return Config{
		Upstreams:       addrs,
		UpstreamTimeout: 500 * time.Millisecond,
		CacheCapacity:   100,
		NegTTLNXDomain:  5 * time.Minute,
		NegTTLServFail:  30 * time.Second,
		MinTTL:          time.Second,
		Now:             clock.Now,
	}
}

func aHandler(ip string, ttl uint32) func(q *Message, raw []byte) []byte {
	return func(q *Message, raw []byte) []byte {
		return buildResponse(q.ID, q.Questions[0].Name, q.Questions[0].Type, RCodeSuccess, ttl, ip)
	}
}

func TestResolverCachesUntilTTL(t *testing.T) {
	clock := newFakeClock()
	srv := newFakeServer(t, aHandler("1.2.3.4", 60))
	r := NewResolver(testConfig(clock, srv.addr))
	defer r.Close()
	ctx := context.Background()

	m1, err := r.Lookup(ctx, "www.example.com", TypeA)
	if err != nil {
		t.Fatalf("lookup: %v", err)
	}
	m2, err := r.Lookup(ctx, "www.example.com", TypeA)
	if err != nil {
		t.Fatalf("lookup: %v", err)
	}
	if srv.queryCount() != 1 {
		t.Fatalf("expected 1 upstream query, got %d", srv.queryCount())
	}
	if m1.Answers[0].Data != "1.2.3.4" || m2.Answers[0].Data != "1.2.3.4" {
		t.Fatalf("bad answers: %+v %+v", m1.Answers, m2.Answers)
	}
	if s := r.Metrics().Snapshot(); s.Hits != 1 || s.Misses != 1 {
		t.Fatalf("bad metrics: %+v", s)
	}

	// TTL 到期后必须重新解析。
	clock.Advance(61 * time.Second)
	if _, err := r.Lookup(ctx, "www.example.com", TypeA); err != nil {
		t.Fatalf("lookup after expiry: %v", err)
	}
	if srv.queryCount() != 2 {
		t.Fatalf("expired entry must trigger re-resolution, queries=%d", srv.queryCount())
	}
}

func TestResolverNegativeCaching(t *testing.T) {
	clock := newFakeClock()
	srv := newFakeServer(t, func(q *Message, raw []byte) []byte {
		name := q.Questions[0].Name
		switch name {
		case "absent.example.com":
			return buildResponse(q.ID, name, q.Questions[0].Type, RCodeNameErr, 0)
		default:
			return buildResponse(q.ID, name, q.Questions[0].Type, RCodeServFail, 0)
		}
	})
	r := NewResolver(testConfig(clock, srv.addr))
	defer r.Close()
	ctx := context.Background()

	// NXDOMAIN：按 NegTTLNXDomain 缓存。
	if _, err := r.Lookup(ctx, "absent.example.com", TypeA); !errors.Is(err, ErrNXDomain) {
		t.Fatalf("expected ErrNXDomain, got %v", err)
	}
	if _, err := r.Lookup(ctx, "absent.example.com", TypeA); !errors.Is(err, ErrNXDomain) {
		t.Fatalf("expected ErrNXDomain from negative cache, got %v", err)
	}
	if srv.queryCount() != 1 {
		t.Fatalf("negative cache hit must not touch upstream, queries=%d", srv.queryCount())
	}

	// SERVFAIL：按 NegTTLServFail 缓存，与 NXDOMAIN 可区分。
	if _, err := r.Lookup(ctx, "broken.example.com", TypeA); !errors.Is(err, ErrServFail) {
		t.Fatalf("expected ErrServFail, got %v", err)
	}
	if _, err := r.Lookup(ctx, "broken.example.com", TypeA); !errors.Is(err, ErrServFail) {
		t.Fatalf("expected ErrServFail from negative cache, got %v", err)
	}
	if srv.queryCount() != 2 {
		t.Fatalf("negative cache hit must not touch upstream, queries=%d", srv.queryCount())
	}

	// SERVFAIL 负缓存 30s 后过期，NXDOMAIN 负缓存仍有效：二者 TTL 独立。
	clock.Advance(31 * time.Second)
	if _, err := r.Lookup(ctx, "broken.example.com", TypeA); !errors.Is(err, ErrServFail) {
		t.Fatalf("expected re-resolved ErrServFail, got %v", err)
	}
	if srv.queryCount() != 3 {
		t.Fatalf("SERVFAIL negative entry should have expired, queries=%d", srv.queryCount())
	}
	if _, err := r.Lookup(ctx, "absent.example.com", TypeA); !errors.Is(err, ErrNXDomain) {
		t.Fatalf("NXDOMAIN negative entry should still be cached, got %v", err)
	}
	if srv.queryCount() != 3 {
		t.Fatalf("NXDOMAIN negative entry expired too early, queries=%d", srv.queryCount())
	}

	if s := r.Metrics().Snapshot(); s.NegHits != 3 {
		t.Fatalf("expected 3 negative hits, got %+v", s)
	}
}

func TestResolverFailover(t *testing.T) {
	clock := newFakeClock()
	dead := newFakeServer(t, func(q *Message, raw []byte) []byte { return nil }) // 全部丢弃
	alive := newFakeServer(t, aHandler("9.9.9.9", 60))
	r := NewResolver(testConfig(clock, dead.addr, alive.addr))
	defer r.Close()

	m, err := r.Lookup(context.Background(), "failover.example.com", TypeA)
	if err != nil {
		t.Fatalf("lookup: %v", err)
	}
	if m.Answers[0].Data != "9.9.9.9" {
		t.Fatalf("expected answer from second upstream, got %+v", m.Answers[0])
	}
	if dead.queryCount() != 1 || alive.queryCount() != 1 {
		t.Fatalf("expected 1 query per upstream, got dead=%d alive=%d", dead.queryCount(), alive.queryCount())
	}
	s := r.Metrics().Snapshot()
	if s.UpstreamSwitches != 1 || s.UpstreamFailures != 1 {
		t.Fatalf("bad failover metrics: %+v", s)
	}
}

func TestResolverCoalescing(t *testing.T) {
	clock := newFakeClock()
	release := make(chan struct{})
	srv := newFakeServer(t, func(q *Message, raw []byte) []byte {
		<-release // 阻塞直到测试放行，保证并发请求重叠
		return buildResponse(q.ID, q.Questions[0].Name, q.Questions[0].Type, RCodeSuccess, 60, "3.3.3.3")
	})
	r := NewResolver(testConfig(clock, srv.addr))
	defer r.Close()

	const n = 20
	var wg sync.WaitGroup
	errs := make([]error, n)
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			_, errs[i] = r.Lookup(context.Background(), "hot.example.com", TypeA)
		}(i)
	}
	// 等待所有请求进入等待状态后放行。
	time.Sleep(100 * time.Millisecond)
	close(release)
	wg.Wait()

	for i, err := range errs {
		if err != nil {
			t.Fatalf("goroutine %d: %v", i, err)
		}
	}
	if srv.queryCount() != 1 {
		t.Fatalf("concurrent queries must coalesce into 1 upstream query, got %d", srv.queryCount())
	}
	if s := r.Metrics().Snapshot(); s.Coalesced != n-1 {
		t.Fatalf("expected %d coalesced, got %+v", n-1, s)
	}
}

func TestResolverCancelDoesNotAffectOthers(t *testing.T) {
	clock := newFakeClock()
	release := make(chan struct{})
	srv := newFakeServer(t, func(q *Message, raw []byte) []byte {
		<-release
		return buildResponse(q.ID, q.Questions[0].Name, q.Questions[0].Type, RCodeSuccess, 60, "4.4.4.4")
	})
	r := NewResolver(testConfig(clock, srv.addr))
	defer r.Close()

	leaderDone := make(chan error, 1)
	go func() {
		_, err := r.Lookup(context.Background(), "cancel.example.com", TypeA)
		leaderDone <- err
	}()
	time.Sleep(20 * time.Millisecond) // 确保 leader 已发起解析

	ctx, cancel := context.WithCancel(context.Background())
	waiterDone := make(chan error, 1)
	go func() {
		_, err := r.Lookup(ctx, "cancel.example.com", TypeA)
		waiterDone <- err
	}()
	time.Sleep(20 * time.Millisecond) // 确保 waiter 已进入等待
	cancel()
	if err := <-waiterDone; !errors.Is(err, context.Canceled) {
		t.Fatalf("waiter should observe cancellation, got %v", err)
	}

	close(release)
	if err := <-leaderDone; err != nil {
		t.Fatalf("leader must not be affected by waiter cancel: %v", err)
	}
	if srv.queryCount() != 1 {
		t.Fatalf("expected 1 upstream query, got %d", srv.queryCount())
	}
}

func TestResolverCapacityEviction(t *testing.T) {
	clock := newFakeClock()
	srv := newFakeServer(t, aHandler("5.5.5.5", 300))
	cfg := testConfig(clock, srv.addr)
	cfg.CacheCapacity = 2
	r := NewResolver(cfg)
	defer r.Close()
	ctx := context.Background()

	for i := 0; i < 5; i++ {
		if _, err := r.Lookup(ctx, fmt.Sprintf("host%d.example.com", i), TypeA); err != nil {
			t.Fatalf("lookup %d: %v", i, err)
		}
	}
	if r.cache.Len() != 2 {
		t.Fatalf("cache must be bounded at capacity 2, got %d", r.cache.Len())
	}
	if s := r.Metrics().Snapshot(); s.Evictions != 3 {
		t.Fatalf("expected 3 evictions, got %+v", s)
	}
}

func TestResolverRejectsTruncatedResponse(t *testing.T) {
	clock := newFakeClock()
	srv := newFakeServer(t, func(q *Message, raw []byte) []byte {
		return truncateResponse(q.ID, q.Questions[0].Name, q.Questions[0].Type)
	})
	r := NewResolver(testConfig(clock, srv.addr))
	defer r.Close()
	ctx := context.Background()

	if _, err := r.Lookup(ctx, "truncated.example.com", TypeA); err == nil {
		t.Fatal("truncated response must not be returned as valid result")
	}
	// 截断应答不得写入缓存：再次查询必须重新访问上游。
	if _, err := r.Lookup(ctx, "truncated.example.com", TypeA); err == nil {
		t.Fatal("truncated response must not be returned as valid result")
	}
	if srv.queryCount() != 2 {
		t.Fatalf("truncated response must not be cached, queries=%d", srv.queryCount())
	}
	if s := r.Metrics().Snapshot(); s.UpstreamFailures != 2 {
		t.Fatalf("expected 2 upstream failures, got %+v", s)
	}
}

func TestResolverBackgroundCleanup(t *testing.T) {
	srv := newFakeServer(t, aHandler("6.6.6.6", 0)) // TTL=0，立即到期
	cfg := Config{
		Upstreams:       []string{srv.addr},
		UpstreamTimeout: 200 * time.Millisecond,
		CacheCapacity:   100,
		MinTTL:          time.Millisecond, // 正向 TTL 下限压到 1ms
		CleanupInterval: 5 * time.Millisecond,
	}
	r := NewResolver(cfg)
	defer r.Close()

	if _, err := r.Lookup(context.Background(), "cleanup.example.com", TypeA); err != nil {
		t.Fatalf("lookup: %v", err)
	}
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if r.Metrics().Snapshot().Expirations > 0 && r.cache.Len() == 0 {
			return // 后台清理生效
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("background cleanup did not purge expired entry, metrics=%+v len=%d",
		r.Metrics().Snapshot(), r.cache.Len())
}
