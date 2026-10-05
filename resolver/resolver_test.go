package resolver

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/huchangjun118/dns-resolver-cache-go/dnsmsg"
	"github.com/huchangjun118/dns-resolver-cache-go/internal/dnstest"
	"github.com/huchangjun118/dns-resolver-cache-go/upstream"
)

func aHandler(ip string, ttl uint32) dnstest.Handler {
	return func(q *dnsmsg.Message) *dnsmsg.Message {
		return &dnsmsg.Message{
			ID: q.ID, Response: true, Question: q.Question,
			Answers: []dnsmsg.Record{
				{Name: q.Question.Name, Type: q.Question.Type, Class: dnsmsg.ClassIN, TTL: ttl, Data: ip},
			},
		}
	}
}

func testConfig(addr string, timeout time.Duration) Config {
	return Config{
		Upstreams:     []upstream.Server{{Addr: addr, Timeout: timeout}},
		CacheCapacity: 128,
		MinTTL:        time.Second,
		MaxTTL:        time.Hour,
		NXDomainTTL:   50 * time.Millisecond,
		FailureTTL:    30 * time.Millisecond,
	}
}

func TestPositiveCacheHit(t *testing.T) {
	s := dnstest.Start(t, aHandler("192.0.2.1", 300))
	r := New(testConfig(s.Addr(), time.Second))
	defer r.Close()
	ctx := context.Background()
	res, err := r.Lookup(ctx, "www.example.com", dnsmsg.TypeA)
	if err != nil || len(res.Answers) != 1 {
		t.Fatalf("lookup: %v %+v", err, res)
	}
	res2, err := r.Lookup(ctx, "www.example.com", dnsmsg.TypeA)
	if err != nil || res2.Answers[0].Data != "192.0.2.1" {
		t.Fatalf("cached lookup: %v %+v", err, res2)
	}
	if s.Queries() != 1 {
		t.Fatalf("upstream queries=%d, want 1 (second lookup from cache)", s.Queries())
	}
	m := r.Metrics()
	if m.Hits != 1 || m.Misses != 1 || m.UpstreamQueries != 1 {
		t.Fatalf("metrics: %+v", m)
	}
}

func TestCacheExpiryTriggersReResolve(t *testing.T) {
	s := dnstest.Start(t, aHandler("192.0.2.1", 1)) // TTL=1s，MinTTL 不压低
	cfg := testConfig(s.Addr(), time.Second)
	cfg.MinTTL = time.Second
	r := New(cfg)
	defer r.Close()
	ctx := context.Background()
	if _, err := r.Lookup(ctx, "a.example", dnsmsg.TypeA); err != nil {
		t.Fatal(err)
	}
	if _, err := r.Lookup(ctx, "a.example", dnsmsg.TypeA); err != nil {
		t.Fatal(err)
	}
	if s.Queries() != 1 {
		t.Fatalf("queries=%d, want 1", s.Queries())
	}
	time.Sleep(1100 * time.Millisecond) // 等条目过期
	if _, err := r.Lookup(ctx, "a.example", dnsmsg.TypeA); err != nil {
		t.Fatal(err)
	}
	if s.Queries() != 2 {
		t.Fatalf("queries=%d, want 2 after expiry", s.Queries())
	}
}

func TestNegativeCacheNXDomain(t *testing.T) {
	s := dnstest.Start(t, func(q *dnsmsg.Message) *dnsmsg.Message {
		return &dnsmsg.Message{ID: q.ID, Response: true, Rcode: dnsmsg.RcodeNameError, Question: q.Question}
	})
	r := New(testConfig(s.Addr(), time.Second))
	defer r.Close()
	ctx := context.Background()
	res, err := r.Lookup(ctx, "no-such.example", dnsmsg.TypeA)
	if err != nil || !res.Negative || !res.NXDomain {
		t.Fatalf("want NXDOMAIN negative, got %v %+v", err, res)
	}
	res, err = r.Lookup(ctx, "no-such.example", dnsmsg.TypeA)
	if err != nil || !res.NXDomain {
		t.Fatalf("cached negative: %v %+v", err, res)
	}
	if s.Queries() != 1 {
		t.Fatalf("queries=%d, want 1 (negative cache hit must not hit upstream)", s.Queries())
	}
	if r.Metrics().NegativeHits != 1 {
		t.Fatalf("metrics: %+v", r.Metrics())
	}
	// 负缓存过期后重新解析
	time.Sleep(60 * time.Millisecond)
	r.Lookup(ctx, "no-such.example", dnsmsg.TypeA)
	if s.Queries() != 2 {
		t.Fatalf("queries=%d, want 2 after negative TTL expiry", s.Queries())
	}
}

func TestNegativeCacheUpstreamFailure(t *testing.T) {
	s := dnstest.Start(t, func(q *dnsmsg.Message) *dnsmsg.Message {
		return &dnsmsg.Message{ID: q.ID, Response: true, Rcode: dnsmsg.RcodeServerFailure, Question: q.Question}
	})
	r := New(testConfig(s.Addr(), time.Second))
	defer r.Close()
	ctx := context.Background()
	_, err := r.Lookup(ctx, "flaky.example", dnsmsg.TypeA)
	if !errors.Is(err, ErrUpstreamFailed) {
		t.Fatalf("want ErrUpstreamFailed, got %v", err)
	}
	_, err = r.Lookup(ctx, "flaky.example", dnsmsg.TypeA)
	if !errors.Is(err, ErrUpstreamFailed) {
		t.Fatalf("cached failure: %v", err)
	}
	if s.Queries() != 1 {
		t.Fatalf("queries=%d, want 1 (failure negative-cached)", s.Queries())
	}
	// 两类负缓存 TTL 不同：FailureTTL(30ms) 先于 NXDomainTTL(50ms) 过期
	time.Sleep(40 * time.Millisecond)
	r.Lookup(ctx, "flaky.example", dnsmsg.TypeA)
	if s.Queries() != 2 {
		t.Fatalf("queries=%d, want 2 after failure TTL expiry", s.Queries())
	}
}

func TestFailover(t *testing.T) {
	dead := dnstest.Start(t, func(q *dnsmsg.Message) *dnsmsg.Message { return nil })
	alive := dnstest.Start(t, aHandler("192.0.2.7", 60))
	cfg := testConfig(alive.Addr(), time.Second)
	cfg.Upstreams = []upstream.Server{
		{Addr: dead.Addr(), Timeout: 50 * time.Millisecond},
		{Addr: alive.Addr(), Timeout: time.Second},
	}
	r := New(cfg)
	defer r.Close()
	res, err := r.Lookup(context.Background(), "www.example.com", dnsmsg.TypeA)
	if err != nil || res.Answers[0].Data != "192.0.2.7" {
		t.Fatalf("failover lookup: %v %+v", err, res)
	}
	m := r.Metrics()
	if m.Failovers != 1 || m.UpstreamFails != 1 {
		t.Fatalf("metrics: %+v", m)
	}
}

func TestConcurrentCoalescing(t *testing.T) {
	release := make(chan struct{})
	s := dnstest.Start(t, func(q *dnsmsg.Message) *dnsmsg.Message {
		<-release // 阻塞首个查询，让并发请求堆积
		return &dnsmsg.Message{
			ID: q.ID, Response: true, Question: q.Question,
			Answers: []dnsmsg.Record{{Name: q.Question.Name, Type: q.Question.Type, Class: dnsmsg.ClassIN, TTL: 300, Data: "192.0.2.3"}},
		}
	})
	r := New(testConfig(s.Addr(), 5*time.Second))
	defer r.Close()
	const n = 32
	var wg sync.WaitGroup
	errs := make([]error, n)
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			_, errs[i] = r.Lookup(context.Background(), "hot.example", dnsmsg.TypeA)
		}(i)
	}
	time.Sleep(50 * time.Millisecond) // 确保所有请求到达
	close(release)
	wg.Wait()
	for i, err := range errs {
		if err != nil {
			t.Fatalf("goroutine %d: %v", i, err)
		}
	}
	if q := s.Queries(); q != 1 {
		t.Fatalf("upstream queries=%d, want 1 (coalesced)", q)
	}
	if uq := r.Metrics().UpstreamQueries; uq != 1 {
		t.Fatalf("UpstreamQueries=%d, want 1", uq)
	}
}

func TestCallerCancelDoesNotAffectOthers(t *testing.T) {
	release := make(chan struct{})
	s := dnstest.Start(t, func(q *dnsmsg.Message) *dnsmsg.Message {
		<-release
		return &dnsmsg.Message{
			ID: q.ID, Response: true, Question: q.Question,
			Answers: []dnsmsg.Record{{Name: q.Question.Name, Type: q.Question.Type, Class: dnsmsg.ClassIN, TTL: 300, Data: "192.0.2.4"}},
		}
	})
	r := New(testConfig(s.Addr(), 5*time.Second))
	defer r.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Millisecond)
	defer cancel()
	cancelled := make(chan error, 1)
	go func() {
		_, err := r.Lookup(ctx, "slow.example", dnsmsg.TypeA)
		cancelled <- err
	}()
	time.Sleep(10 * time.Millisecond)
	if err := <-cancelled; !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("want ctx deadline, got %v", err)
	}
	close(release)
	// 在途解析不受取消影响，结果应已写入缓存
	res, err := r.Lookup(context.Background(), "slow.example", dnsmsg.TypeA)
	if err != nil || len(res.Answers) != 1 {
		t.Fatalf("result must survive caller cancellation: %v %+v", err, res)
	}
	if q := s.Queries(); q != 1 {
		t.Fatalf("queries=%d, want 1", q)
	}
}

func TestCapacityEvictionBounded(t *testing.T) {
	s := dnstest.Start(t, aHandler("192.0.2.1", 300))
	cfg := testConfig(s.Addr(), time.Second)
	cfg.CacheCapacity = 16
	r := New(cfg)
	defer r.Close()
	ctx := context.Background()
	for i := 0; i < 500; i++ {
		name := "host" + string(rune('a'+i%26)) + string(rune('a'+i/26)) + ".example"
		r.Lookup(ctx, name, dnsmsg.TypeA)
	}
	if ev := r.Metrics().Evictions; ev == 0 {
		t.Fatal("expected evictions under capacity pressure")
	}
}

func TestTruncatedResponseNotCached(t *testing.T) {
	// 上游返回 TC 置位报文且 TCP 也不可用 → 视为失败，不写入正缓存
	s := dnstest.Start(t, func(q *dnsmsg.Message) *dnsmsg.Message {
		return &dnsmsg.Message{ID: q.ID, Response: true, Truncated: true, Question: q.Question}
	})
	r := New(testConfig(s.Addr(), 100*time.Millisecond))
	defer r.Close()
	_, err := r.Lookup(context.Background(), "big.example", dnsmsg.TypeA)
	if !errors.Is(err, ErrUpstreamFailed) {
		t.Fatalf("want ErrUpstreamFailed for truncated-only upstream, got %v", err)
	}
	if r.Metrics().Hits != 0 {
		t.Fatal("truncated response must not produce cache hits")
	}
}
