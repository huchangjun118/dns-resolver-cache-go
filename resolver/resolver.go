// Package resolver 组合缓存、负缓存、并发合并与上游故障切换，
// 对外提供域名解析能力。
package resolver

import (
	"context"
	"errors"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/huchangjun118/dns-resolver-cache-go/cache"
	"github.com/huchangjun118/dns-resolver-cache-go/dnsmsg"
	"github.com/huchangjun118/dns-resolver-cache-go/upstream"
)

// ErrUpstreamFailed 表示所有上游临时失败（结果会被负缓存）
var ErrUpstreamFailed = errors.New("resolver: upstream temporarily failed")

// Config 解析器配置
type Config struct {
	Upstreams     []upstream.Server
	CacheCapacity int
	MinTTL        time.Duration // 正缓存 TTL 下限
	MaxTTL        time.Duration // 正缓存 TTL 上限
	NXDomainTTL   time.Duration // 域名不存在负缓存 TTL
	FailureTTL    time.Duration // 上游临时失败负缓存 TTL
}

func (c *Config) withDefaults() {
	if c.CacheCapacity <= 0 {
		c.CacheCapacity = 1024
	}
	if c.MinTTL <= 0 {
		c.MinTTL = 5 * time.Second
	}
	if c.MaxTTL <= 0 {
		c.MaxTTL = 30 * time.Minute
	}
	if c.NXDomainTTL <= 0 {
		c.NXDomainTTL = 60 * time.Second
	}
	if c.FailureTTL <= 0 {
		c.FailureTTL = 5 * time.Second
	}
}

// Metrics 运行计数
type Metrics struct {
	Hits            int64 // 正缓存命中
	NegativeHits    int64 // 负缓存命中（NXDOMAIN + 失败）
	Misses          int64 // 缓存未命中
	UpstreamQueries int64 // 实际发起的上游解析次数（合并后）
	UpstreamFails   int64 // 单个上游失败次数
	Failovers       int64 // 发生上游切换的次数
	Evictions       int64 // 容量淘汰次数
}

// Result 解析结果
type Result struct {
	Answers  []cache.Answer
	Negative bool // 是否为负结果
	NXDomain bool // 负结果时区分：true=域名不存在，false=上游临时失败
}

// call 一次进行中的上游解析（并发合并单元）
type call struct {
	done chan struct{}
	res  *Result
	err  error
}

// Resolver 缓存解析器
type Resolver struct {
	cfg     Config
	cache   *cache.Cache
	pool    *upstream.Pool
	metrics Metrics

	mu       sync.Mutex
	inflight map[string]*call
}

// New 创建解析器
func New(cfg Config) *Resolver {
	cfg.withDefaults()
	r := &Resolver{
		cfg:      cfg,
		cache:    cache.New(cfg.CacheCapacity),
		pool:     upstream.NewPool(cfg.Upstreams),
		inflight: make(map[string]*call),
	}
	r.pool.SetHooks(upstream.Hooks{
		OnFail:     func(addr string, err error) { atomic.AddInt64(&r.metrics.UpstreamFails, 1) },
		OnFailover: func(from, to string) { atomic.AddInt64(&r.metrics.Failovers, 1) },
	})
	r.cache.SetOnEvict(func() { atomic.AddInt64(&r.metrics.Evictions, 1) })
	return r
}

func cacheKey(name string, qtype uint16) string {
	name = strings.ToLower(strings.TrimSuffix(name, "."))
	return name + "|" + strconv.Itoa(int(qtype))
}

// Lookup 解析 name 的 qtype 记录。
// 返回 ErrUpstreamFailed 时结果已被负缓存，短期内重复查询不会再访问上游。
func (r *Resolver) Lookup(ctx context.Context, name string, qtype uint16) (*Result, error) {
	key := cacheKey(name, qtype)
	if e, ok := r.cache.Get(key); ok {
		switch e.Kind {
		case cache.KindPositive:
			atomic.AddInt64(&r.metrics.Hits, 1)
			return &Result{Answers: e.Answers}, nil
		case cache.KindNXDomain:
			atomic.AddInt64(&r.metrics.NegativeHits, 1)
			return &Result{Negative: true, NXDomain: true}, nil
		default: // KindServerFail
			atomic.AddInt64(&r.metrics.NegativeHits, 1)
			return nil, ErrUpstreamFailed
		}
	}
	atomic.AddInt64(&r.metrics.Misses, 1)

	// 并发合并：同名同类型的在途查询只触发一次上游解析
	r.mu.Lock()
	if c, ok := r.inflight[key]; ok {
		r.mu.Unlock()
		select {
		case <-c.done:
			return c.res, c.err
		case <-ctx.Done():
			// 单个等待者取消不影响其余等待者与在途解析
			return nil, ctx.Err()
		}
	}
	c := &call{done: make(chan struct{})}
	r.inflight[key] = c
	r.mu.Unlock()

	// 解析在独立协程与独立上下文中执行：
	// 任何调用方（包括发起者）取消/超时都不中断在途解析
	go func() {
		res, err := r.resolve(context.Background(), key, name, qtype)
		c.res, c.err = res, err
		close(c.done)
		r.mu.Lock()
		delete(r.inflight, key)
		r.mu.Unlock()
	}()

	select {
	case <-c.done:
		return c.res, c.err
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

// resolve 实际访问上游并按结果写入正/负缓存
func (r *Resolver) resolve(ctx context.Context, key, name string, qtype uint16) (*Result, error) {
	atomic.AddInt64(&r.metrics.UpstreamQueries, 1)
	resp, err := r.pool.Exchange(ctx, strings.TrimSuffix(name, "."), qtype)
	if err != nil {
		// 上游临时失败：负缓存 FailureTTL
		r.cache.Set(key, cache.Entry{Kind: cache.KindServerFail}, r.cfg.FailureTTL)
		return nil, ErrUpstreamFailed
	}
	switch resp.Rcode {
	case dnsmsg.RcodeNameError:
		r.cache.Set(key, cache.Entry{Kind: cache.KindNXDomain}, r.cfg.NXDomainTTL)
		return &Result{Negative: true, NXDomain: true}, nil
	case dnsmsg.RcodeServerFailure, dnsmsg.RcodeRefused, dnsmsg.RcodeNotImplemented, dnsmsg.RcodeFormatError:
		r.cache.Set(key, cache.Entry{Kind: cache.KindServerFail}, r.cfg.FailureTTL)
		return nil, ErrUpstreamFailed
	}
	if resp.Rcode != dnsmsg.RcodeSuccess {
		r.cache.Set(key, cache.Entry{Kind: cache.KindServerFail}, r.cfg.FailureTTL)
		return nil, ErrUpstreamFailed
	}
	if len(resp.Answers) == 0 {
		// NODATA：域名存在但无此类型记录，按 NXDOMAIN 类负缓存处理
		r.cache.Set(key, cache.Entry{Kind: cache.KindNXDomain}, r.cfg.NXDomainTTL)
		return &Result{Negative: true, NXDomain: true}, nil
	}
	answers := make([]cache.Answer, 0, len(resp.Answers))
	minTTL := uint32(0)
	for i, a := range resp.Answers {
		answers = append(answers, cache.Answer{Type: a.Type, Data: a.Data})
		if i == 0 || a.TTL < minTTL {
			minTTL = a.TTL
		}
	}
	ttl := time.Duration(minTTL) * time.Second
	if ttl < r.cfg.MinTTL {
		ttl = r.cfg.MinTTL
	}
	if ttl > r.cfg.MaxTTL {
		ttl = r.cfg.MaxTTL
	}
	r.cache.Set(key, cache.Entry{Kind: cache.KindPositive, Answers: answers}, ttl)
	return &Result{Answers: answers}, nil
}

// Metrics 返回当前计数快照
func (r *Resolver) Metrics() Metrics {
	return Metrics{
		Hits:            atomic.LoadInt64(&r.metrics.Hits),
		NegativeHits:    atomic.LoadInt64(&r.metrics.NegativeHits),
		Misses:          atomic.LoadInt64(&r.metrics.Misses),
		UpstreamQueries: atomic.LoadInt64(&r.metrics.UpstreamQueries),
		UpstreamFails:   atomic.LoadInt64(&r.metrics.UpstreamFails),
		Failovers:       atomic.LoadInt64(&r.metrics.Failovers),
		Evictions:       atomic.LoadInt64(&r.metrics.Evictions),
	}
}

// Close 释放资源
func (r *Resolver) Close() { r.cache.Close() }
