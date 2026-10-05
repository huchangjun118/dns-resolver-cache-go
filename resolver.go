package dnsres

import (
	"context"
	"errors"
	"fmt"
	"sync/atomic"
	"time"
)

// 解析结果错误。负缓存命中时同样返回对应错误，且不会再访问上游。
var (
	ErrNXDomain = errors.New("dnsres: name does not exist (NXDOMAIN)")
	ErrServFail = errors.New("dnsres: upstream temporary failure (SERVFAIL)")
)

// Config 是解析器配置。
type Config struct {
	Upstreams       []string         // 上游地址，按既定顺序切换
	UpstreamTimeout time.Duration    // 单个上游单次尝试超时
	CacheCapacity   int              // 缓存容量上限（条目数），<=0 不限
	NegTTLNXDomain  time.Duration    // NXDOMAIN 负缓存 TTL
	NegTTLServFail  time.Duration    // SERVFAIL / 上游全部失败 负缓存 TTL
	MinTTL          time.Duration    // 正向缓存 TTL 下限
	MaxTTL          time.Duration    // 正向缓存 TTL 上限，<=0 不设上限
	CleanupInterval time.Duration    // 过期清理周期；<=0 关闭后台清理
	Now             func() time.Time // 可注入时钟，便于测试复现
}

// Resolver 提供带缓存、负缓存与上游故障切换的域名解析。
type Resolver struct {
	cfg     Config
	cache   *Cache
	pool    *Pool
	group   *flightGroup
	metrics *Metrics
	idSeq   atomic.Uint32 // 查询 ID 序列：固定起点，保证可复现

	stopCleanup chan struct{}
	cleanupDone chan struct{}
}

// NewResolver 创建解析器并应用默认值。
func NewResolver(cfg Config) *Resolver {
	if cfg.UpstreamTimeout <= 0 {
		cfg.UpstreamTimeout = 2 * time.Second
	}
	if cfg.NegTTLNXDomain <= 0 {
		cfg.NegTTLNXDomain = 5 * time.Minute
	}
	if cfg.NegTTLServFail <= 0 {
		cfg.NegTTLServFail = 30 * time.Second
	}
	if cfg.MinTTL <= 0 {
		cfg.MinTTL = time.Second
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	m := &Metrics{}
	r := &Resolver{
		cfg:     cfg,
		cache:   NewCache(cfg.CacheCapacity, cfg.Now),
		pool:    NewPool(cfg.Upstreams, cfg.UpstreamTimeout, m),
		group:   newFlightGroup(),
		metrics: m,
	}
	r.idSeq.Store(1) // 固定起点，行为可复现
	if cfg.CleanupInterval > 0 {
		r.stopCleanup = make(chan struct{})
		r.cleanupDone = make(chan struct{})
		go r.cleanupLoop()
	}
	return r
}

// Lookup 解析 name 的 qtype 记录。
// 命中负缓存或解析失败时返回非 nil error；被截断或校验不通过的
// 应答不会写入缓存，也不会作为有效结果返回。
func (r *Resolver) Lookup(ctx context.Context, name string, qtype uint16) (*Message, error) {
	name = NormalizeName(name)
	if name == "" {
		return nil, fmt.Errorf("%w: empty name", ErrMalformed)
	}
	key := cacheKey(name, qtype)

	if e, ok := r.cache.Get(key); ok {
		if e.neg != NegNone {
			r.metrics.NegHits.Add(1)
			return e.msg, negErr(e.neg)
		}
		r.metrics.Hits.Add(1)
		return e.msg, nil
	}
	r.metrics.Misses.Add(1)

	msg, err, shared := r.group.Do(ctx, key, func() (*Message, error) {
		return r.resolve(ctx, key, name, qtype)
	})
	if shared {
		r.metrics.Coalesced.Add(1)
	}
	return msg, err
}

// resolve 是缓存未命中后的实际解析路径，在 singleflight 内执行。
func (r *Resolver) resolve(ctx context.Context, key, name string, qtype uint16) (*Message, error) {
	// 双检：前一个 in-flight 调用可能已写入缓存。
	if e, ok := r.cache.Get(key); ok {
		if e.neg != NegNone {
			return e.msg, negErr(e.neg)
		}
		return e.msg, nil
	}

	// 使用与调用方取消相隔离的上下文：单个请求取消/超时
	// 不影响其余等待者。解析整体仍受自身超时约束。
	detached := context.WithoutCancel(ctx)
	timeout := r.cfg.UpstreamTimeout * time.Duration(len(r.cfg.Upstreams)+1)
	rctx, cancel := context.WithTimeout(detached, timeout)
	defer cancel()

	id := uint16(r.idSeq.Add(1))
	query, err := EncodeQuery(id, name, qtype)
	if err != nil {
		return nil, err
	}
	msg, err := r.pool.Exchange(rctx, query, id, name, qtype)
	if err != nil {
		// 所有上游均失败（超时/网络错误）：视为上游临时失败，写负缓存。
		// 但应答未通过完整性校验（截断/非法）时不得写入任何缓存。
		if errors.Is(err, ErrAllUpstreamsFailed) && !errors.Is(err, ErrInvalidResponse) {
			r.setNegative(key, NegServFail, nil)
		}
		return nil, err
	}

	switch msg.RCode {
	case RCodeSuccess:
		if len(msg.Answers) == 0 {
			// NOERROR 但无应答记录：按 NXDOMAIN 同类处理（不存在该类型数据）。
			r.setNegative(key, NegNXDomain, msg)
			return msg, ErrNXDomain
		}
		ttl := r.positiveTTL(msg)
		r.setCache(key, &cacheEntry{msg: msg, neg: NegNone, expiresAt: r.cfg.Now().Add(ttl)})
		return msg, nil
	case RCodeNameErr:
		r.setNegative(key, NegNXDomain, msg)
		return msg, ErrNXDomain
	case RCodeServFail:
		r.setNegative(key, NegServFail, msg)
		return msg, ErrServFail
	default:
		return msg, fmt.Errorf("dnsres: unexpected rcode %d", msg.RCode)
	}
}

func (r *Resolver) positiveTTL(msg *Message) time.Duration {
	ttl := time.Duration(msg.MinTTL()) * time.Second
	if ttl < r.cfg.MinTTL {
		ttl = r.cfg.MinTTL
	}
	if r.cfg.MaxTTL > 0 && ttl > r.cfg.MaxTTL {
		ttl = r.cfg.MaxTTL
	}
	return ttl
}

func (r *Resolver) setNegative(key string, kind NegKind, msg *Message) {
	var ttl time.Duration
	if kind == NegNXDomain {
		ttl = r.cfg.NegTTLNXDomain
	} else {
		ttl = r.cfg.NegTTLServFail
	}
	r.setCache(key, &cacheEntry{msg: msg, neg: kind, expiresAt: r.cfg.Now().Add(ttl)})
}

func (r *Resolver) setCache(key string, e *cacheEntry) {
	evicted := r.cache.Set(key, e)
	if evicted > 0 {
		r.metrics.Evictions.Add(int64(evicted))
	}
}

// cleanupLoop 周期性清理过期条目。清理只做内存操作且持锁时间短，
// 不阻塞正在进行的解析。
func (r *Resolver) cleanupLoop() {
	defer close(r.cleanupDone)
	t := time.NewTicker(r.cfg.CleanupInterval)
	defer t.Stop()
	for {
		select {
		case <-r.stopCleanup:
			return
		case <-t.C:
			if n := r.cache.PurgeExpired(); n > 0 {
				r.metrics.Expirations.Add(int64(n))
			}
		}
	}
}

// Metrics 返回运行计数。
func (r *Resolver) Metrics() *Metrics {
	return r.metrics
}

// Close 停止后台清理 goroutine。
func (r *Resolver) Close() {
	if r.stopCleanup != nil {
		close(r.stopCleanup)
		<-r.cleanupDone
	}
}

func cacheKey(name string, qtype uint16) string {
	return fmt.Sprintf("%s|%d", name, qtype)
}

func negErr(kind NegKind) error {
	if kind == NegNXDomain {
		return ErrNXDomain
	}
	return ErrServFail
}
