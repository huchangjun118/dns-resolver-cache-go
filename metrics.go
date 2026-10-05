package dnsres

import "sync/atomic"

// Metrics 暴露运行计数。所有字段通过原子操作更新，读取快照无锁。
type Metrics struct {
	Hits             atomic.Int64 // 正向缓存命中
	NegHits          atomic.Int64 // 负缓存命中
	Misses           atomic.Int64 // 缓存未命中
	Coalesced        atomic.Int64 // 被合并的并发请求数
	UpstreamFailures atomic.Int64 // 上游失败次数（含超时/异常应答）
	UpstreamSwitches atomic.Int64 // 上游切换次数
	Evictions        atomic.Int64 // 容量淘汰次数
	Expirations      atomic.Int64 // 过期清理次数
}

// Snapshot 是某一时刻的计数快照。
type Snapshot struct {
	Hits             int64
	NegHits          int64
	Misses           int64
	Coalesced        int64
	UpstreamFailures int64
	UpstreamSwitches int64
	Evictions        int64
	Expirations      int64
}

// Snapshot 读取当前计数快照。
func (m *Metrics) Snapshot() Snapshot {
	return Snapshot{
		Hits:             m.Hits.Load(),
		NegHits:          m.NegHits.Load(),
		Misses:           m.Misses.Load(),
		Coalesced:        m.Coalesced.Load(),
		UpstreamFailures: m.UpstreamFailures.Load(),
		UpstreamSwitches: m.UpstreamSwitches.Load(),
		Evictions:        m.Evictions.Load(),
		Expirations:      m.Expirations.Load(),
	}
}
