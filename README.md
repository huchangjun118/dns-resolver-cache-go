# dns-resolver-cache-go

带缓存、负缓存、并发合并与多上游故障切换的域名解析库（纯标准库实现，无第三方依赖）。

## 架构

```
resolver (Lookup)
  ├─ cache      TTL 缓存：正缓存 + 两类负缓存，LRU 淘汰，容量有界
  ├─ singleflight  同名同类型在途查询合并为一次上游解析
  └─ upstream   多上游顺序故障切换，UDP 查询、TC 回退 TCP，单上游在途上限
        └─ dnsmsg   最小 DNS 报文编解码与完整性校验
```

## 缓存语义

### 正缓存
- 应答中的每条记录按自身 TTL 参与过期计算，条目整体 TTL 取所有应答记录的**最小 TTL**，并被钳制在 `[MinTTL, MaxTTL]` 区间。
- 过期条目绝不返回给调用方：访问时发现过期即删除并触发重新解析；后台清理协程每秒扫描一次，只短暂持锁，不阻塞进行中的解析。
- 被截断（TC 置位且 TCP 回退也失败）或完整性校验不通过（ID/问题段不匹配、报文畸形）的应答**不写入缓存**，也不返回给调用方。

### 负缓存（两类可区分）
| 类别 | 触发条件 | TTL 配置 | Lookup 返回 |
|---|---|---|---|
| `KindNXDomain` | NXDOMAIN，或 NODATA（成功但无应答记录） | `NXDomainTTL` | `Result{Negative: true, NXDomain: true}` |
| `KindServerFail` | SERVFAIL/REFUSED 等，或所有上游超时/异常 | `FailureTTL` | `ErrUpstreamFailed` |

- 命中负缓存时**不再访问上游**，直接返回缓存的否定结论。
- 两类负缓存使用不同 TTL（通常失败类更短，便于快速恢复），过期后自动重新解析。

### 容量与淘汰
- 缓存容量由 `CacheCapacity` 限定（默认 1024），写满时按 **LRU** 淘汰最久未使用的条目，内存占用收敛在有界范围。
- 每次淘汰计入 `Metrics.Evictions`。

## 并发合并（singleflight）

- 同一 `名称|类型` 的在途查询只触发**一次**上游解析，其余并发请求等待共享结果。
- 解析在独立协程与独立上下文中执行：任何单个调用方（包括发起者）取消或超时，都不会中断在途解析，也不影响其余等待者。

## 上游故障切换

- 按 `Upstreams` 配置顺序依次尝试；单个上游超时、返回异常或校验失败即切换到下一个，全部失败返回 `ErrUpstreamFailed`（并被负缓存）。
- 每个上游有独立的在途请求上限（8），超限请求立即视为该上游失败并切换，**不会**在故障上游上堆积放大成并发风暴。
- UDP 应答 TC 置位时自动回退 TCP 重试。

## 配置项（resolver.Config）

| 字段 | 默认值 | 说明 |
|---|---|---|
| `Upstreams` | 必填 | 上游列表，`{Addr: "host:port", Timeout: 单次超时}`，按顺序切换 |
| `CacheCapacity` | 1024 | 缓存容量上限（LRU 淘汰） |
| `MinTTL` | 5s | 正缓存 TTL 下限 |
| `MaxTTL` | 30m | 正缓存 TTL 上限 |
| `NXDomainTTL` | 60s | 域名不存在负缓存 TTL |
| `FailureTTL` | 5s | 上游临时失败负缓存 TTL |

## 运行指标（resolver.Metrics）

`Hits`（正缓存命中）、`NegativeHits`（负缓存命中）、`Misses`、`UpstreamQueries`（合并后的实际 upstream 解析次数）、`UpstreamFails`（单上游失败次数）、`Failovers`（切换次数）、`Evictions`（淘汰次数）。

## 可复现性

行为在相同输入与时序下可复现：报文 ID 由原子计数器生成（无随机源），上游严格按配置顺序切换，LRU 淘汰顺序确定，无任何随机化逻辑。

## 使用示例

```go
r := resolver.New(resolver.Config{
    Upstreams: []upstream.Server{
        {Addr: "223.5.5.5:53", Timeout: 500 * time.Millisecond},
        {Addr: "8.8.8.8:53", Timeout: time.Second},
    },
    CacheCapacity: 4096,
    NXDomainTTL:   time.Minute,
    FailureTTL:    5 * time.Second,
})
defer r.Close()

res, err := r.Lookup(ctx, "www.example.com", dnsmsg.TypeA)
```

## 测试

```sh
go test ./... -race
```

覆盖：缓存过期重解析、两类负缓存及 TTL 差异、上游故障切换、并发合并、调用方取消隔离、容量淘汰有界、截断应答不缓存、报文编解码与压缩指针。
