# dns-resolver-cache-go

带缓存、负缓存、上游故障切换与并发合并的 DNS 解析库（仅依赖标准库）。

## 能力概览

- **正向缓存**：解析结果按记录自身 TTL 过期（受 `MinTTL`/`MaxTTL` 钳制），过期条目不再返回，触发重新解析。
- **负缓存**：`NXDOMAIN`（域名不存在）与 `SERVFAIL`/上游全部超时（临时失败）按各自 TTL 分别缓存，二者可区分；命中负之一即直接返回对应错误（`ErrNXDomain` / `ErrServFail`），不再访问上游。
- **多上游故障切换**：按 `Upstreams` 顺序尝试，单个上游超时或应答异常即切换下一个；并发合并保证切换重试不会放大为对单一上游的并发风暴。
- **并发合并（singleflight）**：同一名称的并发查询只触发一次上游解析；任一等待方取消/超时仅自身提前返回，不影响其余等待者。
- **容量上限与淘汰**：LRU 淘汰，缓存条目数有界；后台周期清理过期条目（仅内存操作、持锁时间短），不阻塞进行中的解析，长期压测下内存收敛。
- **应答完整性校验**：校验报文边界、压缩指针、ID/问题段匹配与 TC 位；被截断或校验不通过的应答不写入缓存、不作为有效结果返回。
- **可观测与可复现**：`Metrics()` 暴露命中率、负缓存命中、上游切换/失败、淘汰、过期清理、合并计数；时钟与查询 ID 序列可注入/固定起点，相同输入与时序下行为可复现。

## 使用

```go
r := dnsres.NewResolver(dnsres.Config{
    Upstreams:       []string{"223.5.5.5:53", "119.29.29.29:53"},
    UpstreamTimeout: 2 * time.Second,
    CacheCapacity:   10000,
    CleanupInterval: time.Minute,
})
defer r.Close()

msg, err := r.Lookup(ctx, "www.example.com", dnsres.TypeA)
if errors.Is(err, dnsres.ErrNXDomain) { /* 域名不存在（可能来自负缓存） */ }
if errors.Is(err, dnsres.ErrServFail) { /* 上游临时失败（可能来自负缓存） */ }

snap := r.Metrics().Snapshot() // 命中率等计数
```

## 配置项（Config）

| 字段 | 默认 | 说明 |
|---|---|---|
| `Upstreams` | — | 上游地址列表（`host:port`，UDP），按既定顺序切换 |
| `UpstreamTimeout` | 2s | 单个上游单次尝试超时 |
| `CacheCapacity` | 不限 | 缓存条目数上限，超出按 LRU 淘汰 |
| `NegTTLNXDomain` | 5min | NXDOMAIN 负缓存 TTL |
| `NegTTLServFail` | 30s | SERVFAIL / 上游全部失败 负缓存 TTL |
| `MinTTL` | 1s | 正向缓存 TTL 下限 |
| `MaxTTL` | 不限 | 正向缓存 TTL 上限 |
| `CleanupInterval` | 关闭 | 过期条目后台清理周期 |
| `Now` | `time.Now` | 可注入时钟，用于测试复现 |

## 缓存语义

- 缓存键为 `规范化域名|记录类型`（域名小写、去尾点）。
- 正向条目 TTL 取应答中所有记录的最小 TTL，并被钳制在 `[MinTTL, MaxTTL]`。
- 负缓存条目区分 `NegNXDomain` 与 `NegServFail` 两种类型，分别使用
  `NegTTLNXDomain` / `NegTTLServFail`，命中时返回对应错误且不访问上游。
- 过期条目在访问时惰性移除，并由后台清理周期回收；二者都不会把过期结果返回给调用方。
- 截断（TC 置位）或校验不通过的应答：不缓存、不返回，计入 `UpstreamFailures` 并触发对下一上游的重试。

## 计数指标（Metrics.Snapshot）

`Hits` / `NegHits` / `Misses` / `Coalesced` / `UpstreamFailures` /
`UpstreamSwitches` / `Evictions` / `Expirations`。

## 测试

```sh
go test -race ./...
```

覆盖：缓存过期、负缓存（两类 TTL 独立且可区分）、上游故障切换、
并发合并与取消隔离、容量淘汰、截断应答拒绝、后台清理。
