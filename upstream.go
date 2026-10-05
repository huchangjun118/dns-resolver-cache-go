package dnsres

import (
	"context"
	"errors"
	"fmt"
	"net"
	"time"
)

// ErrAllUpstreamsFailed 表示所有上游都失败。
var ErrAllUpstreamsFailed = errors.New("dnsres: all upstreams failed")

// ErrInvalidResponse 表示上游返回了未通过完整性校验的应答
// （被截断或内容非法）。此类结果不得写入缓存。
var ErrInvalidResponse = errors.New("dnsres: invalid response")

// Upstream 表示一个上游 DNS 服务器地址（host:port，UDP）。
type Upstream struct {
	Addr string
}

// Pool 按既定顺序在多个上游间切换与重试。
// 每次 Exchange 从第一个上游开始尝试，单个上游失败（超时或异常应答）
// 才切换到下一个；并发合并由上层 singleflight 保证，
// 因此切换与重试不会放大为对单个上游的并发风暴。
type Pool struct {
	upstreams []Upstream
	timeout   time.Duration
	metrics   *Metrics
	// dial 可注入，便于测试与复现；nil 时使用 UDP。
	dial func(ctx context.Context, addr string) (net.Conn, error)
}

// NewPool 创建上游池。timeout 为单个上游单次尝试的超时。
func NewPool(addrs []string, timeout time.Duration, m *Metrics) *Pool {
	us := make([]Upstream, len(addrs))
	for i, a := range addrs {
		us[i] = Upstream{Addr: a}
	}
	return &Pool{upstreams: us, timeout: timeout, metrics: m}
}

// Exchange 将查询报文按顺序发往上游，返回校验通过的应答。
// wantID/wantName/wantType 用于应答完整性校验。
func (p *Pool) Exchange(ctx context.Context, query []byte, wantID uint16, wantName string, wantType uint16) (*Message, error) {
	var lastErr error
	for i, up := range p.upstreams {
		if i > 0 && p.metrics != nil {
			p.metrics.UpstreamSwitches.Add(1)
		}
		msg, err := p.exchangeOne(ctx, up, query, wantID, wantName, wantType)
		if err == nil {
			return msg, nil
		}
		if p.metrics != nil {
			p.metrics.UpstreamFailures.Add(1)
		}
		lastErr = err
		// 调用方已取消则不再尝试后续上游。
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
	}
	return nil, fmt.Errorf("%w: %w", ErrAllUpstreamsFailed, lastErr)
}

func (p *Pool) exchangeOne(ctx context.Context, up Upstream, query []byte, wantID uint16, wantName string, wantType uint16) (*Message, error) {
	dial := p.dial
	if dial == nil {
		dial = func(ctx context.Context, addr string) (net.Conn, error) {
			var d net.Dialer
			return d.DialContext(ctx, "udp", addr)
		}
	}
	conn, err := dial(ctx, up.Addr)
	if err != nil {
		return nil, fmt.Errorf("upstream %s dial: %w", up.Addr, err)
	}
	defer conn.Close()

	deadline := time.Now().Add(p.timeout)
	if dl, ok := ctx.Deadline(); ok && dl.Before(deadline) {
		deadline = dl
	}
	_ = conn.SetDeadline(deadline)

	if _, err := conn.Write(query); err != nil {
		return nil, fmt.Errorf("upstream %s write: %w", up.Addr, err)
	}
	buf := make([]byte, 4096)
	n, err := conn.Read(buf)
	if err != nil {
		return nil, fmt.Errorf("upstream %s read: %w", up.Addr, err)
	}
	msg, err := ParseMessage(buf[:n])
	if err != nil {
		return nil, fmt.Errorf("upstream %s parse: %w: %v", up.Addr, ErrInvalidResponse, err)
	}
	if err := ValidateResponse(msg, wantID, wantName, wantType); err != nil {
		return nil, fmt.Errorf("upstream %s validate: %w: %v", up.Addr, ErrInvalidResponse, err)
	}
	return msg, nil
}
