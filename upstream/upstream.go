// Package upstream 实现多上游顺序故障切换与重试。
package upstream

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"sync/atomic"
	"time"

	"github.com/huchangjun118/dns-resolver-cache-go/dnsmsg"
)

// ErrAllFailed 表示所有上游都失败
var ErrAllFailed = errors.New("upstream: all servers failed")

// errBusy 表示单个上游的在途请求已达上限
var errBusy = errors.New("upstream: server busy")

// Server 单个上游配置
type Server struct {
	Addr    string        // host:port，UDP 查询，TC 时回退 TCP
	Timeout time.Duration // 单次查询超时
}

// Hooks 运行指标回调（可为 nil）
type Hooks struct {
	OnFail     func(addr string, err error) // 某个上游单次失败
	OnFailover func(from, to string)        // 发生上游切换
}

// Pool 上游池，按既定顺序切换。
// 每个上游有独立的在途请求上限，防止故障时并发风暴打到单一上游。
type Pool struct {
	servers []Server
	sems    []chan struct{} // 每个上游一个信号量
	hooks   Hooks
	idSeq   atomic.Uint32
}

// maxInflightPerServer 单个上游最大在途请求数
const maxInflightPerServer = 8

// NewPool 创建上游池
func NewPool(servers []Server) *Pool {
	p := &Pool{servers: servers}
	for range servers {
		p.sems = append(p.sems, make(chan struct{}, maxInflightPerServer))
	}
	return p
}

// SetHooks 设置指标回调
func (p *Pool) SetHooks(h Hooks) { p.hooks = h }

// Exchange 依次尝试各上游，返回首个校验通过的应答；
// 全部失败时返回 ErrAllFailed。
func (p *Pool) Exchange(ctx context.Context, name string, qtype uint16) (*dnsmsg.Message, error) {
	if len(p.servers) == 0 {
		return nil, ErrAllFailed
	}
	id := uint16(p.idSeq.Add(1))
	query, err := dnsmsg.PackQuery(id, name, qtype)
	if err != nil {
		return nil, err
	}
	var lastErr error
	for i, srv := range p.servers {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		resp, err := p.exchangeOne(ctx, srv, i, query, id, name, qtype)
		if err == nil {
			return resp, nil
		}
		lastErr = err
		if p.hooks.OnFail != nil {
			p.hooks.OnFail(srv.Addr, err)
		}
		if i+1 < len(p.servers) && p.hooks.OnFailover != nil {
			p.hooks.OnFailover(p.servers[i].Addr, p.servers[i+1].Addr)
		}
	}
	return nil, fmt.Errorf("%w: %v", ErrAllFailed, lastErr)
}

// exchangeOne 查询单个上游：先 UDP，报文被截断时回退 TCP。
func (p *Pool) exchangeOne(ctx context.Context, srv Server, idx int, query []byte, id uint16, name string, qtype uint16) (*dnsmsg.Message, error) {
	// 非阻塞获取信号量：满了直接视为该上游失败，避免请求堆积放大
	select {
	case p.sems[idx] <- struct{}{}:
		defer func() { <-p.sems[idx] }()
	default:
		return nil, errBusy
	}
	timeout := srv.Timeout
	if timeout <= 0 {
		timeout = 2 * time.Second
	}
	resp, err := p.udpRoundTrip(ctx, srv.Addr, query, timeout)
	if errors.Is(err, dnsmsg.ErrTruncated) {
		resp, err = p.tcpRoundTrip(ctx, srv.Addr, query, timeout)
	}
	if err != nil {
		return nil, err
	}
	// 完整性校验：ID 与问题段必须与查询一致
	if resp.ID != id {
		return nil, fmt.Errorf("%w: id mismatch", dnsmsg.ErrInvalid)
	}
	if !equalName(resp.Question.Name, name) || resp.Question.Type != qtype {
		return nil, fmt.Errorf("%w: question mismatch", dnsmsg.ErrInvalid)
	}
	return resp, nil
}

func equalName(a, b string) bool {
	// 域名比较忽略大小写与结尾点
	na, nb := len(a), len(b)
	if na > 0 && a[na-1] == '.' {
		a = a[:na-1]
	}
	if nb > 0 && b[nb-1] == '.' {
		b = b[:nb-1]
	}
	if len(a) != len(b) {
		return false
	}
	for i := 0; i < len(a); i++ {
		ca, cb := a[i], b[i]
		if 'A' <= ca && ca <= 'Z' {
			ca += 32
		}
		if 'A' <= cb && cb <= 'Z' {
			cb += 32
		}
		if ca != cb {
			return false
		}
	}
	return true
}

func deadline(ctx context.Context, timeout time.Duration) (context.Context, context.CancelFunc) {
	return context.WithTimeout(ctx, timeout)
}

func (p *Pool) udpRoundTrip(ctx context.Context, addr string, query []byte, timeout time.Duration) (*dnsmsg.Message, error) {
	ctx, cancel := deadline(ctx, timeout)
	defer cancel()
	var d net.Dialer
	conn, err := d.DialContext(ctx, "udp", addr)
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	if dl, ok := ctx.Deadline(); ok {
		conn.SetDeadline(dl)
	}
	if _, err := conn.Write(query); err != nil {
		return nil, err
	}
	buf := make([]byte, 4096)
	n, err := conn.Read(buf)
	if err != nil {
		return nil, err
	}
	return dnsmsg.Unpack(buf[:n])
}

func (p *Pool) tcpRoundTrip(ctx context.Context, addr string, query []byte, timeout time.Duration) (*dnsmsg.Message, error) {
	ctx, cancel := deadline(ctx, timeout)
	defer cancel()
	var d net.Dialer
	conn, err := d.DialContext(ctx, "tcp", addr)
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	if dl, ok := ctx.Deadline(); ok {
		conn.SetDeadline(dl)
	}
	frame := make([]byte, 2+len(query))
	binary.BigEndian.PutUint16(frame, uint16(len(query)))
	copy(frame[2:], query)
	if _, err := conn.Write(frame); err != nil {
		return nil, err
	}
	var hdr [2]byte
	if _, err := io.ReadFull(conn, hdr[:]); err != nil {
		return nil, err
	}
	n := int(binary.BigEndian.Uint16(hdr[:]))
	if n <= 0 || n > 65535 {
		return nil, dnsmsg.ErrInvalid
	}
	buf := make([]byte, n)
	if _, err := io.ReadFull(conn, buf); err != nil {
		return nil, err
	}
	return dnsmsg.Unpack(buf)
}
