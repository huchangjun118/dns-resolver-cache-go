package upstream

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"

	"github.com/huchangjun118/dns-resolver-cache-go/dnsmsg"
	"github.com/huchangjun118/dns-resolver-cache-go/internal/dnstest"
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

func TestExchangeSuccess(t *testing.T) {
	s := dnstest.Start(t, aHandler("192.0.2.1", 300))
	p := NewPool([]Server{{Addr: s.Addr(), Timeout: time.Second}})
	resp, err := p.Exchange(context.Background(), "www.example.com", dnsmsg.TypeA)
	if err != nil {
		t.Fatal(err)
	}
	if len(resp.Answers) != 1 || resp.Answers[0].Data != "192.0.2.1" {
		t.Fatalf("bad resp: %+v", resp)
	}
}

func TestFailoverOrder(t *testing.T) {
	// 第一个上游不应答（超时），第二个正常
	s1 := dnstest.Start(t, func(q *dnsmsg.Message) *dnsmsg.Message { return nil })
	s2 := dnstest.Start(t, aHandler("192.0.2.2", 60))
	var failovers atomic.Int64
	p := NewPool([]Server{
		{Addr: s1.Addr(), Timeout: 100 * time.Millisecond},
		{Addr: s2.Addr(), Timeout: time.Second},
	})
	p.SetHooks(Hooks{OnFailover: func(from, to string) { failovers.Add(1) }})
	resp, err := p.Exchange(context.Background(), "a.example", dnsmsg.TypeA)
	if err != nil {
		t.Fatal(err)
	}
	if resp.Answers[0].Data != "192.0.2.2" {
		t.Fatalf("want answer from second upstream, got %+v", resp.Answers[0])
	}
	if failovers.Load() != 1 {
		t.Fatalf("failovers=%d, want 1", failovers.Load())
	}
	if s1.Queries() == 0 || s2.Queries() == 0 {
		t.Fatal("both upstreams should have been tried")
	}
}

func TestAllFailed(t *testing.T) {
	s1 := dnstest.Start(t, func(q *dnsmsg.Message) *dnsmsg.Message { return nil })
	p := NewPool([]Server{{Addr: s1.Addr(), Timeout: 50 * time.Millisecond}})
	_, err := p.Exchange(context.Background(), "a.example", dnsmsg.TypeA)
	if !errors.Is(err, ErrAllFailed) {
		t.Fatalf("want ErrAllFailed, got %v", err)
	}
}

func TestGarbageResponseSkipped(t *testing.T) {
	// 第一个上游返回损坏报文，应切换到第二个
	s1 := dnstest.Start(t, nil)
	s1.SetHandler(func(q *dnsmsg.Message) *dnsmsg.Message {
		// 返回一个会被 Pack 后截断的报文不可行，改为直接关闭连接场景：
		// 这里用错误 ID 的应答模拟校验失败
		return &dnsmsg.Message{
			ID: q.ID + 1, Response: true, Question: q.Question,
			Answers: []dnsmsg.Record{{Name: q.Question.Name, Type: q.Question.Type, Class: dnsmsg.ClassIN, TTL: 60, Data: "192.0.2.9"}},
		}
	})
	s2 := dnstest.Start(t, aHandler("192.0.2.2", 60))
	p := NewPool([]Server{
		{Addr: s1.Addr(), Timeout: time.Second},
		{Addr: s2.Addr(), Timeout: time.Second},
	})
	resp, err := p.Exchange(context.Background(), "a.example", dnsmsg.TypeA)
	if err != nil {
		t.Fatal(err)
	}
	if resp.Answers[0].Data != "192.0.2.2" {
		t.Fatalf("invalid response must not be used; got %+v", resp.Answers[0])
	}
}

func TestNoConcurrencyStorm(t *testing.T) {
	// 慢上游：超过在途上限的并发请求应快速失败而不是堆积
	block := make(chan struct{})
	var inFlight atomic.Int64
	s := dnstest.Start(t, nil)
	s.SetHandler(func(q *dnsmsg.Message) *dnsmsg.Message {
		inFlight.Add(1)
		<-block
		return nil
	})
	p := NewPool([]Server{{Addr: s.Addr(), Timeout: 5 * time.Second}})
	const total = 64
	var errs atomic.Int64
	done := make(chan struct{})
	for i := 0; i < total; i++ {
		go func() {
			_, err := p.Exchange(context.Background(), "a.example", dnsmsg.TypeA)
			if err != nil {
				errs.Add(1)
			}
			done <- struct{}{}
		}()
	}
	// 等待所有 goroutine 结束（信号量拒绝的请求立即返回）
	deadline := time.After(2 * time.Second)
	got := 0
loop:
	for got < total {
		select {
		case <-done:
			got++
		case <-deadline:
			break loop
		}
	}
	close(block)
	if got == 0 {
		t.Fatal("no request finished")
	}
	if n := inFlight.Load(); n > maxInflightPerServer {
		t.Fatalf("in-flight %d exceeds limit %d: storm not prevented", n, maxInflightPerServer)
	}
}
