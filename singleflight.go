package dnsres

import (
	"context"
	"sync"
)

// flightGroup 合并同一 key 的并发调用，只执行一次 fn。
// fn 由首个到达的调用方执行（使用与调用方取消相隔离的上下文），
// 其余调用方等待共享结果；任一等待方取消其 context 只会让自己
// 提前返回，不会中断 fn，也不影响其余等待者。
type flightGroup struct {
	mu sync.Mutex
	m  map[string]*flightCall
}

type flightCall struct {
	done chan struct{}
	res  flightResult
}

type flightResult struct {
	msg *Message
	err error
}

func newFlightGroup() *flightGroup {
	return &flightGroup{m: make(map[string]*flightCall)}
}

// Do 对同一 key 的并发调用只执行一次 fn。shared 为 true 表示本次
// 结果由其它在途调用共享而来（未真正触发 fn）。
// 等待方 ctx 取消时返回 ctx.Err()，fn 与其余等待者不受影响。
func (g *flightGroup) Do(ctx context.Context, key string, fn func() (*Message, error)) (*Message, error, bool) {
	g.mu.Lock()
	if c, ok := g.m[key]; ok {
		g.mu.Unlock()
		select {
		case <-c.done:
			return c.res.msg, c.res.err, true
		case <-ctx.Done():
			return nil, ctx.Err(), true
		}
	}
	c := &flightCall{done: make(chan struct{})}
	g.m[key] = c
	g.mu.Unlock()

	// 领导者执行 fn；fn 内部使用隔离上下文，领导者自身的取消
	// 不会中断共享工作。
	c.res.msg, c.res.err = fn()
	close(c.done)

	g.mu.Lock()
	delete(g.m, key)
	g.mu.Unlock()
	return c.res.msg, c.res.err, false
}
