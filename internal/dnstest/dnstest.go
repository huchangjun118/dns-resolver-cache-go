// Package dnstest 提供测试用的假 DNS 上游服务器（UDP+TCP）。
package dnstest

import (
	"encoding/binary"
	"io"
	"net"
	"sync"
	"testing"

	"github.com/huchangjun118/dns-resolver-cache-go/dnsmsg"
)

// Handler 根据查询生成应答；返回 nil 表示不应答（模拟超时）。
type Handler func(q *dnsmsg.Message) *dnsmsg.Message

// Server 假上游服务器
type Server struct {
	mu      sync.Mutex
	handler Handler
	udp     *net.UDPConn
	tcp     *net.TCPListener
	queries int
	closed  chan struct{}
}

// Start 在 127.0.0.1 随机端口启动服务器
func Start(t *testing.T, h Handler) *Server {
	t.Helper()
	ua, err := net.ResolveUDPAddr("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	uc, err := net.ListenUDP("udp", ua)
	if err != nil {
		t.Fatal(err)
	}
	ta, err := net.ResolveTCPAddr("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	tl, err := net.ListenTCP("tcp", ta)
	if err != nil {
		t.Fatal(err)
	}
	s := &Server{handler: h, udp: uc, tcp: tl, closed: make(chan struct{})}
	go s.serveUDP()
	go s.serveTCP()
	t.Cleanup(s.Close)
	return s
}

// Addr UDP 地址（与 TCP 不同端口，测试只用 UDP 或显式 TCP 地址）
func (s *Server) Addr() string { return s.udp.LocalAddr().String() }

// TCPAddr TCP 地址
func (s *Server) TCPAddr() string { return s.tcp.Addr().String() }

// SetHandler 动态替换处理器
func (s *Server) SetHandler(h Handler) {
	s.mu.Lock()
	s.handler = h
	s.mu.Unlock()
}

// Queries 收到的查询总数
func (s *Server) Queries() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.queries
}

func (s *Server) handle(q *dnsmsg.Message) *dnsmsg.Message {
	s.mu.Lock()
	s.queries++
	h := s.handler
	s.mu.Unlock()
	if h == nil {
		return nil
	}
	return h(q)
}

func (s *Server) serveUDP() {
	buf := make([]byte, 4096)
	for {
		n, addr, err := s.udp.ReadFromUDP(buf)
		if err != nil {
			return
		}
		data := append([]byte(nil), buf[:n]...)
		go func() {
			q, err := dnsmsg.UnpackQuery(data)
			if err != nil {
				return
			}
			resp := s.handle(q)
			if resp == nil {
				return
			}
			out, err := dnsmsg.Pack(resp)
			if err != nil {
				return
			}
			s.udp.WriteToUDP(out, addr)
		}()
	}
}

func (s *Server) serveTCP() {
	for {
		conn, err := s.tcp.Accept()
		if err != nil {
			return
		}
		go func(c net.Conn) {
			defer c.Close()
			var hdr [2]byte
			if _, err := io.ReadFull(c, hdr[:]); err != nil {
				return
			}
			buf := make([]byte, binary.BigEndian.Uint16(hdr[:]))
			if _, err := io.ReadFull(c, buf); err != nil {
				return
			}
			q, err := dnsmsg.UnpackQuery(buf)
			if err != nil {
				return
			}
			resp := s.handle(q)
			if resp == nil {
				return
			}
			out, err := dnsmsg.Pack(resp)
			if err != nil {
				return
			}
			frame := make([]byte, 2+len(out))
			binary.BigEndian.PutUint16(frame, uint16(len(out)))
			copy(frame[2:], out)
			c.Write(frame)
		}(conn)
	}
}

// Close 关闭服务器
func (s *Server) Close() {
	select {
	case <-s.closed:
	default:
		close(s.closed)
		s.udp.Close()
		s.tcp.Close()
	}
}
