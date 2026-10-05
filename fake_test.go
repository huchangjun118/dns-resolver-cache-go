package dnsres

import (
	"encoding/binary"
	"net"
	"sync"
	"testing"
)

// fakeServer 是一个可编程的 UDP DNS 上游，用于测试。
type fakeServer struct {
	conn *net.UDPConn
	addr string

	mu      sync.Mutex
	queries int
	handler func(q *Message, raw []byte) []byte // 返回 nil 表示丢弃（模拟超时）
}

func newFakeServer(t *testing.T, handler func(q *Message, raw []byte) []byte) *fakeServer {
	t.Helper()
	conn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1")})
	if err != nil {
		t.Fatalf("listen udp: %v", err)
	}
	s := &fakeServer{conn: conn, addr: conn.LocalAddr().String(), handler: handler}
	go s.serve()
	t.Cleanup(func() { conn.Close() })
	return s
}

func (s *fakeServer) serve() {
	buf := make([]byte, 4096)
	for {
		n, peer, err := s.conn.ReadFromUDP(buf)
		if err != nil {
			return
		}
		raw := append([]byte(nil), buf[:n]...)
		s.mu.Lock()
		s.queries++
		s.mu.Unlock()
		q, err := ParseMessage(raw)
		if err != nil {
			continue
		}
		resp := s.handler(q, raw)
		if resp == nil {
			continue // 丢弃，模拟超时
		}
		_, _ = s.conn.WriteToUDP(resp, peer)
	}
}

func (s *fakeServer) queryCount() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.queries
}

// buildResponse 构造一条应答报文：问题段回显查询，答案段使用压缩指针。
func buildResponse(id uint16, name string, qtype uint16, rcode int, ttl uint32, ips ...string) []byte {
	buf := make([]byte, 0, 128)
	buf = appendUint16(buf, id)
	buf = appendUint16(buf, 0x8180|uint16(rcode)) // QR+RD+RA + rcode
	buf = appendUint16(buf, 1)                    // QDCOUNT
	ancount := uint16(0)
	if rcode == RCodeSuccess {
		ancount = uint16(len(ips))
	}
	buf = appendUint16(buf, ancount)
	buf = appendUint16(buf, 0)
	buf = appendUint16(buf, 0)
	q, _ := EncodeQuery(id, name, qtype)
	buf = append(buf, q[12:]...) // 问题段
	for _, ip := range ips {
		buf = appendUint16(buf, 0xC00C) // 指向问题段名字
		buf = appendUint16(buf, qtype)
		buf = appendUint16(buf, ClassIN)
		b4 := make([]byte, 4)
		binary.BigEndian.PutUint32(b4, ttl)
		buf = append(buf, b4...)
		if qtype == TypeA {
			buf = appendUint16(buf, 4)
			buf = append(buf, net.ParseIP(ip).To4()...)
		} else {
			buf = appendUint16(buf, 16)
			buf = append(buf, net.ParseIP(ip).To16()...)
		}
	}
	return buf
}

// truncateResponse 构造 TC 置位的截断应答。
func truncateResponse(id uint16, name string, qtype uint16) []byte {
	resp := buildResponse(id, name, qtype, RCodeSuccess, 60, "1.2.3.4")
	resp[2] |= 0x02           // TC 置位
	return resp[:len(resp)/2] // 并且物理截断
}
