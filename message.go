package dnsres

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"strings"
)

// DNS 消息相关常量。
const (
	RCodeSuccess  = 0
	RCodeNameErr  = 3 // NXDOMAIN：域名不存在
	RCodeServFail = 2 // SERVFAIL：上游临时失败

	TypeA     = 1
	TypeAAAA  = 28
	TypeCNAME = 5

	ClassIN = 1

	headerLen = 12
)

// ErrTruncated 表示应答被截断（TC 位置位）。
var ErrTruncated = errors.New("dnsres: truncated response")

// ErrMalformed 表示应答无法通过完整性校验。
var ErrMalformed = errors.New("dnsres: malformed response")

// Question 是 DNS 查询问题段。
type Question struct {
	Name  string
	Type  uint16
	Class uint16
}

// Record 是一条资源记录。Data 为解码后的文本形式（A/AAAA/CNAME），
// 其余类型保留在 Raw 中。
type Record struct {
	Name  string
	Type  uint16
	Class uint16
	TTL   uint32
	Data  string
	Raw   []byte
}

// Message 是一条 DNS 消息（查询或应答）。
type Message struct {
	ID        uint16
	Response  bool
	RCode     int
	Truncated bool
	Questions []Question
	Answers   []Record
}

// NormalizeName 规范化域名：小写、去尾部点，保证缓存键稳定可复现。
func NormalizeName(name string) string {
	return strings.ToLower(strings.TrimSuffix(strings.TrimSpace(name), "."))
}

// EncodeQuery 构造一个标准查询报文（RD 置位，单个问题）。
func EncodeQuery(id uint16, name string, qtype uint16) ([]byte, error) {
	name = NormalizeName(name)
	if name == "" {
		return nil, fmt.Errorf("%w: empty query name", ErrMalformed)
	}
	buf := make([]byte, 0, 64)
	buf = appendUint16(buf, id)
	buf = appendUint16(buf, 0x0100) // RD=1
	buf = appendUint16(buf, 1)      // QDCOUNT
	buf = appendUint16(buf, 0)
	buf = appendUint16(buf, 0)
	buf = appendUint16(buf, 0)
	var err error
	buf, err = appendName(buf, name)
	if err != nil {
		return nil, err
	}
	buf = appendUint16(buf, qtype)
	buf = appendUint16(buf, ClassIN)
	return buf, nil
}

func appendUint16(b []byte, v uint16) []byte {
	return append(b, byte(v>>8), byte(v))
}

func appendUint32(b []byte, v uint32) []byte {
	return append(b, byte(v>>24), byte(v>>16), byte(v>>8), byte(v))
}

func appendName(b []byte, name string) ([]byte, error) {
	for _, label := range strings.Split(name, ".") {
		if len(label) == 0 || len(label) > 63 {
			return nil, fmt.Errorf("%w: bad label in %q", ErrMalformed, name)
		}
		b = append(b, byte(len(label)))
		b = append(b, label...)
	}
	return append(b, 0), nil
}

// ParseMessage 解析并校验一条 DNS 消息。
// 校验内容：报文长度、各段计数与实际长度一致、域名压缩指针合法、
// 记录边界完整。任何一项不满足都返回错误，调用方不得使用其结果。
func ParseMessage(buf []byte) (*Message, error) {
	if len(buf) < headerLen {
		return nil, fmt.Errorf("%w: header too short (%d bytes)", ErrMalformed, len(buf))
	}
	m := &Message{}
	m.ID = binary.BigEndian.Uint16(buf[0:2])
	flags := binary.BigEndian.Uint16(buf[2:4])
	m.Response = flags&0x8000 != 0
	m.Truncated = flags&0x0200 != 0
	m.RCode = int(flags & 0x000F)
	qd := int(binary.BigEndian.Uint16(buf[4:6]))
	an := int(binary.BigEndian.Uint16(buf[6:8]))
	// NSCOUNT/ARCOUNT 的附加段我们跳过，但必须边界完整。
	ns := int(binary.BigEndian.Uint16(buf[8:10]))
	ar := int(binary.BigEndian.Uint16(buf[10:12]))

	off := headerLen
	var err error
	m.Questions = make([]Question, 0, qd)
	for i := 0; i < qd; i++ {
		var q Question
		q.Name, off, err = parseName(buf, off)
		if err != nil {
			return nil, err
		}
		if off+4 > len(buf) {
			return nil, fmt.Errorf("%w: question %d truncated", ErrMalformed, i)
		}
		q.Type = binary.BigEndian.Uint16(buf[off : off+2])
		q.Class = binary.BigEndian.Uint16(buf[off+2 : off+4])
		off += 4
		m.Questions = append(m.Questions, q)
	}
	m.Answers = make([]Record, 0, an)
	for i := 0; i < an; i++ {
		var rec Record
		rec, off, err = parseRecord(buf, off)
		if err != nil {
			return nil, fmt.Errorf("%w: answer %d: %v", ErrMalformed, i, err)
		}
		m.Answers = append(m.Answers, rec)
	}
	// 权威段与附加段只校验边界，不保留内容。
	for i := 0; i < ns+ar; i++ {
		_, off, err = parseRecord(buf, off)
		if err != nil {
			return nil, fmt.Errorf("%w: extra record %d: %v", ErrMalformed, i, err)
		}
	}
	return m, nil
}

// parseName 解析（可能压缩的）域名，返回解码后的名字与下一偏移。
// 指针跳转次数受限，防止压缩指针成环导致死循环。
func parseName(buf []byte, off int) (string, int, error) {
	var labels []string
	next := off
	jumped := false
	jumps := 0
	for {
		if off >= len(buf) {
			return "", 0, fmt.Errorf("%w: name out of bounds", ErrMalformed)
		}
		l := int(buf[off])
		switch {
		case l&0xC0 == 0xC0:
			if off+1 >= len(buf) {
				return "", 0, fmt.Errorf("%w: pointer out of bounds", ErrMalformed)
			}
			ptr := (l&0x3F)<<8 | int(buf[off+1])
			if ptr >= len(buf) {
				return "", 0, fmt.Errorf("%w: pointer target out of bounds", ErrMalformed)
			}
			jumps++
			if jumps > 16 {
				return "", 0, fmt.Errorf("%w: too many compression jumps", ErrMalformed)
			}
			if !jumped {
				next = off + 2
				jumped = true
			}
			off = ptr
		case l == 0:
			if !jumped {
				next = off + 1
			}
			return strings.Join(labels, "."), next, nil
		case l&0xC0 != 0:
			return "", 0, fmt.Errorf("%w: bad label type", ErrMalformed)
		default:
			if off+1+l > len(buf) {
				return "", 0, fmt.Errorf("%w: label out of bounds", ErrMalformed)
			}
			labels = append(labels, string(buf[off+1:off+1+l]))
			off += 1 + l
		}
	}
}

func parseRecord(buf []byte, off int) (Record, int, error) {
	var rec Record
	name, next, err := parseName(buf, off)
	if err != nil {
		return rec, 0, err
	}
	off = next
	if off+10 > len(buf) {
		return rec, 0, errors.New("record header truncated")
	}
	rec.Name = name
	rec.Type = binary.BigEndian.Uint16(buf[off : off+2])
	rec.Class = binary.BigEndian.Uint16(buf[off+2 : off+4])
	rec.TTL = binary.BigEndian.Uint32(buf[off+4 : off+8])
	rdlen := int(binary.BigEndian.Uint16(buf[off+8 : off+10]))
	off += 10
	if off+rdlen > len(buf) {
		return rec, 0, errors.New("rdata truncated")
	}
	rdata := buf[off : off+rdlen]
	rec.Raw = append([]byte(nil), rdata...)
	switch rec.Type {
	case TypeA:
		if rdlen != 4 {
			return rec, 0, fmt.Errorf("bad A rdata length %d", rdlen)
		}
		rec.Data = net.IP(rdata).String()
	case TypeAAAA:
		if rdlen != 16 {
			return rec, 0, fmt.Errorf("bad AAAA rdata length %d", rdlen)
		}
		rec.Data = net.IP(rdata).String()
	case TypeCNAME:
		cname, _, err := parseName(buf, off)
		if err != nil {
			return rec, 0, err
		}
		rec.Data = cname
	}
	return rec, off + rdlen, nil
}

// MinTTL 返回应答中所有记录的最小 TTL；无记录时返回 0。
func (m *Message) MinTTL() uint32 {
	if len(m.Answers) == 0 {
		return 0
	}
	min := m.Answers[0].TTL
	for _, r := range m.Answers[1:] {
		if r.TTL < min {
			min = r.TTL
		}
	}
	return min
}

// ValidateResponse 对应答做完整性校验：
// 报文本身可解析（ParseMessage 已保证）、未被截断、
// ID 与查询匹配、确为应答报文、问题段与查询一致。
func ValidateResponse(m *Message, wantID uint16, wantName string, wantType uint16) error {
	if m.Truncated {
		return ErrTruncated
	}
	if !m.Response {
		return fmt.Errorf("%w: not a response", ErrMalformed)
	}
	if m.ID != wantID {
		return fmt.Errorf("%w: id mismatch", ErrMalformed)
	}
	if len(m.Questions) == 0 {
		return fmt.Errorf("%w: no question in response", ErrMalformed)
	}
	q := m.Questions[0]
	if NormalizeName(q.Name) != NormalizeName(wantName) || q.Type != wantType {
		return fmt.Errorf("%w: question mismatch", ErrMalformed)
	}
	return nil
}
