// Package dnsmsg 提供最小化的 DNS 报文编解码能力，
// 仅覆盖本解析器所需的记录类型与标志位。
package dnsmsg

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"strings"
)

// Rcode 取值
const (
	RcodeSuccess        = 0
	RcodeFormatError    = 1
	RcodeServerFailure  = 2
	RcodeNameError      = 3 // NXDOMAIN
	RcodeNotImplemented = 4
	RcodeRefused        = 5
)

// 记录类型
const (
	TypeA     = 1
	TypeCNAME = 5
	TypeAAAA  = 28
)

// ClassIN 互联网类别
const ClassIN = 1

// ErrTruncated 表示应答被截断（TC 置位）
var ErrTruncated = errors.New("dnsmsg: truncated response")

// ErrInvalid 表示应答校验不通过
var ErrInvalid = errors.New("dnsmsg: invalid response")

// Question 查询段
type Question struct {
	Name  string
	Type  uint16
	Class uint16
}

// Record 资源记录（仅保留解析器所需字段）
type Record struct {
	Name  string
	Type  uint16
	Class uint16
	TTL   uint32
	Data  string // A/AAAA 为 IP 字符串，CNAME 为目标名
}

// Message DNS 报文
type Message struct {
	ID        uint16
	Response  bool
	Opcode    uint16
	Truncated bool
	Rcode     int
	Question  Question
	Answers   []Record
}

// packName 把点分域名写入报文，返回写入后的 buf
func packName(buf []byte, name string) ([]byte, error) {
	name = strings.TrimSuffix(name, ".")
	if name == "" {
		return append(buf, 0), nil
	}
	for _, label := range strings.Split(name, ".") {
		if len(label) == 0 || len(label) > 63 {
			return nil, fmt.Errorf("%w: bad label %q", ErrInvalid, label)
		}
		buf = append(buf, byte(len(label)))
		buf = append(buf, label...)
	}
	return append(buf, 0), nil
}

// unpackName 从 msg 的 off 处解析域名（支持压缩指针），返回名字与新的偏移
func unpackName(msg []byte, off int) (string, int, error) {
	var labels []string
	cur := off
	next := -1 // 第一个指针之后的偏移
	jumped := false
	for i := 0; i < 128; i++ { // 限制指针跳转次数，防环
		if cur >= len(msg) {
			return "", 0, ErrInvalid
		}
		l := int(msg[cur])
		switch {
		case l&0xC0 == 0xC0: // 压缩指针
			if cur+1 >= len(msg) {
				return "", 0, ErrInvalid
			}
			ptr := (l&0x3F)<<8 | int(msg[cur+1])
			if !jumped {
				next = cur + 2
				jumped = true
			}
			cur = ptr
		case l == 0:
			if !jumped {
				next = cur + 1
			}
			return strings.Join(labels, "."), next, nil
		case l&0xC0 == 0:
			if cur+1+l > len(msg) {
				return "", 0, ErrInvalid
			}
			labels = append(labels, string(msg[cur+1:cur+1+l]))
			cur += 1 + l
		default:
			return "", 0, ErrInvalid
		}
	}
	return "", 0, ErrInvalid
}

// PackQuery 构造查询报文（RD 置位）
func PackQuery(id uint16, name string, qtype uint16) ([]byte, error) {
	buf := make([]byte, 0, 64)
	buf = binary.BigEndian.AppendUint16(buf, id)
	buf = binary.BigEndian.AppendUint16(buf, 0x0100) // RD
	buf = binary.BigEndian.AppendUint16(buf, 1)      // QDCOUNT
	buf = binary.BigEndian.AppendUint16(buf, 0)      // ANCOUNT
	buf = binary.BigEndian.AppendUint16(buf, 0)      // NSCOUNT
	buf = binary.BigEndian.AppendUint16(buf, 0)      // ARCOUNT
	var err error
	if buf, err = packName(buf, name); err != nil {
		return nil, err
	}
	buf = binary.BigEndian.AppendUint16(buf, qtype)
	buf = binary.BigEndian.AppendUint16(buf, ClassIN)
	return buf, nil
}

// Unpack 解析应答报文并做完整性校验：
// 结构畸形、问题段缺失或与查询不符均返回 ErrInvalid；
// TC 置位返回 ErrTruncated（调用方可回退 TCP）。
func Unpack(data []byte) (*Message, error) {
	if len(data) < 12 {
		return nil, ErrInvalid
	}
	m := &Message{}
	m.ID = binary.BigEndian.Uint16(data[0:2])
	flags := binary.BigEndian.Uint16(data[2:4])
	m.Response = flags&0x8000 != 0
	m.Opcode = uint16(flags>>11) & 0xF
	m.Truncated = flags&0x0200 != 0
	m.Rcode = int(flags & 0xF)
	qd := int(binary.BigEndian.Uint16(data[4:6]))
	an := int(binary.BigEndian.Uint16(data[6:8]))
	if !m.Response {
		return nil, fmt.Errorf("%w: not a response", ErrInvalid)
	}
	if m.Truncated {
		return nil, ErrTruncated
	}
	off := 12
	if qd > 0 {
		name, noff, err := unpackName(data, off)
		if err != nil {
			return nil, err
		}
		off = noff
		if off+4 > len(data) {
			return nil, ErrInvalid
		}
		m.Question = Question{
			Name:  name,
			Type:  binary.BigEndian.Uint16(data[off : off+2]),
			Class: binary.BigEndian.Uint16(data[off+2 : off+4]),
		}
		off += 4
	}
	for i := 0; i < an; i++ {
		name, noff, err := unpackName(data, off)
		if err != nil {
			return nil, err
		}
		off = noff
		if off+10 > len(data) {
			return nil, ErrInvalid
		}
		rec := Record{
			Name:  name,
			Type:  binary.BigEndian.Uint16(data[off : off+2]),
			Class: binary.BigEndian.Uint16(data[off+2 : off+4]),
			TTL:   binary.BigEndian.Uint32(data[off+4 : off+8]),
		}
		rdlen := int(binary.BigEndian.Uint16(data[off+8 : off+10]))
		off += 10
		if off+rdlen > len(data) {
			return nil, ErrInvalid
		}
		rdata := data[off : off+rdlen]
		switch rec.Type {
		case TypeA:
			if rdlen != 4 {
				return nil, ErrInvalid
			}
			rec.Data = net.IP(rdata).String()
		case TypeAAAA:
			if rdlen != 16 {
				return nil, ErrInvalid
			}
			rec.Data = net.IP(rdata).String()
		case TypeCNAME:
			target, _, err := unpackName(data, off)
			if err != nil {
				return nil, err
			}
			rec.Data = target
		default:
			// 其他类型跳过 rdata，不保留
			off += rdlen
			continue
		}
		off += rdlen
		m.Answers = append(m.Answers, rec)
	}
	return m, nil
}

// Pack 序列化报文（用于测试构造应答，不使用压缩）
func Pack(m *Message) ([]byte, error) {
	buf := make([]byte, 0, 128)
	buf = binary.BigEndian.AppendUint16(buf, m.ID)
	var flags uint16
	if m.Response {
		flags |= 0x8000
	}
	flags |= uint16(m.Opcode&0xF) << 11
	if m.Truncated {
		flags |= 0x0200
	}
	flags |= uint16(m.Rcode & 0xF)
	buf = binary.BigEndian.AppendUint16(buf, flags)
	buf = binary.BigEndian.AppendUint16(buf, 1) // QDCOUNT
	buf = binary.BigEndian.AppendUint16(buf, uint16(len(m.Answers)))
	buf = binary.BigEndian.AppendUint16(buf, 0)
	buf = binary.BigEndian.AppendUint16(buf, 0)
	var err error
	if buf, err = packName(buf, m.Question.Name); err != nil {
		return nil, err
	}
	buf = binary.BigEndian.AppendUint16(buf, m.Question.Type)
	buf = binary.BigEndian.AppendUint16(buf, m.Question.Class)
	for _, r := range m.Answers {
		if buf, err = packName(buf, r.Name); err != nil {
			return nil, err
		}
		buf = binary.BigEndian.AppendUint16(buf, r.Type)
		buf = binary.BigEndian.AppendUint16(buf, r.Class)
		buf = binary.BigEndian.AppendUint32(buf, r.TTL)
		var rdata []byte
		switch r.Type {
		case TypeA:
			rdata = net.ParseIP(r.Data).To4()
		case TypeAAAA:
			rdata = net.ParseIP(r.Data).To16()
		case TypeCNAME:
			if rdata, err = packName(nil, r.Data); err != nil {
				return nil, err
			}
		default:
			return nil, fmt.Errorf("%w: unsupported record type %d", ErrInvalid, r.Type)
		}
		if rdata == nil {
			return nil, fmt.Errorf("%w: bad rdata %q", ErrInvalid, r.Data)
		}
		buf = binary.BigEndian.AppendUint16(buf, uint16(len(rdata)))
		buf = append(buf, rdata...)
	}
	return buf, nil
}

// UnpackQuery 解析查询报文（供测试服务器使用）
func UnpackQuery(data []byte) (*Message, error) {
	if len(data) < 12 {
		return nil, ErrInvalid
	}
	m := &Message{}
	m.ID = binary.BigEndian.Uint16(data[0:2])
	flags := binary.BigEndian.Uint16(data[2:4])
	m.Response = flags&0x8000 != 0
	m.Opcode = uint16(flags>>11) & 0xF
	m.Rcode = int(flags & 0xF)
	qd := int(binary.BigEndian.Uint16(data[4:6]))
	if m.Response {
		return nil, fmt.Errorf("%w: not a query", ErrInvalid)
	}
	off := 12
	if qd > 0 {
		name, noff, err := unpackName(data, off)
		if err != nil {
			return nil, err
		}
		off = noff
		if off+4 > len(data) {
			return nil, ErrInvalid
		}
		m.Question = Question{
			Name:  name,
			Type:  binary.BigEndian.Uint16(data[off : off+2]),
			Class: binary.BigEndian.Uint16(data[off+2 : off+4]),
		}
	}
	return m, nil
}
