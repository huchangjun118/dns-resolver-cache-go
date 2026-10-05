package dnsmsg

import "testing"

func TestQueryResponseRoundTrip(t *testing.T) {
	q, err := PackQuery(0x1234, "www.example.com", TypeA)
	if err != nil {
		t.Fatal(err)
	}
	resp := &Message{
		ID:       0x1234,
		Response: true,
		Question: Question{Name: "www.example.com", Type: TypeA, Class: ClassIN},
		Answers: []Record{
			{Name: "www.example.com", Type: TypeA, Class: ClassIN, TTL: 300, Data: "192.0.2.1"},
			{Name: "www.example.com", Type: TypeAAAA, Class: ClassIN, TTL: 60, Data: "2001:db8::1"},
		},
	}
	_ = q
	packed, err := Pack(resp)
	if err != nil {
		t.Fatal(err)
	}
	got, err := Unpack(packed)
	if err != nil {
		t.Fatal(err)
	}
	if got.ID != 0x1234 || got.Question.Name != "www.example.com" || len(got.Answers) != 2 {
		t.Fatalf("unexpected: %+v", got)
	}
	if got.Answers[0].Data != "192.0.2.1" || got.Answers[0].TTL != 300 {
		t.Fatalf("bad answer: %+v", got.Answers[0])
	}
	if got.Answers[1].Data != "2001:db8::1" {
		t.Fatalf("bad AAAA: %+v", got.Answers[1])
	}
}

func TestUnpackTruncated(t *testing.T) {
	m := &Message{ID: 1, Response: true, Truncated: true,
		Question: Question{Name: "a.b", Type: TypeA, Class: ClassIN}}
	packed, _ := Pack(m)
	if _, err := Unpack(packed); err != ErrTruncated {
		t.Fatalf("want ErrTruncated, got %v", err)
	}
}

func TestUnpackGarbage(t *testing.T) {
	if _, err := Unpack([]byte{1, 2, 3}); err != ErrInvalid {
		t.Fatalf("want ErrInvalid, got %v", err)
	}
	// 非应答报文
	q, _ := PackQuery(1, "a.b", TypeA)
	if _, err := Unpack(q); err == nil {
		t.Fatal("want error for query packet")
	}
}

func TestUnpackCompressionPointer(t *testing.T) {
	// 手工构造：answer 的 name 用指针指回 question 名
	q, _ := PackQuery(7, "x.example", TypeA)
	// 把查询改成应答：flags 置 QR
	q[2] = 0x80
	q[7] = 1 // ANCOUNT=1
	ans := []byte{0xC0, 0x0C, 0, 1, 0, 1, 0, 0, 0, 30, 0, 4, 127, 0, 0, 1}
	pkt := append(q, ans...)
	m, err := Unpack(pkt)
	if err != nil {
		t.Fatal(err)
	}
	if len(m.Answers) != 1 || m.Answers[0].Name != "x.example" || m.Answers[0].Data != "127.0.0.1" || m.Answers[0].TTL != 30 {
		t.Fatalf("bad: %+v", m.Answers)
	}
}
