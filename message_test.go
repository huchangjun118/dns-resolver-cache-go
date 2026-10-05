package dnsres

import (
	"errors"
	"testing"
)

func TestEncodeParseRoundTrip(t *testing.T) {
	q, err := EncodeQuery(42, "Example.COM.", TypeA)
	if err != nil {
		t.Fatalf("EncodeQuery: %v", err)
	}
	m, err := ParseMessage(q)
	if err != nil {
		t.Fatalf("ParseMessage: %v", err)
	}
	if m.ID != 42 || m.Response {
		t.Fatalf("bad header: %+v", m)
	}
	if len(m.Questions) != 1 || m.Questions[0].Name != "example.com" || m.Questions[0].Type != TypeA {
		t.Fatalf("bad question: %+v", m.Questions)
	}
}

func TestParseResponseWithCompression(t *testing.T) {
	resp := buildResponse(7, "www.example.com", TypeA, RCodeSuccess, 300, "1.2.3.4", "5.6.7.8")
	m, err := ParseMessage(resp)
	if err != nil {
		t.Fatalf("ParseMessage: %v", err)
	}
	if !m.Response || m.RCode != RCodeSuccess {
		t.Fatalf("bad header: %+v", m)
	}
	if len(m.Answers) != 2 {
		t.Fatalf("expected 2 answers, got %d", len(m.Answers))
	}
	if m.Answers[0].Name != "www.example.com" || m.Answers[0].Data != "1.2.3.4" || m.Answers[0].TTL != 300 {
		t.Fatalf("bad answer: %+v", m.Answers[0])
	}
	if m.MinTTL() != 300 {
		t.Fatalf("MinTTL=%d, want 300", m.MinTTL())
	}
}

func TestParseMalformed(t *testing.T) {
	cases := map[string][]byte{
		"empty":          {},
		"short header":   make([]byte, 5),
		"truncated body": buildResponse(1, "a.b", TypeA, RCodeSuccess, 60, "1.2.3.4")[:20],
	}
	// 压缩指针成环。
	loop := make([]byte, 14)
	loop[5] = 1 // QDCOUNT=1
	loop[12] = 0xC0
	loop[13] = 12 // 指向自身
	cases["pointer loop"] = loop

	for name, buf := range cases {
		if _, err := ParseMessage(buf); err == nil {
			t.Errorf("%s: expected error", name)
		} else if !errors.Is(err, ErrMalformed) {
			t.Errorf("%s: expected ErrMalformed, got %v", name, err)
		}
	}
}

func TestValidateResponse(t *testing.T) {
	good, _ := ParseMessage(buildResponse(9, "x.y", TypeA, RCodeSuccess, 60, "1.1.1.1"))
	if err := ValidateResponse(good, 9, "x.y", TypeA); err != nil {
		t.Fatalf("good response rejected: %v", err)
	}

	badID, _ := ParseMessage(buildResponse(8, "x.y", TypeA, RCodeSuccess, 60, "1.1.1.1"))
	if err := ValidateResponse(badID, 9, "x.y", TypeA); !errors.Is(err, ErrMalformed) {
		t.Fatalf("id mismatch: %v", err)
	}

	truncated, _ := ParseMessage(buildResponse(9, "x.y", TypeA, RCodeSuccess, 60, "1.1.1.1"))
	truncated.Truncated = true
	if err := ValidateResponse(truncated, 9, "x.y", TypeA); !errors.Is(err, ErrTruncated) {
		t.Fatalf("truncated: %v", err)
	}

	wrongName, _ := ParseMessage(buildResponse(9, "other.y", TypeA, RCodeSuccess, 60, "1.1.1.1"))
	if err := ValidateResponse(wrongName, 9, "x.y", TypeA); !errors.Is(err, ErrMalformed) {
		t.Fatalf("question mismatch: %v", err)
	}
}
