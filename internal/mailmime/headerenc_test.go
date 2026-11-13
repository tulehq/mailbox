package mailmime

import (
	"bytes"
	"errors"
	"mime"
	"net/mail"
	"strings"
	"testing"
)

// maxLineLen is the longest line of msg, its line ending excluded.
func maxLineLen(msg []byte) int {
	n := 0
	for _, l := range bytes.Split(msg, []byte("\r\n")) {
		n = max(n, len(l))
	}
	return n
}

func simple(subject Text) *Message {
	return &Message{
		Date: date, MessageID: "id", From: "a@example.com", To: []string{"b@example.com"},
		Subject: subject, Text: &Text{Data: "body"},
	}
}

func TestLongSubjectsFold(t *testing.T) {
	tests := map[string]Text{
		"ASCII words":      {Data: strings.TrimSpace(strings.Repeat("word ", 400))},
		"one ASCII word":   {Data: strings.Repeat("x", 2000)},
		"UTF-8":            {Data: strings.Repeat("é", 600)},
		"ISO-8859-1":       {Data: strings.Repeat("é", 600), Charset: "ISO-8859-1"},
		"mixed and spaced": {Data: strings.TrimSpace(strings.Repeat("Grüße an alle, ", 100))},
		"already encoded":  {Data: strings.TrimSpace(strings.Repeat("=?UTF-8?B?w6k=?= ", 100))},
	}
	for name, subject := range tests {
		t.Run(name, func(t *testing.T) {
			msg, err := Build(simple(subject))
			if err != nil {
				t.Fatalf("build: %v", err)
			}
			if n := maxLineLen(msg); n > foldAt {
				t.Fatalf("longest line is %d characters, want at most %d", n, foldAt)
			}
			p, err := Parse(msg)
			if err != nil {
				t.Fatalf("parse: %v", err)
			}
			want := subject.Data
			if name == "already encoded" {
				want, _ = new(mime.WordDecoder).DecodeHeader(subject.Data)
			}
			if p.Subject != want {
				t.Fatalf("subject round-trips as %q, want %q", p.Subject[:min(80, len(p.Subject))],
					want[:min(80, len(want))])
			}
		})
	}
}

func TestANonASCIIFromNameIsEncoded(t *testing.T) {
	m := simple(Text{Data: "hi"})
	m.From = "Jösé Ünïcode <a@example.com>"
	msg, err := Build(m)
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	from := strings.SplitN(string(msg), "\r\n", 2)[0]
	if !isPrintableASCII(from) {
		t.Fatalf("From line %q is not ASCII", from)
	}
	r, err := mail.ReadMessage(bytes.NewReader(msg))
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	a, err := r.Header.AddressList("From")
	if err != nil || a[0].Name != "Jösé Ünïcode" || a[0].Address != "a@example.com" {
		t.Fatalf("From = %v, %v", a, err)
	}
}

func TestAttachmentHeadersCannotBeInjected(t *testing.T) {
	for name, a := range map[string]Attachment{
		"description": {FileName: "f.txt", Description: "d\r\n\r\ninjected body"},
		"content ID":  {FileName: "f.txt", ContentID: "c\r\nX-Evil: 1"},
		"file name":   {FileName: "f\r\nX-Evil: 1.txt"},
	} {
		m := simple(Text{Data: "x"})
		a.Content = []byte("x")
		m.Attachments = []Attachment{a}
		if _, err := Build(m); !errors.Is(err, errControl) {
			t.Errorf("%s with CRLF = %v, want errControl", name, err)
		}
	}
}

func TestLongAndNonASCIIAttachmentHeadersFoldAndRoundTrip(t *testing.T) {
	name := strings.Repeat("ñ", 255) + ".txt"
	m := simple(Text{Data: "x"})
	m.Attachments = []Attachment{{
		FileName: name, Description: strings.Repeat("déscription ", 80), Content: []byte("x"),
	}}
	msg, err := Build(m)
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	if n := maxLineLen(msg); n > foldAt {
		t.Fatalf("longest line is %d characters, want at most %d", n, foldAt)
	}
	if !isPrintableASCII(strings.ReplaceAll(strings.ReplaceAll(string(msg), "\r", ""), "\n", "")) {
		t.Fatal("the message is not ASCII")
	}
	p, err := Parse(msg)
	if err != nil || len(p.Attachments) != 1 || p.Attachments[0].Name != name {
		t.Fatalf("parsed attachments = %+v, %v", p.Attachments, err)
	}
}

func TestAContentTypeMustBeTypeAndSubtype(t *testing.T) {
	m := simple(Text{Data: "x"})
	m.Attachments = []Attachment{{FileName: "f.bin", ContentType: "text", Content: []byte("x")}}
	if _, err := Build(m); err == nil {
		t.Fatal("a ContentType without a subtype was accepted")
	}
}

func TestSevenBitRefusesBareLF(t *testing.T) {
	m := simple(Text{Data: "x"})
	m.Attachments = []Attachment{
		{FileName: "f.txt", Content: []byte("a\nb\n"), Encoding: EncodingSevenBit},
	}
	if _, err := Build(m); !errors.Is(err, ErrNotSevenBit) {
		t.Fatalf("SEVEN_BIT with bare LF = %v, want ErrNotSevenBit", err)
	}
	m.Attachments[0].Content = []byte("a\r\nb\r\n")
	msg, err := Build(m)
	if err != nil {
		t.Fatalf("SEVEN_BIT with CRLF: %v", err)
	}
	p, err := Parse(msg)
	if err != nil || string(p.Attachments[0].Content) != "a\r\nb\r\n" {
		t.Fatalf("parsed = %q, %v", p.Attachments[0].Content, err)
	}
}

func TestALongCustomHeaderFoldsAfterItsName(t *testing.T) {
	m := simple(Text{Data: "x"})
	name, value := "X-"+strings.Repeat("n", 124), strings.Repeat("v", 995)
	m.Headers = []Header{{Name: name, Value: value}}
	msg, err := Build(m)
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	if n := maxLineLen(msg); n > maxLineLength-2 {
		t.Fatalf("longest line is %d characters, want at most %d", n, maxLineLength-2)
	}
	p, err := Parse(msg)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	for _, h := range p.Headers {
		if h.Name == name && h.Value != value {
			t.Fatalf("header value round-trips as %d characters, want %d", len(h.Value), len(value))
		}
	}
}
