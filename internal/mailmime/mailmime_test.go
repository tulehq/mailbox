package mailmime

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"mime"
	"mime/multipart"
	"net/mail"
	"regexp"
	"strings"
	"testing"
	"time"
)

var date = time.Date(2026, 11, 13, 10, 0, 0, 0, time.FixedZone("x", 3600))

func TestNewMessageIDHasSESShape(t *testing.T) {
	id, err := NewMessageID(date)
	if err != nil {
		t.Fatalf("new message ID: %v", err)
	}
	re := regexp.MustCompile(
		`^0100[0-9a-f]{12}-[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-` +
			`[0-9a-f]{12}-000000$`,
	)
	if !re.MatchString(id) {
		t.Fatalf("message ID %q does not have SES's shape", id)
	}
	if prefix := fmt.Sprintf("0100%012x", date.UnixMilli()); !strings.HasPrefix(id, prefix) {
		t.Fatalf("message ID %q does not start with %s, the time in milliseconds", id, prefix)
	}
	other, err := NewMessageID(date)
	if err != nil || other == id {
		t.Fatalf("second ID %q equals the first or failed: %v", other, err)
	}
}

func TestBuildSimpleTextAndHTML(t *testing.T) {
	msg, err := Build(&Message{
		Date:      date,
		MessageID: "0100-abc-000000",
		From:      "Sender <sender@example.com>",
		ReplyTo:   []string{"reply@example.com"},
		To:        []string{"a@example.com", "B <b@example.com>"},
		Cc:        []string{"c@example.com"},
		Subject:   Text{Data: "Grüße"},
		Text:      &Text{Data: "plain\nline"},
		HTML:      &Text{Data: "<p>héllo</p>"},
		Headers:   []Header{{Name: "X-Custom", Value: "yes"}},
	})
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	m, err := mail.ReadMessage(bytes.NewReader(msg))
	if err != nil {
		t.Fatalf("read message: %v", err)
	}
	requireSimpleHeaders(t, m.Header)
	types, bodies := readParts(t, m)
	if strings.Join(types, ",") != "text/plain; charset=UTF-8,text/html; charset=UTF-8" {
		t.Fatalf("part types = %v", types)
	}
	if bodies[0] != "plain\r\nline" || bodies[1] != "<p>héllo</p>" {
		t.Fatalf("bodies = %q", bodies)
	}
}

// requireSimpleHeaders checks the header TestBuildSimpleTextAndHTML builds.
func requireSimpleHeaders(t *testing.T, h mail.Header) {
	t.Helper()
	for name, want := range map[string]string{
		"From":         "Sender <sender@example.com>",
		"Reply-To":     "reply@example.com",
		"Cc":           "c@example.com",
		"X-Custom":     "yes",
		"MIME-Version": "1.0",
		"Date":         "Fri, 13 Nov 2026 09:00:00 +0000",
		"Message-ID":   "<0100-abc-000000@email.amazonses.com>",
	} {
		if got := h.Get(name); got != want {
			t.Errorf("%s = %q, want %q", name, got, want)
		}
	}
	to, err := h.AddressList("To")
	if err != nil || len(to) != 2 || to[1].Address != "b@example.com" {
		t.Errorf("To = %v, %v", to, err)
	}
	if subject, _ := new(mime.WordDecoder).DecodeHeader(h.Get("Subject")); subject != "Grüße" {
		t.Errorf("subject = %q", subject)
	}
	if h.Get("Bcc") != "" {
		t.Error("the message has a Bcc header")
	}
}

// readParts reads the parts of a multipart/alternative message with
// mime/multipart, and returns their content types and bodies.
func readParts(t *testing.T, m *mail.Message) ([]string, []string) {
	t.Helper()
	mediaType, params, err := mime.ParseMediaType(m.Header.Get("Content-Type"))
	if err != nil || mediaType != "multipart/alternative" {
		t.Fatalf("content type = %s, %v", mediaType, err)
	}
	r := multipart.NewReader(m.Body, params["boundary"])
	var types, bodies []string
	for {
		p, pErr := r.NextPart()
		if errors.Is(pErr, io.EOF) {
			return types, bodies
		}
		if pErr != nil {
			t.Fatalf("next part: %v", pErr)
		}
		b, _ := io.ReadAll(p)
		types = append(types, p.Header.Get("Content-Type"))
		bodies = append(bodies, string(b))
	}
}

func TestBuildAttachmentsKeepTheirBytes(t *testing.T) {
	csv := []byte("id,name\n1,Anaya\n2,Liu\n")
	bin := []byte{0, 1, 2, 0xff, '\n'}
	msg, err := Build(&Message{
		Date: date, MessageID: "id", From: "s@example.com", To: []string{"t@example.com"},
		Subject: Text{Data: "files"},
		Text:    &Text{Data: "see attached"},
		Attachments: []Attachment{
			{Content: csv, FileName: "people.csv"},
			{Content: bin, FileName: "blob.bin", Encoding: EncodingQuotedPrintable},
			{
				Content: []byte("logo"), FileName: "logo.png", Disposition: DispositionInline,
				ContentID: "logo1",
			},
		},
	})
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	p, err := Parse(msg)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if p.Text != "see attached" {
		t.Fatalf("text = %q", p.Text)
	}
	if len(p.Attachments) != 3 {
		t.Fatalf("attachments = %d, want 3", len(p.Attachments))
	}
	// The inline attachment comes first: it sits with the body, in
	// multipart/related, ahead of the others.
	want := []ParsedAttachment{
		{Name: "logo.png", Content: []byte("logo")},
		{Name: "people.csv", Content: csv},
		{Name: "blob.bin", Content: bin},
	}
	for i, w := range want {
		a := p.Attachments[i]
		if a.Name != w.Name || !bytes.Equal(a.Content, w.Content) {
			t.Errorf("attachment %d = %s %q, want %s %q", i, a.Name, a.Content, w.Name, w.Content)
		}
	}
	// Only image/png is in Go's own extension table; the other types depend
	// on the system's MIME tables.
	if p.Attachments[0].ContentType != "image/png" {
		t.Errorf("logo.png content type = %s, want image/png from its extension",
			p.Attachments[0].ContentType)
	}
	if !bytes.Contains(msg, []byte("multipart/related")) {
		t.Error("the inline attachment is not in multipart/related")
	}
}

func TestBuildRefusesSevenBitBinary(t *testing.T) {
	_, err := Build(&Message{
		Date: date, MessageID: "id", Subject: Text{Data: "x"},
		Attachments: []Attachment{
			{Content: []byte{0, 0xff}, FileName: "b", Encoding: EncodingSevenBit},
		},
	})
	if !errors.Is(err, ErrNotSevenBit) {
		t.Fatalf("binary content as SEVEN_BIT = %v, want ErrNotSevenBit", err)
	}
}

func TestBuildEncodesInTheRequestedCharset(t *testing.T) {
	msg, err := Build(&Message{
		Date: date, MessageID: "id", Subject: Text{Data: "é", Charset: "ISO-8859-1"},
		Text: &Text{Data: "café", Charset: "ISO-8859-1"},
	})
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	if !bytes.Contains(msg, []byte("caf=E9")) {
		t.Fatalf("the text is not ISO-8859-1 quoted-printable:\n%s", msg)
	}
	p, err := Parse(msg)
	if err != nil || p.Text != "café" || p.Subject != "é" {
		t.Fatalf("parsed = %+v, %v", p, err)
	}
	if _, err = Build(&Message{
		Date: date, MessageID: "id", Text: &Text{Data: "x", Charset: "no-such-charset"},
	}); err == nil {
		t.Fatal("build with an unknown charset succeeded")
	}
}

const rawMessage = "From: Sender <sender@example.com>\r\n" +
	"To: a@example.com\r\n" +
	"Bcc: hidden@example.com\r\n" +
	"Message-ID: <mine@example.com>\r\n" +
	"Date: Mon, 1 Jan 2001 00:00:00 +0000\r\n" +
	"X-SES-CONFIGURATION-SET: cs\r\n" +
	"X-SES-MESSAGE-TAGS: a=1, b=2\r\n" +
	"Subject: =?utf-8?Q?caf=C3=A9?=\r\n" +
	"\r\n" +
	"Body.\r\n"

func TestPrepareRawAppliesWhatSESChanges(t *testing.T) {
	raw, err := PrepareRaw([]byte(rawMessage), "0100-id-000000", date)
	if err != nil {
		t.Fatalf("prepare: %v", err)
	}
	if raw.From != "Sender <sender@example.com>" || raw.To != "a@example.com" ||
		raw.Bcc != "hidden@example.com" || raw.ConfigurationSet != "cs" ||
		raw.Tags != "a=1, b=2" {
		t.Fatalf("read = %+v", raw)
	}
	requirePrepared(t, string(raw.MIME))
	p, err := Parse(raw.MIME)
	if err != nil || p.Subject != "café" || p.Text != "Body.\r\n" {
		t.Fatalf("parsed = %+v, %v", p, err)
	}
}

// requirePrepared checks what PrepareRaw made of rawMessage.
func requirePrepared(t *testing.T, out string) {
	t.Helper()
	for _, gone := range []string{"Bcc:", "mine@example.com", "2001", "X-SES-"} {
		if strings.Contains(out, gone) {
			t.Errorf("the prepared message still has %q:\n%s", gone, out)
		}
	}
	for _, kept := range []string{
		"From: Sender <sender@example.com>\r\nTo: a@example.com\r\n",
		"Subject: =?utf-8?Q?caf=C3=A9?=\r\n",
		"Date: Fri, 13 Nov 2026 09:00:00 +0000\r\n",
		"Message-ID: <0100-id-000000@email.amazonses.com>\r\n\r\nBody.\r\n",
	} {
		if !strings.Contains(out, kept) {
			t.Errorf("the prepared message lacks %q:\n%s", kept, out)
		}
	}
}

func TestPrepareRawRefusesMalformedMessages(t *testing.T) {
	tests := map[string]string{
		"no blank line":    "Subject: x\r\n",
		"not a header":     "this is not a header\r\n\r\nbody",
		"continuation":     " folded\r\nSubject: x\r\n\r\nbody",
		"long line":        "Subject: x\r\n\r\n" + strings.Repeat("x", 999) + "\r\n",
		"no boundary":      "Content-Type: multipart/mixed\r\n\r\nbody",
		"broken multipart": "Content-Type: multipart/mixed; boundary=b\r\n\r\n--b\r\nno end",
	}
	for name, msg := range tests {
		t.Run(name, func(t *testing.T) {
			if _, err := PrepareRaw([]byte(msg), "id", date); err == nil {
				t.Fatal("prepare succeeded")
			}
		})
	}
}

func TestParseCountsParts(t *testing.T) {
	var b strings.Builder
	b.WriteString("Content-Type: multipart/mixed; boundary=b\r\n\r\n")
	for range MaxParts {
		b.WriteString("--b\r\nContent-Type: text/plain\r\n\r\nx\r\n")
	}
	b.WriteString("--b--\r\n")
	if _, err := Parse([]byte(b.String())); !errors.Is(err, ErrTooManyParts) {
		t.Fatalf("parse of %d parts = %v, want ErrTooManyParts", MaxParts+1, err)
	}
}

func TestBuildGivesAnInlineAttachmentItsContentID(t *testing.T) {
	msg, err := Build(&Message{
		Date: date, MessageID: "id", Subject: Text{Data: "x"}, HTML: &Text{Data: "<img>"},
		Attachments: []Attachment{{
			Content: []byte("png"), FileName: "logo.png", Disposition: DispositionInline,
			ContentID: "logo1",
		}},
	})
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	if !bytes.Contains(msg, []byte("Content-ID: <logo1>")) ||
		!bytes.Contains(msg, []byte("Content-Disposition: inline")) {
		t.Fatalf("the inline attachment lacks its Content-ID or disposition:\n%s", msg)
	}
}

func TestPrepareRawRefusesASecondFrom(t *testing.T) {
	msg := []byte("From: a@example.com\r\nFrom: b@example.com\r\nTo: c@example.com\r\n" +
		"Subject: s\r\n\r\nBody.\r\n")
	if _, err := PrepareRaw(msg, "id", time.Now()); err == nil {
		t.Fatal("a message with two From headers was prepared")
	}
}

func TestPrepareRawTakesTheFirstSESHeader(t *testing.T) {
	// "If you include multiple instances of an X-header, Amazon SES uses
	// only the first instance."
	msg := []byte("From: a@example.com\r\nTo: c@example.com\r\nSubject: s\r\n" +
		"X-SES-CONFIGURATION-SET: first\r\nX-SES-CONFIGURATION-SET: second\r\n" +
		"X-SES-MESSAGE-TAGS: a=1\r\nX-SES-MESSAGE-TAGS: a=2\r\n\r\nBody.\r\n")
	raw, err := PrepareRaw(msg, "id", time.Now())
	if err != nil {
		t.Fatalf("prepare: %v", err)
	}
	if raw.ConfigurationSet != "first" || raw.Tags != "a=1" {
		t.Fatalf("configuration set %q, tags %q; want the first of each", raw.ConfigurationSet,
			raw.Tags)
	}
}

func TestPrepareRawRefusesHeaderBytesReadersDisagreeOn(t *testing.T) {
	const rest = "To: to@example.com\r\nSubject: s\r\n\r\nBody.\r\n"
	for name, header := range map[string]string{
		// A reader that ends lines on a bare CR sees a From this parser
		// would not.
		"a bare CR hiding a From":    "X-A: x\rFrom: ceo@victim.com\r\nFrom: me@allowed.com\r\n",
		"a bare CR hiding a Cc":      "From: me@allowed.com\r\nX-A: x\rCc: extra@victim.com\r\n",
		"a CR before the blank line": "From: me@allowed.com\r\n\r\r\n",
		"a NUL":                      "From: me@allowed.com\x00\r\n",
		"a vertical tab":             "X-A: x\vFrom: ceo@victim.com\r\nFrom: me@allowed.com\r\n",
		"a form feed":                "X-A: x\fy\r\nFrom: me@allowed.com\r\n",
		"a DEL":                      "X-A: x\x7fy\r\nFrom: me@allowed.com\r\n",
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := PrepareRaw([]byte(header+rest), "id", time.Now()); err == nil {
				t.Fatal("prepared")
			}
		})
	}
	for name, msg := range map[string]string{
		"LF line ends":          "From: me@allowed.com\nTo: to@example.com\nSubject: s\n\nBody.\n",
		"a tab in a value":      "From: me@allowed.com\r\nSubject: a\tb\r\n\r\nBody.\r\n",
		"a bare CR in the body": "From: me@allowed.com\r\nSubject: s\r\n\r\nBo\rdy.\r\n",
		"UTF-8 in a value":      "From: me@allowed.com\r\nSubject: caf\xc3\xa9\r\n\r\nBody.\r\n",
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := PrepareRaw([]byte(msg), "id", time.Now()); err != nil {
				t.Fatalf("refused: %v", err)
			}
		})
	}
}
