//go:build e2e

package e2e

import (
	"bytes"
	"encoding/base64"
	"io"
	"mime"
	"mime/multipart"
	"mime/quotedprintable"
	"net/mail"
	"net/textproto"
	"strings"
	"testing"
	"time"
)

// parsedMIME is a stored message as a recipient's mail reader sees it,
// parsed with net/mail and mime/multipart.
type parsedMIME struct {
	Header mail.Header
	// Leaves are the parts that hold content, in order, each decoded from
	// its Content-Transfer-Encoding.
	Leaves []leaf
}

// leaf is a part of a message that is not itself multipart.
type leaf struct {
	Header      textproto.MIMEHeader
	Params      map[string]string
	DispParams  map[string]string
	MediaType   string
	Disposition string
	// Parents are the media types of the multipart parts that enclose the
	// leaf, outermost first.
	Parents []string
	Body    []byte
}

// parseMIME parses raw as RFC 5322 and MIME, failing the test if a reader
// could not.
func parseMIME(t *testing.T, raw []byte) *parsedMIME {
	t.Helper()

	msg, err := mail.ReadMessage(bytes.NewReader(raw))
	requireNoErr(t, err, "parse the message with net/mail")
	p := &parsedMIME{Header: msg.Header}
	p.walk(t, textproto.MIMEHeader(msg.Header), msg.Body, nil)
	return p
}

func (p *parsedMIME) walk(t *testing.T, h textproto.MIMEHeader, body io.Reader, parents []string) {
	t.Helper()

	mediaType, params := "text/plain", map[string]string{"charset": "us-ascii"}
	if ct := h.Get("Content-Type"); ct != "" {
		var err error
		mediaType, params, err = mime.ParseMediaType(ct)
		requireNoErr(t, err, "parse Content-Type "+ct)
	}

	if strings.HasPrefix(mediaType, "multipart/") {
		r := multipart.NewReader(body, params["boundary"])
		for {
			part, err := r.NextRawPart()
			if err == io.EOF {
				return
			}
			requireNoErr(t, err, "read a part of "+mediaType)
			p.walk(t, part.Header, part, append(append([]string(nil), parents...), mediaType))
		}
	}

	l := leaf{
		Header:    h,
		MediaType: mediaType,
		Params:    params,
		Parents:   parents,
		Body:      decodeBody(t, h.Get("Content-Transfer-Encoding"), body),
	}
	if cd := h.Get("Content-Disposition"); cd != "" {
		var err error
		l.Disposition, l.DispParams, err = mime.ParseMediaType(cd)
		requireNoErr(t, err, "parse Content-Disposition "+cd)
	}
	p.Leaves = append(p.Leaves, l)
}

func decodeBody(t *testing.T, encoding string, body io.Reader) []byte {
	t.Helper()

	var r io.Reader
	switch strings.ToLower(strings.TrimSpace(encoding)) {
	case "base64":
		r = base64.NewDecoder(base64.StdEncoding, &stripSpace{r: body})
	case "quoted-printable":
		r = quotedprintable.NewReader(body)
	default:
		r = body
	}
	b, err := io.ReadAll(r)
	requireNoErr(t, err, "decode a "+encoding+" body")
	return b
}

// stripSpace drops the line breaks and spaces of a base64 body.
type stripSpace struct {
	r io.Reader
}

func (s *stripSpace) Read(p []byte) (int, error) {
	n, err := s.r.Read(p)
	j := 0
	for _, c := range p[:n] {
		if c != '\r' && c != '\n' && c != ' ' && c != '\t' {
			p[j] = c
			j++
		}
	}
	return j, err //nolint:wrapcheck // io.EOF must pass through as it is
}

// bodies returns the content of the leaves of mediaType that are not
// attachments.
func (p *parsedMIME) bodies(mediaType string) []string {
	var out []string
	for _, l := range p.Leaves {
		if l.MediaType == mediaType && l.Disposition != "attachment" {
			out = append(out, string(l.Body))
		}
	}
	return out
}

// attachments returns the leaves that carry a file name.
func (p *parsedMIME) attachments() []leaf {
	var out []leaf
	for _, l := range p.Leaves {
		if l.DispParams["filename"] != "" || l.Params["name"] != "" {
			out = append(out, l)
		}
	}
	return out
}

// subject returns the decoded Subject.
func (p *parsedMIME) subject(t *testing.T) string {
	t.Helper()
	s, err := new(mime.WordDecoder).DecodeHeader(p.Header.Get("Subject"))
	requireNoErr(t, err, "decode the subject")
	return s
}

// addresses returns the bare addresses of an address header, empty when it
// is absent.
func (p *parsedMIME) addresses(t *testing.T, name string) []string {
	t.Helper()
	if p.Header.Get(name) == "" {
		return nil
	}
	list, err := p.Header.AddressList(name)
	requireNoErr(t, err, "parse the "+name+" header")
	out := make([]string, 0, len(list))
	for _, a := range list {
		out = append(out, a.Address)
	}
	return out
}

// requireBody fails unless the message has exactly one body of mediaType
// and it is want.
func (p *parsedMIME) requireBody(t *testing.T, mediaType, want string) {
	t.Helper()
	got := p.bodies(mediaType)
	if len(got) != 1 {
		t.Fatalf("%s bodies: got %d (%q), want 1", mediaType, len(got), got)
	}
	requireEqual(
		t,
		strings.TrimRight(got[0], "\r\n"),
		strings.TrimRight(want, "\r\n"),
		mediaType+" body",
	)
}

// requireNoBody fails if the message has a body of mediaType.
func (p *parsedMIME) requireNoBody(t *testing.T, mediaType string) {
	t.Helper()
	if got := p.bodies(mediaType); len(got) != 0 {
		t.Fatalf("%s bodies: got %q, want none", mediaType, got)
	}
}

// requireSESHeaders fails unless the message carries the headers SES adds
// to a message it assembles: Message-ID, a Date in the send window, and
// MIME-Version 1.0 (Email format in Amazon SES; Amazon SES header fields).
func (p *parsedMIME) requireSESHeaders(t *testing.T, sent time.Time) {
	t.Helper()

	id := p.Header.Get("Message-ID")
	if !strings.HasPrefix(id, "<") || !strings.HasSuffix(id, ">") || !strings.Contains(id, "@") {
		t.Fatalf("Message-ID %q is not a msg-id", id)
	}
	requireEqual(t, strings.TrimSpace(p.Header.Get("MIME-Version")), "1.0", "MIME-Version")
	requireDateNear(t, p.Header, sent)
}

// requireDateNear fails unless the Date header parses and is within a
// minute of sent.
func requireDateNear(t *testing.T, h mail.Header, sent time.Time) time.Time {
	t.Helper()
	date, err := h.Date()
	requireNoErr(t, err, "parse the Date header")
	if d := date.Sub(sent); d < -time.Minute || d > time.Minute {
		t.Fatalf("Date %s is %s from the send at %s", date, d, sent)
	}
	return date
}

// requireNoHeader fails if the message's header holds name.
func (p *parsedMIME) requireNoHeader(t *testing.T, name string) {
	t.Helper()
	if v := p.Header[textproto.CanonicalMIMEHeaderKey(name)]; len(v) != 0 {
		t.Fatalf("header %s: got %q, want none", name, v)
	}
}

// hasParent reports whether l is enclosed in a part of mediaType.
func (l leaf) hasParent(mediaType string) bool {
	for _, p := range l.Parents {
		if p == mediaType {
			return true
		}
	}
	return false
}
