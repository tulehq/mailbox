package mailmime

import (
	"bytes"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"mime"
	"mime/multipart"
	"mime/quotedprintable"
	"net/textproto"
	"strings"
)

// MaxParts is how many MIME parts a message may have, multipart containers
// included, per SES's quota.
const MaxParts = 500

// maxDepth bounds how deep multiparts may nest, so a hostile message cannot
// recurse without end. The part limit bounds it already; this keeps the
// stack shallow.
const maxDepth = 50

// ErrTooManyParts is returned for a message of more than MaxParts parts.
var ErrTooManyParts = fmt.Errorf("the message has more than %d MIME parts", MaxParts)

// ErrTooDeep is returned for multiparts nested more than maxDepth deep.
var ErrTooDeep = errors.New("the message's multipart parts nest too deep")

// Parsed is what the retrieval API reports of a message: its top-level
// headers, decoded, its subject, its text and HTML bodies, and its
// attachments.
type Parsed struct {
	Headers     []Header
	Subject     string
	Text        string
	HTML        string
	Attachments []ParsedAttachment
}

// ParsedAttachment is one attachment of a message, decoded.
type ParsedAttachment struct {
	Name        string
	ContentType string
	Content     []byte
}

// Parse parses msg. The first text/plain and the first text/html part that
// are not attachments are the bodies; every other leaf part is an
// attachment. A part is an attachment when its disposition is attachment or
// it has a file name.
func Parse(msg []byte) (*Parsed, error) {
	fields, body, err := splitHeader(msg)
	if err != nil {
		return nil, err
	}
	p := &Parsed{Headers: make([]Header, 0, len(fields))}
	for _, f := range fields {
		p.Headers = append(p.Headers, Header{Name: f.name, Value: decodeHeader(f.value)})
	}
	h := mimeHeader(fields)
	p.Subject = decodeHeader(h.Get("Subject"))

	w := walker{parsed: p}
	if err = w.walk(h, bytes.NewReader(body), 0); err != nil {
		return nil, err
	}
	return p, nil
}

type walker struct {
	parsed  *Parsed
	parts   int
	hasText bool
	hasHTML bool
}

func (w *walker) walk(h textproto.MIMEHeader, body io.Reader, depth int) error {
	w.parts++
	if w.parts > MaxParts {
		return ErrTooManyParts
	}
	if depth > maxDepth {
		return ErrTooDeep
	}
	mediaType, params := contentType(h)
	if strings.HasPrefix(mediaType, "multipart/") {
		return w.walkMultipart(mediaType, params["boundary"], body, depth)
	}
	content, err := decodeTransfer(h.Get("Content-Transfer-Encoding"), body)
	if err != nil {
		return err
	}
	w.leaf(h, mediaType, params, content)
	return nil
}

func (w *walker) walkMultipart(mediaType, boundary string, body io.Reader, depth int) error {
	if boundary == "" {
		return fmt.Errorf("a %s part has no boundary", mediaType)
	}
	r := multipart.NewReader(body, boundary)
	for {
		part, err := r.NextRawPart()
		if errors.Is(err, io.EOF) {
			return nil
		}
		if err != nil {
			return fmt.Errorf("a %s part is malformed: %w", mediaType, err)
		}
		if err = w.walk(part.Header, part, depth+1); err != nil {
			return err
		}
	}
}

// leaf files a decoded leaf part as the text body, the HTML body or an
// attachment.
func (w *walker) leaf(
	h textproto.MIMEHeader,
	mediaType string,
	params map[string]string,
	content []byte,
) {
	disposition, dParams, _ := mime.ParseMediaType(h.Get("Content-Disposition"))
	name := dParams["filename"]
	if name == "" {
		name = params["name"]
	}
	isAttachment := disposition == "attachment" || name != ""

	switch {
	case !isAttachment && mediaType == "text/plain" && !w.hasText:
		w.hasText = true
		w.parsed.Text = decodeCharset(content, params["charset"])
	case !isAttachment && mediaType == "text/html" && !w.hasHTML:
		w.hasHTML = true
		w.parsed.HTML = decodeCharset(content, params["charset"])
	default:
		w.parsed.Attachments = append(w.parsed.Attachments, ParsedAttachment{
			Name:        decodeHeader(name),
			ContentType: mediaType,
			Content:     content,
		})
	}
}

// contentType returns a part's media type, lowercased, and its parameters.
// A part without one, or with one that does not parse, is text/plain, as
// RFC 2045 has it.
func contentType(h textproto.MIMEHeader) (string, map[string]string) {
	v := h.Get("Content-Type")
	if v == "" {
		return "text/plain", map[string]string{}
	}
	mediaType, params, err := mime.ParseMediaType(v)
	if err != nil {
		return "text/plain", map[string]string{}
	}
	return mediaType, params
}

// decodeTransfer reads body and undoes its Content-Transfer-Encoding. An
// encoding RFC 2045 does not define is read as it is, as identity encodings
// are.
func decodeTransfer(enc string, body io.Reader) ([]byte, error) {
	var r io.Reader
	switch strings.ToLower(strings.TrimSpace(enc)) {
	case "base64":
		r = base64.NewDecoder(base64.StdEncoding, body)
	case "quoted-printable":
		r = quotedprintable.NewReader(body)
	default:
		r = body
	}
	b, err := io.ReadAll(r)
	if err != nil {
		return nil, fmt.Errorf("a part's %s content does not decode: %w", enc, err)
	}
	return b, nil
}
