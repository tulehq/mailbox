package mailmime

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"mime"
	"mime/quotedprintable"
	"path"
	"strings"
	"time"
)

// DefaultCharset is the character set of a text whose request names none.
const DefaultCharset = "UTF-8"

// The attachment settings the SES API model enumerates.
const (
	DispositionAttachment = "ATTACHMENT"
	DispositionInline     = "INLINE"

	EncodingBase64          = "BASE64"
	EncodingQuotedPrintable = "QUOTED_PRINTABLE"
	EncodingSevenBit        = "SEVEN_BIT"
)

// Text is a text and the character set to send it in, DefaultCharset when
// empty.
type Text struct {
	Data    string
	Charset string
}

// Header is a header field to add to a built message.
type Header struct {
	Name  string
	Value string
}

// Attachment is a file to attach. An empty ContentType is derived from the
// file name's extension, an empty Disposition is DispositionAttachment, and
// an empty Encoding picks 7bit for content that is 7-bit text in short
// CRLF-ended lines, which goes into the message unchanged, and base64 for
// any other, so the recipient's copy is the same bytes.
type Attachment struct {
	FileName    string
	ContentType string
	Disposition string
	Description string
	ContentID   string
	Encoding    string
	Content     []byte
}

// Message is what SES assembles a message from for Simple and Template
// content. Text and HTML are nil when absent. Addresses are as the request
// gives them.
type Message struct {
	Date        time.Time
	MessageID   string
	From        string
	ReplyTo     []string
	To          []string
	Cc          []string
	Subject     Text
	Text        *Text
	HTML        *Text
	Headers     []Header
	Attachments []Attachment
}

// Build assembles m as a MIME message, the way SES does: the address and
// subject headers, the headers the request adds, MIME-Version, Date and
// Message-ID; a text and an HTML body as multipart/alternative; inline
// attachments with the body in multipart/related; and other attachments
// with all of it in multipart/mixed. Bcc recipients get no header.
func Build(m *Message) ([]byte, error) {
	var b bytes.Buffer
	if m.From != "" {
		writeAddresses(&b, "From", []string{m.From})
	}
	writeAddresses(&b, "Reply-To", m.ReplyTo)
	writeAddresses(&b, "To", m.To)
	writeAddresses(&b, "Cc", m.Cc)
	subject, err := encodeWord(m.Subject)
	if err != nil {
		return nil, err
	}
	writeField(&b, "Subject", subject)
	for _, h := range m.Headers {
		writeField(&b, h.Name, h.Value)
	}
	writeField(&b, "MIME-Version", "1.0")
	writeField(&b, "Date", HeaderDate(m.Date))
	writeField(&b, "Message-ID", HeaderMessageID(m.MessageID))

	body, err := buildBody(m)
	if err != nil {
		return nil, err
	}
	if err = body.write(&b); err != nil {
		return nil, err
	}
	// Every header is folded and every body line is short, so this only
	// guards that the message is within SES's line limit.
	if err = checkLineLengths(b.Bytes()); err != nil {
		return nil, err
	}
	return b.Bytes(), nil
}

// entity is a MIME entity: its content headers and either content or parts.
type entity struct {
	subtype string
	headers []Header
	content []byte
	parts   []*entity
}

func (e *entity) write(b *bytes.Buffer) error {
	for _, h := range e.headers {
		writeField(b, h.Name, h.Value)
	}
	if e.parts == nil {
		b.WriteString("\r\n")
		b.Write(e.content)
		return nil
	}
	boundary, err := newBoundary()
	if err != nil {
		return err
	}
	writeField(b, "Content-Type", mime.FormatMediaType("multipart/"+e.subtype,
		map[string]string{"boundary": boundary}))
	b.WriteString("\r\n")
	for _, p := range e.parts {
		b.WriteString("--" + boundary + "\r\n")
		if err = p.write(b); err != nil {
			return err
		}
		b.WriteString("\r\n")
	}
	b.WriteString("--" + boundary + "--\r\n")
	return nil
}

func buildBody(m *Message) (*entity, error) {
	body, err := textBody(m)
	if err != nil {
		return nil, err
	}
	var inline, attached []*entity
	for i := range m.Attachments {
		a := &m.Attachments[i]
		e, aErr := attachmentEntity(a)
		if aErr != nil {
			return nil, aErr
		}
		if a.Disposition == DispositionInline {
			inline = append(inline, e)
		} else {
			attached = append(attached, e)
		}
	}
	if len(inline) > 0 {
		body = &entity{subtype: "related", parts: append([]*entity{body}, inline...)}
	}
	if len(attached) > 0 {
		body = &entity{subtype: "mixed", parts: append([]*entity{body}, attached...)}
	}
	return body, nil
}

// textBody is the text and HTML of m: one part, both in
// multipart/alternative, or an empty text when m has neither, which keeps
// the message valid MIME, since SES requires no body part.
func textBody(m *Message) (*entity, error) {
	var texts []*entity
	for _, t := range []struct {
		text    *Text
		subtype string
	}{{m.Text, "plain"}, {m.HTML, "html"}} {
		if t.text == nil {
			continue
		}
		e, err := textEntity(t.text, t.subtype)
		if err != nil {
			return nil, err
		}
		texts = append(texts, e)
	}
	switch len(texts) {
	case 0:
		return &entity{headers: []Header{
			{"Content-Type", "text/plain; charset=" + DefaultCharset},
			{"Content-Transfer-Encoding", "7bit"},
		}}, nil
	case 1:
		return texts[0], nil
	default:
		return &entity{subtype: "alternative", parts: texts}, nil
	}
}

func textEntity(t *Text, subtype string) (*entity, error) {
	charset := t.Charset
	if charset == "" {
		charset = DefaultCharset
	}
	data, err := encodeCharset(t.Data, charset)
	if err != nil {
		return nil, err
	}
	enc, content := encodeText(data)
	return &entity{
		headers: []Header{
			{"Content-Type", mime.FormatMediaType("text/"+subtype,
				map[string]string{"charset": charset})},
			{"Content-Transfer-Encoding", enc},
		},
		content: content,
	}, nil
}

// encodeText sends 7-bit text in short lines as it is, and anything else
// quoted-printable.
func encodeText(data []byte) (string, []byte) {
	if isSevenBit(data) {
		return "7bit", crlf(data)
	}
	var b bytes.Buffer
	w := quotedprintable.NewWriter(&b)
	_, _ = w.Write(data) // a bytes.Buffer does not fail
	_ = w.Close()
	return "quoted-printable", b.Bytes()
}

// isSevenBit reports whether data can be sent as 7bit: ASCII without NUL or
// a lone CR, in lines of at most 998 characters.
func isSevenBit(data []byte) bool {
	line := 0
	for i, c := range data {
		switch {
		case c == 0 || c >= 0x80:
			return false
		case c == '\n':
			line = 0
			continue
		case c == '\r' && (i+1 == len(data) || data[i+1] != '\n'):
			return false
		}
		line++
		if line > maxLineLength-2 {
			return false
		}
	}
	return true
}

// crlf ends every line of 7-bit text with CRLF.
func crlf(data []byte) []byte {
	s := strings.ReplaceAll(string(data), "\r\n", "\n")
	return []byte(strings.ReplaceAll(s, "\n", "\r\n"))
}

// hasBareLF reports whether data has a line ending in LF alone, which a
// recipient's MIME parser may read back as CRLF.
func hasBareLF(data []byte) bool {
	for i, c := range data {
		if c == '\n' && (i == 0 || data[i-1] != '\r') {
			return true
		}
	}
	return false
}

// ErrNotSevenBit is returned for an attachment sent SEVEN_BIT whose content
// is not 7-bit text.
var ErrNotSevenBit = errors.New("the attachment's ContentTransferEncoding is SEVEN_BIT, " +
	"but its content is not 7-bit text in CRLF-ended lines of at most 998 characters")

func attachmentEntity(a *Attachment) (*entity, error) {
	contentType := a.ContentType
	if contentType == "" {
		contentType = typeByExtension(a.FileName)
	}
	disposition := "attachment"
	if a.Disposition == DispositionInline {
		disposition = "inline"
	}
	mediaType, params, err := mime.ParseMediaType(contentType)
	if err != nil || !strings.Contains(mediaType, "/") {
		return nil, fmt.Errorf("the attachment's ContentType %q is not a type/subtype media type",
			contentType)
	}
	if err = checkAttachmentHeaders(a); err != nil {
		return nil, err
	}
	params["name"] = a.FileName

	e := &entity{headers: []Header{
		{"Content-Type", formatMediaType(mediaType, params)},
		{"Content-Disposition", formatMediaType(disposition,
			map[string]string{"filename": a.FileName})},
	}}
	if a.Description != "" {
		desc, dErr := encodeWord(Text{Data: a.Description})
		if dErr != nil {
			return nil, dErr
		}
		e.headers = append(e.headers, Header{"Content-Description", desc})
	}
	if a.ContentID != "" {
		e.headers = append(e.headers, Header{"Content-ID", "<" + a.ContentID + ">"})
	}

	enc, content, err := encodeAttachment(a.Encoding, a.Content)
	if err != nil {
		return nil, err
	}
	a.Encoding = enc
	e.content = content
	e.headers = append(e.headers, Header{"Content-Transfer-Encoding", transferEncoding(enc)})
	return e, nil
}

// checkAttachmentHeaders refuses attachment fields that would break the
// headers they go into: a control character in any, and a ContentId that is
// not printable ASCII, since it goes in as it is.
func checkAttachmentHeaders(a *Attachment) error {
	for _, v := range []string{a.FileName, a.Description, a.ContentID} {
		if hasControl(v) {
			return errControl
		}
	}
	if !isPrintableASCII(a.ContentID) {
		return fmt.Errorf("the attachment's ContentId %q is not printable ASCII", a.ContentID)
	}
	return nil
}

// encodeAttachment encodes an attachment's content with enc, or, when enc is
// empty, picks the encoding as Attachment describes. It returns the encoding
// used. Every encoding keeps the bytes: quoted-printable is written in its
// binary form, which encodes line breaks rather than rewriting them.
func encodeAttachment(enc string, content []byte) (string, []byte, error) {
	switch enc {
	case EncodingBase64:
		return enc, base64Lines(content), nil
	case EncodingQuotedPrintable:
		var b bytes.Buffer
		w := quotedprintable.NewWriter(&b)
		w.Binary = true
		_, _ = w.Write(content) // a bytes.Buffer does not fail
		_ = w.Close()
		return enc, b.Bytes(), nil
	case EncodingSevenBit:
		// 7bit content is lines ended by CRLF (RFC 2045); a bare LF would be
		// read back as CRLF, changing the bytes, so it is refused rather
		// than rewritten.
		if !isSevenBit(content) || hasBareLF(content) {
			return "", nil, ErrNotSevenBit
		}
		return enc, content, nil
	default:
		if isSevenBit(content) && !hasBareLF(content) {
			return EncodingSevenBit, content, nil
		}
		return EncodingBase64, base64Lines(content), nil
	}
}

func transferEncoding(enc string) string {
	switch enc {
	case EncodingBase64:
		return "base64"
	case EncodingQuotedPrintable:
		return "quoted-printable"
	default:
		return "7bit"
	}
}

// typeByExtension is the media type of a file name's extension, or
// application/octet-stream for one with no known type.
func typeByExtension(name string) string {
	t := mime.TypeByExtension(path.Ext(name))
	if t == "" {
		return "application/octet-stream"
	}
	mediaType, _, err := mime.ParseMediaType(t)
	if err != nil {
		return "application/octet-stream"
	}
	return mediaType
}

// base64Lines encodes b in base64 lines of 76 characters.
func base64Lines(b []byte) []byte {
	enc := base64.StdEncoding.EncodeToString(b)
	var out bytes.Buffer
	for len(enc) > 76 {
		out.WriteString(enc[:76] + "\r\n")
		enc = enc[76:]
	}
	out.WriteString(enc + "\r\n")
	return out.Bytes()
}

// newBoundary returns a MIME boundary in the style of the boundaries SES's
// messages carry.
func newBoundary() (string, error) {
	var r [12]byte
	if _, err := rand.Read(r[:]); err != nil {
		return "", fmt.Errorf("failed to generate a MIME boundary: %w", err)
	}
	return "----=_Part_" + hex.EncodeToString(r[:]), nil
}
