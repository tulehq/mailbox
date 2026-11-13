// Package mailmime builds messages the way SES builds them from Simple and
// Template content, applies to Raw content what SES adds and rewrites, and
// parses a stored message back into the parts the retrieval API reports.
package mailmime

import (
	"bytes"
	"errors"
	"fmt"
	"mime"
	"net/textproto"
	"strings"
)

// maxLineLength is the longest line SES accepts, the CRLF included, per RFC
// 5321.
const maxLineLength = 1000

// ErrNoBody is returned for a message with no blank line ending its header.
var ErrNoBody = errors.New("the message must have a header and a body separated by a blank line")

// field is one header field as it appears in a message: its name, its value
// unfolded, and its lines as sent, their line endings included.
type field struct {
	name  string
	value string
	raw   []byte
}

// splitHeader splits a message into its header fields and its body, which
// starts after the blank line. It refuses a header line with no colon, or a
// continuation line before the first field.
func splitHeader(msg []byte) ([]field, []byte, error) {
	var fields []field
	rest := msg
	for {
		if len(rest) == 0 {
			return nil, nil, ErrNoBody
		}
		line, next := cutLine(rest)
		if isBlank(line) {
			return fields, next, nil
		}
		if line[0] == ' ' || line[0] == '\t' {
			if len(fields) == 0 {
				return nil, nil, errors.New("the message header starts with a continuation line")
			}
			f := &fields[len(fields)-1]
			f.raw = append(f.raw, line...)
			f.value = strings.TrimSpace(f.value + " " + strings.TrimSpace(string(trimEOL(line))))
			rest = next
			continue
		}
		name, value, ok := bytes.Cut(trimEOL(line), []byte(":"))
		if !ok || len(bytes.TrimSpace(name)) == 0 || bytes.ContainsAny(name, " \t") {
			return nil, nil, fmt.Errorf("the header line %q is not a header field",
				truncate(string(trimEOL(line))))
		}
		fields = append(fields, field{
			name:  string(name),
			value: strings.TrimSpace(string(value)),
			raw:   append([]byte(nil), line...),
		})
		rest = next
	}
}

// cutLine returns the first line of b, its line ending included, and what
// follows it.
func cutLine(b []byte) ([]byte, []byte) {
	i := bytes.IndexByte(b, '\n')
	if i < 0 {
		return b, nil
	}
	return b[:i+1], b[i+1:]
}

func trimEOL(line []byte) []byte {
	return bytes.TrimRight(line, "\r\n")
}

func isBlank(line []byte) bool {
	return len(trimEOL(line)) == 0
}

func truncate(s string) string {
	const n = 60
	if len(s) > n {
		return s[:n] + "..."
	}
	return s
}

// mimeHeader returns the fields as a textproto.MIMEHeader, for the lookups
// that need no order.
func mimeHeader(fields []field) textproto.MIMEHeader {
	h := make(textproto.MIMEHeader, len(fields))
	for _, f := range fields {
		h.Add(f.name, f.value)
	}
	return h
}

var wordDecoder = mime.WordDecoder{CharsetReader: charsetReader}

// decodeHeader decodes the RFC 2047 encoded words of a header value. A value
// whose words do not decode is kept as sent.
func decodeHeader(v string) string {
	d, err := wordDecoder.DecodeHeader(v)
	if err != nil {
		return v
	}
	return d
}

// checkHeaderBytes refuses a raw message whose header holds a byte that
// readers of the message may not agree on: a CR that does not end a line
// with its LF, which some parsers, Python's email among them, read as a
// line end where this one does not, so it would hide a field from the
// sender and recipients SES is authorized for; and any other control
// character but HTAB, NUL included, which RFC 5322 does not allow in a
// header field (3.6.8 and 2.2) and some readers split lines on. A lone LF
// ends a line here as everywhere, and bytes of 128 and up (RFC 6532's UTF-8)
// stay as they are.
func checkHeaderBytes(msg []byte) error {
	for rest := msg; len(rest) > 0; {
		var line []byte
		line, rest = cutLine(rest)
		content := bytes.TrimSuffix(line, []byte("\n"))
		content = bytes.TrimSuffix(content, []byte("\r"))
		for _, c := range content {
			switch {
			case c == '\r':
				return errors.New("the message header has a CR that does not end a line")
			case c < 0x20 && c != '\t', c == 0x7f:
				return fmt.Errorf("the message header has the control character 0x%02x", c)
			}
		}
		if len(content) == 0 {
			return nil // the blank line that ends the header
		}
	}
	return nil
}

// checkLineLengths refuses a message with a line longer than maxLineLength.
func checkLineLengths(msg []byte) error {
	for rest := msg; len(rest) > 0; {
		var line []byte
		line, rest = cutLine(rest)
		n := len(trimEOL(line)) + len("\r\n")
		if n > maxLineLength {
			return fmt.Errorf("the message has a line of %d characters; "+
				"a line can be at most %d, its CRLF included", n, maxLineLength)
		}
	}
	return nil
}
