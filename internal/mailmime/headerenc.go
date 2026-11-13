package mailmime

import (
	"bytes"
	"encoding/base64"
	"errors"
	"mime"
	"net/mail"
	"slices"
	"strconv"
	"strings"
	"unicode/utf8"
)

// The lengths header folding works to, from RFC 5322: lines of at most 78
// characters where a line can be folded, and never more than 998. An
// encoded word is at most 66 characters, so "Subject: " and one fits in 78;
// a word of more than maxWord characters is encoded, so it can be split.
const (
	foldAt  = 78
	maxWord = 66
	// maxToken is the longest run of non-space characters a header value
	// keeps as it is: longer, no fold could keep its line within 998.
	maxToken = 900
)

// errControl is returned for a header value from the request that holds a
// control character, which would end the header line or start another.
var errControl = errors.New("a header value contains a control character")

// hasControl reports whether s holds an ASCII control character.
func hasControl(s string) bool {
	return strings.ContainsFunc(s, func(r rune) bool { return r < 0x20 || r == 0x7f })
}

func isPrintableASCII(s string) bool {
	for i := range len(s) {
		if s[i] < 0x20 || s[i] > 0x7e {
			return false
		}
	}
	return true
}

// hasLongToken reports whether s has a run of non-space characters longer
// than maxToken.
func hasLongToken(s string) bool {
	return slices.ContainsFunc(strings.Split(s, " "), func(t string) bool {
		return len(t) > maxToken
	})
}

// encodeWord returns t as an unstructured header value: as it is when it is
// printable ASCII that folds, which includes a subject the client encoded
// already, and as RFC 2047 encoded words in its character set otherwise.
func encodeWord(t Text) (string, error) {
	if isPrintableASCII(t.Data) && !hasLongToken(t.Data) {
		return t.Data, nil
	}
	charset := t.Charset
	if charset == "" {
		charset = DefaultCharset
	}
	return encodeWords(t.Data, charset)
}

// encodeWords encodes s as RFC 2047 B-encoded words in charset, each at most
// maxWord characters, separated by spaces so the header folds between them.
// Each word holds whole characters, encoded on its own, so it decodes on
// its own.
func encodeWords(s, charset string) (string, error) {
	overhead := len("=?") + len(charset) + len("?B?") + len("?=")
	maxBytes := (maxWord - overhead) / 4 * 3
	var (
		words []string
		chunk strings.Builder
		size  int
	)
	flush := func() error {
		if chunk.Len() == 0 {
			return nil
		}
		b, err := encodeCharset(chunk.String(), charset)
		if err != nil {
			return err
		}
		words = append(words, "=?"+charset+"?B?"+base64.StdEncoding.EncodeToString(b)+"?=")
		chunk.Reset()
		size = 0
		return nil
	}
	for _, r := range s {
		n := utf8.RuneLen(r)
		if !isUTF8(charset) {
			b, err := encodeCharset(string(r), charset)
			if err != nil {
				return "", err
			}
			n = len(b)
		}
		if size+n > maxBytes {
			if err := flush(); err != nil {
				return "", err
			}
		}
		chunk.WriteRune(r)
		size += n
	}
	if err := flush(); err != nil {
		return "", err
	}
	return strings.Join(words, " "), nil
}

// writeAddresses writes an address list header.
func writeAddresses(b *bytes.Buffer, name string, addrs []string) {
	if len(addrs) == 0 {
		return
	}
	encoded := make([]string, len(addrs))
	for i, a := range addrs {
		encoded[i] = encodeAddress(a)
	}
	writeField(b, name, strings.Join(encoded, ", "))
}

// encodeAddress returns an address as the request gives it when it is
// printable ASCII that folds, and otherwise its display name in encoded
// words and its address, which the request's checks hold to 7-bit ASCII
// with no control characters.
func encodeAddress(a string) string {
	if isPrintableASCII(a) && !hasLongToken(a) {
		return a
	}
	parsed, err := mail.ParseAddress(a)
	if err != nil {
		return a
	}
	if parsed.Name == "" {
		return "<" + parsed.Address + ">"
	}
	name, err := encodeWords(parsed.Name, DefaultCharset)
	if err != nil {
		// UTF-8 encodes every string.
		return "<" + parsed.Address + ">"
	}
	return name + " <" + parsed.Address + ">"
}

// writeField writes a header field, folded: a line breaks before a space
// once it would run past foldAt characters, the space starting the next.
func writeField(b *bytes.Buffer, name, value string) {
	line := name + ":"
	for i, tok := range strings.Split(value, " ") {
		// The first fold may come straight after the colon: a field body
		// may start with folding white space (RFC 5322 2.2.3).
		if tok != "" && len(line)+1+len(tok) > foldAt && (i > 0 || len(line) > 1) {
			b.WriteString(line + "\r\n")
			line = ""
		}
		line += " " + tok
	}
	b.WriteString(line + "\r\n")
}

// paramChunk is the longest piece of an RFC 2231 parameter value per line.
const paramChunk = 45

// formatMediaType writes a media type and its parameters, as
// mime.FormatMediaType does, but with a value that is not short ASCII written
// as RFC 2231 continuations (name*0*=utf-8”..., name*1*=...), so the
// header folds between them however long the value is.
func formatMediaType(mediaType string, params map[string]string) string {
	var b strings.Builder
	b.WriteString(mediaType)
	keys := make([]string, 0, len(params))
	for k := range params {
		keys = append(keys, k)
	}
	slices.Sort(keys)
	for _, k := range keys {
		v := params[k]
		if isPrintableASCII(v) && len(v) <= paramChunk {
			b.WriteString("; " + strings.TrimPrefix(mime.FormatMediaType("x/x",
				map[string]string{k: v}), "x/x; "))
			continue
		}
		enc := percentEncode(v)
		for i := 0; len(enc) > 0; i++ {
			n := min(paramChunk, len(enc))
			// A piece never splits a %XX escape.
			if j := strings.LastIndexByte(enc[max(0, n-2):n], '%'); j >= 0 && n < len(enc) {
				n = max(0, n-2) + j
			}
			piece := enc[:n]
			enc = enc[n:]
			if i == 0 {
				piece = "utf-8''" + piece
			}
			b.WriteString("; " + k + "*" + strconv.Itoa(i) + "*=" + piece)
		}
	}
	return b.String()
}

// percentEncode encodes s for an RFC 2231 value: attribute characters as
// they are, every other byte of its UTF-8 as %XX.
func percentEncode(s string) string {
	const hex = "0123456789ABCDEF"
	var b strings.Builder
	for i := range len(s) {
		c := s[i]
		if c < 0x80 && (c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' ||
			strings.IndexByte("!#$&+-.^_`|~", c) >= 0) {
			b.WriteByte(c)
			continue
		}
		b.WriteByte('%')
		b.WriteByte(hex[c>>4])
		b.WriteByte(hex[c&0xf])
	}
	return b.String()
}
