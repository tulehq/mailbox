package mailmime

import (
	"fmt"
	"io"
	"strings"

	"golang.org/x/text/encoding/htmlindex"
)

// isUTF8 reports whether charset names UTF-8 or its subset US-ASCII, which
// need no conversion from a Go string.
func isUTF8(charset string) bool {
	switch strings.ToLower(charset) {
	case "utf-8", "utf8", "us-ascii", "ascii":
		return true
	}
	return false
}

// encodeCharset encodes s, which is UTF-8, in charset.
func encodeCharset(s, charset string) ([]byte, error) {
	if isUTF8(charset) {
		return []byte(s), nil
	}
	enc, err := htmlindex.Get(charset)
	if err != nil {
		return nil, fmt.Errorf("unknown character set %q", charset)
	}
	b, err := enc.NewEncoder().Bytes([]byte(s))
	if err != nil {
		return nil, fmt.Errorf("the text cannot be encoded in %s: %w", charset, err)
	}
	return b, nil
}

// charsetReader decodes r from charset to UTF-8, for mime.WordDecoder.
func charsetReader(charset string, r io.Reader) (io.Reader, error) {
	if isUTF8(charset) {
		return r, nil
	}
	enc, err := htmlindex.Get(charset)
	if err != nil {
		return nil, fmt.Errorf("unknown character set %q", charset)
	}
	return enc.NewDecoder().Reader(r), nil
}

// decodeCharset decodes b from charset to UTF-8. Text in a character set
// this package does not know is kept as sent.
func decodeCharset(b []byte, charset string) string {
	if charset == "" || isUTF8(charset) {
		return string(b)
	}
	enc, err := htmlindex.Get(charset)
	if err != nil {
		return string(b)
	}
	d, err := enc.NewDecoder().Bytes(b)
	if err != nil {
		return string(b)
	}
	return string(d)
}
