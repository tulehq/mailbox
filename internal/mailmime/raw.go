package mailmime

import (
	"bytes"
	"errors"
	"net/textproto"
	"slices"
	"strings"
	"time"
)

// The headers SES reads from a raw message and removes before sending it.
const (
	headerConfigurationSet = "X-Ses-Configuration-Set"
	headerMessageTags      = "X-Ses-Message-Tags"
	headerSourceARN        = "X-Ses-Source-Arn"
	headerFromARN          = "X-Ses-From-Arn"
	headerReturnPathARN    = "X-Ses-Return-Path-Arn"
)

// sesHeaders are the X-SES headers SES documents removing from a raw message.
var sesHeaders = []string{
	headerConfigurationSet, headerMessageTags,
	headerSourceARN, headerFromARN, headerReturnPathARN,
}

// Raw is a raw message as SES sends it, and what SES read from its header.
// From, To, Cc and Bcc are the header values, unparsed; ConfigurationSet,
// Tags and the ARNs are the X-SES headers' values: SourceARN, FromARN and
// ReturnPathARN are the sending authorization identities of the envelope
// sender, the From header and the return path.
type Raw struct {
	From             string
	To               string
	Cc               string
	Bcc              string
	ConfigurationSet string
	Tags             string
	SourceARN        string
	FromARN          string
	ReturnPathARN    string
	MIME             []byte
	// froms counts the From fields, of which SES takes one only.
	froms int
}

// PrepareRaw checks msg is a message SES would send and applies what SES
// does to one: its Message-ID and Date headers are replaced by SES's own,
// the Bcc header and the X-SES headers are removed, and everything else is
// kept byte for byte. The new headers go at the end of the header, with the
// message's own line ending.
func PrepareRaw(msg []byte, messageID string, date time.Time) (*Raw, error) {
	if err := checkLineLengths(msg); err != nil {
		return nil, err
	}
	if err := checkHeaderBytes(msg); err != nil {
		return nil, err
	}
	fields, body, err := splitHeader(msg)
	if err != nil {
		return nil, err
	}

	eol := "\r\n"
	if len(fields) > 0 && !bytes.HasSuffix(fields[0].raw, []byte("\r\n")) {
		eol = "\n"
	}

	out := &Raw{}
	var b bytes.Buffer
	for _, f := range fields {
		if out.read(f) {
			b.Write(f.raw)
		}
	}
	// From is a field SES refuses to see twice. The sender a send is
	// authorized for must be the one its recipients see, so a second From
	// is refused here, before anything reads the first.
	if out.froms > 1 {
		return nil, errors.New("the message has more than one From header")
	}
	b.WriteString("Date: " + HeaderDate(date) + eol)
	b.WriteString("Message-ID: " + HeaderMessageID(messageID) + eol)
	b.WriteString(eol)
	b.Write(body)
	out.MIME = b.Bytes()

	// Parsing the result checks its MIME structure the way the retrieval
	// API will read it.
	if _, err = Parse(out.MIME); err != nil {
		return nil, err
	}
	return out, nil
}

// read takes from a header field what SES reads of it, and reports whether
// the field stays in the message.
func (r *Raw) read(f field) bool {
	name := canonical(f.name)
	switch name {
	case "From":
		r.From = f.value
		r.froms++
	case "To":
		r.To = joinList(r.To, f.value)
	case "Cc":
		r.Cc = joinList(r.Cc, f.value)
	case "Bcc":
		r.Bcc = joinList(r.Bcc, f.value)
		return false
	case "Message-Id", "Date":
		return false
	}
	// "If you include multiple instances of an X-header, Amazon SES uses only
	// the first instance" (SES Developer Guide, Using sending authorization
	// with Amazon SES, X-headers).
	if dst := r.xHeader(name); dst != nil {
		if *dst == "" {
			*dst = f.value
		}
		return false
	}
	return !slices.Contains(sesHeaders, name)
}

// xHeader is where the X-SES header of the canonical name is kept, or nil
// for any other header.
func (r *Raw) xHeader(name string) *string {
	switch name {
	case headerConfigurationSet:
		return &r.ConfigurationSet
	case headerMessageTags:
		return &r.Tags
	case headerSourceARN:
		return &r.SourceARN
	case headerFromARN:
		return &r.FromARN
	case headerReturnPathARN:
		return &r.ReturnPathARN
	}
	return nil
}

func canonical(name string) string {
	return textproto.CanonicalMIMEHeaderKey(strings.TrimSpace(name))
}

// joinList joins the values of a repeated address header.
func joinList(a, b string) string {
	if a == "" {
		return b
	}
	return a + ", " + b
}
