//go:build e2e

package e2e

import (
	"bytes"
	"maps"
	"net/http"
	"net/textproto"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/sesv2"
	"github.com/aws/aws-sdk-go-v2/service/sesv2/types"
)

// RFC 5322 header fields are lines ended by CRLF, so an address or an
// attachment field that carries a CR, an LF or another control character
// could end its header and start one the sender never wrote. Each such
// input is refused with BadRequestException and stores nothing.

func TestControlCharactersInAddressesAreRefused(t *testing.T) {
	c, mb := newClient(t)

	values := map[string]string{
		"CRLF and a header":         "a@example.com\r\nBcc: evil@example.com",
		"CRLF inside a comment":     "a@example.com (x\r\nBcc: evil@example.com)",
		"CRLF inside a name":        "\"Alice\r\nBcc: evil@example.com\" <a@example.com>",
		"bare LF":                   "a@example.com\nBcc: evil@example.com",
		"bare CR":                   "a@example.com\rBcc: evil@example.com",
		"NUL":                       "a\x00@example.com",
		"BEL inside a comment":      "a@example.com (x\x07)",
		"DEL inside a name":         "\"Al\x7fice\" <a@example.com>",
		"vertical tab in a comment": "a@example.com (x\vy)",
	}
	fields := map[string]func(*sesv2.SendEmailInput, string){
		"From":     func(in *sesv2.SendEmailInput, v string) { in.FromEmailAddress = aws.String(v) },
		"Reply-To": func(in *sesv2.SendEmailInput, v string) { in.ReplyToAddresses = []string{v} },
		"To":       func(in *sesv2.SendEmailInput, v string) { in.Destination.ToAddresses = []string{v} },
		"Cc":       func(in *sesv2.SendEmailInput, v string) { in.Destination.CcAddresses = []string{v} },
	}
	for field, set := range fields {
		for name, value := range values {
			t.Run(field+" "+name, func(t *testing.T) {
				in := simpleInput("sender@example.com", "Injected", "Body.", "to@example.com")
				set(in, value)
				err := errOf(c.SendEmail(t.Context(), in))
				requireAs[*types.BadRequestException](t, err)
				requireStatus(t, err, http.StatusBadRequest)
			})
		}
	}
	requireEqual(t, len(mb.listAll(t, nil)), 0, "messages stored")
}

func TestControlCharactersInAttachmentFieldsAreRefused(t *testing.T) {
	c, mb := newClient(t)

	tests := map[string]func(*types.Attachment){
		"ContentDescription with CRLF": func(a *types.Attachment) {
			a.ContentDescription = aws.String("report\r\nBcc: evil@example.com")
		},
		"ContentDescription with LF": func(a *types.Attachment) {
			a.ContentDescription = aws.String("report\nX-Evil: yes")
		},
		"ContentId with CRLF": func(a *types.Attachment) {
			a.ContentId = aws.String("<img1@example.com>\r\nBcc: evil@example.com")
		},
		"ContentId with CR": func(a *types.Attachment) {
			a.ContentId = aws.String("<img1@example.com>\rX-Evil: yes")
		},
	}
	for name, edit := range tests {
		t.Run(name, func(t *testing.T) {
			in := simpleInput("sender@example.com", "Attachment", "Body.", "to@example.com")
			a := types.Attachment{
				FileName:    aws.String("report.txt"),
				ContentType: aws.String("text/plain"),
				RawContent:  []byte("hello"),
			}
			edit(&a)
			in.Content.Simple.Attachments = []types.Attachment{a}
			err := errOf(c.SendEmail(t.Context(), in))
			requireAs[*types.BadRequestException](t, err)
			requireStatus(t, err, http.StatusBadRequest)
		})
	}
	requireEqual(t, len(mb.listAll(t, nil)), 0, "messages stored")
}

// sesHeaders are the header fields SES sets on a message it assembles
// (Amazon SES header fields: the headers Simple content cannot set), with
// the Content-Transfer-Encoding a MIME body may need.
var sesHeaders = []string{
	"Bcc", "Cc", "Content-Disposition", "Content-Type", "Date", "From", "Message-Id",
	"Mime-Version", "Reply-To", "Return-Path", "Subject", "To", "Content-Transfer-Encoding",
}

// requireHeaderSet fails unless every header field of m is one SES sets or
// one of custom, and none of From, To, Cc, Reply-To and Subject appears
// more than once (RFC 5322 3.6, Amazon SES header fields). Assumption: the
// stored message has no header beyond these, such as X-SES-Outgoing, which
// SES itself adds in delivery.
func requireHeaderSet(t *testing.T, m *parsedMIME, custom ...string) {
	t.Helper()

	allowed := map[string]bool{}
	for _, h := range append(slices.Clone(sesHeaders), custom...) {
		allowed[textproto.CanonicalMIMEHeaderKey(h)] = true
	}
	for name, values := range m.Header {
		if !allowed[textproto.CanonicalMIMEHeaderKey(name)] {
			t.Errorf("unintended header %s: %q", name, values)
		}
	}
	for _, name := range []string{"From", "To", "Cc", "Reply-To", "Subject", "Bcc"} {
		if n := len(m.Header[name]); n > 1 {
			t.Errorf("header %s appears %d times", name, n)
		}
	}
	m.requireNoHeader(t, "Bcc")
}

func TestLegalAddressCommentsAddNoHeaders(t *testing.T) {
	// Comments, quoted names and specials are legal in RFC 5322 addresses;
	// they stay inside their own header field.
	c, mb := newClient(t)

	in := simpleInput("\"Shop: Sales\" <shop@example.com>", "Comments", "Body.",
		"to@example.com (Bcc: evil@example.com)")
	in.Destination.CcAddresses = []string{"\"Cc; Person\" <cc@example.com>"}
	in.Destination.BccAddresses = []string{"hidden@example.com"}
	in.ReplyToAddresses = []string{"reply@example.com (Reply-To: x@example.com)"}
	in.Content.Simple.Headers = []types.MessageHeader{
		{Name: aws.String("X-Note"), Value: aws.String("one")},
	}
	id := send(t, c, in)

	s := mb.byMessageID(t, id)
	raw := mb.raw(t, s.ID)
	m := parseMIME(t, raw)
	requireHeaderSet(t, m, "X-Note")
	requireSameSet(t, m.addresses(t, "To"), []string{"to@example.com"}, "To header")
	requireSameSet(t, m.addresses(t, "Cc"), []string{"cc@example.com"}, "Cc header")
	requireSameSet(t, m.addresses(t, "From"), []string{"shop@example.com"}, "From header")
	requireSameSet(t, m.addresses(t, "Reply-To"), []string{"reply@example.com"}, "Reply-To header")
	if bytes.Contains(raw, []byte("hidden@example.com")) {
		t.Fatal("the stored MIME names the Bcc recipient")
	}
}

func TestAttachmentBytesRoundTrip(t *testing.T) {
	// The attachment a recipient saves is the bytes attached, whatever their
	// line endings or content type.
	c, mb := newClient(t)
	contents := map[string][]byte{
		"lf.txt":    []byte("one\ntwo\nthree\n"),
		"crlf.txt":  []byte("one\r\ntwo\r\n"),
		"mixed.txt": []byte("a\rb\nc\r\nd\n\n\r\r"),
		"nul.bin":   {0, 0, '\n', 0xff, '\r', 0x80, 0},
		"long.txt":  []byte(strings.Repeat("x", 2500) + "\n"),
		"utf8.txt":  []byte("Grüße\nمرحبا\n"),
	}
	contentTypes := map[string]string{
		"lf.txt": "text/plain", "crlf.txt": "text/plain", "mixed.txt": "text/plain",
		"nul.bin": "application/octet-stream", "long.txt": "text/plain", "utf8.txt": "text/plain",
	}
	names := slices.Sorted(maps.Keys(contents))

	in := simpleInput("sender@example.com", "Bytes", "See attached.", "to@example.com")
	for _, name := range names {
		in.Content.Simple.Attachments = append(in.Content.Simple.Attachments, types.Attachment{
			FileName:    aws.String(name),
			ContentType: aws.String(contentTypes[name]),
			RawContent:  contents[name],
		})
	}
	msg, m := mb.stored(t, send(t, c, in))

	requireEqual(t, len(msg.Attachments), len(names), "attachments")
	parts := m.attachments()
	requireEqual(t, len(parts), len(names), "attachment parts in the MIME")
	for i, name := range names {
		want := contents[name]
		requireEqual(t, msg.Attachments[i].Name, name, "attachment name")
		requireEqual(t, msg.Attachments[i].Size, int64(len(want)), name+" size")
		requireBytes(t, parts[i].Body, want, name+" in the MIME")
		res := mb.attachmentAt(t, msg.ID, i)
		requireOK(t, res, "get "+name)
		requireBytes(t, res.Body, want, name+" from the API")
	}
	requireLinesAtMost998(t, mb.raw(t, msg.ID))
}

// requireLinesAtMost998 fails unless every line of raw is at most 998
// characters before its CRLF (RFC 5322 2.1.1).
func requireLinesAtMost998(t *testing.T, raw []byte) {
	t.Helper()
	for i, line := range bytes.Split(raw, []byte("\n")) {
		if n := len(bytes.TrimSuffix(line, []byte("\r"))); n > 998 {
			t.Fatalf("line %d is %d characters: %.80q...", i+1, n, line)
		}
	}
}

func TestLongSubjectsAreFoldedAndDecodeBack(t *testing.T) {
	c, mb := newClient(t)

	var ascii strings.Builder
	for i := 0; ascii.Len() < 2000; i++ {
		ascii.WriteString("word" + strconv.Itoa(i) + " ")
	}
	tests := map[string]string{
		"ASCII of 2000 characters": strings.TrimSpace(ascii.String())[:2000],
		"ASCII with no spaces":     strings.Repeat("y", 2000),
		"non-ASCII":                strings.Repeat("Grüße aus Kairo مرحبا ", 60),
	}
	for name, subject := range tests {
		t.Run(name, func(t *testing.T) {
			in := simpleInput("sender@example.com", subject, "Body.", "to@example.com")
			in.Content.Simple.Subject.Charset = aws.String("UTF-8")
			in.Content.Simple.Body.Html = &types.Content{
				Data: aws.String(
					"<p>" + strings.Repeat("é long html line ", 200) + "</p>",
				),
				Charset: aws.String("UTF-8"),
			}
			msg, m := mb.stored(t, send(t, c, in))
			requireLinesAtMost998(t, mb.raw(t, msg.ID))
			requireEqual(t, m.subject(t), subject, "decoded Subject header")
			requireEqual(t, msg.Subject, subject, "summary subject")
			m.requireBody(t, "text/html", "<p>"+strings.Repeat("é long html line ", 200)+"</p>")
		})
	}
}

func TestNonASCIIDisplayNameIsEncoded(t *testing.T) {
	// A header field holds only ASCII (RFC 5322 2.2), so a display name that
	// is not ASCII travels as RFC 2047 encoded words, which net/mail decodes.
	c, mb := newClient(t)
	const from = "Grüße Shop <shop@example.com>"

	in := simpleInput(from, "Name", "Body.", "to@example.com")
	in.ReplyToAddresses = []string{"Ägypten Hilfe <help@example.com>"}
	msg, m := mb.stored(t, send(t, c, in))
	requireEqual(t, msg.From, from, "summary from as sent")

	raw := mb.raw(t, msg.ID)
	head, _, _ := bytes.Cut(raw, []byte("\r\n\r\n"))
	for i, b := range head {
		if b >= 0x80 {
			t.Fatalf("header byte %d is %#x, not ASCII: %.200q", i, b, head)
		}
	}
	for header, want := range map[string][2]string{
		"From":     {"Grüße Shop", "shop@example.com"},
		"Reply-To": {"Ägypten Hilfe", "help@example.com"},
	} {
		list, err := m.Header.AddressList(header)
		requireNoErr(t, err, "parse "+header)
		requireEqual(t, len(list), 1, header+" addresses")
		requireEqual(t, list[0].Name, want[0], header+" display name")
		requireEqual(t, list[0].Address, want[1], header+" address")
	}
}

func TestNULInSearchIsABadRequest(t *testing.T) {
	_, mb := newClient(t)
	res := mb.do(t, http.MethodGet, "/_mailbox/messages", url.Values{"q": {"\x00"}})
	requireAPIErrorBody(t, res, http.StatusBadRequest, "BadRequestException", "q=%00")
}
