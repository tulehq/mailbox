//go:build e2e

package e2e

import (
	"bytes"
	"encoding/base64"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/service/sesv2"
	"github.com/aws/aws-sdk-go-v2/service/sesv2/types"
)

// rawAttachment is the attachment of rawMessage.
var rawAttachment = []byte("ID,FirstName,LastName,Country\n348,John,Stiles,Canada\n")

// rawMessage is a multipart/mixed message holding a multipart/alternative
// text and HTML body and an attachment, shaped as the example of Sending raw
// email using the Amazon SES API v2, with a Date and a Message-ID of its own
// and CRLF line endings.
func rawMessage() []byte {
	lines := []string{
		`From: "Sender Name" <sender@example.com>`,
		`To: recipient@example.com`,
		`Cc: copy@example.com`,
		`Subject: Customer service contact info`,
		`Date: Mon, 02 Jan 2006 15:04:05 -0700`,
		`Message-ID: <client-chosen-id@example.com>`,
		`X-Custom: kept as sent`,
		`MIME-Version: 1.0`,
		`Content-Type: multipart/mixed; boundary="outer-boundary"`,
		``,
		`--outer-boundary`,
		`Content-Type: multipart/alternative; boundary="inner-boundary"`,
		``,
		`--inner-boundary`,
		`Content-Type: text/plain; charset=utf-8`,
		`Content-Transfer-Encoding: quoted-printable`,
		``,
		`Please see the attached file. Gr=C3=BC=C3=9Fe.`,
		``,
		`--inner-boundary`,
		`Content-Type: text/html; charset=utf-8`,
		`Content-Transfer-Encoding: quoted-printable`,
		``,
		`<p>Please see the attached file.</p>`,
		``,
		`--inner-boundary--`,
		``,
		`--outer-boundary`,
		`Content-Type: text/csv; name="customers.csv"`,
		`Content-Disposition: attachment; filename="customers.csv"`,
		`Content-Transfer-Encoding: base64`,
		``,
		base64.StdEncoding.EncodeToString(rawAttachment),
		``,
		`--outer-boundary--`,
		``,
	}
	return []byte(strings.Join(lines, "\r\n"))
}

func TestRawRoundTrips(t *testing.T) {
	c, mb := newClient(t)
	data := rawMessage()
	before := time.Now()

	id := send(t, c, &sesv2.SendEmailInput{
		Destination: &types.Destination{
			ToAddresses:  []string{"recipient@example.com"},
			CcAddresses:  []string{"copy@example.com"},
			BccAddresses: []string{"hidden@example.com"},
		},
		Content: &types.EmailContent{Raw: &types.RawMessage{Data: data}},
	})

	msg, m := mb.stored(t, id)
	requireEqual(t, msg.Subject, "Customer service contact info", "subject")
	requireSameSet(t, msg.To, []string{"recipient@example.com"}, "to")
	requireSameSet(t, msg.Cc, []string{"copy@example.com"}, "cc")
	requireSameSet(t, msg.Bcc, []string{"hidden@example.com"}, "bcc")
	requireEqual(
		t,
		strings.TrimRight(msg.Text, "\r\n"),
		"Please see the attached file. Grüße.",
		"text",
	)
	requireEqual(
		t,
		strings.TrimRight(msg.HTML, "\r\n"),
		"<p>Please see the attached file.</p>",
		"html",
	)
	requireAttachments(t, msg.Attachments, []attachment{
		{Name: "customers.csv", ContentType: "text/csv", Size: int64(len(rawAttachment))},
	})
	requireEqual(t, m.Header.Get("X-Custom"), "kept as sent", "X-Custom")
	requireBytes(t, m.attachments()[0].Body, rawAttachment, "attachment in the MIME")

	requireRawAsSent(t, mb.raw(t, msg.ID), data)
	requireSESOverrides(t, m, before)
}

// requireRawAsSent fails unless stored is sent byte for byte, apart from the
// Date and Message-ID headers, which SES overrides (Amazon SES header
// fields, Considerations). Where SES puts its own headers is not
// documented, so the headers are compared as a set of lines and the body,
// after the first blank line, byte for byte.
func requireRawAsSent(t *testing.T, stored, sent []byte) {
	t.Helper()

	sentHead, sentBody, ok := bytes.Cut(sent, []byte("\r\n\r\n"))
	if !ok {
		t.Fatal("the sent message has no blank line")
	}
	storedHead, storedBody, ok := bytes.Cut(stored, []byte("\r\n\r\n"))
	if !ok {
		t.Fatalf("the stored message has no CRLF blank line: %.300q", stored)
	}
	requireBytes(t, storedBody, sentBody, "stored body")

	storedLines := map[string]bool{}
	for _, line := range strings.Split(string(storedHead), "\r\n") {
		storedLines[line] = true
	}
	for _, line := range strings.Split(string(sentHead), "\r\n") {
		lower := strings.ToLower(line)
		if strings.HasPrefix(lower, "date:") || strings.HasPrefix(lower, "message-id:") {
			continue
		}
		if !storedLines[line] {
			t.Errorf("header line %q was not stored as sent", line)
		}
	}
}

// requireSESOverrides fails unless SES's own Message-ID replaced the
// message's, and the Date is the UTC time SES accepted it (Amazon SES header
// fields, Considerations).
func requireSESOverrides(t *testing.T, m *parsedMIME, before time.Time) {
	t.Helper()

	if got := m.Header["Message-Id"]; len(got) != 1 || got[0] == "<client-chosen-id@example.com>" {
		t.Fatalf("Message-ID %q, want one of SES's own", got)
	}
	if got := m.Header["Date"]; len(got) != 1 {
		t.Fatalf("Date headers %q, want one", got)
	}
	date := requireDateNear(t, m.Header, before)
	if _, offset := date.Zone(); offset != 0 {
		t.Fatalf("Date %s is not in UTC", m.Header.Get("Date"))
	}
}

func TestRawFromHeaderIsTheSender(t *testing.T) {
	// FromEmailAddress is optional for raw content, whose From header names
	// the sender (SendEmailInput.FromEmailAddress is not required).
	c, mb := newClient(t)

	data := []byte("From: header-sender@example.com\r\nTo: to@example.com\r\n" +
		"Subject: From the header\r\nMIME-Version: 1.0\r\n" +
		"Content-Type: text/plain; charset=us-ascii\r\n\r\nBody.\r\n")
	id := send(t, c, &sesv2.SendEmailInput{
		Destination: &types.Destination{ToAddresses: []string{"to@example.com"}},
		Content:     &types.EmailContent{Raw: &types.RawMessage{Data: data}},
	})

	msg, m := mb.stored(t, id)
	requireEqual(t, msg.From, "header-sender@example.com", "from")
	requireEqual(t, strings.TrimRight(msg.Text, "\r\n"), "Body.", "text")
	m.requireBody(t, "text/plain", "Body.")
}
