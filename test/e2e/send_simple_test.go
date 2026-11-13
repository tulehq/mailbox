//go:build e2e

package e2e

import (
	"bytes"
	"net/http"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/sesv2"
	"github.com/aws/aws-sdk-go-v2/service/sesv2/types"
)

// Simple content: SES assembles the MIME message from the subject, bodies,
// headers and attachments (SendEmail API reference; Email format in Amazon
// SES, "Simple (formatted)").

func TestSimpleTextOnly(t *testing.T) {
	c, mb := newClient(t)
	sent := time.Now()

	id := send(t, c, &sesv2.SendEmailInput{
		FromEmailAddress: aws.String("sender@example.com"),
		Destination: &types.Destination{
			ToAddresses:  []string{"to@example.com"},
			CcAddresses:  []string{"cc@example.com"},
			BccAddresses: []string{"bcc@example.com"},
		},
		ReplyToAddresses: []string{"reply@example.com"},
		Content: &types.EmailContent{Simple: &types.Message{
			Subject: &types.Content{Data: aws.String("Plain hello")},
			Body: &types.Body{
				Text: &types.Content{Data: aws.String("Just text.\r\nTwo lines.")},
			},
		}},
	})

	s := mb.byMessageID(t, id)
	requireEqual(t, s.From, "sender@example.com", "summary from")
	requireSameSet(t, s.To, []string{"to@example.com"}, "summary to")
	requireSameSet(t, s.Cc, []string{"cc@example.com"}, "summary cc")
	// The design keeps Bcc as the sender knows it.
	requireSameSet(t, s.Bcc, []string{"bcc@example.com"}, "summary bcc")
	requireEqual(t, s.Subject, "Plain hello", "summary subject")
	requireEqual(t, s.AttachmentCount, 0, "summary attachment count")
	requireEqual(t, s.ConfigurationSet, "", "summary configuration set")
	requireEqual(t, len(s.Tags), 0, "summary tags")
	if at := s.at(t); at.Sub(sent) < -time.Minute || at.Sub(sent) > time.Minute {
		t.Fatalf("summary time %s is not near the send at %s", s.Time, sent)
	}

	msg := mb.get(t, s.ID)
	requireEqual(t, strings.TrimRight(msg.Text, "\r\n"), "Just text.\r\nTwo lines.", "full text")
	requireEqual(t, msg.HTML, "", "full html")
	requireEqual(t, msg.ID, s.ID, "full id")

	raw := mb.raw(t, s.ID)
	// size is the bytes of the stored MIME.
	requireEqual(t, s.Size, int64(len(raw)), "summary size")

	m := parseMIME(t, raw)
	m.requireSESHeaders(t, sent)
	m.requireBody(t, "text/plain", "Just text.\r\nTwo lines.")
	m.requireNoBody(t, "text/html")
	requireEqual(t, m.subject(t), "Plain hello", "Subject header")
	requireSameSet(t, m.addresses(t, "From"), []string{"sender@example.com"}, "From header")
	requireSameSet(t, m.addresses(t, "To"), []string{"to@example.com"}, "To header")
	requireSameSet(t, m.addresses(t, "Cc"), []string{"cc@example.com"}, "Cc header")
	requireSameSet(t, m.addresses(t, "Reply-To"), []string{"reply@example.com"}, "Reply-To header")
	// No recipient's copy carries Bcc (Email format in Amazon SES: a BCC
	// recipient comes from the envelope, not the header).
	m.requireNoHeader(t, "Bcc")
	if bytes.Contains(bytes.ToLower(raw), []byte("bcc@example.com")) {
		t.Fatal("the stored MIME names the Bcc recipient")
	}
}

func TestSimpleHTMLOnly(t *testing.T) {
	c, mb := newClient(t)
	sent := time.Now()
	const html = "<html><body><h1>Hi</h1><p>HTML only.</p></body></html>"

	id := send(t, c, &sesv2.SendEmailInput{
		FromEmailAddress: aws.String("sender@example.com"),
		Destination:      &types.Destination{ToAddresses: []string{"to@example.com"}},
		Content: &types.EmailContent{Simple: &types.Message{
			Subject: &types.Content{Data: aws.String("HTML hello")},
			Body:    &types.Body{Html: &types.Content{Data: aws.String(html)}},
		}},
	})

	msg, m := mb.stored(t, id)
	requireEqual(t, msg.Subject, "HTML hello", "subject")
	requireEqual(t, strings.TrimRight(msg.HTML, "\r\n"), html, "full html")
	requireEqual(t, msg.Text, "", "full text")
	m.requireSESHeaders(t, sent)
	m.requireBody(t, "text/html", html)
	m.requireNoBody(t, "text/plain")
}

func TestSimpleTextAndHTMLWithUTF8(t *testing.T) {
	// Non-ASCII content needs its charset (types.Content.Charset), and a
	// non-ASCII subject needs encoded words (types.Message.Subject).
	c, mb := newClient(t)
	sent := time.Now()
	const (
		text    = "Grüße aus Kairo: مرحبا"
		html    = "<p>Grüße aus <b>Kairo</b>: مرحبا</p>"
		subject = "Grüße"
	)
	utf8 := aws.String("UTF-8")

	id := send(t, c, &sesv2.SendEmailInput{
		FromEmailAddress: aws.String("sender@example.com"),
		Destination:      &types.Destination{ToAddresses: []string{"to@example.com"}},
		Content: &types.EmailContent{Simple: &types.Message{
			Subject: &types.Content{Data: aws.String("=?UTF-8?B?R3LDvMOfZQ==?="), Charset: utf8},
			Body: &types.Body{
				Text: &types.Content{Data: aws.String(text), Charset: utf8},
				Html: &types.Content{Data: aws.String(html), Charset: utf8},
			},
		}},
	})

	msg, m := mb.stored(t, id)
	requireEqual(t, strings.TrimRight(msg.Text, "\r\n"), text, "full text")
	requireEqual(t, strings.TrimRight(msg.HTML, "\r\n"), html, "full html")
	requireEqual(t, m.subject(t), subject, "decoded Subject header")
	// Header values are decoded from RFC 2047.
	requireSameSet(
		t,
		headerValues(msg.Headers, "Subject"),
		[]string{subject},
		"Subject in the full message",
	)
	m.requireSESHeaders(t, sent)
	m.requireBody(t, "text/plain", text)
	m.requireBody(t, "text/html", html)
	// The design: multipart/alternative for text and HTML.
	for _, l := range m.Leaves {
		if !l.hasParent("multipart/alternative") {
			t.Fatalf(
				"%s part is not inside multipart/alternative (parents %q)",
				l.MediaType,
				l.Parents,
			)
		}
		if !strings.EqualFold(l.Params["charset"], "utf-8") {
			t.Fatalf("%s part charset %q, want UTF-8", l.MediaType, l.Params["charset"])
		}
	}
}

func TestSimpleCustomHeaders(t *testing.T) {
	c, mb := newClient(t)

	in := simpleInput("sender@example.com", "Headers", "Body.", "to@example.com")
	in.Content.Simple.Headers = []types.MessageHeader{
		{Name: aws.String("X-Campaign"), Value: aws.String("autumn-2026")},
		{Name: aws.String("List-Unsubscribe"), Value: aws.String("<mailto:unsub@example.com>")},
	}
	id := send(t, c, in)

	msg, m := mb.stored(t, id)
	requireEqual(t, m.Header.Get("X-Campaign"), "autumn-2026", "X-Campaign in the MIME")
	requireEqual(
		t,
		m.Header.Get("List-Unsubscribe"),
		"<mailto:unsub@example.com>",
		"List-Unsubscribe in the MIME",
	)
	requireSameSet(
		t,
		headerValues(msg.Headers, "X-Campaign"),
		[]string{"autumn-2026"},
		"X-Campaign in the full message",
	)
}

func TestSimpleHeadersSESSetsAreRefused(t *testing.T) {
	// Simple and Templated content cannot set the headers SES sets: BCC, CC,
	// Content-Disposition, Content-Type, Date, From, Message-ID,
	// MIME-Version, Reply-To, Return-Path, Subject and To (Amazon SES header
	// fields).
	c, mb := newClient(t)

	for _, name := range []string{"From", "To", "Bcc", "Subject", "Message-ID", "Date", "Content-Type"} {
		t.Run(name, func(t *testing.T) {
			in := simpleInput("sender@example.com", "Header "+name, "Body.", "to@example.com")
			in.Content.Simple.Headers = []types.MessageHeader{
				{Name: aws.String(name), Value: aws.String("overridden@example.com")},
			}
			requireRejected(t, errOf(c.SendEmail(t.Context(), in)))
		})
	}
	requireEqual(t, len(mb.listAll(t, nil)), 0, "messages stored")
}

func TestSimpleAttachments(t *testing.T) {
	c, mb := newClient(t)
	pdf := append([]byte("%PDF-1.4\n"), bytes.Repeat([]byte{0, 1, 2, 0xfe, 0xff}, 300)...)
	csv := []byte("id,name\n1,Ada\n2,Grace\n")

	in := simpleInput("sender@example.com", "Report", "See attached.", "to@example.com")
	in.Content.Simple.Body.Html = &types.Content{Data: aws.String("<p>See attached.</p>")}
	in.Content.Simple.Attachments = []types.Attachment{
		{
			FileName:    aws.String("report.pdf"),
			ContentType: aws.String("application/pdf"),
			RawContent:  pdf,
		},
		{
			FileName:           aws.String("people.csv"),
			ContentType:        aws.String("text/csv"),
			ContentDisposition: types.AttachmentContentDispositionAttachment,
			RawContent:         csv,
		},
	}
	id := send(t, c, in)

	msg, m := mb.stored(t, id)
	requireEqual(t, msg.AttachmentCount, 2, "attachment count")
	want := []attachment{
		{Name: "report.pdf", ContentType: "application/pdf", Size: int64(len(pdf))},
		{Name: "people.csv", ContentType: "text/csv", Size: int64(len(csv))},
	}
	requireAttachments(t, msg.Attachments, want)
	m.requireBody(t, "text/plain", "See attached.")
	m.requireBody(t, "text/html", "<p>See attached.</p>")

	contents := [][]byte{pdf, csv}
	parts := m.attachments()
	requireEqual(t, len(parts), 2, "attachment parts in the MIME")
	for i, part := range parts {
		name := part.DispParams["filename"]
		if name == "" {
			name = part.Params["name"]
		}
		requireEqual(t, name, want[i].Name, "attachment part file name")
		requireEqual(t, part.MediaType, want[i].ContentType, "attachment part type")
		requireBytes(t, part.Body, contents[i], "attachment part "+name)

		// Attachments are indexed from 0, in the order of the full message's
		// list.
		res := mb.attachmentAt(t, msg.ID, i)
		requireOK(t, res, "get attachment "+name)
		requireMediaType(t, res, want[i].ContentType)
		requireBytes(t, res.Body, contents[i], "attachment "+name+" bytes")
	}

	// Assumption: an index past the last attachment is not found.
	res := mb.attachmentAt(t, msg.ID, 2)
	requireAPIErrorBody(t, res, http.StatusNotFound, "NotFoundException", "attachment past the end")
}

// requireAttachments fails unless the attachments' metadata is want, in
// order, comparing media types without parameters.
func requireAttachments(t *testing.T, got, want []attachment) {
	t.Helper()
	if len(got) != len(want) {
		t.Fatalf("attachments: got %+v, want %+v", got, want)
	}
	for i := range want {
		g := got[i]
		g.ContentType, _, _ = strings.Cut(g.ContentType, ";")
		if g != want[i] {
			t.Fatalf("attachment %d: got %+v, want %+v", i, got[i], want[i])
		}
	}
}

func TestSendersNeedNoIdentity(t *testing.T) {
	// The design: any From address is accepted, with no identity created.
	c, mb := newClient(t)

	out, err := c.ListEmailIdentities(t.Context(), &sesv2.ListEmailIdentitiesInput{})
	requireNoErr(t, err, "list identities")
	requireEqual(t, len(out.EmailIdentities), 0, "identities")

	id := send(t, c, simpleInput("nobody@unverified.example", "Hi", "Body.", "to@example.com"))
	requireEqual(t, mb.byMessageID(t, id).From, "nobody@unverified.example", "from")
}

func TestMessageIDsAreUnique(t *testing.T) {
	c, mb := newClient(t)

	seen := map[string]bool{}
	for range 5 {
		id := send(t, c, simpleInput("sender@example.com", "Same", "Same.", "to@example.com"))
		if seen[id] {
			t.Fatalf("message ID %s returned twice", id)
		}
		seen[id] = true
	}
	requireEqual(t, len(mb.listAll(t, nil)), 5, "messages stored")
}

func TestConfigurationSetAndTagsAreStored(t *testing.T) {
	// The design: configuration sets are not modeled, so any name is
	// accepted and recorded with the message, as its EmailTags are.
	c, mb := newClient(t)

	in := simpleInput("sender@example.com", "Tagged", "Body.", "to@example.com")
	in.ConfigurationSetName = aws.String("transactional")
	in.EmailTags = []types.MessageTag{
		{Name: aws.String("campaign"), Value: aws.String("welcome")},
		{Name: aws.String("tier"), Value: aws.String("gold_1")},
	}
	id := send(t, c, in)

	s := mb.byMessageID(t, id)
	requireEqual(t, s.ConfigurationSet, "transactional", "configuration set")
	// Tags are kept in sent order.
	want := []nameValue{{Name: "campaign", Value: "welcome"}, {Name: "tier", Value: "gold_1"}}
	if !slices.Equal(s.Tags, want) {
		t.Fatalf("tags %+v, want %+v", s.Tags, want)
	}
}
