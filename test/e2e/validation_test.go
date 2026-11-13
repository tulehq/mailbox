//go:build e2e

package e2e

import (
	"bytes"
	"net/http"
	"strconv"
	"strings"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/sesv2"
	"github.com/aws/aws-sdk-go-v2/service/sesv2/types"
)

// Each case below is input SES documents as invalid. SES documents that it
// is refused, not which of BadRequestException and MessageRejected answers
// it, so requireRejected accepts either; every case must also leave nothing
// stored.

func TestInvalidSendsAreRefused(t *testing.T) {
	c, mb := newClient(t)

	tests := []struct {
		edit func(*sesv2.SendEmailInput)
		name string
	}{
		// "A standard email message ... you specify the sender, the
		// recipient, and the message body" (SendEmail API reference).
		{name: "no From", edit: func(in *sesv2.SendEmailInput) { in.FromEmailAddress = nil }},
		{name: "no Destination", edit: func(in *sesv2.SendEmailInput) { in.Destination = nil }},
		{name: "empty Destination", edit: func(in *sesv2.SendEmailInput) {
			in.Destination = &types.Destination{}
		}},
		{name: "invalid To", edit: func(in *sesv2.SendEmailInput) {
			in.Destination.ToAddresses = []string{"not-an-address"}
		}},
		{name: "invalid Cc", edit: func(in *sesv2.SendEmailInput) {
			in.Destination.CcAddresses = []string{"two@@example.com"}
		}},
		{name: "invalid From", edit: func(in *sesv2.SendEmailInput) {
			in.FromEmailAddress = aws.String("not an address")
		}},
		{name: "invalid Reply-To", edit: func(in *sesv2.SendEmailInput) {
			in.ReplyToAddresses = []string{"nobody"}
		}},
		// 50 recipients per message, To, CC and BCC together (Service
		// quotas in Amazon SES).
		{name: "51 recipients", edit: func(in *sesv2.SendEmailInput) {
			in.Destination = &types.Destination{
				ToAddresses:  addresses("to", 20),
				CcAddresses:  addresses("cc", 20),
				BccAddresses: addresses("bcc", 11),
			}
		}},
		// A tag name or value holds only ASCII letters, digits, _ and -, at
		// most 256 characters (types.MessageTag).
		{name: "tag name with a space", edit: func(in *sesv2.SendEmailInput) {
			in.EmailTags = []types.MessageTag{
				{Name: aws.String("bad name"), Value: aws.String("v")},
			}
		}},
		{name: "tag value of 257 characters", edit: func(in *sesv2.SendEmailInput) {
			in.EmailTags = []types.MessageTag{
				{Name: aws.String("n"), Value: aws.String(strings.Repeat("v", 257))},
			}
		}},
		// A header name has no colon; a value at most 995 characters
		// (types.MessageHeader).
		{name: "header name with a colon", edit: func(in *sesv2.SendEmailInput) {
			in.Content.Simple.Headers = []types.MessageHeader{
				{Name: aws.String("X:Bad"), Value: aws.String("v")},
			}
		}},
		{name: "header value of 996 characters", edit: func(in *sesv2.SendEmailInput) {
			in.Content.Simple.Headers = []types.MessageHeader{
				{Name: aws.String("X-Long"), Value: aws.String(strings.Repeat("v", 996))},
			}
		}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			in := simpleInput("sender@example.com", "Invalid", "Body.", "to@example.com")
			tt.edit(in)
			requireRejected(t, errOf(c.SendEmail(t.Context(), in)))
		})
	}
	requireEqual(t, len(mb.listAll(t, nil)), 0, "messages stored")
}

func TestFiftyRecipientsAreAccepted(t *testing.T) {
	// The other side of the quota: 50 recipients, To, CC and BCC together.
	c, mb := newClient(t)

	in := simpleInput("sender@example.com", "Fifty", "Body.")
	in.Destination = &types.Destination{
		ToAddresses:  addresses("to", 20),
		CcAddresses:  addresses("cc", 20),
		BccAddresses: addresses("bcc", 10),
	}
	id := send(t, c, in)
	s := mb.byMessageID(t, id)
	requireEqual(t, len(s.To)+len(s.Cc)+len(s.Bcc), 50, "recipients stored")
}

func TestInvalidRawMessagesAreRefused(t *testing.T) {
	c, mb := newClient(t)
	head := "From: sender@example.com\r\nTo: to@example.com\r\n"

	tests := map[string][]byte{
		// "The message has to contain a header and a body, separated by one
		// blank line" (types.RawMessage).
		"no header": []byte("just some words with no header at all"),
		// Subject "can't appear more than once" (Amazon SES header fields).
		"two Subject headers": []byte(head + "Subject: one\r\nSubject: two\r\n\r\nBody.\r\n"),
		// "The length of any single line of text in the message can't exceed
		// 1,000 characters" (types.RawMessage).
		"a line over 1000 characters": []byte(
			head + "Subject: long\r\n\r\n" + strings.Repeat("x", 1001) + "\r\n",
		),
	}
	for name, data := range tests {
		t.Run(name, func(t *testing.T) {
			err := errOf(c.SendEmail(t.Context(), &sesv2.SendEmailInput{
				FromEmailAddress: aws.String("sender@example.com"),
				Destination:      &types.Destination{ToAddresses: []string{"to@example.com"}},
				Content:          &types.EmailContent{Raw: &types.RawMessage{Data: data}},
			}))
			requireRejected(t, err)
		})
	}
	requireEqual(t, len(mb.listAll(t, nil)), 0, "messages stored")
}

func TestOversizedMessageIsRefused(t *testing.T) {
	// The SES v2 API takes messages of at most 40 MB, attachments included,
	// after base64 encoding (Service quotas in Amazon SES, Message quotas).
	// This one is 41 MiB, over the bound whichever megabyte is meant.
	if testing.Short() {
		t.Skip("sends a 41 MiB message")
	}
	c, mb := newClient(t)

	var b bytes.Buffer
	b.WriteString("From: sender@example.com\r\nTo: to@example.com\r\nSubject: Big\r\n" +
		"MIME-Version: 1.0\r\nContent-Type: application/octet-stream\r\n" +
		"Content-Transfer-Encoding: base64\r\n\r\n")
	line := strings.Repeat("A", 76) + "\r\n"
	for b.Len() < 41<<20 {
		b.WriteString(line)
	}

	err := errOf(c.SendEmail(t.Context(), &sesv2.SendEmailInput{
		FromEmailAddress: aws.String("sender@example.com"),
		Destination:      &types.Destination{ToAddresses: []string{"to@example.com"}},
		Content:          &types.EmailContent{Raw: &types.RawMessage{Data: b.Bytes()}},
	}))
	requireRejected(t, err)
	requireEqual(t, len(mb.listAll(t, nil)), 0, "messages stored")
}

func TestTemplateSendErrors(t *testing.T) {
	c, mb := newClient(t)
	createTemplate(t, c, "MyTemplate", greeting)

	t.Run("a missing template", func(t *testing.T) {
		// Assumption: NotFoundException, "The resource you attempted to
		// access doesn't exist" (HTTP 404), the one error SendEmail models
		// for a missing resource.
		err := errOf(c.SendEmail(t.Context(), templateInput(&types.Template{
			TemplateName: aws.String("NoSuchTemplate"),
			TemplateData: aws.String(`{}`),
		}, "to@example.com")))
		requireAs[*types.NotFoundException](t, err)
		requireStatus(t, err, http.StatusNotFound)
	})
	t.Run("TemplateData that is not JSON", func(t *testing.T) {
		// Assumption: refused as invalid input. TemplateData is "a JSON
		// object" (TestRenderEmailTemplateInput.TemplateData); SES documents
		// that invalid personalization content may be accepted and not
		// delivered, but not what it answers data that is not JSON at all.
		err := errOf(c.SendEmail(t.Context(), templateInput(&types.Template{
			TemplateName: aws.String("MyTemplate"),
			TemplateData: aws.String(`{"name": "unterminated`),
		}, "to@example.com")))
		requireRejected(t, err)
	})
	t.Run("more than 50 bulk entries", func(t *testing.T) {
		// "You can send email to up to 50 destination objects in each call
		// to the SendBulkEmail operation" (Using templates to send
		// personalized email with the Amazon SES API).
		entries := make([]types.BulkEmailEntry, 0, 51)
		for _, addr := range addresses("bulk", 51) {
			entries = append(entries, types.BulkEmailEntry{
				Destination: &types.Destination{ToAddresses: []string{addr}},
			})
		}
		err := errOf(c.SendBulkEmail(t.Context(), &sesv2.SendBulkEmailInput{
			FromEmailAddress: aws.String("sender@example.com"),
			DefaultContent: &types.BulkEmailContent{Template: &types.Template{
				TemplateName: aws.String("MyTemplate"),
				TemplateData: aws.String(`{"name":"friend","favoriteanimal":"cat"}`),
			}},
			BulkEmailEntries: entries,
		}))
		requireRejected(t, err)
	})
	requireEqual(t, len(mb.listAll(t, nil)), 0, "messages stored")
}

// addresses returns n distinct addresses with the given prefix.
func addresses(prefix string, n int) []string {
	out := make([]string, 0, n)
	for i := range n {
		out = append(out, prefix+strconv.Itoa(i)+"@example.com")
	}
	return out
}
