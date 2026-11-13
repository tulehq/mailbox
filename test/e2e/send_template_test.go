//go:build e2e

package e2e

import (
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/sesv2"
	"github.com/aws/aws-sdk-go-v2/service/sesv2/types"
)

// greeting is the template of Using templates to send personalized email
// with the Amazon SES API, Part 2.
var greeting = &types.EmailTemplateContent{
	Subject: aws.String("Greetings, {{name}}!"),
	Text:    aws.String("Dear {{name}},\r\nYour favorite animal is {{favoriteanimal}}."),
	Html: aws.String(
		"<h1>Hello {{name}},</h1><p>Your favorite animal is {{favoriteanimal}}.</p>",
	),
}

func createTemplate(
	t *testing.T,
	c *sesv2.Client,
	name string,
	content *types.EmailTemplateContent,
) {
	t.Helper()
	_, err := c.CreateEmailTemplate(t.Context(), &sesv2.CreateEmailTemplateInput{
		TemplateName:    aws.String(name),
		TemplateContent: content,
	})
	requireNoErr(t, err, "create template "+name)
}

func templateInput(tmpl *types.Template, to ...string) *sesv2.SendEmailInput {
	return &sesv2.SendEmailInput{
		FromEmailAddress: aws.String("Mary Major <mary.major@example.com>"),
		Destination:      &types.Destination{ToAddresses: to},
		Content:          &types.EmailContent{Template: tmpl},
	}
}

// requireGreeting fails unless the stored message is greeting rendered for
// name and animal.
func requireGreeting(t *testing.T, mb *mailbox, id, name, animal string, sent time.Time) message {
	t.Helper()

	msg, m := mb.stored(t, id)
	subject := "Greetings, " + name + "!"
	text := "Dear " + name + ",\r\nYour favorite animal is " + animal + "."
	html := "<h1>Hello " + name + ",</h1><p>Your favorite animal is " + animal + ".</p>"

	requireEqual(t, msg.Subject, subject, "summary subject")
	requireEqual(t, strings.TrimRight(msg.Text, "\r\n"), text, "full text")
	requireEqual(t, strings.TrimRight(msg.HTML, "\r\n"), html, "full html")
	requireEqual(t, m.subject(t), subject, "Subject header")
	m.requireSESHeaders(t, sent)
	m.requireBody(t, "text/plain", text)
	m.requireBody(t, "text/html", html)
	return msg
}

func TestTemplateByName(t *testing.T) {
	c, mb := newClient(t)
	createTemplate(t, c, "MyTemplate", greeting)
	sent := time.Now()

	in := templateInput(&types.Template{
		TemplateName: aws.String("MyTemplate"),
		TemplateData: aws.String(`{ "name":"Alejandro", "favoriteanimal": "alligator" }`),
		Headers: []types.MessageHeader{
			{Name: aws.String("X-Template"), Value: aws.String("yes")},
		},
	}, "alejandro.rosalez@example.com", "jimmy.jet@example.com")
	in.ConfigurationSetName = aws.String("ConfigSet")
	id := send(t, c, in)

	msg := requireGreeting(t, mb, id, "Alejandro", "alligator", sent)
	// from is the From as sent, display name included.
	requireEqual(t, msg.From, "Mary Major <mary.major@example.com>", "from")
	requireSameSet(
		t,
		msg.To,
		[]string{"alejandro.rosalez@example.com", "jimmy.jet@example.com"},
		"to",
	)
	requireEqual(t, msg.ConfigurationSet, "ConfigSet", "configuration set")
	requireSameSet(
		t,
		headerValues(msg.Headers, "X-Template"),
		[]string{"yes"},
		"template header",
	)
}

func TestTemplateByARN(t *testing.T) {
	// Assumption: the account is 000000000000, the Tule default management
	// account, and a template's ARN is arn:aws:ses:<region>:<account>:template/<name>,
	// the form of SES resource ARNs. Nothing returns the ARN to check it
	// against: GetEmailTemplate has no ARN in its output.
	c, mb := newClient(t)
	createTemplate(t, c, "ByArn", greeting)
	sent := time.Now()

	id := send(t, c, templateInput(&types.Template{
		TemplateArn:  aws.String("arn:aws:ses:" + region + ":000000000000:template/ByArn"),
		TemplateData: aws.String(`{"name":"Liu","favoriteanimal":"lion"}`),
	}, "liu.jie@example.com"))

	requireGreeting(t, mb, id, "Liu", "lion", sent)
}

func TestTemplateHTMLIsNotEscaped(t *testing.T) {
	// "SES doesn't escape HTML content when rendering the HTML template for
	// a message" (Advanced email personalization).
	c, mb := newClient(t)
	createTemplate(t, c, "Raw", &types.EmailTemplateContent{
		Subject: aws.String("Note"),
		Html:    aws.String("<div>{{note}}</div>"),
	})

	id := send(t, c, templateInput(&types.Template{
		TemplateName: aws.String("Raw"),
		TemplateData: aws.String(`{"note":"<b>bold</b> & more"}`),
	}, "to@example.com"))

	msg := mb.get(t, mb.byMessageID(t, id).ID)
	requireEqual(t, strings.TrimRight(msg.HTML, "\r\n"), "<div><b>bold</b> & more</div>", "html")
}

func TestBulkEmail(t *testing.T) {
	c, mb := newClient(t)
	createTemplate(t, c, "MyTemplate", greeting)
	sent := time.Now()

	out, err := c.SendBulkEmail(t.Context(), &sesv2.SendBulkEmailInput{
		FromEmailAddress: aws.String("Mary Major <mary.major@example.com>"),
		DefaultContent: &types.BulkEmailContent{Template: &types.Template{
			TemplateName: aws.String("MyTemplate"),
			TemplateData: aws.String(`{ "name":"friend", "favoriteanimal":"unknown" }`),
			Headers: []types.MessageHeader{
				{Name: aws.String("X-Shared"), Value: aws.String("template")},
				{Name: aws.String("X-Override"), Value: aws.String("template")},
			},
		}},
		DefaultEmailTags: []types.MessageTag{
			{Name: aws.String("batch"), Value: aws.String("b1")},
		},
		ConfigurationSetName: aws.String("ConfigSet"),
		BulkEmailEntries:     bulkEntries(),
	})
	requireNoErr(t, err, "send bulk email")
	requireEqual(t, len(out.BulkEmailEntryResults), 3, "entry results")

	seen := map[string]bool{}
	for i, r := range out.BulkEmailEntryResults {
		requireEqual(t, r.Status, types.BulkEmailStatusSuccess, "entry status")
		id := aws.ToString(r.MessageId)
		if id == "" || seen[id] {
			t.Fatalf("entry %d message ID %q is empty or repeated", i, id)
		}
		seen[id] = true
	}
	requireEqual(t, len(mb.listAll(t, nil)), 3, "messages stored")

	requireBulkStored(t, mb, out.BulkEmailEntryResults, sent)
}

// requireBulkStored fails unless each entry of bulkEntries was stored as
// its own message, rendered with its data.
func requireBulkStored(
	t *testing.T,
	mb *mailbox,
	results []types.BulkEmailEntryResult,
	sent time.Time,
) {
	t.Helper()

	// Assumption: the results are in the order of the entries, which the
	// model implies ("one object per intended recipient") but does not state.
	anaya := requireGreeting(t, mb, aws.ToString(results[0].MessageId), "Anaya", "angelfish", sent)
	requireSameSet(t, anaya.To, []string{"anaya.iyengar@example.com"}, "entry 0 to")
	requireEqual(t, anaya.ConfigurationSet, "ConfigSet", "entry 0 configuration set")
	requireEqual(t, tagsOf(anaya.Tags)["batch"], "b1", "entry 0 default tag")
	// A header in both the template and the entry takes the entry's value;
	// one only in the template is added (BulkEmailEntry.ReplacementHeaders).
	requireSameSet(
		t,
		headerValues(anaya.Headers, "X-Override"),
		[]string{"entry"},
		"entry 0 replaced header",
	)
	requireSameSet(
		t,
		headerValues(anaya.Headers, "X-Shared"),
		[]string{"template"},
		"entry 0 template header",
	)
	requireSameSet(
		t,
		headerValues(anaya.Headers, "X-Entry"),
		[]string{"anaya"},
		"entry 0 own header",
	)

	liu := requireGreeting(t, mb, aws.ToString(results[1].MessageId), "Liu", "lion", sent)
	requireSameSet(t, liu.Cc, []string{"liu.cc@example.com"}, "entry 1 cc")
	requireEqual(t, tagsOf(liu.Tags)["segment"], "vip", "entry 1 replacement tag")
	requireSameSet(
		t,
		headerValues(liu.Headers, "X-Override"),
		[]string{"template"},
		"entry 1 template header",
	)

	// "{}" falls back to the default TemplateData (Part 3, ReplacementTemplateData).
	roe := requireGreeting(t, mb, aws.ToString(results[2].MessageId), "friend", "unknown", sent)
	requireSameSet(t, roe.To, []string{"richard.roe@example.com"}, "entry 2 to")
}

func bulkEntries() []types.BulkEmailEntry {
	replacement := func(data string) *types.ReplacementEmailContent {
		return &types.ReplacementEmailContent{
			ReplacementTemplate: &types.ReplacementTemplate{
				ReplacementTemplateData: aws.String(data),
			},
		}
	}
	return []types.BulkEmailEntry{
		{
			Destination: &types.Destination{
				ToAddresses: []string{"anaya.iyengar@example.com"},
			},
			ReplacementEmailContent: replacement(
				`{ "name":"Anaya", "favoriteanimal":"angelfish" }`,
			),
			ReplacementHeaders: []types.MessageHeader{
				{Name: aws.String("X-Override"), Value: aws.String("entry")},
				{Name: aws.String("X-Entry"), Value: aws.String("anaya")},
			},
		},
		{
			Destination: &types.Destination{
				ToAddresses: []string{"liu.jie@example.com"},
				CcAddresses: []string{"liu.cc@example.com"},
			},
			ReplacementEmailContent: replacement(`{ "name":"Liu", "favoriteanimal":"lion" }`),
			ReplacementTags: []types.MessageTag{
				{Name: aws.String("segment"), Value: aws.String("vip")},
			},
		},
		{
			Destination: &types.Destination{
				ToAddresses: []string{"richard.roe@example.com"},
			},
			ReplacementEmailContent: replacement(`{}`),
		},
	}
}
