//go:build e2e

package e2e

import (
	"net/http"
	"strconv"
	"strings"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/sesv2"
	"github.com/aws/aws-sdk-go-v2/service/sesv2/types"
)

func TestTemplateLifecycle(t *testing.T) {
	c, _ := newClient(t)
	ctx := t.Context()
	name := aws.String("MyTemplate")
	createTemplate(t, c, "MyTemplate", greeting)

	got, err := c.GetEmailTemplate(ctx, &sesv2.GetEmailTemplateInput{TemplateName: name})
	requireNoErr(t, err, "get template")
	requireEqual(t, aws.ToString(got.TemplateName), "MyTemplate", "name")
	requireContent(t, got.TemplateContent, greeting)

	// "Any lines that you omit are removed from the template" (Managing
	// email templates, Updating an email template).
	updated := &types.EmailTemplateContent{
		Subject: aws.String("New subject {{name}}"),
		Text:    aws.String("New text {{name}}"),
	}
	_, err = c.UpdateEmailTemplate(ctx, &sesv2.UpdateEmailTemplateInput{
		TemplateName:    name,
		TemplateContent: updated,
	})
	requireNoErr(t, err, "update template")
	got, err = c.GetEmailTemplate(ctx, &sesv2.GetEmailTemplateInput{TemplateName: name})
	requireNoErr(t, err, "get updated template")
	requireContent(t, got.TemplateContent, updated)

	_, err = c.DeleteEmailTemplate(ctx, &sesv2.DeleteEmailTemplateInput{TemplateName: name})
	requireNoErr(t, err, "delete template")
	err = errOf(c.GetEmailTemplate(ctx, &sesv2.GetEmailTemplateInput{TemplateName: name}))
	requireAs[*types.NotFoundException](t, err)
}

func requireContent(t *testing.T, got, want *types.EmailTemplateContent) {
	t.Helper()
	if got == nil {
		t.Fatal("no template content")
	}
	requireEqual(t, aws.ToString(got.Subject), aws.ToString(want.Subject), "template subject")
	requireEqual(t, aws.ToString(got.Text), aws.ToString(want.Text), "template text")
	requireEqual(t, aws.ToString(got.Html), aws.ToString(want.Html), "template html")
}

func TestDuplicateTemplateAlreadyExists(t *testing.T) {
	// CreateEmailTemplate models AlreadyExistsException.
	c, _ := newClient(t)
	createTemplate(t, c, "Dup", greeting)

	err := errOf(c.CreateEmailTemplate(t.Context(), &sesv2.CreateEmailTemplateInput{
		TemplateName:    aws.String("Dup"),
		TemplateContent: greeting,
	}))
	requireAs[*types.AlreadyExistsException](t, err)
	requireStatus(t, err, http.StatusBadRequest)
}

func TestUnknownTemplateIsNotFound(t *testing.T) {
	// Get, Update, Delete and TestRender model NotFoundException, HTTP 404.
	// The developer guide names TemplateDoesNotExist for an update, the SES
	// v1 error; the v2 model has only NotFoundException for it.
	c, _ := newClient(t)
	ctx := t.Context()
	name := aws.String("NoSuchTemplate")

	calls := map[string]error{
		"get": errOf(c.GetEmailTemplate(ctx, &sesv2.GetEmailTemplateInput{TemplateName: name})),
		"update": errOf(c.UpdateEmailTemplate(ctx, &sesv2.UpdateEmailTemplateInput{
			TemplateName: name, TemplateContent: greeting,
		})),
		"delete": errOf(
			c.DeleteEmailTemplate(ctx, &sesv2.DeleteEmailTemplateInput{TemplateName: name}),
		),
		"render": errOf(c.TestRenderEmailTemplate(ctx, &sesv2.TestRenderEmailTemplateInput{
			TemplateName: name, TemplateData: aws.String(`{}`),
		})),
	}
	for op, err := range calls {
		t.Run(op, func(t *testing.T) {
			requireAs[*types.NotFoundException](t, err)
			requireStatus(t, err, http.StatusNotFound)
		})
	}
}

func TestListTemplatesPaginates(t *testing.T) {
	c, _ := newClient(t)
	want := []string{"One", "Two", "Three"}
	for _, name := range want {
		createTemplate(t, c, name, greeting)
	}

	var got []string
	pages := 0
	p := sesv2.NewListEmailTemplatesPaginator(
		c,
		&sesv2.ListEmailTemplatesInput{PageSize: aws.Int32(1)},
	)
	for p.HasMorePages() {
		page, err := p.NextPage(t.Context())
		requireNoErr(t, err, "list templates")
		pages++
		if len(page.TemplatesMetadata) > 1 {
			t.Fatalf("page of %d templates, want at most 1", len(page.TemplatesMetadata))
		}
		for _, meta := range page.TemplatesMetadata {
			got = append(got, aws.ToString(meta.TemplateName))
			if meta.CreatedTimestamp == nil || meta.CreatedTimestamp.IsZero() {
				t.Fatalf("template %s has no creation time", aws.ToString(meta.TemplateName))
			}
		}
	}
	requireSameSet(t, got, want, "templates listed")
	if pages < 3 {
		t.Fatalf("listed in %d pages of 1, want at least 3", pages)
	}
}

// preferences follows the Preferences2 template of Advanced email
// personalization: a nested attribute, #if with else, and #each, on one
// line so that no whitespace rule of Handlebars is in play.
var preferences = &types.EmailTemplateContent{
	Subject: aws.String("Preferences for {{contact.firstName}} {{contact.lastName}}"),
	Text: aws.String("Dear {{contact.firstName}}: " +
		"{{#if subscription}}you like{{#each subscription}} [{{interest}}]{{/each}}." +
		"{{else}}please choose.{{/if}}"),
	Html: aws.String("<p>{{contact.firstName}}</p>" +
		"{{#if subscription}}<ul>{{#each subscription}}<li>{{interest}}</li>{{/each}}</ul>" +
		"{{else}}<p>none</p>{{/if}}"),
}

func TestRenderTemplate(t *testing.T) {
	c, _ := newClient(t)
	createTemplate(t, c, "Preferences2", preferences)

	tests := []struct {
		name, data, subject, text, html string
	}{
		{
			name: "with a list",
			data: `{"contact":{"firstName":"Anaya","lastName":"Iyengar"},` +
				`"subscription":[{"interest":"Sports"},{"interest":"Cooking"}]}`,
			subject: "Preferences for Anaya Iyengar",
			text:    "Dear Anaya: you like [Sports] [Cooking].",
			html:    "<p>Anaya</p><ul><li>Sports</li><li>Cooking</li></ul>",
		},
		{
			name:    "without a list",
			data:    `{"contact":{"firstName":"Shirley","lastName":"Rodriguez"}}`,
			subject: "Preferences for Shirley Rodriguez",
			text:    "Dear Shirley: please choose.",
			html:    "<p>Shirley</p><p>none</p>",
		},
		{
			// SES does not escape HTML when it renders (Advanced email
			// personalization).
			name:    "with HTML in the data",
			data:    `{"contact":{"firstName":"<b>Bo</b>","lastName":"&"},"subscription":[]}`,
			subject: "Preferences for <b>Bo</b> &",
			text:    "Dear <b>Bo</b>: please choose.",
			html:    "<p><b>Bo</b></p><p>none</p>",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			out, err := c.TestRenderEmailTemplate(t.Context(), &sesv2.TestRenderEmailTemplateInput{
				TemplateName: aws.String("Preferences2"),
				TemplateData: aws.String(tt.data),
			})
			requireNoErr(t, err, "render template")

			// RenderedTemplate is "the complete MIME message"
			// (TestRenderEmailTemplateOutput).
			m := parseMIME(t, []byte(aws.ToString(out.RenderedTemplate)))
			requireEqual(t, m.subject(t), tt.subject, "rendered subject")
			m.requireBody(t, "text/plain", tt.text)
			m.requireBody(t, "text/html", tt.html)
		})
	}
}

func TestRenderTemplateWithDataThatIsNotJSON(t *testing.T) {
	// Assumption: BadRequestException, "The input you provided is invalid",
	// the error TestRenderEmailTemplate models for invalid input;
	// TemplateData is "a JSON object" (TestRenderEmailTemplateInput).
	c, _ := newClient(t)
	createTemplate(t, c, "MyTemplate", greeting)

	err := errOf(c.TestRenderEmailTemplate(t.Context(), &sesv2.TestRenderEmailTemplateInput{
		TemplateName: aws.String("MyTemplate"),
		TemplateData: aws.String(`{"name": `),
	}))
	requireAs[*types.BadRequestException](t, err)
	requireStatus(t, err, http.StatusBadRequest)
}

func TestEachOverAnObjectRendersStably(t *testing.T) {
	// #each iterates an object's keys as well as an array (Handlebars
	// built-in helpers, which SES's templates use). The order is not
	// asserted, only that the same template and data render the same way
	// every time.
	c, _ := newClient(t)
	createTemplate(t, c, "Each", &types.EmailTemplateContent{
		Subject: aws.String("Each"),
		Text:    aws.String("{{#each m}}{{@key}}={{this}};{{/each}}"),
		Html:    aws.String("<ul>{{#each m}}<li>{{@key}}={{this}}</li>{{/each}}</ul>"),
	})
	data := aws.String(`{"m":{"alpha":"1","bravo":"2","charlie":"3","delta":"4",` +
		`"echo":"5","foxtrot":"6","golf":"7","hotel":"8"}}`)

	var first string
	for i := range 20 {
		out, err := c.TestRenderEmailTemplate(t.Context(), &sesv2.TestRenderEmailTemplateInput{
			TemplateName: aws.String("Each"),
			TemplateData: data,
		})
		requireNoErr(t, err, "render")
		m := parseMIME(t, []byte(aws.ToString(out.RenderedTemplate)))
		text := m.bodies("text/plain")
		html := m.bodies("text/html")
		requireEqual(t, len(text), 1, "text bodies")
		requireEqual(t, len(html), 1, "html bodies")
		got := text[0] + "|" + html[0]
		if i == 0 {
			first = got
			for _, kv := range []string{"alpha=1;", "bravo=2;", "echo=5;", "hotel=8;"} {
				if !strings.Contains(text[0], kv) {
					t.Fatalf("text %q lacks %q", text[0], kv)
				}
			}
			continue
		}
		requireEqual(t, got, first, "render "+strconv.Itoa(i))
	}
}
