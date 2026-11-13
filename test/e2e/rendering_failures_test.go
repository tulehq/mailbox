//go:build e2e

package e2e

import (
	"encoding/json"
	"net/http"
	"net/url"
	"slices"
	"strconv"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/sesv2"
	"github.com/aws/aws-sdk-go-v2/service/sesv2/types"
)

// SES may accept a templated message it cannot render and then not deliver
// it, publishing a Rendering Failure event instead (SendEmailOutput.MessageId;
// Using templates to send personalized email, Part 1). mailbox records such
// a message under GET /_mailbox/rendering-failures rather than storing it.

// renderingFailure is an item of GET /_mailbox/rendering-failures.
type renderingFailure struct {
	MessageID        string      `json:"messageId"`
	Time             string      `json:"time"`
	Source           string      `json:"source"`
	Template         string      `json:"template"`
	From             string      `json:"from"`
	ConfigurationSet string      `json:"configurationSet"`
	Error            string      `json:"error"`
	To               []string    `json:"to"`
	Cc               []string    `json:"cc"`
	Bcc              []string    `json:"bcc"`
	Tags             []nameValue `json:"tags"`
}

type failurePage struct {
	NextCursor string             `json:"nextCursor"`
	Items      []renderingFailure `json:"items"`
}

// failures lists rendering failures matching query, following the cursor.
func (m *mailbox) failures(t *testing.T, query url.Values) []renderingFailure {
	t.Helper()

	q := url.Values{}
	for k, v := range query {
		q[k] = v
	}
	var all []renderingFailure
	for range 1000 {
		res := m.do(t, http.MethodGet, "/_mailbox/rendering-failures", q)
		requireOK(t, res, "list rendering failures")
		var p failurePage
		decode(t, res, &p)
		var shape struct {
			Items []json.RawMessage `json:"items"`
		}
		decode(t, res, &shape)
		for _, item := range shape.Items {
			requireArrays(t, item, "to", "cc", "bcc", "tags")
		}
		all = append(all, p.Items...)
		if p.NextCursor == "" {
			return all
		}
		q.Set("cursor", p.NextCursor)
	}
	t.Fatal("the cursor did not end after 1000 pages")
	return nil
}

// missingX is a template whose text needs x.
var missingX = &types.EmailTemplateContent{
	Subject: aws.String("Hello {{name}}"),
	Text:    aws.String("Dear {{name}}, {{x}}"),
	Html:    aws.String("<p>Dear {{name}}, {{x}}</p>"),
}

const missingXError = "Attribute 'x' is not present in the rendering data."

func TestMissingVariableIsARenderingFailure(t *testing.T) {
	c, mb := newClient(t)
	createTemplate(t, c, "NeedsX", missingX)

	in := templateInput(&types.Template{
		TemplateName: aws.String("NeedsX"),
		TemplateData: aws.String(`{"name":"Ada"}`),
	}, "to@example.com")
	in.Destination.CcAddresses = []string{"cc@example.com"}
	in.Destination.BccAddresses = []string{"bcc@example.com"}
	in.ConfigurationSetName = aws.String("ConfigSet")
	in.EmailTags = []types.MessageTag{{Name: aws.String("campaign"), Value: aws.String("x")}}
	id := send(t, c, in)

	requireEqual(t, len(mb.listAll(t, nil)), 0, "messages stored")
	requireEqual(t, len(mb.listAll(t, url.Values{"messageId": {id}})), 0, "messages with the ID")
	requireAPIErrorBody(t, mb.do(t, http.MethodGet, "/_mailbox/messages/"+url.PathEscape(id), nil),
		http.StatusNotFound, "NotFoundException", "get the unrendered message")

	got := mb.failures(t, nil)
	requireEqual(t, len(got), 1, "rendering failures")
	f := got[0]
	requireEqual(t, f.MessageID, id, "messageId")
	requireEqual(t, f.Error, missingXError, "error")
	requireEqual(t, f.Template, "NeedsX", "template")
	// Assumption: source names the API, as the design records it.
	requireEqual(t, f.Source, "SendEmail", "source")
	requireEqual(t, f.From, "Mary Major <mary.major@example.com>", "from")
	requireSameSet(t, f.To, []string{"to@example.com"}, "to")
	requireSameSet(t, f.Cc, []string{"cc@example.com"}, "cc")
	requireSameSet(t, f.Bcc, []string{"bcc@example.com"}, "bcc")
	requireEqual(t, f.ConfigurationSet, "ConfigSet", "configurationSet")
	if !slices.Equal(f.Tags, []nameValue{{Name: "campaign", Value: "x"}}) {
		t.Fatalf("tags %+v", f.Tags)
	}
	requireMatch(t, timeFormat, f.Time, "time")
}

func TestBulkEntryWithMissingVariableIsARenderingFailure(t *testing.T) {
	c, mb := newClient(t)
	createTemplate(t, c, "NeedsX", missingX)

	out, err := c.SendBulkEmail(t.Context(), &sesv2.SendBulkEmailInput{
		FromEmailAddress: aws.String("sender@example.com"),
		DefaultContent: &types.BulkEmailContent{Template: &types.Template{
			TemplateName: aws.String("NeedsX"),
			TemplateData: aws.String(`{"name":"friend","x":"default"}`),
		}},
		BulkEmailEntries: []types.BulkEmailEntry{
			{Destination: &types.Destination{ToAddresses: []string{"ok@example.com"}}},
			{
				Destination: &types.Destination{ToAddresses: []string{"broken@example.com"}},
				ReplacementEmailContent: &types.ReplacementEmailContent{
					ReplacementTemplate: &types.ReplacementTemplate{
						ReplacementTemplateData: aws.String(`{"name":"Bo"}`),
					},
				},
			},
		},
	})
	requireNoErr(t, err, "send bulk email")
	requireEqual(t, len(out.BulkEmailEntryResults), 2, "entry results")
	for i, r := range out.BulkEmailEntryResults {
		requireEqual(t, r.Status, types.BulkEmailStatusSuccess, "status of entry "+strconv.Itoa(i))
	}
	okID, brokenID := aws.ToString(out.BulkEmailEntryResults[0].MessageId),
		aws.ToString(out.BulkEmailEntryResults[1].MessageId)

	stored := mb.listAll(t, nil)
	requireEqual(t, len(stored), 1, "messages stored")
	requireSameSet(t, stored[0].To, []string{"ok@example.com"}, "stored message's to")
	mb.byMessageID(t, okID)
	requireEqual(
		t,
		len(mb.listAll(t, url.Values{"messageId": {brokenID}})),
		0,
		"the broken entry stored",
	)

	got := mb.failures(t, nil)
	requireEqual(t, len(got), 1, "rendering failures")
	requireEqual(t, got[0].MessageID, brokenID, "failure messageId")
	requireEqual(t, got[0].Error, missingXError, "failure error")
	requireEqual(t, got[0].Source, "SendBulkEmail", "failure source")
	requireSameSet(t, got[0].To, []string{"broken@example.com"}, "failure to")
}

func TestRenderingFailureFiltersAndPages(t *testing.T) {
	c, mb := newClient(t)
	createTemplate(t, c, "NeedsX", missingX)
	createTemplate(t, c, "AlsoNeedsX", missingX)
	fail := func(tmpl string) string {
		return send(t, c, templateInput(&types.Template{
			TemplateName: aws.String(tmpl),
			TemplateData: aws.String(`{"name":"Ada"}`),
		}, "to@example.com"))
	}

	first := fail("NeedsX")
	time.Sleep(1500 * time.Millisecond)
	between := time.Now().UTC().Format(time.RFC3339)
	time.Sleep(1500 * time.Millisecond)
	second := fail("AlsoNeedsX")

	ids := func(fs []renderingFailure) []string {
		out := make([]string, 0, len(fs))
		for _, f := range fs {
			out = append(out, f.MessageID)
		}
		return out
	}
	for name, tt := range map[string]struct {
		query url.Values
		want  []string
	}{
		"none, newest first": {nil, []string{second, first}},
		"messageId":          {url.Values{"messageId": {first}}, []string{first}},
		"template":           {url.Values{"template": {"AlsoNeedsX"}}, []string{second}},
		"since":              {url.Values{"since": {between}}, []string{second}},
		"until":              {url.Values{"until": {between}}, []string{first}},
		"template and since": {url.Values{"template": {"NeedsX"}, "since": {between}}, nil},
		"limit 1":            {url.Values{"limit": {"1"}}, []string{second, first}},
	} {
		t.Run(name, func(t *testing.T) {
			got := ids(mb.failures(t, tt.query))
			if !slices.Equal(got, tt.want) {
				t.Fatalf("got %q, want %q", got, tt.want)
			}
		})
	}

	res := mb.do(
		t,
		http.MethodGet,
		"/_mailbox/rendering-failures",
		url.Values{"since": {"yesterday"}},
	)
	requireAPIErrorBody(t, res, http.StatusBadRequest, "BadRequestException", "since=yesterday")
}

func TestResetClearsRenderingFailures(t *testing.T) {
	c, mb := newClient(t)
	createTemplate(t, c, "NeedsX", missingX)
	send(t, c, templateInput(&types.Template{
		TemplateName: aws.String("NeedsX"),
		TemplateData: aws.String(`{"name":"Ada"}`),
	}, "to@example.com"))
	requireEqual(t, len(mb.failures(t, nil)), 1, "failures before reset")

	mb.reset(t)

	requireEqual(t, len(mb.failures(t, nil)), 0, "failures after reset")
}
