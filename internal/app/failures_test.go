package app

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/sesv2"
	"github.com/aws/aws-sdk-go-v2/service/sesv2/types"
)

// getJSON sends a signed GET or DELETE for path and decodes the JSON it
// answers into dst, when dst is not nil. It returns the status.
func getJSON(t *testing.T, srv *httptest.Server, method, path string, dst any) int {
	t.Helper()
	res, err := srv.Client().Do(signedRequest(t, method, srv.URL+path))
	if err != nil {
		t.Fatalf("%s %s: %v", method, path, err)
	}
	defer func() { _ = res.Body.Close() }()
	if dst != nil {
		if err = json.NewDecoder(res.Body).Decode(dst); err != nil {
			t.Fatalf("decode %s %s: %v", method, path, err)
		}
	}
	return res.StatusCode
}

type failurePage struct {
	Items []struct {
		MessageID string   `json:"messageId"`
		Source    string   `json:"source"`
		Template  string   `json:"template"`
		From      string   `json:"from"`
		Error     string   `json:"error"`
		To        []string `json:"to"`
		Tags      []struct {
			Name  string `json:"name"`
			Value string `json:"value"`
		} `json:"tags"`
	} `json:"items"`
}

type messagePage struct {
	Items []struct {
		ID string `json:"id"`
	} `json:"items"`
}

func createGreeting(t *testing.T, c *sesv2.Client) {
	t.Helper()
	if _, err := c.CreateEmailTemplate(context.Background(), &sesv2.CreateEmailTemplateInput{
		TemplateName: aws.String("Greeting"),
		TemplateContent: &types.EmailTemplateContent{
			Subject: aws.String("Hi {{name}}"), Text: aws.String("Hello {{name}}."),
		},
	}); err != nil {
		t.Fatalf("create template: %v", err)
	}
}

const missingName = "Attribute 'name' is not present in the rendering data."

func TestARenderingFailureIsRecordedAndNotStored(t *testing.T) {
	ctx := context.Background()
	c, srv := startApp(t, t.TempDir())
	createGreeting(t, c)

	out, err := c.SendEmail(ctx, &sesv2.SendEmailInput{
		FromEmailAddress: aws.String("sender@example.com"),
		Destination:      &types.Destination{ToAddresses: []string{"to@example.com"}},
		EmailTags:        []types.MessageTag{{Name: aws.String("k"), Value: aws.String("v")}},
		Content: &types.EmailContent{Template: &types.Template{
			TemplateName: aws.String("Greeting"), TemplateData: aws.String(`{}`),
		}},
	})
	if err != nil {
		t.Fatalf("send email: %v", err)
	}
	id := aws.ToString(out.MessageId)
	if id == "" {
		t.Fatal("send email answered no MessageId")
	}

	if status := getJSON(t, srv, http.MethodGet, "/_mailbox/messages/"+id, nil); status !=
		http.StatusNotFound {
		t.Fatalf("get the failed message = %d, want 404", status)
	}
	requireOneFailure(t, srv, id)

	// A reset clears the failures with the messages.
	getJSON(t, srv, http.MethodDelete, "/_mailbox/messages", nil)
	var page failurePage
	getJSON(t, srv, http.MethodGet, "/_mailbox/rendering-failures", &page)
	if len(page.Items) != 0 {
		t.Fatalf("failures after reset = %+v", page.Items)
	}
}

// requireOneFailure fails unless the failures list holds the SendEmail
// failure of TestARenderingFailureIsRecordedAndNotStored for id.
func requireOneFailure(t *testing.T, srv *httptest.Server, id string) {
	t.Helper()
	var page failurePage
	getJSON(t, srv, http.MethodGet, "/_mailbox/rendering-failures?messageId="+id, &page)
	if len(page.Items) != 1 {
		t.Fatalf("failures = %+v, want one", page.Items)
	}
	f := page.Items[0]
	if f.Source != "SendEmail" || f.Template != "Greeting" || f.Error != missingName ||
		f.From != "sender@example.com" || len(f.To) != 1 || len(f.Tags) != 1 {
		t.Fatalf("failure = %+v", f)
	}
}

func TestABulkEntryThatFailsToRenderIsRecorded(t *testing.T) {
	ctx := context.Background()
	c, srv := startApp(t, t.TempDir())
	createGreeting(t, c)

	entry := func(to, data string) types.BulkEmailEntry {
		return types.BulkEmailEntry{
			Destination: &types.Destination{ToAddresses: []string{to}},
			ReplacementEmailContent: &types.ReplacementEmailContent{
				ReplacementTemplate: &types.ReplacementTemplate{
					ReplacementTemplateData: aws.String(data),
				},
			},
		}
	}
	out, err := c.SendBulkEmail(ctx, &sesv2.SendBulkEmailInput{
		FromEmailAddress: aws.String("sender@example.com"),
		DefaultContent: &types.BulkEmailContent{Template: &types.Template{
			TemplateName: aws.String("Greeting"), TemplateData: aws.String(`{"other":1}`),
		}},
		BulkEmailEntries: []types.BulkEmailEntry{
			entry("a@example.com", `{"name":"A"}`),
			entry("b@example.com", `{"nom":"B"}`),
		},
	})
	if err != nil {
		t.Fatalf("send bulk email: %v", err)
	}
	requireAllSucceeded(t, out.BulkEmailEntryResults)

	var messages messagePage
	getJSON(t, srv, http.MethodGet, "/_mailbox/messages", &messages)
	if len(messages.Items) != 1 ||
		messages.Items[0].ID != aws.ToString(out.BulkEmailEntryResults[0].MessageId) {
		t.Fatalf("messages = %+v, want the first entry's alone", messages.Items)
	}
	var page failurePage
	getJSON(t, srv, http.MethodGet, "/_mailbox/rendering-failures?template=Greeting", &page)
	if len(page.Items) != 1 || page.Items[0].Source != "SendBulkEmail" ||
		page.Items[0].MessageID != aws.ToString(out.BulkEmailEntryResults[1].MessageId) ||
		page.Items[0].Error != missingName {
		t.Fatalf("failures = %+v, want the second entry's", page.Items)
	}
}

func TestTestRenderReportsAMissingHelper(t *testing.T) {
	ctx := context.Background()
	c, _ := startApp(t, t.TempDir())
	if _, err := c.CreateEmailTemplate(ctx, &sesv2.CreateEmailTemplateInput{
		TemplateName:    aws.String("Helper"),
		TemplateContent: &types.EmailTemplateContent{Subject: aws.String("{{eq 1 1}}")},
	}); err != nil {
		t.Fatalf("create template: %v", err)
	}
	_, err := c.TestRenderEmailTemplate(ctx, &sesv2.TestRenderEmailTemplateInput{
		TemplateName: aws.String("Helper"), TemplateData: aws.String(`{}`),
	})
	var bad *types.BadRequestException
	if !errors.As(err, &bad) || aws.ToString(bad.Message) != `Missing helper: "eq"` {
		t.Fatalf("test render = %v, want BadRequestException for the missing helper", err)
	}
}

func TestAFromWithAnInjectedHeaderIsRefused(t *testing.T) {
	ctx := context.Background()
	c, srv := startApp(t, t.TempDir())

	_, err := c.SendEmail(ctx, &sesv2.SendEmailInput{
		FromEmailAddress: aws.String("a@example.com (x\r\nBcc: evil@example.com)"),
		Destination:      &types.Destination{ToAddresses: []string{"to@example.com"}},
		Content: &types.EmailContent{Simple: &types.Message{
			Subject: &types.Content{Data: aws.String("x")},
			Body:    &types.Body{Text: &types.Content{Data: aws.String("x")}},
		}},
	})
	var bad *types.BadRequestException
	if !errors.As(err, &bad) {
		t.Fatalf("send with CRLF in the From = %v, want BadRequestException", err)
	}
	var messages messagePage
	getJSON(t, srv, http.MethodGet, "/_mailbox/messages", &messages)
	if len(messages.Items) != 0 {
		t.Fatalf("messages = %+v, want none", messages.Items)
	}
}

func TestANULInAFilterIsABadRequest(t *testing.T) {
	_, srv := startApp(t, t.TempDir())
	for _, path := range []string{
		"/_mailbox/messages?q=%00", "/_mailbox/rendering-failures?template=%00",
	} {
		var body struct{ Code string }
		status := getJSON(t, srv, http.MethodGet, path, &body)
		if status != http.StatusBadRequest || body.Code != "BadRequestException" {
			t.Errorf("%s = %d %s, want 400 BadRequestException", path, status, body.Code)
		}
	}
}

func requireAllSucceeded(t *testing.T, results []types.BulkEmailEntryResult) {
	t.Helper()
	for i, r := range results {
		if r.Status != types.BulkEmailStatusSuccess || aws.ToString(r.MessageId) == "" {
			t.Fatalf("entry %d = %+v, want SUCCESS with a MessageId", i, r)
		}
	}
}
