//go:build e2e

package e2e

import (
	"context"
	"io/fs"
	"strings"
	"testing"
	"time"

	"github.com/gasmod/gas"
	"github.com/gasmod/gas/email/ses"
)

// Gas's email/ses sender, unchanged, against mailbox. Its package
// documentation, Requests: one SendEmail with Simple content, the subject and
// bodies in UTF-8, a non-ASCII subject as RFC 2047 encoded words, the
// headers in name order, Reply-To when set, and To, Cc and Bcc.

func TestGasSESSender(t *testing.T) {
	srv := startServer(t, nil)
	mb := mailboxFor(srv)

	cfg := ses.DefaultConfig()
	cfg.Email.Region = region
	cfg.Email.Endpoint = srv.URL
	cfg.Email.FromEmail = "Shop <shop@example.com>"
	cfg.Email.AccessKeyID = "test"
	cfg.Email.SecretAccessKey = ses.Secret("test")
	cfg.Email.MaxRetries = 0

	mailer, err := ses.New(ses.WithConfig(cfg))(noTemplates{}, nil, &gas.NopLogger{})
	requireNoErr(t, err, "new sender")
	requireNoErr(t, mailer.Init(t.Context()), "init sender")
	t.Cleanup(func() { requireNoErr(t, mailer.Close(context.Background()), "close sender") })

	sent := time.Now()
	err = mailer.Send(t.Context(), &gas.Email{
		ReplyTo:  "help@example.com",
		Subject:  "Ihre Bestellung: Grüße",
		TextBody: "It ships today.",
		HTMLBody: "<p>It ships <b>today</b>.</p>",
		Headers:  map[string]string{"X-Order": "1234", "X-Campaign": "autumn"},
		To:       []string{"alice@example.com"},
		Cc:       []string{"carol@example.com"},
		Bcc:      []string{"audit@example.com"},
	})
	requireNoErr(t, err, "send through the gas sender")

	items := mb.listAll(t, nil)
	requireEqual(t, len(items), 1, "messages stored")
	msg := mb.get(t, items[0].ID)
	m := parseMIME(t, mb.raw(t, msg.ID))

	requireSameSet(t, msg.To, []string{"alice@example.com"}, "to")
	requireSameSet(t, msg.Cc, []string{"carol@example.com"}, "cc")
	requireSameSet(t, msg.Bcc, []string{"audit@example.com"}, "bcc")
	requireEqual(t, strings.TrimRight(msg.Text, "\r\n"), "It ships today.", "text")
	requireEqual(t, strings.TrimRight(msg.HTML, "\r\n"), "<p>It ships <b>today</b>.</p>", "html")
	requireSameSet(t, headerValues(msg.Headers, "X-Order"), []string{"1234"}, "X-Order")

	m.requireSESHeaders(t, sent)
	requireEqual(t, m.subject(t), "Ihre Bestellung: Grüße", "decoded subject")
	requireSameSet(t, m.addresses(t, "From"), []string{"shop@example.com"}, "From header")
	requireSameSet(t, m.addresses(t, "Reply-To"), []string{"help@example.com"}, "Reply-To header")
	requireEqual(t, m.Header.Get("X-Campaign"), "autumn", "X-Campaign header")
	m.requireNoHeader(t, "Bcc")
	m.requireBody(t, "text/plain", "It ships today.")
	m.requireBody(t, "text/html", "<p>It ships <b>today</b>.</p>")

	// Gas reads GetAccount through its client for what it has no method
	// for (package documentation, Client).
	acct, err := mailer.Client().GetAccount(t.Context(), nil)
	requireNoErr(t, err, "get account through the gas client")
	requireEqual(t, acct.SendingEnabled, true, "sending enabled")
}

// noTemplates is a gas.TemplateProvider with no templates: Send uses none,
// and the constructor refuses a nil provider.
type noTemplates struct{}

func (noTemplates) Get(context.Context, string) ([]byte, error) { return nil, fs.ErrNotExist }

func (noTemplates) List(context.Context) ([]string, error) { return nil, nil }

func (noTemplates) Register(context.Context, string, []byte) error { return nil }

func (noTemplates) RegisterFS(context.Context, fs.FS) error { return nil }
