package sqlimpl

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"testing"
	"time"

	"github.com/gasmod/gas"
	"github.com/gasmod/gas/database"
	"github.com/gasmod/gas/migrate"
	_ "modernc.org/sqlite"

	"tule.dev/mailbox/internal/contracts"
)

// newStore opens a store on a fresh database file the way the app wires it:
// gas/database, then gas/migrate applying the schema the store registers.
func newStore(t *testing.T) *Service {
	t.Helper()
	ctx := context.Background()
	logger := &gas.NopLogger{}

	cfg := database.DefaultConfig()
	cfg.Database.Dialect = database.DialectSQLite
	cfg.Database.DSN = gas.Secret("file:" + filepath.Join(t.TempDir(), "mailbox.db"))
	cfg.Database.MaxOpenConns = 1
	cfg.Database.MaxIdleConns = 1

	db, err := database.New(database.WithConfig(cfg))(nil, logger)
	if err != nil {
		t.Fatalf("new database: %v", err)
	}
	if err = db.Init(ctx); err != nil {
		t.Fatalf("init database: %v", err)
	}
	t.Cleanup(func() {
		if cErr := db.Close(ctx); cErr != nil {
			t.Errorf("close database: %v", cErr)
		}
	})

	mm, err := migrate.New()(db, logger)
	if err != nil {
		t.Fatalf("new migrate: %v", err)
	}
	if err = mm.Init(ctx); err != nil {
		t.Fatalf("init migrate: %v", err)
	}
	s := NewService(db, mm)
	if err = s.Init(ctx); err != nil {
		t.Fatalf("init store: %v", err)
	}
	if err = mm.RunPendingContext(ctx); err != nil {
		t.Fatalf("run migrations: %v", err)
	}
	return s
}

var base = time.Date(2026, 11, 13, 10, 0, 0, 0, time.UTC)

// message returns a message with ID id, sent n minutes after base.
func message(id string, n int) contracts.Message {
	return contracts.Message{
		Time:        base.Add(time.Duration(n) * time.Minute),
		ID:          id,
		Source:      contracts.SourceSendEmail,
		Kind:        contracts.KindSimple,
		From:        "Sender <sender@example.com>",
		FromAddress: "sender@example.com",
		Subject:     "Subject " + id,
		Text:        "body of " + id,
		To:          []string{"to-" + id + "@example.com"},
		Recipients:  []string{"to-" + id + "@example.com"},
		MIME:        []byte("Subject: " + id + "\r\n\r\nbody\r\n"),
		Size:        len("Subject: " + id + "\r\n\r\nbody\r\n"),
	}
}

func ids(page *contracts.Page[contracts.Message]) []string {
	out := make([]string, 0, len(page.Items))
	for _, m := range page.Items {
		out = append(out, m.ID)
	}
	return out
}

func requireIDs(t *testing.T, got []string, want ...string) {
	t.Helper()
	if fmt.Sprint(got) != fmt.Sprint(want) {
		t.Fatalf("ids = %v, want %v", got, want)
	}
}

func TestMessagesListNewestFirstAndPage(t *testing.T) {
	ctx := t.Context()
	s := newStore(t)
	for i, id := range []string{"a", "b", "c"} {
		if err := s.PutSend(ctx, []contracts.Message{message(id, i)}, nil); err != nil {
			t.Fatalf("put %s: %v", id, err)
		}
	}

	first, err := s.ListMessages(ctx, contracts.MessageFilter{}, contracts.PageInput{Size: 2})
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	requireIDs(t, ids(first), "c", "b")
	if first.NextToken == "" {
		t.Fatal("first page has no next token")
	}
	second, err := s.ListMessages(ctx, contracts.MessageFilter{},
		contracts.PageInput{Size: 2, Token: first.NextToken})
	if err != nil {
		t.Fatalf("list second page: %v", err)
	}
	requireIDs(t, ids(second), "a")
	if second.NextToken != "" {
		t.Fatalf("last page token = %q, want none", second.NextToken)
	}
}

func TestMessagesFilter(t *testing.T) {
	ctx := t.Context()
	s := newStore(t)
	a := message("a", 0)
	a.Tags = []contracts.MessageTag{{Name: "kind", Value: "welcome"}}
	a.ConfigurationSet = "cs"
	a.Text = "the quick brown fox"
	b := message("b", 1)
	b.Bcc = []string{"Hidden@Example.com"}
	b.Recipients = append(b.Recipients, "Hidden@Example.com")
	b.FromAddress = "other@example.com"
	if err := s.PutSend(ctx, []contracts.Message{a, b}, nil); err != nil {
		t.Fatalf("put: %v", err)
	}

	since := base.Add(time.Minute)
	until := base
	tests := []struct {
		name string
		f    contracts.MessageFilter
		want []string
	}{
		{"from, any case", contracts.MessageFilter{From: "SENDER@example.com"}, []string{"a"}},
		{"bcc recipient", contracts.MessageFilter{To: "hidden@example.com"}, []string{"b"}},
		{"subject substring", contracts.MessageFilter{Subject: "ject B"}, []string{"b"}},
		{"full text", contracts.MessageFilter{Query: "quick fox"}, []string{"a"}},
		{"full text, FTS syntax is plain words", contracts.MessageFilter{Query: `"AND OR (`}, nil},
		{"since", contracts.MessageFilter{Since: &since}, []string{"b"}},
		{"until", contracts.MessageFilter{Until: &until}, []string{"a"}},
		{"configuration set", contracts.MessageFilter{ConfigurationSet: "cs"}, []string{"a"}},
		{"tag", contracts.MessageFilter{
			Tags: []contracts.MessageTag{{Name: "kind", Value: "welcome"}},
		}, []string{"a"}},
		{"tag with another value", contracts.MessageFilter{
			Tags: []contracts.MessageTag{{Name: "kind", Value: "other"}},
		}, nil},
		{"message ID", contracts.MessageFilter{MessageID: "b"}, []string{"b"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			page, err := s.ListMessages(ctx, tt.f, contracts.PageInput{Size: 10})
			if err != nil {
				t.Fatalf("list: %v", err)
			}
			requireIDs(t, ids(page), tt.want...)
		})
	}
}

// must fails the test when err is not nil.
func must(t *testing.T, err error, what string) {
	t.Helper()
	if err != nil {
		t.Fatalf("%s: %v", what, err)
	}
}

// mustIs fails the test unless err is target.
func mustIs(t *testing.T, err, target error, what string) {
	t.Helper()
	if !errors.Is(err, target) {
		t.Fatalf("%s = %v, want %v", what, err, target)
	}
}

// check fails the test unless ok.
func check(t *testing.T, ok bool, format string, args ...any) {
	t.Helper()
	if !ok {
		t.Fatalf(format, args...)
	}
}

func TestMessageReadBackAndDelete(t *testing.T) {
	ctx := t.Context()
	s := newStore(t)
	a := message("a", 0)
	a.Headers = []contracts.Header{{Name: "Subject", Value: "Subject a"}}
	a.Attachments = []contracts.AttachmentInfo{{Name: "x.txt", ContentType: "text/plain", Size: 3}}
	must(t, s.PutSend(ctx, []contracts.Message{a, message("b", 1)}, nil), "put")

	got, err := s.GetMessage(ctx, "a")
	must(t, err, "get")
	check(t, got.Text == a.Text && len(got.Headers) == 1 && len(got.Attachments) == 1 &&
		got.Time.Equal(a.Time) && got.Size == a.Size, "get = %+v, want %+v", got, a)
	mime, err := s.GetMessageMIME(ctx, "a")
	must(t, err, "get MIME")
	check(t, string(mime) == string(a.MIME), "mime = %q, want %q", mime, a.MIME)

	must(t, s.DeleteMessage(ctx, "a"), "delete")
	_, err = s.GetMessage(ctx, "a")
	mustIs(t, err, contracts.ErrMessageNotFound, "get deleted")
	mustIs(t, s.DeleteMessage(ctx, "a"), contracts.ErrMessageNotFound, "delete again")

	// The full-text index lost the deleted message too.
	page, err := s.ListMessages(ctx, contracts.MessageFilter{Query: "body"},
		contracts.PageInput{Size: 10})
	must(t, err, "list")
	requireIDs(t, ids(page), "b")
}

func TestResetKeepsIdentitiesAndTemplates(t *testing.T) {
	ctx := t.Context()
	s := newStore(t)
	if err := s.CreateIdentity(ctx, contracts.Identity{
		Name: "example.com", Type: contracts.IdentityTypeDomain, CreatedAt: base,
	}); err != nil {
		t.Fatalf("create identity: %v", err)
	}
	if err := s.CreateTemplate(ctx, contracts.Template{
		Name: "t", Content: contracts.TemplateContent{Subject: "s"}, CreatedAt: base,
	}); err != nil {
		t.Fatalf("create template: %v", err)
	}
	if err := s.PutSend(ctx, []contracts.Message{message("a", 0)}, nil); err != nil {
		t.Fatalf("put: %v", err)
	}

	if err := s.DeleteMessages(ctx); err != nil {
		t.Fatalf("reset: %v", err)
	}
	page, err := s.ListMessages(ctx, contracts.MessageFilter{}, contracts.PageInput{Size: 10})
	if err != nil || len(page.Items) != 0 {
		t.Fatalf("messages after reset = %v, %v", page, err)
	}
	if _, err = s.GetIdentity(ctx, "example.com"); err != nil {
		t.Fatalf("identity after reset: %v", err)
	}
	if _, err = s.GetTemplate(ctx, "t"); err != nil {
		t.Fatalf("template after reset: %v", err)
	}
}

func TestIdentities(t *testing.T) {
	ctx := t.Context()
	s := newStore(t)
	in := contracts.Identity{
		Name: "a@example.com", Type: contracts.IdentityTypeEmail, CreatedAt: base,
		Tags: []contracts.Tag{{Key: "k", Value: "v"}},
		DKIM: contracts.DKIM{Origin: "AWS_SES"},
	}
	must(t, s.CreateIdentity(ctx, in), "create")
	mustIs(t, s.CreateIdentity(ctx, in), contracts.ErrIdentityExists, "create twice")
	must(t, s.CreateIdentity(ctx, contracts.Identity{
		Name: "example.org", Type: contracts.IdentityTypeDomain, CreatedAt: base,
	}), "create domain")

	got, err := s.GetIdentity(ctx, "a@example.com")
	must(t, err, "get")
	check(t, got.Tags[0] == in.Tags[0] && got.DKIM.Origin == "AWS_SES", "get = %+v", got)

	for _, tt := range []struct {
		f    contracts.IdentityFilter
		want string
	}{
		{contracts.IdentityFilter{Type: contracts.IdentityTypeDomain}, "example.org"},
		{contracts.IdentityFilter{NameContains: "EXAMPLE.C"}, "a@example.com"},
	} {
		page, lErr := s.ListIdentities(ctx, tt.f, contracts.PageInput{Size: 10})
		must(t, lErr, "list")
		check(t, len(page.Items) == 1 && page.Items[0].Name == tt.want,
			"list %+v = %+v, want %s", tt.f, page.Items, tt.want)
	}
	_, err = s.ListIdentities(ctx, contracts.IdentityFilter{},
		contracts.PageInput{Size: 1, Token: encodeToken(listTemplates, 1)})
	mustIs(t, err, contracts.ErrInvalidToken, "list with another listing's token")

	must(t, s.DeleteIdentity(ctx, "a@example.com"), "delete")
	mustIs(t, s.DeleteIdentity(ctx, "a@example.com"), contracts.ErrIdentityNotFound,
		"delete twice")
}

func TestIdentityPolicies(t *testing.T) {
	ctx := t.Context()
	s := newStore(t)
	const id = "example.com"
	p := func(name, doc string) contracts.IdentityPolicy {
		return contracts.IdentityPolicy{Name: name, Document: doc}
	}
	mustIs(t, s.CreateIdentityPolicy(ctx, id, p("a", "{}")), contracts.ErrIdentityNotFound,
		"create on a missing identity")
	mustIs(t, s.UpdateIdentityPolicy(ctx, id, p("a", "{}")), contracts.ErrIdentityNotFound,
		"update on a missing identity")
	mustIs(t, s.DeleteIdentityPolicy(ctx, id, "a"), contracts.ErrIdentityNotFound,
		"delete on a missing identity")
	must(t, s.CreateIdentity(ctx, contracts.Identity{
		Name: id, Type: contracts.IdentityTypeDomain, CreatedAt: base,
	}), "create identity")

	must(t, s.CreateIdentityPolicy(ctx, id, p("b", "doc-b")), "create b")
	must(t, s.CreateIdentityPolicy(ctx, id, p("a", "doc-a")), "create a")
	mustIs(t, s.CreateIdentityPolicy(ctx, id, p("a", "again")),
		contracts.ErrIdentityPolicyExists, "create a twice")
	must(t, s.UpdateIdentityPolicy(ctx, id, p("a", "doc-a2")), "update a")
	must(t, s.UpdateIdentityPolicy(ctx, id, p("missing", "x")), "update a missing policy")
	must(t, s.DeleteIdentityPolicy(ctx, id, "missing"), "delete a missing policy")

	got, err := s.GetIdentity(ctx, id)
	must(t, err, "get")
	check(t, len(got.Policies) == 2 && got.Policies[0] == p("a", "doc-a2") &&
		got.Policies[1] == p("b", "doc-b"), "policies = %+v", got.Policies)

	for i := len(got.Policies); i < contracts.MaxIdentityPolicies; i++ {
		must(t, s.CreateIdentityPolicy(ctx, id, p(fmt.Sprintf("p%02d", i), "{}")), "fill")
	}
	mustIs(t, s.CreateIdentityPolicy(ctx, id, p("over", "{}")),
		contracts.ErrIdentityPolicyLimit, "create past the limit")

	// An identity's policies go with it, and a new identity of the same
	// name starts with none.
	must(t, s.DeleteIdentity(ctx, id), "delete identity")
	must(t, s.CreateIdentity(ctx, contracts.Identity{
		Name: id, Type: contracts.IdentityTypeDomain, CreatedAt: base,
	}), "create identity again")
	got, err = s.GetIdentity(ctx, id)
	must(t, err, "get again")
	check(t, len(got.Policies) == 0, "policies of the new identity = %+v", got.Policies)
}

func TestTemplates(t *testing.T) {
	ctx := t.Context()
	s := newStore(t)
	for _, name := range []string{"one", "two", "three"} {
		must(t, s.CreateTemplate(ctx, contracts.Template{
			Name: name, Content: contracts.TemplateContent{Subject: name}, CreatedAt: base,
		}), "create "+name)
	}
	mustIs(t, s.CreateTemplate(ctx, contracts.Template{Name: "one"}),
		contracts.ErrTemplateExists, "create twice")

	page, err := s.ListTemplates(ctx, contracts.PageInput{Size: 2})
	must(t, err, "list")
	check(t, len(page.Items) == 2 && page.NextToken != "", "first page = %+v", page)
	page, err = s.ListTemplates(ctx, contracts.PageInput{Size: 2, Token: page.NextToken})
	must(t, err, "list second page")
	check(t, len(page.Items) == 1 && page.Items[0].Name == "three", "second page = %+v", page)

	update := contracts.TemplateContent{Subject: "new", HTML: "<p>{{x}}</p>"}
	must(t, s.UpdateTemplate(ctx, "one", update), "update")
	got, err := s.GetTemplate(ctx, "one")
	must(t, err, "get updated")
	check(t, got.Content == update, "updated content = %+v, want %+v", got.Content, update)
	mustIs(t, s.UpdateTemplate(ctx, "none", update), contracts.ErrTemplateNotFound,
		"update missing")
	must(t, s.DeleteTemplate(ctx, "one"), "delete")
	_, err = s.GetTemplate(ctx, "one")
	mustIs(t, err, contracts.ErrTemplateNotFound, "get deleted")
}

func TestRecipientsSince(t *testing.T) {
	ctx := t.Context()
	s := newStore(t)
	a := message("a", 0)
	b := message("b", 10)
	b.Recipients = []string{"x@example.com", "y@example.com"}
	if err := s.PutSend(ctx, []contracts.Message{a, b}, nil); err != nil {
		t.Fatalf("put: %v", err)
	}
	n, err := s.RecipientsSince(ctx, base.Add(5*time.Minute))
	if err != nil || n != 2 {
		t.Fatalf("recipients since = %d, %v, want 2", n, err)
	}
}

func TestRenderingFailuresAreRecordedAndReset(t *testing.T) {
	ctx := t.Context()
	s := newStore(t)
	failure := func(id, template string, n int) contracts.RenderingFailure {
		return contracts.RenderingFailure{
			Time: base.Add(time.Duration(n) * time.Minute), MessageID: id,
			Source: contracts.SourceSendEmail, Template: template, From: "s@example.com",
			To:    []string{"t@example.com"},
			Tags:  []contracts.MessageTag{{Name: "k", Value: "v"}},
			Error: "Attribute 'name' is not present in the rendering data.",
		}
	}
	must(t, s.PutSend(ctx, []contracts.Message{message("m", 0)},
		[]contracts.RenderingFailure{failure("f1", "Welcome", 0), failure("f2", "", 1)}), "put")

	page, err := s.ListRenderingFailures(
		ctx,
		contracts.FailureFilter{},
		contracts.PageInput{Size: 1},
	)
	must(t, err, "list")
	check(t, len(page.Items) == 1 && page.Items[0].MessageID == "f2" && page.NextToken != "",
		"first page = %+v", page)
	page, err = s.ListRenderingFailures(ctx, contracts.FailureFilter{},
		contracts.PageInput{Size: 1, Token: page.NextToken})
	must(t, err, "list second page")
	check(t, len(page.Items) == 1 && page.Items[0].MessageID == "f1" &&
		page.Items[0].Tags[0].Name == "k" && page.Items[0].To[0] == "t@example.com",
		"second page = %+v", page)

	page, err = s.ListRenderingFailures(ctx, contracts.FailureFilter{Template: "Welcome"},
		contracts.PageInput{Size: 10})
	must(t, err, "list by template")
	check(t, len(page.Items) == 1 && page.Items[0].MessageID == "f1", "by template = %+v", page)

	// A failure is not a message.
	_, err = s.GetMessage(ctx, "f1")
	mustIs(t, err, contracts.ErrMessageNotFound, "get a failed message")

	must(t, s.DeleteMessages(ctx), "reset")
	page, err = s.ListRenderingFailures(
		ctx,
		contracts.FailureFilter{},
		contracts.PageInput{Size: 10},
	)
	must(t, err, "list after reset")
	check(t, len(page.Items) == 0, "failures after reset = %+v", page.Items)
}
