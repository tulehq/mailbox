//go:build e2e

package e2e

import (
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

// corpus is four messages sent in order, so the newest is d.
type corpus struct {
	// ses maps each stored id to the SES message ID.
	ses        map[string]string
	a, b, c, d string // the stored ids
}

// seed sends the corpus: a and c from alice, bob a recipient of a in To, of
// b in Cc and of c in Bcc; a and c in configuration set billing.
func seed(t *testing.T, c *sesv2.Client, mb *mailbox) corpus {
	t.Helper()

	tag := func(kind, region string) []types.MessageTag {
		return []types.MessageTag{
			{Name: aws.String("kind"), Value: aws.String(kind)},
			{Name: aws.String("region"), Value: aws.String(region)},
		}
	}
	inputs := []*sesv2.SendEmailInput{
		simpleInput(
			"alice@example.com",
			"Invoice 42 ready",
			"Your invoice is attached. zebra",
			"bob@example.com",
		),
		simpleInput(
			"carol@example.com",
			"Weekly digest",
			"News about giraffe sightings",
			"dave@example.com",
		),
		simpleInput(
			"alice@example.com",
			"Invoice 43 overdue",
			"Please pay soon. giraffe",
			"erin@example.com",
		),
		simpleInput("frank@example.com", "Hello", "nothing here", "grace@example.com"),
	}
	inputs[0].ConfigurationSetName, inputs[0].EmailTags = aws.String(
		"billing",
	), tag(
		"invoice",
		"eu",
	)
	inputs[1].ConfigurationSetName, inputs[1].EmailTags = aws.String("news"), tag("digest", "eu")
	inputs[1].Destination.CcAddresses = []string{"bob@example.com"}
	inputs[2].ConfigurationSetName, inputs[2].EmailTags = aws.String(
		"billing",
	), tag(
		"invoice",
		"us",
	)
	inputs[2].Destination.BccAddresses = []string{"bob@example.com"}

	stored := make([]string, 0, len(inputs))
	ses := map[string]string{}
	for _, in := range inputs {
		id := send(t, c, in)
		s := mb.byMessageID(t, id)
		stored = append(stored, s.ID)
		ses[s.ID] = id
		time.Sleep(20 * time.Millisecond)
	}
	return corpus{a: stored[0], b: stored[1], c: stored[2], d: stored[3], ses: ses}
}

func TestFilters(t *testing.T) {
	c, mb := newClient(t)
	k := seed(t, c, mb)

	for _, tt := range filterCases(k) {
		t.Run(tt.name, func(t *testing.T) {
			got := ids(mb.listAll(t, tt.query))
			if !slices.Equal(got, tt.want) {
				t.Fatalf("got %q, want %q", got, tt.want)
			}
		})
	}
}

// filterCase is a list query and the stored ids it lists, newest first.
type filterCase struct {
	query url.Values
	name  string
	want  []string
}

func filterCases(k corpus) []filterCase {
	return []filterCase{
		{name: "none", query: nil, want: []string{k.d, k.c, k.b, k.a}},
		{name: "from", query: url.Values{"from": {"alice@example.com"}}, want: []string{k.c, k.a}},
		// The design: to matches To, Cc or Bcc.
		{
			name:  "to in To, Cc and Bcc",
			query: url.Values{"to": {"bob@example.com"}},
			want:  []string{k.c, k.b, k.a},
		},
		{
			name:  "to in To only",
			query: url.Values{"to": {"grace@example.com"}},
			want:  []string{k.d},
		},
		{
			name:  "subject substring",
			query: url.Values{"subject": {"voice 4"}},
			want:  []string{k.c, k.a},
		},
		{name: "subject word", query: url.Values{"subject": {"overdue"}}, want: []string{k.c}},
		// The design: q is full text over the subject and the text body.
		{name: "q in the body", query: url.Values{"q": {"giraffe"}}, want: []string{k.c, k.b}},
		{name: "q in the subject", query: url.Values{"q": {"digest"}}, want: []string{k.b}},
		{name: "q matching nothing", query: url.Values{"q": {"platypus"}}, want: nil},
		{
			name:  "configurationSet",
			query: url.Values{"configurationSet": {"billing"}},
			want:  []string{k.c, k.a},
		},
		{name: "tag", query: url.Values{"tag": {"kind:invoice"}}, want: []string{k.c, k.a}},
		// Assumption: repeated tags must all match.
		{
			name:  "two tags",
			query: url.Values{"tag": {"kind:invoice", "region:eu"}},
			want:  []string{k.a},
		},
		{name: "messageId", query: url.Values{"messageId": {k.ses[k.b]}}, want: []string{k.b}},
		{name: "from and to", query: url.Values{
			"from": {"alice@example.com"}, "to": {"bob@example.com"},
		}, want: []string{k.c, k.a}},
		{name: "subject and tag", query: url.Values{
			"subject": {"Invoice"}, "tag": {"region:us"},
		}, want: []string{k.c}},
		{name: "q and from", query: url.Values{
			"q": {"giraffe"}, "from": {"carol@example.com"},
		}, want: []string{k.b}},
		{name: "configurationSet and to", query: url.Values{
			"configurationSet": {"news"}, "to": {"bob@example.com"},
		}, want: []string{k.b}},
		{name: "filters matching nothing together", query: url.Values{
			"from": {"frank@example.com"}, "configurationSet": {"billing"},
		}, want: nil},
	}
}

func TestSummaryFields(t *testing.T) {
	c, mb := newClient(t)
	k := seed(t, c, mb)

	p := mb.list(t, url.Values{"messageId": {k.ses[k.c]}})
	requireEqual(t, len(p.Items), 1, "items")
	s := p.Items[0]
	requireEqual(t, s.ID, k.c, "id")
	requireEqual(t, s.From, "alice@example.com", "from")
	requireSameSet(t, s.To, []string{"erin@example.com"}, "to")
	requireSameSet(t, s.Bcc, []string{"bob@example.com"}, "bcc")
	requireEqual(t, s.Subject, "Invoice 43 overdue", "subject")
	requireEqual(t, s.ConfigurationSet, "billing", "configurationSet")
	requireEqual(t, tagsOf(s.Tags)["region"], "us", "tag region")
	if s.Size <= 0 {
		t.Fatalf("size %d", s.Size)
	}
	s.at(t)
}

func TestTimeBounds(t *testing.T) {
	// The bounds are RFC 3339 to the second, so the sends are 1.5s apart
	// and each bound falls strictly between two of them.
	c, mb := newClient(t)

	first := mb.byMessageID(
		t,
		send(t, c, simpleInput("a@example.com", "first", "1", "to@example.com")),
	).ID
	time.Sleep(1500 * time.Millisecond)
	between := time.Now().UTC().Format(time.RFC3339)
	time.Sleep(1500 * time.Millisecond)
	second := mb.byMessageID(
		t,
		send(t, c, simpleInput("a@example.com", "second", "2", "to@example.com")),
	).ID
	time.Sleep(1500 * time.Millisecond)
	after := time.Now().UTC().Format(time.RFC3339)

	tests := []struct {
		query url.Values
		name  string
		want  []string
	}{
		{name: "since", query: url.Values{"since": {between}}, want: []string{second}},
		{name: "until", query: url.Values{"until": {between}}, want: []string{first}},
		{
			name:  "since and until",
			query: url.Values{"since": {between}, "until": {after}},
			want:  []string{second},
		},
		{name: "since after both", query: url.Values{"since": {after}}, want: nil},
		{name: "a zone offset", query: url.Values{"since": {
			mustParse(t, between).In(time.FixedZone("EET", 2*3600)).Format(time.RFC3339),
		}}, want: []string{second}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := ids(mb.listAll(t, tt.query))
			if !slices.Equal(got, tt.want) {
				t.Fatalf("got %q, want %q", got, tt.want)
			}
		})
	}
}

func mustParse(t *testing.T, s string) time.Time {
	t.Helper()
	v, err := time.Parse(time.RFC3339, s)
	requireNoErr(t, err, "parse "+s)
	return v
}

func TestInvalidListParametersAreBadRequests(t *testing.T) {
	// An invalid limit, cursor, since, until or tag is 400
	// BadRequestException. Which values are invalid is this test's reading:
	// a limit outside 1 to 100 or not a number, a cursor the API did not
	// issue, a time that is not RFC 3339, a tag with no colon.
	_, mb := newClient(t)

	for name, q := range map[string]url.Values{
		"limit 0":            {"limit": {"0"}},
		"limit 101":          {"limit": {"101"}},
		"limit -1":           {"limit": {"-1"}},
		"limit not a number": {"limit": {"ten"}},
		"cursor not issued":  {"cursor": {"not-a-cursor!"}},
		"since not RFC 3339": {"since": {"yesterday"}},
		"until not RFC 3339": {"until": {"2026-11-13 10:00"}},
		"tag without colon":  {"tag": {"kind"}},
	} {
		t.Run(name, func(t *testing.T) {
			res := mb.do(t, http.MethodGet, "/_mailbox/messages", q)
			requireAPIErrorBody(t, res, http.StatusBadRequest, "BadRequestException", name)
		})
	}
}

func TestListLimits(t *testing.T) {
	// limit defaults to 20 and may be up to 100.
	c, mb := newClient(t)
	for i := range 25 {
		send(t, c, simpleInput("bulk@example.com", "n"+strconv.Itoa(i), "Body.", "to@example.com"))
	}

	p := mb.list(t, nil)
	requireEqual(t, len(p.Items), 20, "items with the default limit")
	if p.NextCursor == "" {
		t.Fatal("no nextCursor after the first 20 of 25")
	}
	rest := mb.list(t, url.Values{"cursor": {p.NextCursor}})
	requireEqual(t, len(rest.Items), 5, "items on the second page")
	requireEqual(t, rest.NextCursor, "", "nextCursor on the last page")

	requireEqual(t, len(mb.list(t, url.Values{"limit": {"100"}}).Items), 25, "items with limit 100")
}

func TestPaginationVisitsEachMessageOnce(t *testing.T) {
	c, mb := newClient(t)
	k := seed(t, c, mb)
	e := mb.byMessageID(
		t,
		send(t, c, simpleInput("z@example.com", "fifth", "5", "to@example.com")),
	).ID
	want := []string{e, k.d, k.c, k.b, k.a}

	var got []string
	q := url.Values{"limit": {"1"}}
	for pages := 0; ; pages++ {
		if pages > len(want) {
			t.Fatalf("more than %d pages of 1 for %d messages", len(want), len(want))
		}
		p := mb.list(t, q)
		if len(p.Items) > 1 {
			t.Fatalf("page of %d items with limit 1", len(p.Items))
		}
		got = append(got, ids(p.Items)...)
		if p.NextCursor == "" {
			break
		}
		q.Set("cursor", p.NextCursor)
	}
	if !slices.Equal(got, want) {
		t.Fatalf("paged %q, want %q", got, want)
	}

	// Paging a filtered list keeps the filter.
	got = ids(mb.listAll(t, url.Values{"limit": {"1"}, "from": {"alice@example.com"}}))
	if !slices.Equal(got, []string{k.c, k.a}) {
		t.Fatalf("paged from alice %q, want %q", got, []string{k.c, k.a})
	}
}

func TestDeleteOne(t *testing.T) {
	c, mb := newClient(t)
	k := seed(t, c, mb)

	mb.remove(t, k.b)

	requireAPIErrorBody(t, mb.do(t, http.MethodGet, "/_mailbox/messages/"+k.b, nil),
		http.StatusNotFound, "NotFoundException", "get the deleted message")
	got := ids(mb.listAll(t, nil))
	if !slices.Equal(got, []string{k.d, k.c, k.a}) {
		t.Fatalf("after delete: %q", got)
	}
	requireAPIErrorBody(t, mb.do(t, http.MethodDelete, "/_mailbox/messages/"+k.b, nil),
		http.StatusNotFound, "NotFoundException", "delete the deleted message again")
}

func TestResetKeepsIdentitiesAndTemplates(t *testing.T) {
	// The design: reset deletes every message; identities and templates
	// are configuration and are kept.
	c, mb := newClient(t)
	seed(t, c, mb)
	_, err := c.CreateEmailIdentity(t.Context(), &sesv2.CreateEmailIdentityInput{
		EmailIdentity: aws.String("kept@example.com"),
	})
	requireNoErr(t, err, "create identity")
	createTemplate(t, c, "Kept", greeting)

	mb.reset(t)

	requireEqual(t, len(mb.listAll(t, nil)), 0, "messages after reset")
	_, err = c.GetEmailIdentity(
		t.Context(),
		&sesv2.GetEmailIdentityInput{EmailIdentity: aws.String("kept@example.com")},
	)
	requireNoErr(t, err, "get the identity after reset")
	_, err = c.GetEmailTemplate(
		t.Context(),
		&sesv2.GetEmailTemplateInput{TemplateName: aws.String("Kept")},
	)
	requireNoErr(t, err, "get the template after reset")

	// Sending works after a reset.
	id := send(t, c, simpleInput("a@example.com", "after", "Body.", "to@example.com"))
	requireEqual(t, len(mb.listAll(t, url.Values{"messageId": {id}})), 1, "message after reset")
}

func TestUnknownIDsAreNotFound(t *testing.T) {
	_, mb := newClient(t)

	for _, req := range []struct{ method, path string }{
		{http.MethodGet, "/_mailbox/messages/no-such-id"},
		{http.MethodGet, "/_mailbox/messages/no-such-id/raw"},
		{http.MethodGet, "/_mailbox/messages/no-such-id/attachments/0"},
		{http.MethodDelete, "/_mailbox/messages/no-such-id"},
	} {
		t.Run(req.method+" "+req.path, func(t *testing.T) {
			requireAPIErrorBody(
				t,
				mb.do(t, req.method, req.path, nil),
				http.StatusNotFound,
				"NotFoundException",
				req.path,
			)
		})
	}
}

func TestRetrievalRefusesBadSignatures(t *testing.T) {
	// Assumption: refused with 403, as tule.dev/sigv4 refuses a request
	// it cannot authenticate, and with the API's JSON error.
	srv := startServer(t, nil)
	c, mb := clientFor(srv), mailboxFor(srv)
	id := send(t, c, simpleInput("a@example.com", "kept", "Body.", "to@example.com"))

	wrongSecret := mailboxWith(srv, aws.Credentials{AccessKeyID: "test", SecretAccessKey: "wrong"})
	unknownKey := mailboxWith(srv, aws.Credentials{AccessKeyID: "other", SecretAccessKey: "test"})
	otherService := mailboxFor(srv)
	otherService.service = "s3"

	for name, do := range map[string]func(method, path string) response{
		"unsigned":      func(m, p string) response { return mb.doUnsigned(t, m, p) },
		"wrong secret":  func(m, p string) response { return wrongSecret.do(t, m, p, nil) },
		"unknown key":   func(m, p string) response { return unknownKey.do(t, m, p, nil) },
		"signed for s3": func(m, p string) response { return otherService.do(t, m, p, nil) },
	} {
		t.Run(name, func(t *testing.T) {
			requireAPIErrorBody(
				t,
				do(http.MethodGet, "/_mailbox/messages"),
				http.StatusForbidden,
				"",
				"list",
			)
			requireAPIErrorBody(
				t,
				do(http.MethodDelete, "/_mailbox/messages"),
				http.StatusForbidden,
				"",
				"reset",
			)
		})
	}
	// None of the refused resets deleted anything.
	mb.byMessageID(t, id)
}

func TestSESRefusesBadSignatures(t *testing.T) {
	// Assumption: refused with 403, the status AWS answers a key or
	// signature it does not accept with; the error code is not asserted,
	// since the SES v2 model does not list one.
	srv := startServer(t, nil)
	mb := mailboxFor(srv)

	c := sesClientWith(srv, aws.Credentials{AccessKeyID: "test", SecretAccessKey: "wrong"})
	err := errOf(
		c.SendEmail(t.Context(), simpleInput("a@example.com", "no", "Body.", "to@example.com")),
	)
	requireAPIError(t, err)
	requireStatus(t, err, http.StatusForbidden)
	requireEqual(t, len(mb.listAll(t, nil)), 0, "messages stored")
}
