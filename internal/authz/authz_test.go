package authz

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	v4 "github.com/aws/aws-sdk-go-v2/aws/signer/v4"
	"tule.dev/sigv4"

	"tule.dev/mailbox/internal/contracts"
	"tule.dev/mailbox/internal/sesapi"
)

const (
	testAccount = "123456789012"
	testRegion  = "eu-west-1"
	userARN     = "arn:aws:iam::" + testAccount + ":user/dev"
)

// keys is a sigv4.KeySource of fixed principals, by access key ID, each
// with the secret "secret-" + its ID.
type keys map[string]sigv4.Principal

func (k keys) SigningKey(_ context.Context, s sigv4.Scope) (sigv4.Key, error) {
	p, ok := k[s.AccessKeyID]
	if !ok {
		return sigv4.Key{}, sigv4.ErrUnknownAccessKey
	}
	return sigv4.Key{
		Signing:   sigv4.DeriveSigningKey("secret-"+s.AccessKeyID, s.Date, s.Region, s.Service),
		Principal: p,
	}, nil
}

// store is a MailboxProvider of fixed identities and templates; only the
// lookups the Authorizer makes are implemented.
type store struct {
	contracts.MailboxProvider
	identities map[string][]contracts.Tag
	templates  map[string][]contracts.Tag
}

func (s *store) GetIdentity(_ context.Context, name string) (*contracts.Identity, error) {
	tags, ok := s.identities[name]
	if !ok {
		return nil, contracts.ErrIdentityNotFound
	}
	return &contracts.Identity{Name: name, Tags: tags}, nil
}

func (s *store) GetTemplate(_ context.Context, name string) (*contracts.Template, error) {
	tags, ok := s.templates[name]
	if !ok {
		return nil, contracts.ErrTemplateNotFound
	}
	return &contracts.Template{Name: name, Tags: tags}, nil
}

func doc(statements ...string) json.RawMessage {
	return json.RawMessage(`{"Version":"2012-10-17","Statement":[` +
		strings.Join(statements, ",") + `]}`)
}

// harness serves one operation through a verifier and the operation's
// guard, with a handler that authorizes target, unless skip is set, and
// answers 200.
type harness struct {
	t   *testing.T
	srv *httptest.Server
	// region is the region requests are signed for, testRegion when empty.
	region  string
	target  Target
	skip    bool
	handled bool
}

func newHarness(t *testing.T, opName string, principals sigv4.KeySource, st *store) *harness {
	t.Helper()
	op := operationNamed(t, opName)
	v, err := sigv4.New(principals, sigv4.WithService("ses"))
	if err != nil {
		t.Fatalf("new verifier: %v", err)
	}
	a := New(st, testAccount, testRegion)
	h := &harness{t: t}
	handler := a.Guard(op)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h.handled = true
		if !h.skip {
			if err := a.Authorize(r.Context(), h.target); err != nil {
				sesapi.WriteHTTPError(w, r, err)
				return
			}
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{}`))
	}))
	h.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		verified, vErr := v.Verify(r)
		if vErr != nil {
			http.Error(w, vErr.Error(), http.StatusForbidden)
			return
		}
		handler.ServeHTTP(w, verified)
	}))
	t.Cleanup(h.srv.Close)
	return h
}

func operationNamed(t *testing.T, name string) Operation {
	t.Helper()
	for _, op := range operations {
		if op.Name == name {
			return op
		}
	}
	t.Fatalf("no operation %s", name)
	return Operation{}
}

// call sends a request signed with the key and returns its status and the
// error document, if any.
func (h *harness) call(keyID string) (int, sesapi.Error) {
	h.t.Helper()
	h.handled = false
	req, err := http.NewRequestWithContext(h.t.Context(), http.MethodPost, h.srv.URL, nil)
	if err != nil {
		h.t.Fatalf("new request: %v", err)
	}
	sum := sha256.Sum256(nil)
	region := h.region
	if region == "" {
		region = testRegion
	}
	if err = v4.NewSigner().SignHTTP(h.t.Context(), aws.Credentials{
		AccessKeyID: keyID, SecretAccessKey: "secret-" + keyID,
	}, req, hex.EncodeToString(sum[:]), "ses", region, time.Now()); err != nil {
		h.t.Fatalf("sign: %v", err)
	}
	res, err := h.srv.Client().Do(req)
	if err != nil {
		h.t.Fatalf("do: %v", err)
	}
	defer func() { _ = res.Body.Close() }()
	body, err := io.ReadAll(res.Body)
	if err != nil {
		h.t.Fatalf("read: %v", err)
	}
	var e sesapi.Error
	if res.StatusCode != http.StatusOK {
		if err = json.Unmarshal(body, &e); err != nil {
			h.t.Fatalf("decode %s: %v", body, err)
		}
		if got := res.Header.Get("X-Amzn-Errortype"); got != e.Type {
			h.t.Fatalf("X-Amzn-ErrorType %q, body code %q", got, e.Type)
		}
	}
	return res.StatusCode, e
}

func user(policies ...json.RawMessage) sigv4.Principal {
	return sigv4.Principal{AccountID: testAccount, ARN: userARN, Policies: policies}
}

func sesARN(resource string) string {
	return "arn:aws:ses:" + testRegion + ":" + testAccount + ":" + resource
}

func notAllowed(action, resource string) string {
	return "User: " + userARN + " is not authorized to perform: " + action +
		" on resource: " + resource + " because no identity-based policy allows the " +
		action + " action"
}

func requireDenied(t *testing.T, status int, e sesapi.Error, message string) {
	t.Helper()
	if status != http.StatusForbidden || e.Type != sesapi.TypeAccessDenied || e.Message != message {
		t.Fatalf("got %d %s %q, want 403 AccessDeniedException %q", status, e.Type, e.Message,
			message)
	}
}

func TestTheRootIsNeverEvaluated(t *testing.T) {
	h := newHarness(t, "SendEmail", keys{
		"ROOT": {AccountID: testAccount, ARN: "arn:aws:iam::" + testAccount + ":root", Root: true},
	}, &store{})
	h.target = Target{Sender: "a@example.com"}
	if status, e := h.call("ROOT"); status != http.StatusOK {
		t.Fatalf("root: %d %+v", status, e)
	}
}

func TestAPrincipalWithNoPolicyIsDenied(t *testing.T) {
	h := newHarness(t, "SendEmail", keys{"USER": user()}, &store{})
	h.target = Target{Sender: "a@example.com"}
	status, e := h.call("USER")
	requireDenied(t, status, e, notAllowed("ses:SendEmail", sesARN("identity/example.com")))
}

func TestAnExplicitDenyIsReportedAsOne(t *testing.T) {
	h := newHarness(t, "GetEmailIdentity", keys{"USER": user(doc(
		`{"Effect":"Allow","Action":"ses:*","Resource":"*"}`,
		`{"Effect":"Deny","Action":"ses:GetEmailIdentity","Resource":"`+
			sesARN("identity/secret.example")+`"}`,
	))}, &store{})
	h.target = Target{Identity: "open.example"}
	if status, e := h.call("USER"); status != http.StatusOK {
		t.Fatalf("allowed identity: %d %+v", status, e)
	}
	h.target = Target{Identity: "secret.example"}
	status, e := h.call("USER")
	requireDenied(t, status, e, "User: "+userARN+" is not authorized to perform: "+
		"ses:GetEmailIdentity on resource: "+sesARN("identity/secret.example")+
		" with an explicit deny in an identity-based policy")
}

func TestASendIsEvaluatedOnEachResourceItUses(t *testing.T) {
	h := newHarness(t, "SendEmail", keys{"USER": user(doc(
		`{"Effect":"Allow","Action":"ses:SendEmail","Resource":["` +
			sesARN("identity/example.com") + `","` + sesARN("template/welcome") + `"]}`,
	))}, &store{templates: map[string][]contracts.Tag{"welcome": nil}})

	for _, tc := range []struct {
		name   string
		denied string
		target Target
	}{
		{name: "identity", target: Target{Sender: "a@example.com"}},
		{
			name:   "identity and template",
			target: Target{Sender: "a@example.com", Template: "welcome"},
		},
		{
			name:   "another template",
			target: Target{Sender: "a@example.com", Template: "other"},
			denied: sesARN("template/other"),
		},
		{
			name:   "a configuration set",
			target: Target{Sender: "a@example.com", ConfigurationSet: "cs"},
			denied: sesARN("configuration-set/cs"),
		},
		{
			name:   "another identity",
			target: Target{Sender: "a@other.example", Template: "other"},
			denied: sesARN("identity/other.example"),
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h.target = tc.target
			status, e := h.call("USER")
			if tc.denied == "" {
				if status != http.StatusOK {
					t.Fatalf("%d %+v", status, e)
				}
				return
			}
			requireDenied(t, status, e, notAllowed("ses:SendEmail", tc.denied))
		})
	}
}

func TestACreateWithTagsNeedsTagResource(t *testing.T) {
	h := newHarness(t, "CreateEmailTemplate", keys{"USER": user(doc(
		`{"Effect":"Allow","Action":"ses:CreateEmailTemplate","Resource":"*",`+
			`"Condition":{"Null":{"aws:TagKeys":"false"}}}`,
		`{"Effect":"Allow","Action":"ses:CreateEmailTemplate","Resource":"*",`+
			`"Condition":{"Null":{"aws:TagKeys":"true"}}}`,
	))}, &store{})
	h.target = Target{Template: "t"}
	if status, e := h.call("USER"); status != http.StatusOK {
		t.Fatalf("untagged: %d %+v", status, e)
	}
	h.target = Target{Template: "t", Tags: []contracts.Tag{{Key: "team", Value: "mail"}}}
	status, e := h.call("USER")
	requireDenied(t, status, e, notAllowed("ses:TagResource", sesARN("template/t")))
}

func TestResourceTagsAreSupplied(t *testing.T) {
	h := newHarness(t, "DeleteEmailIdentity", keys{"USER": user(doc(
		`{"Effect":"Allow","Action":"ses:DeleteEmailIdentity","Resource":"*",` +
			`"Condition":{"StringEquals":{"aws:ResourceTag/env":"dev"}}}`,
	))}, &store{identities: map[string][]contracts.Tag{
		"dev.example":  {{Key: "env", Value: "dev"}},
		"prod.example": {{Key: "env", Value: "prod"}},
	}})
	h.target = Target{Identity: "dev.example"}
	if status, e := h.call("USER"); status != http.StatusOK {
		t.Fatalf("dev: %d %+v", status, e)
	}
	h.target = Target{Identity: "prod.example"}
	status, e := h.call("USER")
	requireDenied(t, status, e, notAllowed("ses:DeleteEmailIdentity",
		sesARN("identity/prod.example")))
}

func TestTheRetrievalAPINeedsInspect(t *testing.T) {
	h := newHarness(t, "ListMessages", keys{
		"USER": user(),
		"INSPECTOR": user(doc(
			`{"Effect":"Allow","Action":"tule:Inspect","Resource":"arn:aws:ses:*:` +
				testAccount + `:*"}`,
		)),
	}, &store{})
	h.skip = true
	status, e := h.call("USER")
	requireDenied(t, status, e, notAllowed(InspectAction, sesARN("*")))
	if h.handled {
		t.Fatal("the handler ran for a denied request")
	}
	if status, e = h.call("INSPECTOR"); status != http.StatusOK {
		t.Fatalf("inspector: %d %+v", status, e)
	}
}

func TestAHandlerThatDoesNotAuthorizeFailsClosed(t *testing.T) {
	h := newHarness(t, "GetEmailTemplate", keys{"USER": user(doc(
		`{"Effect":"Allow","Action":"ses:*","Resource":"*"}`,
	))}, &store{})
	h.skip = true
	status, e := h.call("USER")
	if status != http.StatusInternalServerError || e.Type != sesapi.TypeInternalFailure {
		t.Fatalf("got %d %+v, want 500 InternalFailure", status, e)
	}
}

func TestAMalformedPolicyIsAFault(t *testing.T) {
	h := newHarness(t, "GetAccount", keys{"USER": user(json.RawMessage(`{"Statement":`))},
		&store{})
	h.skip = true
	status, e := h.call("USER")
	if status != http.StatusInternalServerError || e.Type != sesapi.TypeInternalFailure {
		t.Fatalf("got %d %+v, want 500 InternalFailure", status, e)
	}
}

func TestSenderIdentityCandidates(t *testing.T) {
	for in, want := range map[string][]string{
		"a@example.com":         {"a@example.com", "example.com"},
		"a@mail.eu.example.com": {"a@mail.eu.example.com", "mail.eu.example.com", "eu.example.com", "example.com"},
		"a@localhost":           {"a@localhost", "localhost"},
		"not-an-address":        {"not-an-address"},
		"a@":                    {"a@"},
		"Ops@Mail.Example.COM":  {"Ops@Mail.Example.COM", "mail.example.com", "example.com"},
	} {
		if got := SenderIdentityCandidates(in); !reflect.DeepEqual(got, want) {
			t.Errorf("%s: got %q, want %q", in, got, want)
		}
	}
}

func TestCanonicalIdentity(t *testing.T) {
	for in, want := range map[string]string{
		"Example.COM":        "example.com",
		"example.com":        "example.com",
		"Sender@EXAMPLE.com": "Sender@EXAMPLE.com",
		"sender@example.com": "sender@example.com",
	} {
		if got := CanonicalIdentity(in); got != want {
			t.Errorf("%s: got %q, want %q", in, got, want)
		}
	}
}

// denySend is a policy that allows every send but those on resource.
func denySend(resource string) json.RawMessage {
	return doc(`{"Effect":"Allow","Action":"ses:SendEmail","Resource":"*"}`,
		`{"Effect":"Deny","Action":"ses:SendEmail","Resource":"`+sesARN(resource)+`"}`)
}

func explicitlyDenied(action, resource string) string {
	return "User: " + userARN + " is not authorized to perform: " + action + " on " +
		"resource: " + sesARN(resource) + " with an explicit deny in an identity-based policy"
}

func TestTheSenderIdentityIsCanonicalAndADenyIsNotSidestepped(t *testing.T) {
	for _, tc := range []struct {
		name, deny, sender, denied string
		identities                 []string
	}{
		{
			name: "a domain in another case", deny: "identity/example.com",
			sender: "a@Example.COM", denied: "identity/example.com",
		},
		{
			name: "a created domain in another case", deny: "identity/example.com",
			sender: "a@EXAMPLE.com", denied: "identity/example.com",
			identities: []string{"example.com"},
		},
		{
			name: "a subdomain with no identity", deny: "identity/example.com",
			sender: "a@mail.example.com", denied: "identity/example.com",
		},
		{
			name: "a subdomain under a created parent", deny: "identity/example.com",
			sender: "a@mail.example.com", denied: "identity/example.com",
			identities: []string{"example.com"},
		},
		{
			name: "an address with no identity", deny: "identity/a@example.com",
			sender: "a@example.com", denied: "identity/a@example.com",
			identities: []string{"example.com"},
		},
		{
			// The address identity is a different identity: SES matches
			// addresses with their case.
			name: "an address in another case", deny: "identity/A@example.com",
			sender: "a@example.com", identities: []string{"a@example.com"},
		},
		{
			// The subdomain's own identity is the one the send goes
			// through; its parent's Deny is not evaluated.
			name: "a created subdomain", deny: "identity/example.com",
			sender: "a@mail.example.com", identities: []string{"mail.example.com"},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			st := &store{identities: map[string][]contracts.Tag{}}
			for _, id := range tc.identities {
				st.identities[id] = nil
			}
			h := newHarness(t, "SendEmail", keys{"USER": user(denySend(tc.deny))}, st)
			h.target = Target{Sender: tc.sender}
			status, e := h.call("USER")
			if tc.denied == "" {
				if status != http.StatusOK {
					t.Fatalf("%d %+v", status, e)
				}
				return
			}
			requireDenied(t, status, e, explicitlyDenied("ses:SendEmail", tc.denied))
		})
	}
}

func TestPrincipalKeys(t *testing.T) {
	for arn, want := range map[string]map[string]string{
		"arn:aws:iam::123456789012:user/dev": {
			"aws:PrincipalArn":  "arn:aws:iam::123456789012:user/dev",
			"aws:PrincipalType": "User", "aws:username": "dev",
		},
		"arn:aws:iam::123456789012:user/team/a/dev": {
			"aws:PrincipalArn":  "arn:aws:iam::123456789012:user/team/a/dev",
			"aws:PrincipalType": "User", "aws:username": "dev",
		},
		"arn:aws:sts::123456789012:assumed-role/sender/s1": {
			"aws:PrincipalArn":  "arn:aws:iam::123456789012:role/sender",
			"aws:PrincipalType": "AssumedRole",
		},
		"arn:aws:iam::123456789012:root": {"aws:PrincipalArn": "arn:aws:iam::123456789012:root"},
		"not-an-arn":                     nil,
	} {
		if got := principalKeys(arn); !reflect.DeepEqual(got, want) {
			t.Errorf("%s: got %v, want %v", arn, got, want)
		}
	}
}

func TestGlobalKeys(t *testing.T) {
	r := httptest.NewRequest(http.MethodGet, "https://mailbox.local/", nil)
	r.RemoteAddr = "192.0.2.7:4242"
	r.TLS = &tls.ConnectionState{}
	now := time.Date(2026, 11, 13, 10, 0, 0, 0, time.FixedZone("x", 3600))
	got := globalKeys(r, user(), testRegion, now)
	want := map[string][]string{
		"aws:PrincipalAccount": {testAccount},
		"aws:PrincipalArn":     {userARN},
		"aws:PrincipalType":    {"User"},
		"aws:username":         {"dev"},
		"aws:CurrentTime":      {"2026-11-13T09:00:00Z"},
		"aws:EpochTime":        {"1794560400"},
		"aws:SecureTransport":  {"true"},
		"aws:RequestedRegion":  {testRegion},
		"aws:SourceIp":         {"192.0.2.7"},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %v\nwant %v", got, want)
	}
}

func TestOperationKeys(t *testing.T) {
	target := Target{
		Sender: "m@example.com", SenderDisplayName: "Marketing", Feedback: "fb@example.com",
		Recipients: []string{"a@example.com", "b@example.com"},
		Tags:       []contracts.Tag{{Key: "team", Value: "mail"}},
	}
	for name, want := range map[string]map[string][]string{
		"SendEmail": {
			"ses:ApiVersion":      {"2"},
			"ses:FromAddress":     {"m@example.com"},
			"ses:FromDisplayName": {"Marketing"},
			"ses:FeedbackAddress": {"fb@example.com"},
			"ses:Recipients":      {"a@example.com", "b@example.com"},
		},
		"SendBulkEmail": {"ses:ApiVersion": {"2"}},
		"CreateEmailTemplate": {
			"ses:ApiVersion":      {"2"},
			"aws:RequestTag/team": {"mail"},
			"aws:TagKeys":         {"team"},
		},
		"ListMessages": {},
	} {
		if got := operationKeys(operationNamed(t, name), target); !reflect.DeepEqual(got, want) {
			t.Errorf("%s: got %v, want %v", name, got, want)
		}
	}
	got := operationKeys(operationNamed(t, "SendEmail"), Target{Sender: "m@example.com"})
	if _, ok := got["ses:FromDisplayName"]; ok {
		t.Errorf("an empty display name is supplied: %v", got)
	}
}

func TestTheContextIsCapped(t *testing.T) {
	many := make([]string, maxKeyValues+1)
	for i := range many {
		many[i] = "a@example.com"
	}
	for name, k := range map[string]map[string][]string{
		"too many values": {"ses:Recipients": many},
		"too long":        {"ses:FromDisplayName": {strings.Repeat("x", maxValueLength+1)}},
	} {
		if err := checkKeys(k); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	if err := checkKeys(map[string][]string{"ses:Recipients": many[:maxKeyValues]}); err != nil {
		t.Errorf("at the bound: %v", err)
	}
}

func TestPoliciesAreCachedByContentAndBounded(t *testing.T) {
	c := newPolicyCache(2)
	d1 := doc(`{"Effect":"Allow","Action":"ses:GetAccount","Resource":"*"}`)
	d2 := doc(`{"Effect":"Allow","Action":"ses:SendEmail","Resource":"*"}`)
	d3 := doc(`{"Effect":"Allow","Action":"ses:SendBulkEmail","Resource":"*"}`)

	first, err := c.parse([]json.RawMessage{d1, d2})
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	again, err := c.parse([]json.RawMessage{append(json.RawMessage(nil), d1...)})
	if err != nil || again[0] != first[0] {
		t.Fatalf("the same document was parsed again: %v", err)
	}
	if _, err = c.parse([]json.RawMessage{d3}); err != nil {
		t.Fatalf("parse: %v", err)
	}
	if n := c.len(); n != 2 {
		t.Fatalf("%d cached, want 2", n)
	}
	// d1 was used last before d3, so d2 was dropped.
	again, _ = c.parse([]json.RawMessage{d1})
	if again[0] != first[0] {
		t.Fatal("the most recently used document was dropped")
	}
	if _, err = c.parse([]json.RawMessage{json.RawMessage(`{"Statement":[]}`)}); err == nil {
		t.Fatal("a malformed document parsed")
	}
}

func TestARawFromHeaderIsAuthorizedAsASecondSender(t *testing.T) {
	h := newHarness(t, "SendEmail", keys{"USER": user(doc(
		`{"Effect":"Allow","Action":"ses:SendEmail","Resource":"*",`+
			`"Condition":{"StringEquals":{"ses:FromAddress":["app@example.com","news@example.com"]},`+
			`"StringLike":{"ses:FromDisplayName":"News*"}}}`,
		`{"Effect":"Deny","Action":"ses:SendEmail","Resource":"`+
			sesARN("identity/blocked.example")+`"}`,
	))}, &store{})

	for _, tc := range []struct {
		name, denied string
		target       Target
	}{
		{name: "both senders allowed", target: Target{
			Sender: "app@example.com", SenderDisplayName: "News",
			HeaderSender: "news@example.com", HeaderSenderDisplayName: "News desk",
		}},
		{
			name: "a header from a denied identity", denied: explicitlyDenied("ses:SendEmail",
				"identity/blocked.example"),
			target: Target{
				Sender: "app@example.com", SenderDisplayName: "News",
				HeaderSender: "news@blocked.example", HeaderSenderDisplayName: "News",
			},
		},
		{
			// ses:FromAddress is the header's address on its identity.
			name:   "a header address the condition refuses",
			denied: notAllowed("ses:SendEmail", sesARN("identity/example.com")),
			target: Target{
				Sender: "app@example.com", SenderDisplayName: "News",
				HeaderSender: "other@example.com", HeaderSenderDisplayName: "News",
			},
		},
		{
			// The header has no display name, so none is supplied for it.
			name:   "a header without a display name",
			denied: notAllowed("ses:SendEmail", sesARN("identity/example.com")),
			target: Target{
				Sender: "app@example.com", SenderDisplayName: "News",
				HeaderSender: "news@example.com",
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h.target = tc.target
			status, e := h.call("USER")
			if tc.denied == "" {
				if status != http.StatusOK {
					t.Fatalf("%d %+v", status, e)
				}
				return
			}
			requireDenied(t, status, e, tc.denied)
		})
	}
}

func TestAPrincipalOfAnotherAccountIsRefused(t *testing.T) {
	const otherARN = "arn:aws:sts::999999999999:assumed-role/admin/s1"
	other := func(policies ...json.RawMessage) sigv4.Principal {
		return sigv4.Principal{AccountID: "999999999999", ARN: otherARN, Policies: policies}
	}
	message := func(reason, action, resource string) string {
		return "User: " + otherARN + " is not authorized to perform: " + action +
			" on resource: " + resource + " " + reason
	}
	allowAll := doc(`{"Effect":"Allow","Action":["ses:*","tule:Inspect"],"Resource":"*"}`)
	for _, tc := range []struct {
		name, op, key, want string
		target              Target
	}{
		{
			name: "allowed by its identity policies", op: "SendEmail", key: "ALLOWED",
			target: Target{Sender: "a@example.com"},
			want: message("because no resource-based policy allows the ses:SendEmail action",
				"ses:SendEmail", sesARN("identity/example.com")),
		},
		{
			name: "inspect", op: "ListMessages", key: "ALLOWED",
			want: message("because no resource-based policy allows the tule:Inspect action",
				InspectAction, sesARN("*")),
		},
		{
			name: "with no policy", op: "GetAccount", key: "NONE",
			want: message("because no identity-based policy allows the ses:GetAccount action",
				"ses:GetAccount", "*"),
		},
		{
			name: "explicitly denied", op: "GetAccount", key: "DENIED",
			want: message("with an explicit deny in an identity-based policy",
				"ses:GetAccount", "*"),
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h := newHarness(t, tc.op, keys{
				"ALLOWED": other(allowAll),
				"NONE":    other(),
				"DENIED": other(allowAll,
					doc(`{"Effect":"Deny","Action":"ses:GetAccount","Resource":"*"}`)),
			}, &store{})
			h.target = tc.target
			status, e := h.call(tc.key)
			requireDenied(t, status, e, tc.want)
		})
	}
}

func TestADenyOnAnEscapedTagKeyApplies(t *testing.T) {
	// The tags of an existing resource are always supplied, whatever the
	// policy's bytes look like: "R" is an escaped "R".
	h := newHarness(t, "GetEmailTemplate", keys{"USER": user(doc(
		`{"Effect":"Allow","Action":"ses:*","Resource":"*"}`,
		`{"Effect":"Deny","Action":"ses:GetEmailTemplate","Resource":"*",`+
			`"Condition":{"StringEquals":{"aws:ResourceTag/env":"prod"}}}`,
	))}, &store{templates: map[string][]contracts.Tag{
		"dev":  {{Key: "env", Value: "dev"}},
		"prod": {{Key: "env", Value: "prod"}},
	}})
	h.target = Target{Template: "dev"}
	if status, e := h.call("USER"); status != http.StatusOK {
		t.Fatalf("dev: %d %+v", status, e)
	}
	h.target = Target{Template: "prod"}
	status, e := h.call("USER")
	requireDenied(t, status, e, explicitlyDenied("ses:GetEmailTemplate", "template/prod"))
}

func TestRootIsBoundToTheServicesAccount(t *testing.T) {
	// The static key of a service configured for a non-default account.
	static, err := sigv4.NewStaticKey(sigv4.StaticKeyConfig{
		AccessKeyID: "STATIC", SecretAccessKey: "secret-STATIC", AccountID: testAccount,
	})
	if err != nil {
		t.Fatalf("static key: %v", err)
	}
	h := newHarness(t, "GetAccount", static, &store{})
	h.skip = true
	if status, e := h.call("STATIC"); status != http.StatusOK {
		t.Fatalf("the service's static key: %d %+v", status, e)
	}

	const otherRoot = "arn:aws:iam::999999999999:root"
	h = newHarness(t, "GetAccount", keys{
		"ROOT": {AccountID: "999999999999", ARN: otherRoot, Root: true},
	}, &store{})
	h.skip = true
	status, e := h.call("ROOT")
	requireDenied(t, status, e, "User: "+otherRoot+" is not authorized to perform: "+
		"ses:GetAccount on resource: * because no identity-based policy allows the "+
		"ses:GetAccount action")
}

func TestTagKeysThatDifferOnlyByCaseAreRefused(t *testing.T) {
	allow := doc(`{"Effect":"Allow","Action":"ses:*","Resource":"*"}`)
	principals := keys{
		"USER": user(allow),
		"ROOT": {AccountID: testAccount, ARN: "arn:aws:iam::" + testAccount + ":root", Root: true},
	}
	clash := []contracts.Tag{{Key: "Env", Value: "dev"}, {Key: "env", Value: "prod"}}

	h := newHarness(t, "CreateEmailTemplate", principals, &store{})
	h.target = Target{Template: "t", Tags: clash}
	status, e := h.call("USER")
	if status != http.StatusBadRequest || e.Type != sesapi.TypeBadRequest {
		t.Fatalf("a request's clashing keys: %d %+v, want 400 BadRequestException", status, e)
	}
	if status, e = h.call("ROOT"); status != http.StatusOK {
		t.Fatalf("the root's write: %d %+v", status, e)
	}

	// A stored resource with such keys is not evaluated at all.
	h = newHarness(t, "GetEmailTemplate", principals, &store{
		templates: map[string][]contracts.Tag{"t": clash},
	})
	h.target = Target{Template: "t"}
	status, e = h.call("USER")
	if status != http.StatusInternalServerError || e.Type != sesapi.TypeInternalFailure {
		t.Fatalf("stored clashing keys: %d %+v, want 500 InternalFailure", status, e)
	}
	h = newHarness(t, "SendEmail", principals, &store{
		identities: map[string][]contracts.Tag{"example.com": clash},
	})
	h.target = Target{Sender: "a@example.com"}
	if status, e = h.call("USER"); status != http.StatusInternalServerError {
		t.Fatalf("stored clashing keys on a sender identity: %d %+v", status, e)
	}
}

func TestTheRegionIsTheServicesNotTheSignedOne(t *testing.T) {
	// Signing for another region changes neither aws:RequestedRegion nor the
	// ARN: a Deny on the service's region still applies.
	h := newHarness(t, "SendEmail", keys{"USER": user(doc(
		`{"Effect":"Allow","Action":"ses:SendEmail","Resource":"*"}`,
		`{"Effect":"Deny","Action":"ses:SendEmail","Resource":"*",`+
			`"Condition":{"StringEquals":{"aws:RequestedRegion":"`+testRegion+`"}}}`,
	))}, &store{})
	h.region = "us-east-1"
	h.target = Target{Sender: "a@example.com"}
	status, e := h.call("USER")
	requireDenied(t, status, e, explicitlyDenied("ses:SendEmail", "identity/example.com"))
}

func TestResourceNamesAreBoundedBeforeEvaluation(t *testing.T) {
	long := func(n int) string { return strings.Repeat("a", n) }
	for _, tc := range []struct {
		name, op string
		target   Target
	}{
		{"a long domain", "GetEmailIdentity", Target{Identity: long(254) + ".com"}},
		{"a long address", "GetEmailIdentity", Target{Identity: long(320) + "@x.com"}},
		{"a long sender", "SendEmail", Target{Sender: long(320) + "@x.com"}},
		{"a long header sender", "SendEmail", Target{
			Sender: "a@example.com", HeaderSender: long(320) + "@x.com",
		}},
		{"a long configuration set", "SendEmail", Target{
			Sender: "a@example.com", ConfigurationSet: long(65),
		}},
		{"a long template", "GetEmailTemplate", Target{Template: long(257)}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h := newHarness(t, tc.op, keys{"USER": user(doc(
				`{"Effect":"Allow","Action":"ses:*","Resource":"*"}`,
			))}, &store{})
			h.target = tc.target
			status, e := h.call("USER")
			if status != http.StatusBadRequest || e.Type != sesapi.TypeBadRequest {
				t.Fatalf("%d %+v, want 400 BadRequestException", status, e)
			}
		})
	}
	h := newHarness(t, "SendEmail", keys{"USER": user(doc(
		`{"Effect":"Allow","Action":"ses:*","Resource":"*"}`,
	))}, &store{})
	h.target = Target{Sender: long(64) + "@" + long(251) + ".com", ConfigurationSet: long(64)}
	if status, e := h.call("USER"); status != http.StatusOK {
		t.Fatalf("names at the bounds: %d %+v", status, e)
	}
}
