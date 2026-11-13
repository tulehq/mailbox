package authz

import (
	"encoding/json"
	"net/http"
	"testing"

	"tule.dev/sigv4"

	"tule.dev/mailbox/internal/contracts"
	"tule.dev/mailbox/internal/sesapi"
)

const (
	otherAccount = "999999999999"
	otherUserARN = "arn:aws:iam::" + otherAccount + ":user/delegate"
)

// delegate is an IAM user of another account.
func delegate(policies ...json.RawMessage) sigv4.Principal {
	return sigv4.Principal{
		AccountID: otherAccount, ARN: otherUserARN, PrincipalARN: otherUserARN,
		UserID: "AIDAEXAMPLEDELEGATE1", Type: sigv4.PrincipalTypeUser, Policies: policies,
	}
}

var allowSend = doc(`{"Effect":"Allow","Action":"ses:SendEmail","Resource":"*"}`)

// grant is a sending authorization policy of identity/example.com with
// one statement of the effect for the AWS principal.
func grant(effect, principal string) string {
	return string(doc(`{"Effect":"` + effect + `","Principal":{"AWS":"` + principal + `"},` +
		`"Action":"ses:SendEmail","Resource":"` + sesARN("identity/example.com") + `"}`))
}

func deniedAs(callerARN, action, resource, reason string) string {
	return "User: " + callerARN + " is not authorized to perform: " + action +
		" on resource: " + resource + " " + reason
}

type resourceCase struct {
	target Target
	name   string
	// want is the AccessDeniedException's message, or empty for an Allow.
	want     string
	policies []string
	p        sigv4.Principal
}

var (
	example = sesARN("identity/example.com")
	send    = Target{Sender: "a@example.com"}
)

func crossAccountCases() []resourceCase {
	return []resourceCase{
		{
			name: "another account allowed by both", p: delegate(allowSend),
			policies: []string{grant("Allow", otherAccount)}, target: send,
		},
		{
			name: "another account without a resource grant", p: delegate(allowSend),
			policies: []string{grant("Allow", "111111111111")}, target: send,
			want: deniedAs(otherUserARN, "ses:SendEmail", example,
				"because no resource-based policy allows the ses:SendEmail action"),
		},
		{
			name: "another account without an identity allow", p: delegate(),
			policies: []string{grant("Allow", otherUserARN)}, target: send,
			want: deniedAs(otherUserARN, "ses:SendEmail", example,
				"because no identity-based policy allows the ses:SendEmail action"),
		},
		{
			name: "a Deny in a second policy", p: delegate(allowSend),
			policies: []string{grant("Allow", otherAccount), grant("Deny", otherUserARN)},
			target:   send,
			want: deniedAs(otherUserARN, "ses:SendEmail", example,
				"with an explicit deny in a resource-based policy"),
		},
		{
			name: "an Allow in a second policy", p: delegate(allowSend),
			policies: []string{grant("Allow", "111111111111"), grant("Allow", otherUserARN)},
			target:   send,
		},
	}
}

func sameAccountCases() []resourceCase {
	return []resourceCase{
		{
			name: "a resource Deny beats an identity Allow in one account", p: user(allowSend),
			policies: []string{grant("Deny", userARN)}, target: send,
			want: deniedAs(userARN, "ses:SendEmail", example,
				"with an explicit deny in a resource-based policy"),
		},
		{
			name: "a user named in one account needs no identity policy", p: user(),
			policies: []string{grant("Allow", userARN)}, target: send,
		},
		{
			name: "the account named in one account needs an identity allow", p: user(),
			policies: []string{grant("Allow", testAccount)}, target: send,
			want: deniedAs(userARN, "ses:SendEmail", example,
				"because no identity-based policy allows the ses:SendEmail action"),
		},
	}
}

func otherCallerCases() []resourceCase {
	const roleARN = "arn:aws:iam::" + otherAccount + ":role/mail/sender"
	return []resourceCase{
		{
			name:     "a role session by its role's ARN with a path",
			p:        session(otherAccount, roleARN, allowSend),
			policies: []string{grant("Allow", roleARN)}, target: send,
		},
		{
			name: "the root of another account by the resource grant alone",
			p:    otherRootPrincipal(), policies: []string{grant("Allow", otherAccount)},
			target: send,
		},
		{
			// The delegate's own configuration set, in its own account.
			name: "another account's configuration set", p: delegate(allowSend),
			policies: []string{grant("Allow", otherAccount)},
			target:   Target{Sender: "a@example.com", ConfigurationSet: "cs"},
		},
		{
			name: "a stored template of the identity's account", p: delegate(allowSend),
			policies: []string{grant("Allow", otherAccount)},
			target:   Target{Sender: "a@example.com", Template: "welcome"},
			want: deniedAs(otherUserARN, "ses:SendEmail", sesARN("template/welcome"),
				"because no resource-based policy allows the ses:SendEmail action"),
		},
		{
			// A sending authorization policy authorizes sends, nothing else.
			name: "another operation on the identity", p: delegate(doc(
				`{"Effect":"Allow","Action":"ses:*","Resource":"*"}`)),
			policies: []string{grant("Allow", otherAccount)},
			target:   Target{Identity: "example.com"},
			want: deniedAs(otherUserARN, "ses:GetEmailIdentity", example,
				"because no resource-based policy allows the ses:GetEmailIdentity action"),
		},
	}
}

func TestSendsAreEvaluatedWithTheIdentitysPolicies(t *testing.T) {
	cases := append(append(crossAccountCases(), sameAccountCases()...), otherCallerCases()...)
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			op := "SendEmail"
			if tc.target.Identity != "" {
				op = "GetEmailIdentity"
			}
			h := newHarness(t, op, keys{"KEY": tc.p}, &store{
				policies:  map[string][]string{"example.com": tc.policies},
				templates: map[string][]contracts.Tag{"welcome": nil},
			})
			h.target = tc.target
			status, e := h.call("KEY")
			if tc.want == "" {
				if status != http.StatusOK {
					t.Fatalf("%d %+v", status, e)
				}
				return
			}
			requireDenied(t, status, e, tc.want)
		})
	}
}

func TestAStoredPolicyThatDoesNotParseFailsClosed(t *testing.T) {
	h := newHarness(t, "SendEmail", keys{"KEY": user(allowSend)}, &store{
		policies: map[string][]string{"example.com": {grant("Allow", testAccount), `{"x":`}},
	})
	h.target = Target{Sender: "a@example.com"}
	status, e := h.call("KEY")
	if status != http.StatusInternalServerError || e.Type != sesapi.TypeInternalFailure {
		t.Fatalf("got %d %+v, want 500 InternalFailure", status, e)
	}
}

func TestIdentityARNsMustNameTheSendersIdentity(t *testing.T) {
	a := New(&store{policies: map[string][]string{
		"example.com": nil, "ops@example.com": nil,
	}}, testAccount, testRegion)
	for _, tc := range []struct {
		name, arn, address string
		status             int
	}{
		{"the domain", sesARN("identity/example.com"), "a@example.com", http.StatusOK},
		{
			"the domain in another case", sesARN("identity/Example.COM"), "a@example.com",
			http.StatusOK,
		},
		{
			"the address identity", sesARN("identity/ops@example.com"), "ops@example.com",
			http.StatusOK,
		},
		{
			"a domain the address identity overrides", sesARN("identity/example.com"),
			"ops@example.com", http.StatusBadRequest,
		},
		{
			"another identity", sesARN("identity/other.example"), "a@example.com",
			http.StatusBadRequest,
		},
		{"not an identity ARN", sesARN("template/t"), "a@example.com", http.StatusBadRequest},
		{"not an ARN", "example.com", "a@example.com", http.StatusBadRequest},
		{"another account", "arn:aws:ses:" + testRegion + ":" + otherAccount +
			":identity/example.com", "a@example.com", http.StatusNotFound},
		{
			"another region", "arn:aws:ses:us-west-2:" + testAccount + ":identity/example.com",
			"a@example.com", http.StatusNotFound,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := a.CheckIdentityARN(t.Context(), "FromEmailAddressIdentityArn", tc.arn,
				tc.address)
			if tc.status == http.StatusOK {
				if err != nil {
					t.Fatalf("refused: %v", err)
				}
				return
			}
			e := sesapi.ToError(t.Context(), err)
			if e.Status != tc.status {
				t.Fatalf("got %v, want status %d", err, tc.status)
			}
		})
	}
}
