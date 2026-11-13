package authz

import (
	"errors"
	"net/http"
	"strings"
	"testing"

	"tule.dev/mailbox/internal/sesapi"
)

func TestPolicyNames(t *testing.T) {
	for name, ok := range map[string]bool{
		"a":                     true,
		"Send-From_Marketing1":  true,
		strings.Repeat("a", 64): true,
		"":                      false,
		strings.Repeat("a", 65): false,
		"has space":             false,
		"dot.name":              false,
		"slash/name":            false,
		"ünï":                   false,
	} {
		if err := CheckIdentityPolicyName(name); (err == nil) != ok {
			t.Errorf("%q: %v, want accepted %v", name, err, ok)
		}
	}
}

// policyCase is a document CheckIdentityPolicy accepts, or refuses.
type policyCase struct {
	name, doc string
	ok        bool
}

func identityPolicyCases() []policyCase {
	arn := sesARN("identity/example.com")
	statement := func(resource string) string {
		return `{"Effect":"Allow","Principal":{"AWS":"999999999999"},` +
			`"Action":"ses:SendEmail","Resource":` + resource + `}`
	}
	return []policyCase{
		{name: "the identity's ARN", doc: string(doc(statement(`"` + arn + `"`))), ok: true},
		{
			name: "a list of it, and the ARN of any region",
			doc: string(doc(statement(`["` + arn + `","arn:aws:ses:*:` + testAccount +
				`:identity/example.com"]`))),
			ok: true,
		},
		{
			name: "one statement, not a list",
			doc:  `{"Version":"2012-10-17","Statement":` + statement(`"`+arn+`"`) + `}`,
			ok:   true,
		},
		{
			name: "a Sid of any characters",
			doc: string(doc(`{"Sid":"send from marketing","Effect":"Allow",` +
				`"Principal":{"AWS":"999999999999"},"Action":"ses:SendEmail",` +
				`"Resource":"` + arn + `"}`)),
			ok: true,
		},
		{name: "empty", doc: ""},
		{name: "over 4 KB", doc: string(doc(statement(`"`+arn+`"`))) +
			strings.Repeat(" ", MaxIdentityPolicySize)},
		{name: "not JSON", doc: `{"Statement":`},
		{name: "no Principal", doc: string(doc(`{"Effect":"Allow","Action":"ses:SendEmail",` +
			`"Resource":"` + arn + `"}`))},
		{name: "an invalid principal", doc: string(doc(`{"Effect":"Allow",` +
			`"Principal":{"AWS":"arn:aws:iam::999999999999:group/g"},` +
			`"Action":"ses:SendEmail","Resource":"` + arn + `"}`))},
		{name: "another identity", doc: string(doc(statement(`"` +
			sesARN("identity/other.example") + `"`)))},
		{name: "another account", doc: string(doc(statement(
			`"arn:aws:ses:` + testRegion + `:999999999999:identity/example.com"`)))},
		{name: "a wildcard", doc: string(doc(statement(`"*"`)))},
		{name: "NotResource", doc: string(doc(`{"Effect":"Deny","Principal":"*",` +
			`"Action":"ses:SendEmail","NotResource":"` + arn + `"}`))},
		{name: "one bad statement of two", doc: string(doc(statement(`"`+arn+`"`),
			statement(`"`+sesARN("identity/other.example")+`"`)))},
	}
}

func TestIdentityPolicyDocuments(t *testing.T) {
	a := New(&store{}, testAccount, testRegion)
	for _, tc := range identityPolicyCases() {
		t.Run(tc.name, func(t *testing.T) {
			err := a.CheckIdentityPolicy("example.com", tc.doc)
			if tc.ok {
				if err != nil {
					t.Fatalf("refused: %v", err)
				}
				return
			}
			var e *sesapi.Error
			if !errors.As(err, &e) || e.Status != http.StatusBadRequest ||
				e.Type != sesapi.TypeBadRequest {
				t.Fatalf("got %v, want BadRequestException", err)
			}
		})
	}
}
