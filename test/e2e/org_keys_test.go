//go:build e2e

package e2e

import (
	"net/http"
	"strconv"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	"github.com/aws/aws-sdk-go-v2/service/organizations"
	orgtypes "github.com/aws/aws-sdk-go-v2/service/organizations/types"
	"github.com/aws/aws-sdk-go-v2/service/sesv2"
	"github.com/aws/aws-sdk-go-v2/service/sts"
)

// orgStack is an identity stack whose identity knows an organization with
// one member account and one account removed from it, with an IAM client
// acting in each.
type orgStack struct {
	*identityStack
	memberIAM  *iam.Client
	removedIAM *iam.Client
	orgID      string
	rootID     string
	member     string
	removed    string
}

func startOrgStack(t *testing.T) *orgStack {
	t.Helper()
	root := aws.Credentials{AccessKeyID: identityRootKeyID, SecretAccessKey: identityRootSecret}

	accountsPort := identityFreePort(t)
	accountsURL := "http://127.0.0.1:" + strconv.Itoa(accountsPort)
	startSibling(t, "accounts", accountsDirEnv, accountsPort)
	oc := organizations.New(organizations.Options{
		Region:           region,
		BaseEndpoint:     aws.String(accountsURL),
		Credentials:      credentials.StaticCredentialsProvider{Value: root},
		HTTPClient:       &http.Client{Timeout: clientTimeout},
		RetryMaxAttempts: 1,
	})
	org, err := oc.CreateOrganization(t.Context(), &organizations.CreateOrganizationInput{})
	requireNoErr(t, err, "create organization")
	roots, err := oc.ListRoots(t.Context(), &organizations.ListRootsInput{})
	requireNoErr(t, err, "list roots")
	if len(roots.Roots) != 1 {
		t.Fatalf("roots = %d, want 1", len(roots.Roots))
	}

	s := &orgStack{
		identityStack: startIdentityStack(t, "TULE_Identity_AccountsEndpoint="+accountsURL),
		orgID:         aws.ToString(org.Organization.Id),
		rootID:        aws.ToString(roots.Roots[0].Id),
		member:        createOrgAccount(t, oc, "Member", "member@example.com"),
		removed:       createOrgAccount(t, oc, "Removed", "removed@example.com"),
	}
	s.memberIAM = iamClient(aws.ToString(s.iam.Options().BaseEndpoint),
		s.assumeAdmin(t, s.member))
	// The removed account's session is taken while it is a member, then the
	// account is removed before anything asks for its organization keys,
	// which identity keeps for 30 seconds.
	s.removedIAM = iamClient(aws.ToString(s.iam.Options().BaseEndpoint),
		s.assumeAdmin(t, s.removed))
	_, err = oc.RemoveAccountFromOrganization(t.Context(),
		&organizations.RemoveAccountFromOrganizationInput{AccountId: aws.String(s.removed)})
	requireNoErr(t, err, "remove the account from the organization")
	return s
}

// createOrgAccount creates an account in the organization and returns its
// ID.
func createOrgAccount(t *testing.T, oc *organizations.Client, name, email string) string {
	t.Helper()
	created, err := oc.CreateAccount(t.Context(), &organizations.CreateAccountInput{
		AccountName: aws.String(name), Email: aws.String(email),
	})
	requireNoErr(t, err, "create account "+name)
	st := created.CreateAccountStatus
	if st == nil || st.State != orgtypes.CreateAccountStateSucceeded {
		t.Fatalf("create account %s: %+v", name, st)
	}
	return aws.ToString(st.AccountId)
}

// assumeAdmin assumes the account's OrganizationAccountAccessRole as the
// root.
func (s *orgStack) assumeAdmin(t *testing.T, account string) aws.Credentials {
	t.Helper()
	out, err := stsClient(s.identityStack, s.rootCreds).AssumeRole(t.Context(),
		&sts.AssumeRoleInput{
			RoleArn: aws.String(
				"arn:aws:iam::" + account + ":role/OrganizationAccountAccessRole"),
			RoleSessionName: aws.String("admin"),
		})
	requireNoErr(t, err, "assume the role of account "+account)
	return sessionCreds(out)
}

// TestOrganizationKeysInASendingAuthorizationPolicy grants sending to
// every principal of the organization, by aws:PrincipalOrgID on one
// identity and aws:PrincipalOrgPaths on another: a user of a member account
// sends through both, and a user of an account removed from the
// organization through neither.
func TestOrganizationKeysInASendingAuthorizationPolicy(t *testing.T) {
	s := startOrgStack(t)
	byID, byPath := "org-id.example", "org-path.example"
	s.createIdentity(t, byID)
	s.createIdentity(t, byPath)
	orgGrant := func(identity, operator, key, value string) string {
		st := grantSend("Allow", identity, "*")
		st.Condition = map[string]map[string]any{operator: {key: value}}
		return policyDoc(st)
	}
	s.putPolicy(t, byID, "org", orgGrant(byID, "StringEquals", "aws:PrincipalOrgID", s.orgID))
	s.putPolicy(t, byPath, "org", orgGrant(byPath, "ForAnyValue:StringLike",
		"aws:PrincipalOrgPaths", s.orgID+"/"+s.rootID+"/*"))

	delegate := func(ic *iam.Client, name string) *sesv2.Client {
		key := createUserKey(t, ic, name)
		putUserPolicy(t, ic, name, allowPolicy("ses:SendEmail"))
		return sesClientWith(s.srv, key)
	}
	from := func(identity string) *sesv2.SendEmailInput {
		in := simpleInput("a@"+identity, "Organization", "Body.", "to@example.com")
		in.FromEmailAddressIdentityArn = aws.String(sesARN("identity/" + identity))
		return in
	}

	t.Run("a member account's user sends", func(t *testing.T) {
		c := delegate(s.memberIAM, "inside")
		send(t, c, from(byID))
		send(t, c, from(byPath))
	})
	t.Run("a removed account's user is refused", func(t *testing.T) {
		c := delegate(s.removedIAM, "outside")
		userARN := "arn:aws:iam::" + s.removed + ":user/outside"
		for _, identity := range []string{byID, byPath} {
			requireAccessDenied(t, errOf(c.SendEmail(t.Context(), from(identity))),
				"User: "+userARN+" is not authorized to perform: ses:SendEmail on "+
					"resource: "+sesARN("identity/"+identity)+" because no "+
					"resource-based policy allows the ses:SendEmail action")
		}
	})
}
