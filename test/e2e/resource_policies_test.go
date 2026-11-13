//go:build e2e

package e2e

import (
	"net/http"
	"strconv"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	iamtypes "github.com/aws/aws-sdk-go-v2/service/iam/types"
	"github.com/aws/aws-sdk-go-v2/service/organizations"
	orgtypes "github.com/aws/aws-sdk-go-v2/service/organizations/types"
	"github.com/aws/aws-sdk-go-v2/service/sesv2"
	"github.com/aws/aws-sdk-go-v2/service/sesv2/types"
	"github.com/aws/aws-sdk-go-v2/service/sts"
)

// These tests run mailbox against real identity and accounts services and
// check that an identity's sending authorization policies are evaluated
// with the caller's identity policies, within the account and from a
// member account of the organization.

// crossStack is an identity stack whose identity knows an organization
// with one member account, and an IAM client acting in that account.
type crossStack struct {
	*identityStack
	memberIAM *iam.Client
	member    string
}

func startCrossStack(t *testing.T) *crossStack {
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
	_, err := oc.CreateOrganization(t.Context(), &organizations.CreateOrganizationInput{})
	requireNoErr(t, err, "create organization")
	created, err := oc.CreateAccount(t.Context(), &organizations.CreateAccountInput{
		AccountName: aws.String("Member"), Email: aws.String("member@example.com"),
	})
	requireNoErr(t, err, "create account")
	st := created.CreateAccountStatus
	if st == nil || st.State != orgtypes.CreateAccountStateSucceeded {
		t.Fatalf("create account: %+v", st)
	}

	s := &crossStack{
		identityStack: startIdentityStack(t, "TULE_Identity_AccountsEndpoint="+accountsURL),
		member:        aws.ToString(st.AccountId),
	}
	out, err := stsClient(s.identityStack, root).AssumeRole(t.Context(), &sts.AssumeRoleInput{
		RoleArn: aws.String(
			"arn:aws:iam::" + s.member + ":role/OrganizationAccountAccessRole",
		),
		RoleSessionName: aws.String("admin"),
	})
	requireNoErr(t, err, "assume the member account's role")
	s.memberIAM = iamClient(aws.ToString(s.iam.Options().BaseEndpoint), sessionCreds(out))
	return s
}

func sessionCreds(out *sts.AssumeRoleOutput) aws.Credentials {
	return aws.Credentials{
		AccessKeyID:     aws.ToString(out.Credentials.AccessKeyId),
		SecretAccessKey: aws.ToString(out.Credentials.SecretAccessKey),
		SessionToken:    aws.ToString(out.Credentials.SessionToken),
	}
}

func (s *identityStack) createIdentity(t *testing.T, name string) {
	t.Helper()
	_, err := sesClientWith(s.srv, s.rootCreds).CreateEmailIdentity(t.Context(),
		&sesv2.CreateEmailIdentityInput{EmailIdentity: aws.String(name)})
	requireNoErr(t, err, "create identity "+name)
}

// putPolicy gives the identity a sending authorization policy, as the root.
func (s *identityStack) putPolicy(t *testing.T, identity, name, doc string) {
	t.Helper()
	createPolicy(t, sesClientWith(s.srv, s.rootCreds), identity, name, doc)
}

// grantSend is a sending authorization policy statement of the identity
// for the principal, with the effect.
func grantSend(effect, identity, principal string) statement {
	return statement{
		Effect: effect, Principal: map[string]string{"AWS": principal},
		Action: []string{"ses:SendEmail"}, Resource: []string{sesARN("identity/" + identity)},
	}
}

func TestAnotherAccountSendsWhenBothPoliciesAllow(t *testing.T) {
	s := startCrossStack(t)
	s.createIdentity(t, "example.com")
	s.createIdentity(t, "blocked.example")
	key := createUserKey(t, s.memberIAM, "delegate")
	putUserPolicy(t, s.memberIAM, "delegate", allowPolicy("ses:SendEmail"))
	c := sesClientWith(s.srv, key)
	delegateARN := "arn:aws:iam::" + s.member + ":user/delegate"
	from := func(address, identity string) *sesv2.SendEmailInput {
		in := simpleInput(address, "Delegated", "Body.", "to@example.com")
		in.FromEmailAddressIdentityArn = aws.String(sesARN("identity/" + identity))
		return in
	}

	t.Run("no policy grants it", func(t *testing.T) {
		requireAccessDenied(t, errOf(c.SendEmail(t.Context(), from("a@example.com",
			"example.com"))), "User: "+delegateARN+" is not authorized to perform: "+
			"ses:SendEmail on resource: "+sesARN("identity/example.com")+" because no "+
			"resource-based policy allows the ses:SendEmail action")
		s.putPolicy(t, "example.com", "others", policyDoc(
			grantSend("Allow", "example.com", "111111111111")))
		requireAccessDenied(t, errOf(c.SendEmail(t.Context(), from("a@example.com",
			"example.com"))), "User: "+delegateARN+" is not authorized to perform: "+
			"ses:SendEmail on resource: "+sesARN("identity/example.com")+" because no "+
			"resource-based policy allows the ses:SendEmail action")
	})
	t.Run("a policy grants its account", func(t *testing.T) {
		s.putPolicy(t, "example.com", "member", policyDoc(
			grantSend("Allow", "example.com", s.member)))
		id := send(t, c, from("a@example.com", "example.com"))
		requireEqual(t, mailboxWith(s.srv, s.rootCreds).byMessageID(t, id).From,
			"a@example.com", "the delegated message's sender")
		// The identity's policies authorize the address with or without
		// the ARN, which only has to name that identity.
		send(t, c, simpleInput("b@example.com", "Delegated", "Body.", "to@example.com"))
		requireAs[*types.BadRequestException](t, errOf(c.SendEmail(t.Context(),
			from("a@example.com", "blocked.example"))))
	})
	t.Run("an explicit Deny in the resource policy", func(t *testing.T) {
		s.putPolicy(t, "blocked.example", "member", policyDoc(
			grantSend("Allow", "blocked.example", s.member),
			grantSend("Deny", "blocked.example", delegateARN)))
		requireAccessDenied(t, errOf(c.SendEmail(t.Context(), from("a@blocked.example",
			"blocked.example"))), "User: "+delegateARN+" is not authorized to perform: "+
			"ses:SendEmail on resource: "+sesARN("identity/blocked.example")+" with an "+
			"explicit deny in a resource-based policy")
	})
	t.Run("without its own identity allow", func(t *testing.T) {
		other := createUserKey(t, s.memberIAM, "nopolicy")
		requireAccessDenied(t, errOf(sesClientWith(s.srv, other).SendEmail(t.Context(),
			from("a@example.com", "example.com"))), "User: arn:aws:iam::"+s.member+
			":user/nopolicy is not authorized to perform: ses:SendEmail on resource: "+
			sesARN("identity/example.com")+" because no identity-based policy allows the "+
			"ses:SendEmail action")
	})
	t.Run("the retrieval API", func(t *testing.T) {
		requireAPIErrorBody(t, mailboxWith(s.srv, key).do(t, http.MethodGet,
			"/_mailbox/messages", nil), http.StatusForbidden, "AccessDeniedException",
			"inspect from another account")
	})
}

func TestAResourcePolicyWithinTheAccount(t *testing.T) {
	s := startIdentityStack(t)
	s.createIdentity(t, "users.example")
	s.createIdentity(t, "account.example")
	key := createUserKey(t, s.iam, "plain")
	userARN := "arn:aws:iam::" + account + ":user/plain"
	c := sesClientWith(s.srv, key)

	t.Run("naming the IAM user is enough", func(t *testing.T) {
		s.putPolicy(t, "users.example", "user", policyDoc(
			grantSend("Allow", "users.example", userARN)))
		send(t, c, simpleInput("a@users.example", "Granted", "Body.", "to@example.com"))
	})
	t.Run("granting the account needs the identity allow", func(t *testing.T) {
		s.putPolicy(t, "account.example", "account", policyDoc(
			grantSend("Allow", "account.example", account)))
		requireAccessDenied(t, errOf(c.SendEmail(t.Context(), simpleInput("a@account.example",
			"Denied", "Body.", "to@example.com"))), "User: "+userARN+" is not authorized to "+
			"perform: ses:SendEmail on resource: "+sesARN("identity/account.example")+
			" because no identity-based policy allows the ses:SendEmail action")
		putUserPolicy(t, s.iam, "plain", policyDoc(statement{
			Effect: "Allow", Action: []string{"ses:SendEmail"},
			Resource: []string{sesARN("identity/account.example")},
		}))
		send(t, c, simpleInput("a@account.example", "Allowed", "Body.", "to@example.com"))
	})
}

func TestAResourcePolicyMatchesARoleWithItsPath(t *testing.T) {
	s := startIdentityStack(t)
	s.createIdentity(t, "role.example")
	s.createIdentity(t, "cond.example")
	userKey := createUserKey(t, s.iam, "dev")
	roleARN := "arn:aws:iam::" + account + ":role/mail/sender"
	assume := func(role, path string) aws.Credentials {
		_, err := s.iam.CreateRole(t.Context(), &iam.CreateRoleInput{
			RoleName: aws.String(role), Path: aws.String(path),
			AssumeRolePolicyDocument: aws.String(policyDoc(statement{
				Effect: "Allow", Action: []string{"sts:AssumeRole"},
				Principal: map[string]string{"AWS": "arn:aws:iam::" + account + ":user/dev"},
			})),
		})
		requireNoErr(t, err, "create role "+role)
		out, err := stsClient(s, userKey).AssumeRole(t.Context(), &sts.AssumeRoleInput{
			RoleArn:         aws.String("arn:aws:iam::" + account + ":role" + path + role),
			RoleSessionName: aws.String("s1"),
		})
		requireNoErr(t, err, "assume role "+role)
		return sessionCreds(out)
	}
	sender := sesClientWith(s.srv, assume("sender", "/mail/"))
	other := sesClientWith(s.srv, assume("sender2", "/other/"))

	// The role has no identity policy: a grant of its ARN, path included,
	// reaches its sessions on its own.
	s.putPolicy(t, "role.example", "role", policyDoc(grantSend("Allow", "role.example", roleARN)))
	send(t, sender, simpleInput("a@role.example", "Role", "Body.", "to@example.com"))
	requireDenied(t, errOf(other.SendEmail(t.Context(),
		simpleInput("a@role.example", "Other", "Body.", "to@example.com"))))

	// aws:PrincipalArn is the role's ARN with its path.
	byPath := grantSend("Allow", "cond.example", "*")
	byPath.Condition = map[string]map[string]any{
		"ArnLike": {"aws:PrincipalArn": "arn:aws:iam::" + account + ":role/mail/*"},
	}
	s.putPolicy(t, "cond.example", "path", policyDoc(byPath))
	send(t, sender, simpleInput("a@cond.example", "Path", "Body.", "to@example.com"))
	requireAccessDenied(t, errOf(other.SendEmail(t.Context(),
		simpleInput("a@cond.example", "Other", "Body.", "to@example.com"))),
		"User: arn:aws:sts::"+account+":assumed-role/sender2/s1 is not authorized to "+
			"perform: ses:SendEmail on resource: "+sesARN("identity/cond.example")+
			" because no identity-based policy allows the ses:SendEmail action")
}

func TestAResourcePolicyConditionOnAPrincipalTag(t *testing.T) {
	s := startIdentityStack(t)
	s.createIdentity(t, "tags.example")
	_, err := s.iam.CreateUser(t.Context(), &iam.CreateUserInput{
		UserName: aws.String("tagged"),
		Tags:     []iamtypes.Tag{{Key: aws.String("team"), Value: aws.String("mail")}},
	})
	requireNoErr(t, err, "create tagged user")
	keyOut, err := s.iam.CreateAccessKey(t.Context(),
		&iam.CreateAccessKeyInput{UserName: aws.String("tagged")})
	requireNoErr(t, err, "create access key")
	tagged := aws.Credentials{
		AccessKeyID:     aws.ToString(keyOut.AccessKey.AccessKeyId),
		SecretAccessKey: aws.ToString(keyOut.AccessKey.SecretAccessKey),
	}
	untagged := createUserKey(t, s.iam, "untagged")

	byTag := grantSend("Allow", "tags.example", "*")
	byTag.Condition = map[string]map[string]any{
		"StringEquals": {"aws:PrincipalTag/team": "mail"},
	}
	s.putPolicy(t, "tags.example", "team", policyDoc(byTag))
	send(t, sesClientWith(s.srv, tagged),
		simpleInput("a@tags.example", "Tagged", "Body.", "to@example.com"))
	requireDenied(t, errOf(sesClientWith(s.srv, untagged).SendEmail(t.Context(),
		simpleInput("a@tags.example", "Untagged", "Body.", "to@example.com"))))
}

func TestARawMessagesIdentityARNHeaders(t *testing.T) {
	// X-SES-SOURCE-ARN and X-SES-FROM-ARN must name the identity their
	// address sends from, and FromEmailAddressIdentityArn overrides both.
	c, _ := newClient(t)
	_, err := c.CreateEmailIdentity(t.Context(),
		&sesv2.CreateEmailIdentityInput{EmailIdentity: aws.String("example.com")})
	requireNoErr(t, err, "create identity")
	good := "X-SES-FROM-ARN: " + sesARN("identity/example.com") + "\r\n"
	bad := "X-SES-FROM-ARN: " + sesARN("identity/other.example") + "\r\n"

	send(t, c, rawInput("From: a@example.com\r\n"+good))
	requireAs[*types.BadRequestException](t, errOf(c.SendEmail(t.Context(),
		rawInput("From: a@example.com\r\n"+bad))))
	requireAs[*types.BadRequestException](t, errOf(c.SendEmail(t.Context(),
		rawInput("From: a@example.com\r\nX-SES-SOURCE-ARN: "+
			sesARN("identity/other.example")+"\r\n"))))
	overridden := rawInput("From: a@example.com\r\n" + bad)
	overridden.FromEmailAddressIdentityArn = aws.String(sesARN("identity/example.com"))
	send(t, c, overridden)
	// An ARN of another account names no identity mailbox holds.
	requireAs[*types.NotFoundException](t, errOf(c.SendEmail(t.Context(),
		rawInput("From: a@example.com\r\nX-SES-FROM-ARN: arn:aws:ses:"+region+
			":111111111111:identity/example.com\r\n"))))
}

func TestADelegatesARNsChooseTheIdentitiesEvaluated(t *testing.T) {
	s := startCrossStack(t)
	s.createIdentity(t, "example.com")
	s.putPolicy(t, "example.com", "member", policyDoc(
		grantSend("Allow", "example.com", s.member)))
	key := createUserKey(t, s.memberIAM, "delegate")
	putUserPolicy(t, s.memberIAM, "delegate", allowPolicy("ses:SendEmail"))
	c := sesClientWith(s.srv, key)
	delegateARN := "arn:aws:iam::" + s.member + ":user/delegate"
	from := func(address, identity string) *sesv2.SendEmailInput {
		in := simpleInput(address, "Delegated", "Body.", "to@example.com")
		in.FromEmailAddressIdentityArn = aws.String(sesARN("identity/" + identity))
		return in
	}

	t.Run("an ARN chooses the identity whose policies apply", func(t *testing.T) {
		// The address has an identity of its own, which grants nothing;
		// the ARN chooses its domain's, which grants the member account.
		s.createIdentity(t, "ops@example.com")
		requireAccessDenied(t, errOf(c.SendEmail(t.Context(), simpleInput("ops@example.com",
			"Denied", "Body.", "to@example.com"))), "User: "+delegateARN+" is not authorized "+
			"to perform: ses:SendEmail on resource: "+sesARN("identity/ops@example.com")+
			" because no resource-based policy allows the ses:SendEmail action")
		send(t, c, from("ops@example.com", "example.com"))
	})
	t.Run("a Deny of the identity an ARN passes over", func(t *testing.T) {
		// mailbox fails closed: the address identity's Deny applies though
		// the ARN chooses the domain's grant.
		s.putPolicy(t, "ops@example.com", "deny", policyDoc(
			grantSend("Deny", "ops@example.com", delegateARN)))
		requireAccessDenied(t, errOf(c.SendEmail(t.Context(), from("ops@example.com",
			"example.com"))), "User: "+delegateARN+" is not authorized to perform: "+
			"ses:SendEmail on resource: "+sesARN("identity/ops@example.com")+" with an "+
			"explicit deny in a resource-based policy")
	})
	t.Run("the feedback address's identity", func(t *testing.T) {
		s.createIdentity(t, "bounces.example")
		in := from("a@example.com", "example.com")
		in.FeedbackForwardingEmailAddress = aws.String("fb@bounces.example")
		requireAccessDenied(t, errOf(c.SendEmail(t.Context(), in)), "User: "+delegateARN+
			" is not authorized to perform: ses:SendEmail on resource: "+
			sesARN("identity/bounces.example")+" because no resource-based policy allows "+
			"the ses:SendEmail action")
		s.putPolicy(t, "bounces.example", "member", policyDoc(
			grantSend("Allow", "bounces.example", s.member)))
		in.FeedbackForwardingEmailAddressIdentityArn = aws.String(
			sesARN("identity/bounces.example"))
		send(t, c, in)
		in.FeedbackForwardingEmailAddressIdentityArn = aws.String(sesARN("identity/example.com"))
		requireAs[*types.BadRequestException](t, errOf(c.SendEmail(t.Context(), in)))
	})
}
