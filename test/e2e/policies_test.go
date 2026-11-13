//go:build e2e

package e2e

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	"github.com/aws/aws-sdk-go-v2/service/sesv2"
	"github.com/aws/aws-sdk-go-v2/service/sesv2/types"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	"github.com/aws/smithy-go"
)

// These tests run mailbox against a real identity service, as identity_test
// does, and check that identity-issued keys are held to their identity
// policies.

// account is identity's default management account, the account of every
// principal here.
const account = "000000000000"

// sesARN is the ARN of an SES resource of the account in region.
func sesARN(resource string) string {
	return "arn:aws:ses:" + region + ":" + account + ":" + resource
}

func TestAKeyWithNoPolicyIsDenied(t *testing.T) {
	s := startIdentityStack(t)
	key := createUserKey(t, s.iam, "nopolicy")

	err := errOf(sesClientWith(s.srv, key).SendEmail(t.Context(),
		simpleInput("app@example.com", "Denied", "Body.", "to@example.com")))
	requireAccessDenied(t, err, "User: arn:aws:iam::"+account+":user/nopolicy is not "+
		"authorized to perform: ses:SendEmail on resource: "+sesARN("identity/example.com")+
		" because no identity-based policy allows the ses:SendEmail action")

	res := mailboxWith(s.srv, key).do(t, http.MethodGet, "/_mailbox/messages", nil)
	requireAPIErrorBody(t, res, http.StatusForbidden, "AccessDeniedException", "inspect")
	requireMessage(t, res, "User: arn:aws:iam::"+account+":user/nopolicy is not authorized "+
		"to perform: tule:Inspect on resource: "+sesARN("*")+" because no identity-based "+
		"policy allows the tule:Inspect action")

	requireEqual(t, len(mailboxWith(s.srv, s.rootCreds).listAll(t, nil)), 0,
		"messages after the denied send")
}

func TestAPolicyAllowsExactlyItsAction(t *testing.T) {
	s := startIdentityStack(t)
	key := createUserKey(t, s.iam, "lister")
	putUserPolicy(t, s.iam, "lister", allowPolicy("ses:ListEmailTemplates"))
	c := sesClientWith(s.srv, key)

	_, err := c.ListEmailTemplates(t.Context(), &sesv2.ListEmailTemplatesInput{})
	requireNoErr(t, err, "the allowed action")

	err = errOf(c.GetAccount(t.Context(), &sesv2.GetAccountInput{}))
	requireAccessDenied(t, err, "User: arn:aws:iam::"+account+":user/lister is not "+
		"authorized to perform: ses:GetAccount on resource: * because no identity-based "+
		"policy allows the ses:GetAccount action")
	requireDenied(t, errOf(c.ListEmailIdentities(t.Context(), &sesv2.ListEmailIdentitiesInput{})))
	requireDenied(t, errOf(c.SendEmail(t.Context(),
		simpleInput("app@example.com", "Denied", "Body.", "to@example.com"))))
	requireDenied(t, errOf(c.CreateEmailTemplate(t.Context(), policyTemplateInput("t", nil))))
	requireAPIErrorBody(t, mailboxWith(s.srv, key).do(t, http.MethodGet,
		"/_mailbox/rendering-failures", nil), http.StatusForbidden, "AccessDeniedException",
		"inspect")
}

func TestAResourceScopedPolicyAllowsOnlyItsResource(t *testing.T) {
	s := startIdentityStack(t)
	root := sesClientWith(s.srv, s.rootCreds)
	for _, id := range []string{"allowed.example", "denied.example", "ops@allowed.example"} {
		_, err := root.CreateEmailIdentity(t.Context(),
			&sesv2.CreateEmailIdentityInput{EmailIdentity: aws.String(id)})
		requireNoErr(t, err, "create identity "+id)
	}
	key := createUserKey(t, s.iam, "scoped")
	putUserPolicy(t, s.iam, "scoped", policyDoc(statement{
		Effect: "Allow", Action: []string{"ses:SendEmail", "ses:GetEmailIdentity"},
		Resource: []string{sesARN("identity/allowed.example")},
	}))
	c := sesClientWith(s.srv, key)

	t.Run("its own identity", func(t *testing.T) {
		send(t, c, simpleInput("app@allowed.example", "Allowed", "Body.", "to@example.com"))
		// A subdomain sends through its verified parent domain.
		send(t, c, simpleInput("app@mail.allowed.example", "Allowed", "Body.", "to@example.com"))
		_, err := c.GetEmailIdentity(t.Context(),
			&sesv2.GetEmailIdentityInput{EmailIdentity: aws.String("allowed.example")})
		requireNoErr(t, err, "get the allowed identity")
		// Domains are compared without regard to case.
		send(t, c, simpleInput("app@ALLOWED.Example", "Allowed", "Body.", "to@example.com"))
		_, err = c.GetEmailIdentity(t.Context(),
			&sesv2.GetEmailIdentityInput{EmailIdentity: aws.String("Allowed.EXAMPLE")})
		requireNoErr(t, err, "get the allowed identity in another case")
	})
	t.Run("another identity", func(t *testing.T) {
		err := errOf(c.SendEmail(t.Context(),
			simpleInput("app@denied.example", "Denied", "Body.", "to@example.com")))
		requireAccessDenied(t, err, "User: arn:aws:iam::"+account+":user/scoped is not "+
			"authorized to perform: ses:SendEmail on resource: "+
			sesARN("identity/denied.example")+" because no identity-based policy allows the "+
			"ses:SendEmail action")
		requireDenied(t, errOf(c.GetEmailIdentity(t.Context(),
			&sesv2.GetEmailIdentityInput{EmailIdentity: aws.String("denied.example")})))
		requireDenied(t, errOf(c.SendEmail(t.Context(),
			simpleInput("app@Denied.EXAMPLE", "Denied", "Body.", "to@example.com"))))
	})
	t.Run("an address identity of its domain", func(t *testing.T) {
		// The address has an identity of its own, which the send goes
		// through rather than the domain's.
		err := errOf(c.SendEmail(t.Context(),
			simpleInput("ops@allowed.example", "Denied", "Body.", "to@example.com")))
		requireAccessDenied(t, err, "User: arn:aws:iam::"+account+":user/scoped is not "+
			"authorized to perform: ses:SendEmail on resource: "+
			sesARN("identity/ops@allowed.example")+" because no identity-based policy allows "+
			"the ses:SendEmail action")
	})
	t.Run("a raw From header of another identity", func(t *testing.T) { testRawHeader(t, c) })
	t.Run("a configuration set it is not allowed", func(t *testing.T) {
		in := simpleInput("app@allowed.example", "Denied", "Body.", "to@example.com")
		in.ConfigurationSetName = aws.String("tracking")
		requireAccessDenied(t, errOf(c.SendEmail(t.Context(), in)), "User: arn:aws:iam::"+
			account+":user/scoped is not authorized to perform: ses:SendEmail on resource: "+
			sesARN("configuration-set/tracking")+" because no identity-based policy allows "+
			"the ses:SendEmail action")
	})
}

func TestAnExplicitDenyBeatsAnAllow(t *testing.T) {
	s := startIdentityStack(t)
	key := createUserKey(t, s.iam, "denied")
	putUserPolicy(t, s.iam, "denied", policyDoc(
		statement{
			Effect:   "Allow",
			Action:   []string{"ses:*", "tule:Inspect"},
			Resource: []string{"*"},
		},
		statement{
			Effect: "Deny", Action: []string{"ses:SendEmail"},
			Resource: []string{sesARN("identity/blocked.example")},
		},
	))
	c := sesClientWith(s.srv, key)

	send(t, c, simpleInput("app@example.com", "Allowed", "Body.", "to@example.com"))
	err := errOf(c.SendEmail(t.Context(),
		simpleInput("app@blocked.example", "Denied", "Body.", "to@example.com")))
	requireAccessDenied(t, err, "User: arn:aws:iam::"+account+":user/denied is not "+
		"authorized to perform: ses:SendEmail on resource: "+sesARN("identity/blocked.example")+
		" with an explicit deny in an identity-based policy")
	requireEqual(t, len(mailboxWith(s.srv, key).listAll(t, nil)), 1, "messages stored")
}

func TestConditionsAreHonored(t *testing.T) {
	s := startIdentityStack(t)
	t.Run("aws:SourceIp", s.testSourceIP)
	t.Run("ses:FromAddress and ses:Recipients", s.testSendKeys)
	t.Run("aws:RequestTag on create", s.testRequestTags)
}

func (s *identityStack) testSourceIP(t *testing.T) {
	key := createUserKey(t, s.iam, "local")
	putUserPolicy(t, s.iam, "local", policyDoc(
		statement{
			Effect: "Allow", Action: []string{"ses:GetAccount"}, Resource: []string{"*"},
			Condition: map[string]map[string]any{
				"IpAddress": {"aws:SourceIp": "127.0.0.0/8"},
			},
		},
		statement{
			Effect:   "Allow",
			Action:   []string{"ses:ListEmailTemplates"},
			Resource: []string{"*"},
			Condition: map[string]map[string]any{
				"IpAddress": {"aws:SourceIp": "203.0.113.0/24"},
			},
		},
	))
	c := sesClientWith(s.srv, key)
	_, err := c.GetAccount(t.Context(), &sesv2.GetAccountInput{})
	requireNoErr(t, err, "from the allowed network")
	requireDenied(t, errOf(c.ListEmailTemplates(t.Context(), &sesv2.ListEmailTemplatesInput{})))
}

func (s *identityStack) testSendKeys(t *testing.T) {
	key := createUserKey(t, s.iam, "marketing")
	putUserPolicy(t, s.iam, "marketing", policyDoc(statement{
		Effect: "Allow", Action: []string{"ses:SendEmail"}, Resource: []string{"*"},
		Condition: map[string]map[string]any{
			"StringEquals":            {"ses:FromAddress": "marketing@example.com"},
			"ForAllValues:StringLike": {"ses:Recipients": []string{"*@example.com"}},
		},
	}))
	c := sesClientWith(s.srv, key)
	send(t, c, simpleInput("Marketing <marketing@example.com>", "Allowed", "Body.",
		"a@example.com", "b@example.com"))
	requireDenied(t, errOf(c.SendEmail(t.Context(),
		simpleInput("sales@example.com", "Denied", "Body.", "a@example.com"))))
	requireDenied(t, errOf(c.SendEmail(t.Context(),
		simpleInput("marketing@example.com", "Denied", "Body.", "a@example.com",
			"b@elsewhere.example"))))
}

func (s *identityStack) testRequestTags(t *testing.T) {
	key := createUserKey(t, s.iam, "tagger")
	putUserPolicy(t, s.iam, "tagger", policyDoc(
		statement{
			Effect: "Allow", Action: []string{"ses:CreateEmailTemplate"},
			Resource: []string{"*"},
		},
		statement{
			Effect: "Allow", Action: []string{"ses:TagResource"}, Resource: []string{"*"},
			Condition: map[string]map[string]any{
				"StringEquals": {"aws:RequestTag/team": "mail"},
			},
		},
	))
	c := sesClientWith(s.srv, key)
	_, err := c.CreateEmailTemplate(t.Context(), policyTemplateInput("untagged", nil))
	requireNoErr(t, err, "create without tags")
	_, err = c.CreateEmailTemplate(t.Context(), policyTemplateInput("tagged",
		[]types.Tag{{Key: aws.String("team"), Value: aws.String("mail")}}))
	requireNoErr(t, err, "create with the allowed tag")
	err = errOf(c.CreateEmailTemplate(t.Context(), policyTemplateInput("other",
		[]types.Tag{{Key: aws.String("team"), Value: aws.String("web")}})))
	requireAccessDenied(t, err, "User: arn:aws:iam::"+account+":user/tagger is not "+
		"authorized to perform: ses:TagResource on resource: "+sesARN("template/other")+
		" because no identity-based policy allows the ses:TagResource action")
	// A duplicate tag key is refused as invalid before anything is
	// evaluated, rather than becoming two values of one aws:RequestTag key.
	err = errOf(c.CreateEmailTemplate(t.Context(), policyTemplateInput("dup", []types.Tag{
		{Key: aws.String("team"), Value: aws.String("mail")},
		{Key: aws.String("team"), Value: aws.String("web")},
	})))
	requireAs[*types.BadRequestException](t, err)
}

func TestARoleSessionHasTheRolesPermissions(t *testing.T) {
	s := startIdentityStack(t)
	userKey := createUserKey(t, s.iam, "dev")
	trust := policyDoc(statement{
		Effect: "Allow", Action: []string{"sts:AssumeRole"},
		Principal: map[string]string{"AWS": "arn:aws:iam::" + account + ":user/dev"},
	})
	_, err := s.iam.CreateRole(t.Context(), &iam.CreateRoleInput{
		RoleName:                 aws.String("sender"),
		Path:                     aws.String("/mail/"),
		AssumeRolePolicyDocument: aws.String(trust),
	})
	requireNoErr(t, err, "create role")
	_, err = s.iam.PutRolePolicy(t.Context(), &iam.PutRolePolicyInput{
		RoleName:   aws.String("sender"),
		PolicyName: aws.String("send"),
		PolicyDocument: aws.String(policyDoc(
			statement{Effect: "Allow", Action: []string{"ses:SendEmail"}, Resource: []string{"*"}},
			// aws:PrincipalArn of a session is its role's ARN, with the
			// role's path.
			statement{
				Effect: "Allow", Action: []string{"tule:Inspect"}, Resource: []string{"*"},
				Condition: map[string]map[string]any{
					"ArnEquals": {
						"aws:PrincipalArn": "arn:aws:iam::" + account + ":role/mail/sender",
					},
				},
			},
		)),
	})
	requireNoErr(t, err, "put role policy")

	out, err := stsClient(s, userKey).AssumeRole(t.Context(), &sts.AssumeRoleInput{
		RoleArn:         aws.String("arn:aws:iam::" + account + ":role/mail/sender"),
		RoleSessionName: aws.String("s1"),
	})
	requireNoErr(t, err, "assume role")
	session := aws.Credentials{
		AccessKeyID:     aws.ToString(out.Credentials.AccessKeyId),
		SecretAccessKey: aws.ToString(out.Credentials.SecretAccessKey),
		SessionToken:    aws.ToString(out.Credentials.SessionToken),
	}

	id := send(t, sesClientWith(s.srv, session),
		simpleInput("app@example.com", "From a role", "Body.", "to@example.com"))
	mailboxWith(s.srv, session).byMessageID(t, id)
	err = errOf(sesClientWith(s.srv, session).GetAccount(t.Context(), &sesv2.GetAccountInput{}))
	requireAccessDenied(t, err, "User: arn:aws:sts::"+account+":assumed-role/sender/s1 is not "+
		"authorized to perform: ses:GetAccount on resource: * because no identity-based "+
		"policy allows the ses:GetAccount action")
	// The IAM user itself has no policy.
	requireDenied(t, errOf(sesClientWith(s.srv, userKey).SendEmail(t.Context(),
		simpleInput("app@example.com", "Denied", "Body.", "to@example.com"))))
}

func TestTheRootKeyIsAlwaysAllowed(t *testing.T) {
	// The root key is identity's root user's and mailbox's own static key at
	// once: mailbox asks identity with it, so the two are one key.
	s := startIdentityStack(t)
	c := sesClientWith(s.srv, s.rootCreds)
	_, err := c.CreateEmailTemplate(t.Context(), policyTemplateInput("t",
		[]types.Tag{{Key: aws.String("team"), Value: aws.String("mail")}}))
	requireNoErr(t, err, "create a tagged template")
	_, err = c.GetAccount(t.Context(), &sesv2.GetAccountInput{})
	requireNoErr(t, err, "get account")
	id := send(t, c, simpleInput("root@example.com", "Root", "Body.", "to@example.com"))
	mailboxWith(s.srv, s.rootCreds).byMessageID(t, id)
	requireSuccess(t, mailboxWith(s.srv, s.rootCreds).do(t, http.MethodDelete,
		"/_mailbox/messages", nil), "reset")
}

func TestStandaloneEvaluatesNothing(t *testing.T) {
	// Without an identity endpoint the static key is the account's root:
	// every operation is allowed, with no policy anywhere.
	c, mb := newClient(t)
	_, err := c.CreateEmailIdentity(t.Context(),
		&sesv2.CreateEmailIdentityInput{EmailIdentity: aws.String("example.com")})
	requireNoErr(t, err, "create identity")
	_, err = c.GetAccount(t.Context(), &sesv2.GetAccountInput{})
	requireNoErr(t, err, "get account")
	id := send(t, c, simpleInput("app@example.com", "Standalone", "Body.", "to@example.com"))
	mb.byMessageID(t, id)
}

// statement is one statement of a policy document.
type statement struct {
	Principal map[string]string         `json:",omitempty"`
	Condition map[string]map[string]any `json:",omitempty"`
	Effect    string
	Action    []string
	Resource  []string `json:",omitempty"`
}

// policyDoc returns a policy document of the statements.
func policyDoc(statements ...statement) string {
	b, err := json.Marshal(struct {
		Version   string
		Statement []statement
	}{"2012-10-17", statements})
	if err != nil {
		panic(err)
	}
	return string(b)
}

// allowPolicy returns a policy allowing the actions on every resource.
func allowPolicy(actions ...string) string {
	return policyDoc(statement{Effect: "Allow", Action: actions, Resource: []string{"*"}})
}

// putUserPolicy gives the IAM user an inline policy of the document.
func putUserPolicy(t *testing.T, ic *iam.Client, user, doc string) {
	t.Helper()
	_, err := ic.PutUserPolicy(t.Context(), &iam.PutUserPolicyInput{
		UserName:       aws.String(user),
		PolicyName:     aws.String("mailbox"),
		PolicyDocument: aws.String(doc),
	})
	requireNoErr(t, err, "put user policy for "+user)
}

func stsClient(s *identityStack, creds aws.Credentials) *sts.Client {
	return sts.New(sts.Options{
		Region:           region,
		BaseEndpoint:     s.iam.Options().BaseEndpoint,
		Credentials:      credentials.StaticCredentialsProvider{Value: creds},
		HTTPClient:       &http.Client{Timeout: clientTimeout},
		RetryMaxAttempts: 1,
	})
}

func policyTemplateInput(name string, tags []types.Tag) *sesv2.CreateEmailTemplateInput {
	return &sesv2.CreateEmailTemplateInput{
		TemplateName: aws.String(name),
		TemplateContent: &types.EmailTemplateContent{
			Subject: aws.String("Hi"), Text: aws.String("Hello."),
		},
		Tags: tags,
	}
}

// requireDenied fails unless err is SES's AccessDeniedException, 403.
func requireDenied(t *testing.T, err error) {
	t.Helper()
	var apiErr smithy.APIError
	if !errors.As(err, &apiErr) {
		t.Fatalf("want AccessDeniedException, got %v", err)
	}
	requireEqual(t, apiErr.ErrorCode(), "AccessDeniedException", "error code")
	requireStatus(t, err, http.StatusForbidden)
}

// requireAccessDenied is requireDenied with the exact message.
func requireAccessDenied(t *testing.T, err error, message string) {
	t.Helper()
	requireDenied(t, err)
	var apiErr smithy.APIError
	errors.As(err, &apiErr)
	requireEqual(t, apiErr.ErrorMessage(), message, "error message")
}

// requireMessage fails unless the retrieval API's error body has the
// message.
func requireMessage(t *testing.T, res response, message string) {
	t.Helper()
	var e apiError
	if err := json.Unmarshal(res.Body, &e); err != nil {
		t.Fatalf("decode error body: %v", err)
	}
	requireEqual(t, e.Message, message, "error message")
}

// testRawHeader sends raw content whose FromEmailAddress the scoped policy
// allows and whose From header it does not.
func testRawHeader(t *testing.T, c *sesv2.Client) {
	// FromEmailAddress is allowed; the header recipients see is not.
	data := []byte("From: app@denied.example\r\nTo: to@example.com\r\n" +
		"Subject: Raw\r\nMIME-Version: 1.0\r\n" +
		"Content-Type: text/plain; charset=us-ascii\r\n\r\nBody.\r\n")
	in := &sesv2.SendEmailInput{
		FromEmailAddress: aws.String("app@allowed.example"),
		Destination:      &types.Destination{ToAddresses: []string{"to@example.com"}},
		Content:          &types.EmailContent{Raw: &types.RawMessage{Data: data}},
	}
	requireAccessDenied(t, errOf(c.SendEmail(t.Context(), in)), "User: arn:aws:iam::"+
		account+":user/scoped is not authorized to perform: ses:SendEmail on resource: "+
		sesARN("identity/denied.example")+" because no identity-based policy allows "+
		"the ses:SendEmail action")
	in.Content.Raw.Data = []byte(strings.Replace(string(data), "denied", "allowed", 1))
	send(t, c, in)
}

// postJSON sends a signed POST of a raw JSON body, for bodies the SDK
// cannot produce.
func (m *mailbox) postJSON(t *testing.T, path, body string) response {
	t.Helper()
	req, err := http.NewRequestWithContext(t.Context(), http.MethodPost, m.srv.URL+path,
		strings.NewReader(body))
	requireNoErr(t, err, "build POST "+path)
	req.Header.Set("Content-Type", "application/json")
	sum := sha256.Sum256([]byte(body))
	err = m.signer.SignHTTP(t.Context(), m.creds, req, hex.EncodeToString(sum[:]),
		m.service, region, time.Now())
	requireNoErr(t, err, "sign POST "+path)
	return m.send(t, req)
}

func TestAuthorizationAndTheSendReadOneDecoding(t *testing.T) {
	// Each body is decoded once, and the values the send is authorized for
	// are the values it uses: the last of duplicate JSON members, whatever
	// the case of their names, and the first of a raw message's repeated
	// X-SES headers. A second From header is refused before either.
	s := startIdentityStack(t)
	key := createUserKey(t, s.iam, "decoder")
	putUserPolicy(t, s.iam, "decoder", policyDoc(
		statement{
			Effect: "Allow", Action: []string{"ses:SendEmail", "tule:Inspect"},
			Resource: []string{"*"},
		},
		statement{Effect: "Deny", Action: []string{"ses:SendEmail"}, Resource: []string{
			sesARN("identity/denied.example"), sesARN("configuration-set/denied"),
		}},
	))
	mb := mailboxWith(s.srv, key)
	simple := `"Destination":{"ToAddresses":["to@example.com"]},"Content":{"Simple":{` +
		`"Subject":{"Data":"s"},"Body":{"Text":{"Data":"b"}}}}`

	for name, body := range map[string]string{
		"duplicate members": `{"FromEmailAddress":"a@allowed.example",` +
			`"FromEmailAddress":"a@denied.example",` + simple + `}`,
		"members differing by case": `{"FromEmailAddress":"a@allowed.example",` +
			`"fromemailaddress":"a@denied.example",` + simple + `}`,
	} {
		t.Run(name, func(t *testing.T) {
			res := mb.postJSON(t, "/v2/email/outbound-emails", body)
			requireAPIErrorBody(t, res, http.StatusForbidden, "AccessDeniedException", name)
			requireMessage(t, res, "User: arn:aws:iam::"+account+":user/decoder is not "+
				"authorized to perform: ses:SendEmail on resource: "+
				sesARN("identity/denied.example")+" with an explicit deny in an "+
				"identity-based policy")
		})
	}
	t.Run("the last duplicate member is the sender", func(t *testing.T) {
		res := mb.postJSON(
			t,
			"/v2/email/outbound-emails",
			`{"FromEmailAddress":"a@denied.example",`+
				`"FromEmailAddress":"a@allowed.example",`+simple+`}`,
		)
		requireOK(t, res, "send")
		var out struct{ MessageId string }
		decode(t, res, &out)
		requireEqual(t, mb.byMessageID(t, out.MessageId).From, "a@allowed.example", "from")
	})

	c := sesClientWith(s.srv, key)
	t.Run("the first X-SES header is the one used", func(t *testing.T) {
		requireDenied(t, errOf(c.SendEmail(t.Context(), rawInput("From: a@allowed.example\r\n"+
			"X-SES-CONFIGURATION-SET: denied\r\nX-SES-CONFIGURATION-SET: allowed\r\n"))))
		id := send(t, c, rawInput("From: a@allowed.example\r\n"+
			"X-SES-CONFIGURATION-SET: allowed\r\nX-SES-CONFIGURATION-SET: denied\r\n"))
		requireEqual(t, mb.byMessageID(t, id).ConfigurationSet, "allowed", "configuration set")
	})
	t.Run("a bare CR cannot hide a header", func(t *testing.T) { testBareCR(t, c) })
	t.Run("a second From header is refused", func(t *testing.T) {
		err := errOf(c.SendEmail(t.Context(),
			rawInput("From: a@allowed.example\r\nFrom: a@denied.example\r\n")))
		requireAs[*types.MessageRejected](t, err)
	})
}

// rawInput is a SendEmail of raw content with the header lines, then a To,
// a Subject and a body.
func rawInput(headers string) *sesv2.SendEmailInput {
	return &sesv2.SendEmailInput{Content: &types.EmailContent{Raw: &types.RawMessage{
		Data: []byte(headers + "To: to@example.com\r\nSubject: s\r\n\r\nBody.\r\n"),
	}}}
}

// testBareCR sends raw headers whose bare CR would end a line for some
// readers of the message.
func testBareCR(t *testing.T, c *sesv2.Client) {
	// Python's email reads a bare CR as a line end: this header would
	// show ceo@denied.example as the sender, and an extra Cc.
	for _, headers := range []string{
		"X-A: x\rFrom: ceo@denied.example\r\nFrom: me@allowed.example\r\n",
		"From: me@allowed.example\r\nX-A: x\rCc: extra@denied.example\r\n",
	} {
		requireAs[*types.MessageRejected](t, errOf(c.SendEmail(t.Context(),
			rawInput(headers))))
	}
}
