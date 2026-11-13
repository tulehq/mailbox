package authz

import "net/http"

// ResourceType is a kind of resource an operation is evaluated on.
type ResourceType int

// The resource types. The SES ones are the Service Authorization Reference's
// (the service reference JSON for ses, its Resources), with its ARN formats:
// arn:${Partition}:ses:${Region}:${Account}:identity/${IdentityName},
// configuration-set/${ConfigurationSetName} and template/${TemplateName}.
const (
	// Identity is the identity the request names: Target.Identity.
	Identity ResourceType = iota + 1
	// SenderIdentity is the identity a send's From address sends through:
	// the one Target.SenderIdentityName names, or else the first of
	// SenderIdentityCandidates for Target.Sender that exists.
	SenderIdentity
	// HeaderSenderIdentity is the identity of a raw message's From header
	// when the request also gives FromEmailAddress, found from
	// Target.HeaderSender as for SenderIdentity.
	HeaderSenderIdentity
	// ConfigurationSet is the configuration set a send uses,
	// Target.ConfigurationSet, of the caller's account: a principal of the
	// service's account uses the service's, one of another account its own.
	ConfigurationSet
	// Template is the template the request names, Target.Template.
	Template
	// FeedbackIdentity is the identity of a send's feedback forwarding
	// address, Target.Feedback, found as SenderIdentity is, with
	// Target.FeedbackIdentityName. A sending authorization policy permits
	// the use of the address (SES API v2 Reference, SendEmail,
	// FeedbackForwardingEmailAddressIdentityArn).
	FeedbackIdentity
	// Service is the whole service in the caller's account and region,
	// arn:aws:ses:<region>:<account>:*, which the retrieval API's
	// tule:Inspect is evaluated on.
	Service
)

// Resource is one resource an operation is evaluated on. An Optional one is
// evaluated only when the request uses it, as a send's configuration set and
// stored template are.
type Resource struct {
	Type     ResourceType
	Optional bool
}

// The keys a Target supplies, besides the global ones every request has.
// An operation supplies the ones its entry lists, the ones the reference
// lists for its action (ActionConditionKeys).
const (
	KeyAPIVersion      = "ses:ApiVersion"
	KeyFromAddress     = "ses:FromAddress"
	KeyFromDisplayName = "ses:FromDisplayName"
	KeyRecipients      = "ses:Recipients"
	KeyFeedbackAddress = "ses:FeedbackAddress"
	// KeyRequestTags stands for aws:RequestTag/${TagKey} and aws:TagKeys,
	// from Target.Tags.
	KeyRequestTags = "aws:RequestTag/${TagKey}"
)

// InspectAction is the action the retrieval API is evaluated as. It is not
// an AWS action: AWS has no API that reads back the mail SES accepted.
const InspectAction = "tule:Inspect"

// tagAction is the action a create with Tags is also evaluated as, on the
// resource it creates: the service reference's Operations lists
// CreateEmailIdentity and CreateEmailTemplate as authorizing ses:TagResource
// as well as their own action.
const tagAction = "ses:TagResource"

// Operation is how one routed operation is authorized: the IAM action it is
// evaluated as, the resources it is evaluated on, every one of them, and the
// condition keys it supplies. An operation with no Resources is evaluated
// on "*", as an action the reference lists no resource type for is.
type Operation struct {
	// Name is the SES v2 operation, or for the retrieval API a name of its
	// own.
	Name      string
	Method    string
	Path      string
	Action    string
	Resources []Resource
	Keys      []string
	// TagsOnCreate marks a create whose Tags are also evaluated as
	// ses:TagResource on the new resource.
	TagsOnCreate bool
}

// actions are the actions a request to the operation with t is evaluated
// as: its own, and ses:TagResource for a create with tags.
func (op *Operation) actions(t Target) []string {
	if op.TagsOnCreate && len(t.Tags) > 0 {
		return []string{op.Action, tagAction}
	}
	return []string{op.Action}
}

// upfront reports whether the operation can be evaluated before its handler
// runs: it needs nothing from the request but the caller.
func (op *Operation) upfront() bool {
	for _, r := range op.Resources {
		if r.Type != Service {
			return false
		}
	}
	return true
}

var (
	sendResources = []Resource{
		{Type: SenderIdentity},
		{Type: FeedbackIdentity, Optional: true},
		{Type: ConfigurationSet, Optional: true},
		{Type: Template, Optional: true},
	}
	// SendEmail's Raw content can name a second sender, its From header.
	sendEmailResources = []Resource{
		{Type: SenderIdentity},
		{Type: HeaderSenderIdentity, Optional: true},
		{Type: FeedbackIdentity, Optional: true},
		{Type: ConfigurationSet, Optional: true},
		{Type: Template, Optional: true},
	}
	identityResource = []Resource{{Type: Identity}}
	templateResource = []Resource{{Type: Template}}
	serviceResource  = []Resource{{Type: Service}}
)

// operations is every routed operation's authorization, by route. The SES
// actions, their resource types and their condition keys are the Service
// Authorization Reference's for SES (the service reference JSON for ses,
// v1.5, a copy of which is in testdata); a test holds every route to an
// entry here and every entry to the reference.
//
// SendEmail is evaluated on the identity it sends from, on its feedback
// forwarding address's identity when it has one, and on the configuration
// set and the stored template it uses when it uses them, as the reference
// lists all three types for it. Raw content with a From header and
// a FromEmailAddress has two senders, and is evaluated on both identities:
// SES authorizes the "From" address in the header of a raw message apart
// from the envelope's Source (SendRawEmail API reference, FromArn). SendBulkEmail is too: its
// resources are the request's, shared by every entry, so a denial refuses
// the whole request, and the reference lists none of the send keys for it.
var operations = []Operation{
	{
		Name: "SendEmail", Method: http.MethodPost, Path: "/v2/email/outbound-emails",
		Action: "ses:SendEmail", Resources: sendEmailResources,
		Keys: []string{
			KeyAPIVersion, KeyFromAddress, KeyFromDisplayName, KeyRecipients,
			KeyFeedbackAddress,
		},
	},
	{
		Name: "SendBulkEmail", Method: http.MethodPost, Path: "/v2/email/outbound-bulk-emails",
		Action: "ses:SendBulkEmail", Resources: sendResources, Keys: []string{KeyAPIVersion},
	},
	{
		Name: "CreateEmailIdentity", Method: http.MethodPost, Path: "/v2/email/identities",
		Action: "ses:CreateEmailIdentity", Resources: identityResource,
		Keys: []string{KeyAPIVersion, KeyRequestTags}, TagsOnCreate: true,
	},
	{
		Name: "ListEmailIdentities", Method: http.MethodPost, Path: "/v2/email/list-identities",
		Action: "ses:ListEmailIdentities", Keys: []string{KeyAPIVersion},
	},
	{
		// The botocore binding of ListEmailIdentities.
		Name: "ListEmailIdentities", Method: http.MethodGet, Path: "/v2/email/identities",
		Action: "ses:ListEmailIdentities", Keys: []string{KeyAPIVersion},
	},
	{
		Name: "GetEmailIdentity", Method: http.MethodGet,
		Path:   "/v2/email/identities/{EmailIdentity}",
		Action: "ses:GetEmailIdentity", Resources: identityResource, Keys: []string{KeyAPIVersion},
	},
	{
		Name: "DeleteEmailIdentity", Method: http.MethodDelete,
		Path:   "/v2/email/identities/{EmailIdentity}",
		Action: "ses:DeleteEmailIdentity", Resources: identityResource,
		Keys: []string{KeyAPIVersion},
	},
	{
		Name: "CreateEmailIdentityPolicy", Method: http.MethodPost,
		Path:   "/v2/email/identities/{EmailIdentity}/policies/{PolicyName}",
		Action: "ses:CreateEmailIdentityPolicy", Resources: identityResource,
		Keys: []string{KeyAPIVersion},
	},
	{
		Name: "GetEmailIdentityPolicies", Method: http.MethodGet,
		Path:   "/v2/email/identities/{EmailIdentity}/policies",
		Action: "ses:GetEmailIdentityPolicies", Resources: identityResource,
		Keys: []string{KeyAPIVersion},
	},
	{
		Name: "UpdateEmailIdentityPolicy", Method: http.MethodPut,
		Path:   "/v2/email/identities/{EmailIdentity}/policies/{PolicyName}",
		Action: "ses:UpdateEmailIdentityPolicy", Resources: identityResource,
		Keys: []string{KeyAPIVersion},
	},
	{
		Name: "DeleteEmailIdentityPolicy", Method: http.MethodDelete,
		Path:   "/v2/email/identities/{EmailIdentity}/policies/{PolicyName}",
		Action: "ses:DeleteEmailIdentityPolicy", Resources: identityResource,
		Keys: []string{KeyAPIVersion},
	},
	{
		Name: "CreateEmailTemplate", Method: http.MethodPost, Path: "/v2/email/templates",
		Action: "ses:CreateEmailTemplate", Resources: templateResource,
		Keys: []string{KeyAPIVersion, KeyRequestTags}, TagsOnCreate: true,
	},
	{
		Name: "ListEmailTemplates", Method: http.MethodGet, Path: "/v2/email/templates",
		Action: "ses:ListEmailTemplates", Keys: []string{KeyAPIVersion},
	},
	{
		Name: "GetEmailTemplate", Method: http.MethodGet,
		Path:   "/v2/email/templates/{TemplateName}",
		Action: "ses:GetEmailTemplate", Resources: templateResource, Keys: []string{KeyAPIVersion},
	},
	{
		Name: "UpdateEmailTemplate", Method: http.MethodPut,
		Path:   "/v2/email/templates/{TemplateName}",
		Action: "ses:UpdateEmailTemplate", Resources: templateResource,
		Keys: []string{KeyAPIVersion},
	},
	{
		Name: "DeleteEmailTemplate", Method: http.MethodDelete,
		Path:   "/v2/email/templates/{TemplateName}",
		Action: "ses:DeleteEmailTemplate", Resources: templateResource,
		Keys: []string{KeyAPIVersion},
	},
	{
		Name: "TestRenderEmailTemplate", Method: http.MethodPost,
		Path:   "/v2/email/templates/{TemplateName}/render",
		Action: "ses:TestRenderEmailTemplate", Resources: templateResource,
		Keys: []string{KeyAPIVersion},
	},
	{
		Name: "GetAccount", Method: http.MethodGet, Path: "/v2/email/account",
		Action: "ses:GetAccount", Keys: []string{KeyAPIVersion},
	},

	// The retrieval API.
	inspect("ListMessages", http.MethodGet, "/_mailbox/messages"),
	inspect("DeleteMessages", http.MethodDelete, "/_mailbox/messages"),
	inspect("GetMessage", http.MethodGet, "/_mailbox/messages/{id}"),
	inspect("DeleteMessage", http.MethodDelete, "/_mailbox/messages/{id}"),
	inspect("GetMessageRaw", http.MethodGet, "/_mailbox/messages/{id}/raw"),
	inspect("GetAttachment", http.MethodGet, "/_mailbox/messages/{id}/attachments/{index}"),
	inspect("ListRenderingFailures", http.MethodGet, "/_mailbox/rendering-failures"),
}

func inspect(name, method, path string) Operation {
	return Operation{
		Name: name, Method: method, Path: path,
		Action: InspectAction, Resources: serviceResource,
	}
}

// Lookup returns the operation routed at the method and path pattern.
func Lookup(method, path string) (Operation, bool) {
	for _, op := range operations {
		if op.Method == method && op.Path == path {
			return op, true
		}
	}
	return Operation{}, false
}

// Operations returns a copy of every entry, for the tests that hold the
// routes and the reference to them.
func Operations() []Operation {
	return append([]Operation(nil), operations...)
}
