// Package contracts defines the mailbox store interface the HTTP modules
// depend on, with its input and output types and sentinel errors.
package contracts

import (
	"context"
	"errors"
	"time"
)

var (
	// ErrIdentityNotFound is returned when no identity has the given name.
	ErrIdentityNotFound = errors.New("mailbox: identity not found")

	// ErrIdentityExists is returned by CreateIdentity for a name taken
	// already.
	ErrIdentityExists = errors.New("mailbox: identity already exists")

	// ErrIdentityLimit is returned by CreateIdentity when MaxIdentities
	// identities exist already.
	ErrIdentityLimit = errors.New("mailbox: identity limit reached")

	// ErrIdentityPolicyExists is returned by CreateIdentityPolicy for a
	// policy name the identity has already.
	ErrIdentityPolicyExists = errors.New("mailbox: identity policy already exists")

	// ErrIdentityPolicyLimit is returned by CreateIdentityPolicy when the
	// identity has MaxIdentityPolicies policies already.
	ErrIdentityPolicyLimit = errors.New("mailbox: identity policy limit reached")

	// ErrTemplateNotFound is returned when no template has the given name.
	ErrTemplateNotFound = errors.New("mailbox: template not found")

	// ErrTemplateExists is returned by CreateTemplate for a name taken
	// already.
	ErrTemplateExists = errors.New("mailbox: template already exists")

	// ErrTemplateLimit is returned by CreateTemplate when MaxTemplates
	// templates exist already.
	ErrTemplateLimit = errors.New("mailbox: template limit reached")

	// ErrMessageNotFound is returned when no stored message has the given
	// ID.
	ErrMessageNotFound = errors.New("mailbox: message not found")

	// ErrAttachmentNotFound is returned when a stored message has no
	// attachment at the given index.
	ErrAttachmentNotFound = errors.New("mailbox: attachment not found")

	// ErrInvalidToken is returned for a pagination token or cursor the store
	// did not issue for that listing.
	ErrInvalidToken = errors.New("mailbox: invalid pagination token")
)

// The quotas SES fixes that apply here, from the SES service quotas page.
const (
	// MaxIdentities is how many identities may exist in a Region.
	MaxIdentities = 10000
	// MaxTemplates is how many templates may exist in a Region.
	MaxTemplates = 20000
	// MaxIdentityPolicies is how many sending authorization policies an
	// identity may have: "Identity owners can associate up to 20 policies
	// with each unique identity" (SES Developer Guide, "Policy anatomy").
	MaxIdentityPolicies = 20
)

// The identity types.
const (
	IdentityTypeEmail  = "EMAIL_ADDRESS"
	IdentityTypeDomain = "DOMAIN"
)

// The APIs a message can come from, and the kinds of content it can have.
const (
	SourceSendEmail     = "SendEmail"
	SourceSendBulkEmail = "SendBulkEmail"

	KindSimple   = "Simple"
	KindRaw      = "Raw"
	KindTemplate = "Template"
)

// MailboxProvider is the store mailbox serves from: identities, templates
// and the messages it accepted.
type MailboxProvider interface {
	CreateIdentity(ctx context.Context, in Identity) error
	GetIdentity(ctx context.Context, name string) (*Identity, error)
	ListIdentities(ctx context.Context, f IdentityFilter, page PageInput) (*Page[Identity], error)
	// DeleteIdentity deletes the identity and its policies.
	DeleteIdentity(ctx context.Context, name string) error

	// CreateIdentityPolicy adds a sending authorization policy to the
	// identity: ErrIdentityNotFound, ErrIdentityPolicyExists or
	// ErrIdentityPolicyLimit when it cannot.
	CreateIdentityPolicy(ctx context.Context, identity string, p IdentityPolicy) error
	// UpdateIdentityPolicy replaces the document of the identity's policy
	// of p's name. The identity must exist; a policy it does not have is
	// left as it is, not added.
	UpdateIdentityPolicy(ctx context.Context, identity string, p IdentityPolicy) error
	// DeleteIdentityPolicy deletes the identity's policy of that name, if it
	// has one. The identity must exist.
	DeleteIdentityPolicy(ctx context.Context, identity, name string) error

	CreateTemplate(ctx context.Context, in Template) error
	GetTemplate(ctx context.Context, name string) (*Template, error)
	ListTemplates(ctx context.Context, page PageInput) (*Page[Template], error)
	UpdateTemplate(ctx context.Context, name string, content TemplateContent) error
	DeleteTemplate(ctx context.Context, name string) error

	// PutSend stores what one send produced, all or none: the messages it
	// accepted and the renderings that failed.
	PutSend(ctx context.Context, msgs []Message, failures []RenderingFailure) error
	// ListMessages pages through the stored messages that match the filter,
	// newest first. The items carry no headers, bodies or MIME.
	ListMessages(ctx context.Context, f MessageFilter, page PageInput) (*Page[Message], error)
	// GetMessage returns a stored message without its MIME.
	GetMessage(ctx context.Context, id string) (*Message, error)
	// GetMessageMIME returns the MIME of a stored message.
	GetMessageMIME(ctx context.Context, id string) ([]byte, error)
	DeleteMessage(ctx context.Context, id string) error
	// DeleteMessages deletes every stored message and rendering failure,
	// and nothing else.
	DeleteMessages(ctx context.Context) error
	// ListRenderingFailures pages through the recorded rendering failures
	// that match the filter, newest first.
	ListRenderingFailures(
		ctx context.Context,
		f FailureFilter,
		page PageInput,
	) (*Page[RenderingFailure], error)
	// RecipientsSince counts the recipients of the messages stored since t.
	RecipientsSince(ctx context.Context, t time.Time) (int, error)
}

// Tag is a resource tag.
type Tag struct {
	Key   string
	Value string
}

// Identity is an email address or a domain. It is verified from the moment
// it is created. DKIM holds what GetEmailIdentity reports of its signing.
// Policies are its sending authorization policies, in name order, read by
// GetIdentity in the same transaction as the rest of it; ListIdentities
// leaves them out.
type Identity struct {
	CreatedAt        time.Time
	Name             string
	Type             string
	ConfigurationSet string
	DKIM             DKIM
	Tags             []Tag
	Policies         []IdentityPolicy
}

// IdentityPolicy is one of an identity's sending authorization policies: a
// resource-based policy document, by name.
type IdentityPolicy struct {
	Name     string
	Document string
}

// DKIM is an identity's DKIM setup: Easy DKIM (origin AWS_SES) with a key
// length and tokens, or Bring Your Own DKIM (origin EXTERNAL) with a selector.
type DKIM struct {
	Origin    string
	KeyLength string
	Tokens    []string
}

// IdentityFilter selects identities: NameContains is a substring of the
// name, compared without regard to case, and Type the identity type. Empty
// fields match every identity.
type IdentityFilter struct {
	NameContains string
	Type         string
}

// TemplateContent is a template's parts. An empty part is absent.
type TemplateContent struct {
	Subject string
	Text    string
	HTML    string
}

// Template is a stored email template.
type Template struct {
	CreatedAt time.Time
	Name      string
	Content   TemplateContent
	Tags      []Tag
}

// MessageTag is one of a message's tags.
type MessageTag struct {
	Name  string
	Value string
}

// Header is one header of a message, its value decoded.
type Header struct {
	Name  string
	Value string
}

// AttachmentInfo describes one attachment of a stored message.
type AttachmentInfo struct {
	Name        string
	ContentType string
	Size        int
}

// Message is a message mailbox accepted. From and the recipients are as
// sent; FromAddress and the addresses of Recipients are the bare addresses
// the filters match. Size is the length of MIME, the message as a recipient
// receives it.
type Message struct {
	Time               time.Time
	ID                 string
	Source             string
	Kind               string
	From               string
	FromAddress        string
	FeedbackForwarding string
	Subject            string
	ConfigurationSet   string
	Text               string
	HTML               string
	To                 []string
	Cc                 []string
	Bcc                []string
	ReplyTo            []string
	Recipients         []string
	Tags               []MessageTag
	Headers            []Header
	Attachments        []AttachmentInfo
	MIME               []byte
	Size               int
}

// MessageFilter selects stored messages. Every set field must match: From
// is the From's address and To any recipient's, both without regard to
// case; Subject is a substring of the subject; Query is an FTS5 query over
// the subject and the text body; Since and Until bound the time, inclusive;
// and each of Tags must be on the message.
type MessageFilter struct {
	Since            *time.Time
	Until            *time.Time
	From             string
	To               string
	Subject          string
	Query            string
	ConfigurationSet string
	MessageID        string
	Tags             []MessageTag
}

// RenderingFailure is a templated message SES would have accepted and then
// dropped, because its template did not render. Template is the stored
// template's name, or empty for inline content; Error is the failure's text.
type RenderingFailure struct {
	Time             time.Time
	MessageID        string
	Source           string
	Template         string
	From             string
	ConfigurationSet string
	Error            string
	To               []string
	Cc               []string
	Bcc              []string
	Tags             []MessageTag
}

// FailureFilter selects rendering failures. Every set field must match;
// Since and Until bound the time, inclusive.
type FailureFilter struct {
	Since     *time.Time
	Until     *time.Time
	MessageID string
	Template  string
}

// PageInput selects one page of a listing. Size is the page size, always
// positive; Token is empty for the first page.
type PageInput struct {
	Token string
	Size  int
}

// Page is one page of a listing. NextToken is empty on the last page.
type Page[T any] struct {
	NextToken string
	Items     []T
}
