package sesapi

// The request bodies of the in-scope operations, as the SES v2 API model
// names their members. Members this service does not act on (EndpointId,
// TenantName, ListManagementOptions, ConfigurationOverrides and the sending
// authorization ARNs) are left out: they are decoded and ignored, as any
// unknown member is. Blobs are base64 in JSON, which encoding/json decodes
// into []byte.

// SendEmailRequest is the body of SendEmail.
type SendEmailRequest struct {
	FromEmailAddress               *string       `json:"FromEmailAddress"`
	Destination                    *Destination  `json:"Destination"`
	FeedbackForwardingEmailAddress *string       `json:"FeedbackForwardingEmailAddress"`
	Content                        *EmailContent `json:"Content"`
	ConfigurationSetName           *string       `json:"ConfigurationSetName"`
	ReplyToAddresses               []string      `json:"ReplyToAddresses"`
	EmailTags                      []MessageTag  `json:"EmailTags"`
}

// SendBulkEmailRequest is the body of SendBulkEmail.
type SendBulkEmailRequest struct {
	FromEmailAddress               *string           `json:"FromEmailAddress"`
	FeedbackForwardingEmailAddress *string           `json:"FeedbackForwardingEmailAddress"`
	DefaultContent                 *BulkEmailContent `json:"DefaultContent"`
	ConfigurationSetName           *string           `json:"ConfigurationSetName"`
	ReplyToAddresses               []string          `json:"ReplyToAddresses"`
	DefaultEmailTags               []MessageTag      `json:"DefaultEmailTags"`
	BulkEmailEntries               []BulkEmailEntry  `json:"BulkEmailEntries"`
}

// Destination holds a message's recipients.
type Destination struct {
	ToAddresses  []string `json:"ToAddresses"`
	CcAddresses  []string `json:"CcAddresses"`
	BccAddresses []string `json:"BccAddresses"`
}

// EmailContent is one of the three kinds of content SendEmail takes.
type EmailContent struct {
	Simple   *Message    `json:"Simple"`
	Raw      *RawMessage `json:"Raw"`
	Template *Template   `json:"Template"`
}

// Message is Simple content.
type Message struct {
	Subject     *Content        `json:"Subject"`
	Body        *Body           `json:"Body"`
	Headers     []MessageHeader `json:"Headers"`
	Attachments []Attachment    `json:"Attachments"`
}

// Content is a text and its character set.
type Content struct {
	Data    *string `json:"Data"`
	Charset *string `json:"Charset"`
}

// Body holds the text and HTML bodies of Simple content.
type Body struct {
	Text *Content `json:"Text"`
	Html *Content `json:"Html"` //nolint:revive // the model's member name
}

// MessageHeader is a header Simple or Template content adds to the message.
type MessageHeader struct {
	Name  *string `json:"Name"`
	Value *string `json:"Value"`
}

// Attachment is a file Simple or Template content attaches.
type Attachment struct {
	ContentDisposition      *string `json:"ContentDisposition"`
	FileName                *string `json:"FileName"`
	ContentDescription      *string `json:"ContentDescription"`
	ContentID               *string `json:"ContentId"`
	ContentTransferEncoding *string `json:"ContentTransferEncoding"`
	ContentType             *string `json:"ContentType"`
	RawContent              []byte  `json:"RawContent"`
}

// RawMessage is Raw content: the MIME message as sent.
type RawMessage struct {
	Data []byte `json:"Data"`
}

// Template is Template content: a stored template, by name or ARN, or one
// given inline, with the data to render it with.
type Template struct {
	TemplateName    *string               `json:"TemplateName"`
	TemplateArn     *string               `json:"TemplateArn"`
	TemplateContent *EmailTemplateContent `json:"TemplateContent"`
	TemplateData    *string               `json:"TemplateData"`
	Headers         []MessageHeader       `json:"Headers"`
	Attachments     []Attachment          `json:"Attachments"`
}

// EmailTemplateContent is a template's subject, text and HTML.
type EmailTemplateContent struct {
	Subject *string `json:"Subject,omitempty"`
	Text    *string `json:"Text,omitempty"`
	Html    *string `json:"Html,omitempty"` //nolint:revive // the model's member name
}

// MessageTag is one of a message's tags.
type MessageTag struct {
	Name  *string `json:"Name"`
	Value *string `json:"Value"`
}

// BulkEmailContent is the default content of SendBulkEmail.
type BulkEmailContent struct {
	Template *Template `json:"Template"`
}

// BulkEmailEntry is one message of SendBulkEmail.
type BulkEmailEntry struct {
	Destination             *Destination             `json:"Destination"`
	ReplacementTags         []MessageTag             `json:"ReplacementTags"`
	ReplacementEmailContent *ReplacementEmailContent `json:"ReplacementEmailContent"`
	ReplacementHeaders      []MessageHeader          `json:"ReplacementHeaders"`
}

// ReplacementEmailContent replaces the template data of one bulk entry.
type ReplacementEmailContent struct {
	ReplacementTemplate *ReplacementTemplate `json:"ReplacementTemplate"`
}

// ReplacementTemplate holds one bulk entry's template data.
type ReplacementTemplate struct {
	ReplacementTemplateData *string `json:"ReplacementTemplateData"`
}

// CreateEmailIdentityRequest is the body of CreateEmailIdentity.
type CreateEmailIdentityRequest struct {
	DkimSigningAttributes *DkimSigningAttributes `json:"DkimSigningAttributes"`
	ConfigurationSetName  *string                `json:"ConfigurationSetName"`
	EmailIdentity         string                 `json:"EmailIdentity"`
	Tags                  []Tag                  `json:"Tags"`
}

// ListEmailIdentitiesRequest is the body of ListEmailIdentities.
type ListEmailIdentitiesRequest struct {
	Filter    map[string]string `json:"Filter"`
	NextToken *string           `json:"NextToken"`
	PageSize  *int              `json:"PageSize"`
}

// DkimSigningAttributes asks for Bring Your Own DKIM, or picks the Easy DKIM
// key length.
type DkimSigningAttributes struct {
	DomainSigningSelector         *string `json:"DomainSigningSelector"`
	DomainSigningPrivateKey       *string `json:"DomainSigningPrivateKey"`
	NextSigningKeyLength          *string `json:"NextSigningKeyLength"`
	DomainSigningAttributesOrigin *string `json:"DomainSigningAttributesOrigin"`
}

// Tag is a resource tag.
type Tag struct {
	Key   *string `json:"Key"`
	Value *string `json:"Value"`
}

// CreateEmailTemplateRequest is the body of CreateEmailTemplate.
type CreateEmailTemplateRequest struct {
	TemplateName    string                `json:"TemplateName"`
	TemplateContent *EmailTemplateContent `json:"TemplateContent"`
	Tags            []Tag                 `json:"Tags"`
}

// UpdateEmailTemplateRequest is the body of UpdateEmailTemplate; the name is
// in the path.
type UpdateEmailTemplateRequest struct {
	TemplateContent *EmailTemplateContent `json:"TemplateContent"`
}

// TestRenderEmailTemplateRequest is the body of TestRenderEmailTemplate; the
// name is in the path.
type TestRenderEmailTemplateRequest struct {
	TemplateData *string `json:"TemplateData"`
}
