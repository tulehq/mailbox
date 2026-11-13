package sesapi

import (
	"strconv"
	"time"
)

// The response bodies of the in-scope operations, as the SES v2 API model
// names their members.

// SendEmailResponse is the body SendEmail answers with.
type SendEmailResponse struct {
	MessageID string `json:"MessageId"`
}

// SendBulkEmailResponse is the body SendBulkEmail answers with.
type SendBulkEmailResponse struct {
	BulkEmailEntryResults []BulkEmailEntryResult `json:"BulkEmailEntryResults"`
}

// BulkEmailEntryResult is the outcome of one bulk entry.
type BulkEmailEntryResult struct {
	Status    string `json:"Status"`
	Error     string `json:"Error,omitempty"`
	MessageID string `json:"MessageId,omitempty"`
}

// The BulkEmailStatus values this service reports.
const (
	BulkStatusSuccess          = "SUCCESS"
	BulkStatusInvalidParameter = "INVALID_PARAMETER"
	BulkStatusMessageRejected  = "MESSAGE_REJECTED"
)

// CreateEmailIdentityResponse is the body CreateEmailIdentity answers with.
type CreateEmailIdentityResponse struct {
	DkimAttributes           *DkimAttributes `json:"DkimAttributes"`
	IdentityType             string          `json:"IdentityType"`
	VerifiedForSendingStatus bool            `json:"VerifiedForSendingStatus"`
}

// DkimAttributes describes an identity's DKIM setup.
type DkimAttributes struct {
	LastKeyGenerationTimestamp *EpochSeconds `json:"LastKeyGenerationTimestamp,omitempty"`
	Status                     string        `json:"Status"`
	SigningAttributesOrigin    string        `json:"SigningAttributesOrigin"`
	NextSigningKeyLength       string        `json:"NextSigningKeyLength,omitempty"`
	CurrentSigningKeyLength    string        `json:"CurrentSigningKeyLength,omitempty"`
	Tokens                     []string      `json:"Tokens,omitempty"`
	SigningEnabled             bool          `json:"SigningEnabled"`
}

// GetEmailIdentityResponse is the body GetEmailIdentity answers with.
type GetEmailIdentityResponse struct {
	DkimAttributes           *DkimAttributes   `json:"DkimAttributes"`
	Policies                 map[string]string `json:"Policies"`
	IdentityType             string            `json:"IdentityType"`
	ConfigurationSetName     string            `json:"ConfigurationSetName,omitempty"`
	VerificationStatus       string            `json:"VerificationStatus"`
	Tags                     []ResponseTag     `json:"Tags"`
	FeedbackForwardingStatus bool              `json:"FeedbackForwardingStatus"`
	VerifiedForSendingStatus bool              `json:"VerifiedForSendingStatus"`
}

// ResponseTag is a resource tag in a response, where both members are
// always present.
type ResponseTag struct {
	Key   string `json:"Key"`
	Value string `json:"Value"`
}

// ListEmailIdentitiesResponse is the body ListEmailIdentities answers with.
type ListEmailIdentitiesResponse struct {
	NextToken       string         `json:"NextToken,omitempty"`
	EmailIdentities []IdentityInfo `json:"EmailIdentities"`
}

// IdentityInfo is one identity of a listing.
type IdentityInfo struct {
	IdentityType       string `json:"IdentityType"`
	IdentityName       string `json:"IdentityName"`
	VerificationStatus string `json:"VerificationStatus"`
	SendingEnabled     bool   `json:"SendingEnabled"`
}

// GetEmailTemplateResponse is the body GetEmailTemplate answers with.
type GetEmailTemplateResponse struct {
	TemplateName    string               `json:"TemplateName"`
	TemplateContent EmailTemplateContent `json:"TemplateContent"`
	Tags            []ResponseTag        `json:"Tags"`
}

// ListEmailTemplatesResponse is the body ListEmailTemplates answers with.
type ListEmailTemplatesResponse struct {
	NextToken         string                  `json:"NextToken,omitempty"`
	TemplatesMetadata []EmailTemplateMetadata `json:"TemplatesMetadata"`
}

// EmailTemplateMetadata is one template of a listing.
type EmailTemplateMetadata struct {
	CreatedTimestamp EpochSeconds `json:"CreatedTimestamp"`
	TemplateName     string       `json:"TemplateName"`
}

// TestRenderEmailTemplateResponse is the body TestRenderEmailTemplate answers
// with.
type TestRenderEmailTemplateResponse struct {
	RenderedTemplate string `json:"RenderedTemplate"`
}

// GetAccountResponse is the body GetAccount answers with.
type GetAccountResponse struct {
	EnforcementStatus            string    `json:"EnforcementStatus"`
	SendQuota                    SendQuota `json:"SendQuota"`
	DedicatedIPAutoWarmupEnabled bool      `json:"DedicatedIpAutoWarmupEnabled"`
	ProductionAccessEnabled      bool      `json:"ProductionAccessEnabled"`
	SendingEnabled               bool      `json:"SendingEnabled"`
}

// SendQuota is the account's sending quota.
type SendQuota struct {
	Max24HourSend   float64 `json:"Max24HourSend"`
	MaxSendRate     float64 `json:"MaxSendRate"`
	SentLast24Hours float64 `json:"SentLast24Hours"`
}

// EmptyResponse is the body of the operations that answer with no members.
type EmptyResponse struct{}

// EpochSeconds is a timestamp as restJson1 sends one by default: seconds
// since the Unix epoch, as a JSON number with a fraction for the
// milliseconds.
type EpochSeconds time.Time

// MarshalJSON writes the timestamp as fractional epoch seconds.
func (t EpochSeconds) MarshalJSON() ([]byte, error) {
	ms := time.Time(t).UnixMilli()
	return []byte(strconv.FormatFloat(float64(ms)/1000, 'f', -1, 64)), nil
}
