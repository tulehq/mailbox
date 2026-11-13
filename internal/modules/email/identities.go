package email

import (
	"crypto/rand"
	"errors"
	"fmt"
	"net/http"
	"regexp"
	"strings"

	"github.com/gasmod/gas"

	"tule.dev/mailbox/internal/authz"
	"tule.dev/mailbox/internal/contracts"
	"tule.dev/mailbox/internal/sesapi"
)

// Every identity is verified from the moment it is created: no verification
// can happen here.
const (
	verificationSuccess = "SUCCESS"
	dkimNotStarted      = "NOT_STARTED"
	originAWSSES        = "AWS_SES"
	originExternal      = "EXTERNAL"
	keyLength2048       = "RSA_2048_BIT"
	dkimTokenCount      = 3
	dkimTokenLength     = 32
)

// domainPattern is a domain name: dot-separated labels of letters, digits
// and inner hyphens, at least two of them.
var domainPattern = regexp.MustCompile(
	`^(?i)[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+$`)

var selectorPattern = regexp.MustCompile(`^[a-zA-Z0-9](?:[a-zA-Z0-9-]*[a-zA-Z0-9])?$`)

// identityType checks an identity name, an email address or a domain, and
// returns its type.
func identityType(name string) (string, error) {
	if name == "" {
		return "", sesapi.ErrBadRequest("You must specify an EmailIdentity.")
	}
	if strings.Contains(name, "@") {
		a, err := sesapi.Address("EmailIdentity", name)
		if err != nil {
			return "", err
		}
		if a != name {
			return "", sesapi.ErrBadRequest(fmt.Sprintf(
				"Invalid email identity: %s is not a bare email address.", name))
		}
		return contracts.IdentityTypeEmail, nil
	}
	if len(name) > 253 || !domainPattern.MatchString(name) {
		return "", sesapi.ErrBadRequest(fmt.Sprintf("Invalid domain identity: %s", name))
	}
	return contracts.IdentityTypeDomain, nil
}

func (m *Module) createEmailIdentity(ctx gas.Context) error {
	req, err := sesapi.Decode[sesapi.CreateEmailIdentityRequest](ctx)
	if err != nil {
		return err
	}
	typ, err := identityType(req.EmailIdentity)
	if err != nil {
		return err
	}
	req.EmailIdentity = authz.CanonicalIdentity(req.EmailIdentity)
	if err = sesapi.Tags(req.Tags); err != nil {
		return err
	}
	dkim, err := dkimOf(typ, req.DkimSigningAttributes)
	if err != nil {
		return err
	}
	if err = m.authz.Authorize(ctx, authz.Target{
		Identity: req.EmailIdentity, Tags: storeTags(req.Tags),
	}); err != nil {
		return err
	}

	in := contracts.Identity{
		CreatedAt:        m.now(),
		Name:             req.EmailIdentity,
		Type:             typ,
		ConfigurationSet: deref(req.ConfigurationSetName),
		DKIM:             dkim,
		Tags:             storeTags(req.Tags),
	}
	if err = m.store.CreateIdentity(ctx, in); err != nil {
		if errors.Is(err, contracts.ErrIdentityExists) {
			return sesapi.NewError(http.StatusBadRequest, sesapi.TypeAlreadyExists,
				fmt.Sprintf("Email identity %s already exists.", in.Name))
		}
		return err
	}
	return sesapi.Write(ctx, sesapi.CreateEmailIdentityResponse{
		IdentityType:             typ,
		VerifiedForSendingStatus: true,
		DkimAttributes:           wireDKIM(&in),
	})
}

// dkimOf checks the DKIM signing attributes a request gives and returns the
// DKIM setup they make: Easy DKIM, with three tokens, unless the request
// brings its own key, whose selector is then the one token. Only a domain
// takes them.
func dkimOf(typ string, attrs *sesapi.DkimSigningAttributes) (contracts.DKIM, error) {
	if typ == contracts.IdentityTypeEmail {
		if attrs != nil {
			return contracts.DKIM{}, sesapi.ErrBadRequest(
				"DkimSigningAttributes can only be specified for a domain identity.")
		}
		return contracts.DKIM{Origin: originAWSSES}, nil
	}
	if attrs != nil && attrs.DomainSigningSelector != nil {
		return byoDKIM(attrs)
	}
	return easyDKIM(attrs)
}

// byoDKIM is Bring Your Own DKIM: the request's selector and private key.
func byoDKIM(attrs *sesapi.DkimSigningAttributes) (contracts.DKIM, error) {
	sel := *attrs.DomainSigningSelector
	if len(sel) > 63 || !selectorPattern.MatchString(sel) {
		return contracts.DKIM{}, sesapi.ErrBadRequest("Invalid DomainSigningSelector.")
	}
	if attrs.DomainSigningPrivateKey == nil || *attrs.DomainSigningPrivateKey == "" {
		return contracts.DKIM{}, sesapi.ErrBadRequest(
			"DomainSigningPrivateKey is required with DomainSigningSelector.")
	}
	return contracts.DKIM{Origin: originExternal, Tokens: []string{sel}}, nil
}

// easyDKIM is Easy DKIM, with the requested key length, 2048 bits by
// default, and three tokens.
func easyDKIM(attrs *sesapi.DkimSigningAttributes) (contracts.DKIM, error) {
	length := keyLength2048
	if attrs != nil {
		if err := sesapi.Enum("NextSigningKeyLength", attrs.NextSigningKeyLength,
			"RSA_1024_BIT", "RSA_2048_BIT"); err != nil {
			return contracts.DKIM{}, err
		}
		if attrs.NextSigningKeyLength != nil {
			length = *attrs.NextSigningKeyLength
		}
	}
	tokens := make([]string, 0, dkimTokenCount)
	for range dkimTokenCount {
		t, err := dkimToken()
		if err != nil {
			return contracts.DKIM{}, err
		}
		tokens = append(tokens, t)
	}
	return contracts.DKIM{Origin: originAWSSES, KeyLength: length, Tokens: tokens}, nil
}

// dkimToken returns a token in the shape of Easy DKIM's: 32 lowercase
// letters and digits.
func dkimToken() (string, error) {
	const alphabet = "abcdefghijklmnopqrstuvwxyz0123456789"
	b := make([]byte, dkimTokenLength)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("failed to generate a DKIM token: %w", err)
	}
	for i := range b {
		// The modulo favors the first few characters slightly, which does
		// not matter for a token nothing checks.
		b[i] = alphabet[int(b[i])%len(alphabet)]
	}
	return string(b), nil
}

// wireDKIM is what an identity reports of its DKIM: a domain signs, as soon
// as it is created; an email address signs only through its domain, so on
// its own it reports signing not started.
func wireDKIM(id *contracts.Identity) *sesapi.DkimAttributes {
	if id.Type == contracts.IdentityTypeEmail {
		return &sesapi.DkimAttributes{Status: dkimNotStarted, SigningAttributesOrigin: originAWSSES}
	}
	created := sesapi.EpochSeconds(id.CreatedAt)
	out := &sesapi.DkimAttributes{
		SigningEnabled:          true,
		Status:                  verificationSuccess,
		Tokens:                  id.DKIM.Tokens,
		SigningAttributesOrigin: id.DKIM.Origin,
	}
	if id.DKIM.Origin == originAWSSES {
		out.NextSigningKeyLength = id.DKIM.KeyLength
		out.CurrentSigningKeyLength = id.DKIM.KeyLength
		out.LastKeyGenerationTimestamp = &created
	}
	return out
}

// identityParam returns the identity the path names, once the request is
// authorized for it.
func (m *Module) identityParam(ctx gas.Context) (string, error) {
	name, err := sesapi.PathParam(ctx, "EmailIdentity")
	if err != nil {
		return "", err
	}
	if name == "" {
		return "", sesapi.ErrBadRequest("You must specify an EmailIdentity.")
	}
	name = authz.CanonicalIdentity(name)
	return name, m.authz.Authorize(ctx, authz.Target{Identity: name})
}

func identityNotFound(err error, name string) error {
	if errors.Is(err, contracts.ErrIdentityNotFound) {
		return sesapi.ErrNotFound(fmt.Sprintf("Email identity %s does not exist.", name))
	}
	return err
}

func (m *Module) getEmailIdentity(ctx gas.Context) error {
	name, err := m.identityParam(ctx)
	if err != nil {
		return err
	}
	id, err := m.store.GetIdentity(ctx, name)
	if err != nil {
		return identityNotFound(err, name)
	}
	return sesapi.Write(ctx, sesapi.GetEmailIdentityResponse{
		IdentityType:             id.Type,
		FeedbackForwardingStatus: true,
		VerifiedForSendingStatus: true,
		DkimAttributes:           wireDKIM(id),
		Policies:                 map[string]string{},
		Tags:                     wireTags(id.Tags),
		ConfigurationSetName:     id.ConfigurationSet,
		VerificationStatus:       verificationSuccess,
	})
}

// The PageSize bounds of ListEmailIdentities: 0 to 1000, 0 getting the
// default page.
const (
	minIdentityPage = 0
	maxIdentityPage = 1000
)

func (m *Module) listEmailIdentities(ctx gas.Context) error {
	req, err := sesapi.Decode[sesapi.ListEmailIdentitiesRequest](ctx)
	if err != nil {
		return err
	}
	page, err := pageInput(deref(req.NextToken), req.PageSize, minIdentityPage, maxIdentityPage)
	if err != nil {
		return err
	}
	return m.listIdentities(ctx, req.Filter, page)
}

func (m *Module) listEmailIdentitiesByQuery(ctx gas.Context) error {
	page, err := pageOf(ctx, minIdentityPage, maxIdentityPage)
	if err != nil {
		return err
	}
	return m.listIdentities(ctx, nil, page)
}

// listIdentities lists the identities filter selects. Every identity is
// verified, so a VERIFICATION_STATUS filter for any other status selects
// none.
func (m *Module) listIdentities(
	ctx gas.Context,
	filter map[string]string,
	page contracts.PageInput,
) error {
	f, none, err := identityFilter(filter)
	if err != nil {
		return err
	}
	out, err := m.store.ListIdentities(ctx, f, page)
	if err != nil {
		return err
	}
	resp := sesapi.ListEmailIdentitiesResponse{EmailIdentities: []sesapi.IdentityInfo{}}
	if none {
		return sesapi.Write(ctx, resp)
	}
	resp.NextToken = out.NextToken
	for _, id := range out.Items {
		resp.EmailIdentities = append(resp.EmailIdentities, sesapi.IdentityInfo{
			IdentityType:       id.Type,
			IdentityName:       id.Name,
			SendingEnabled:     true,
			VerificationStatus: verificationSuccess,
		})
	}
	return sesapi.Write(ctx, resp)
}

// identityFilter checks a ListEmailIdentities filter, by the model's keys
// and enumerations. none reports a filter no identity here can match.
func identityFilter(filter map[string]string) (contracts.IdentityFilter, bool, error) {
	var (
		f    contracts.IdentityFilter
		none bool
	)
	for k, v := range filter {
		if v == "" {
			return f, false, sesapi.ErrBadRequest(fmt.Sprintf(
				"The Filter value for %s is empty.", k))
		}
		matchesNone, err := applyIdentityFilter(&f, k, v)
		if err != nil {
			return f, false, err
		}
		none = none || matchesNone
	}
	return f, none, nil
}

// applyIdentityFilter adds one filter key to f, and reports a value no
// identity here can match.
func applyIdentityFilter(f *contracts.IdentityFilter, k, v string) (bool, error) {
	switch k {
	case "IDENTITY_NAME_CONTAINS":
		f.NameContains = v
		return false, nil
	case "IDENTITY_TYPE":
		if err := sesapi.Enum("Filter.IDENTITY_TYPE", &v, contracts.IdentityTypeEmail,
			contracts.IdentityTypeDomain, "MANAGED_DOMAIN"); err != nil {
			return false, err
		}
		f.Type = v
		return v == "MANAGED_DOMAIN", nil
	case "VERIFICATION_STATUS":
		if err := sesapi.Enum("Filter.VERIFICATION_STATUS", &v, "PENDING", "SUCCESS",
			"FAILED", "TEMPORARY_FAILURE", "NOT_STARTED"); err != nil {
			return false, err
		}
		return v != verificationSuccess, nil
	default:
		return false, sesapi.ErrBadRequest(fmt.Sprintf("Filter key %s must be one of "+
			"IDENTITY_NAME_CONTAINS, IDENTITY_TYPE, VERIFICATION_STATUS.", k))
	}
}

func (m *Module) deleteEmailIdentity(ctx gas.Context) error {
	name, err := m.identityParam(ctx)
	if err != nil {
		return err
	}
	if err = m.store.DeleteIdentity(ctx, name); err != nil {
		return identityNotFound(err, name)
	}
	return sesapi.Write(ctx, sesapi.EmptyResponse{})
}
