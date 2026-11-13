// Package authz authorizes requests by the caller's IAM identity policies
// and the resources' resource-based policies, as AWS authorizes them within
// an account and across accounts: the root principal of the service's
// account is always allowed, and any other principal needs the operation's
// action allowed on every resource the operation is evaluated on, and no
// Deny.
//
// Each route is wrapped in Guard with its entry in the operations table.
// An operation evaluated on "*" or on the whole service is authorized there,
// before its handler runs; any other handler calls Authorize with the
// resources and keys of its request once it has validated them, and before
// it touches the store. A handler that answers a success without having been
// authorized is answered with InternalFailure instead, so a missing call
// fails closed.
package authz

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"slices"
	"strconv"
	"strings"
	"time"

	"tule.dev/policy"
	"tule.dev/sigv4"

	"tule.dev/mailbox/internal/contracts"
	"tule.dev/mailbox/internal/httpx"
	"tule.dev/mailbox/internal/sesapi"
)

// The bounds on the request context passed to the evaluator, whose cost
// grows with the number and length of the values (tule.dev/policy, "Matching
// cost"). Validation already bounds what a request can carry (50
// recipients, 50 tags); these hold whatever reaches the evaluator to them.
const (
	maxKeyValues   = 100
	maxValueLength = 1024
)

// apiVersion is ses:ApiVersion for every SES v2 operation ("Allowing Access
// to only SES API version 2", SES Developer Guide, Controlling access to
// Amazon SES).
const apiVersion = "2"

// Authorizer evaluates requests against the caller's identity policies and
// the resources' resource-based policies.
type Authorizer struct {
	store    contracts.MailboxProvider
	identity *policyCache
	// stored are the identities' sending authorization policies, parsed.
	stored  *policyCache
	now     func() time.Time
	account string
	region  string
}

// New returns an Authorizer for the service's account and region, whose
// resources' ARNs it evaluates on, and which looks up identities and
// templates, for their tags, in store. The region is the service's, not the
// one a request was signed for: every signed region verifies, so a caller
// would otherwise pick the region its ARNs and aws:RequestedRegion carry.
func New(store contracts.MailboxProvider, account, region string) *Authorizer {
	return &Authorizer{
		store: store, identity: newPolicyCache(maxCachedPolicies, policy.ParseIdentity),
		stored:  newPolicyCache(maxCachedPolicies, policy.ParseResource),
		now:     time.Now,
		account: account, region: region,
	}
}

// Target is what a request acts on, and what it carries that the
// operation's condition keys are made of. Only the fields the operation's
// entry uses are read.
type Target struct {
	// Identity is the identity an identity operation names.
	Identity string
	// Sender is the bare From address of a send.
	Sender string
	// SenderDisplayName is the display name of the From address, if any.
	SenderDisplayName string
	// HeaderSender is the bare address of a raw message's From header, when
	// the request also gives FromEmailAddress, which Sender is then.
	HeaderSender string
	// HeaderSenderDisplayName is the display name of that header, if any.
	HeaderSenderDisplayName string
	// Feedback is the bare FeedbackForwardingEmailAddress, if any.
	Feedback string
	// SenderIdentityName, HeaderSenderIdentityName and FeedbackIdentityName
	// are the identities a send's sending authorization ARNs choose for
	// Sender, HeaderSender and Feedback, as IdentityFromARN returns them;
	// empty, the identity is the one the address resolves to.
	SenderIdentityName       string
	HeaderSenderIdentityName string
	FeedbackIdentityName     string
	// ConfigurationSet is the configuration set a send uses, if any.
	ConfigurationSet string
	// Template is the template a template operation names, or the stored
	// template a send uses, if any.
	Template string
	// Recipients are the bare To, Cc and Bcc addresses of a send.
	Recipients []string
	// Tags are the tags a create gives the new resource.
	Tags []contracts.Tag
}

// call is one guarded request: its operation, and whether it has been
// authorized.
type call struct {
	r          *http.Request
	op         Operation
	authorized bool
}

type callKey struct{}

// Guard returns the middleware for op's route. It authorizes an operation
// that needs nothing from the request but the caller, and refuses a success
// its handler answers without having been authorized.
func (a *Authorizer) Guard(op Operation) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			c := &call{op: op}
			ctx := context.WithValue(r.Context(), callKey{}, c)
			c.r = r.WithContext(ctx)
			if op.upfront() {
				if err := a.authorize(ctx, c, Target{}); err != nil {
					sesapi.WriteHTTPError(w, c.r, err)
					return
				}
			}
			next.ServeHTTP(&guardWriter{ResponseWriter: w, c: c}, c.r)
		})
	}
}

// ARNPrefix is the start of the ARNs of the service's resources,
// arn:aws:ses:<region>:<account>:. A handler checks an ARN a request names
// against it, and acts on the name.
func (a *Authorizer) ARNPrefix() string {
	return arnBase(a.region, a.account)
}

// Authorize authorizes the guarded request ctx belongs to against t: nil
// when it is allowed, else its AccessDeniedException, or an error of the
// service's own.
func (a *Authorizer) Authorize(ctx context.Context, t Target) error {
	c, ok := ctx.Value(callKey{}).(*call)
	if !ok {
		return errors.New("authz: the request is not guarded")
	}
	return a.authorize(ctx, c, t)
}

func (a *Authorizer) authorize(ctx context.Context, c *call, t Target) error {
	p, ok := sigv4.PrincipalFrom(ctx)
	if !ok {
		return errors.New("authz: the request has no verified principal")
	}
	// Root skips evaluation, and policy.Authorize gives an Account caller
	// the root's full identity access: the two must agree, checked before
	// either is relied on, in the service's account as in any other.
	if (p.Type == sigv4.PrincipalTypeAccount) != p.Root {
		return fmt.Errorf("authz: principal %s has Root %t and type %q, which disagree",
			p.ARN, p.Root, p.Type)
	}
	// Root is the root of its own account only: a root principal of
	// another account is evaluated like any other principal of it.
	if !p.Root || p.AccountID != a.account {
		if err := a.evaluate(ctx, c, t, p); err != nil {
			return err
		}
	}
	c.authorized = true
	return nil
}

// evaluate evaluates a principal other than the root: each of the
// operation's actions on each of its resources must be allowed, in the
// order of its entry, and the first that is not is the one reported. Each
// is decided by policy.Authorize with the caller's identity policies and
// the resource's resource-based policies, as AWS evaluates them within one
// account and across accounts (IAM User Guide, "Policy evaluation logic"
// and "Cross-account policy evaluation logic").
func (a *Authorizer) evaluate(ctx context.Context, c *call, t Target, p sigv4.Principal) error {
	policies, err := a.identity.parse(p.Policies)
	if err != nil {
		return err
	}
	if err = checkNames(t); err != nil {
		return err
	}
	if k, dup := caseDuplicate(t.Tags); dup {
		// Condition keys match without regard to case, so Env and env
		// would be two values of one aws:RequestTag key.
		return sesapi.ErrBadRequest(fmt.Sprintf("Duplicate tag key: %s", k))
	}
	resources, err := a.resources(ctx, c.op, t, p.AccountID)
	if err != nil {
		return err
	}
	keys, err := a.requestKeys(c, t, p, resources)
	if err != nil {
		return err
	}
	caller := callerOf(p)
	for _, action := range c.op.actions(t) {
		for _, res := range resources {
			if err = decide(caller, action, res, keys, policies); err != nil {
				return err
			}
		}
	}
	return nil
}

// callerOf is the policy.Caller of a principal, from the attributes its
// KeySource supplies. tule.dev/policy derives aws:PrincipalArn,
// aws:PrincipalAccount, aws:userid, aws:PrincipalType and aws:username from
// it, and refuses a caller whose fields disagree.
func callerOf(p sigv4.Principal) policy.Caller {
	return policy.Caller{
		AccountID:    p.AccountID,
		ARN:          p.ARN,
		PrincipalARN: p.PrincipalARN,
		UserID:       p.UserID,
		Type:         policy.PrincipalType(p.Type),
	}
}

// requestKeys are the request's condition keys, held to the bounds with the
// keys the resources replace them with.
func (a *Authorizer) requestKeys(
	c *call,
	t Target,
	p sigv4.Principal,
	resources []resource,
) (map[string][]string, error) {
	keys := globalKeys(c.r, p, a.region, a.now())
	for k, v := range operationKeys(c.op, t) {
		keys[k] = v
	}
	if err := checkKeys(keys); err != nil {
		return nil, err
	}
	for _, res := range resources {
		if err := checkKeys(res.keys); err != nil {
			return nil, err
		}
	}
	return keys, nil
}

// decide is nil when the caller's identity policies and the resource's
// policies allow the action on the resource, else its AccessDeniedException.
// An explicit Deny on any of the resource's denyAlso, in the identity
// policies or in that one's own policies, with its tags, refuses it too;
// their Allows do not count.
func decide(
	caller policy.Caller,
	action string,
	res resource,
	keys map[string][]string,
	identity []*policy.Policy,
) error {
	req := policy.AuthorizeRequest{
		Action:          action,
		Resource:        res.arn,
		ResourceAccount: res.account,
		Caller:          caller,
		Context:         contextFor(keys, res),
	}
	az := authorize(req, res.policies, identity)
	if az.Decision != policy.ExplicitDeny {
		for _, other := range res.denyAlso {
			also := req
			also.Resource = other.arn
			also.Context = contextFor(keys, resource{keys: res.keys, tags: other.tags})
			d := authorize(also, other.policies, identity)
			if d.Decision == policy.ExplicitDeny {
				return sesapi.ErrAccessDenied(caller.ARN, action, other.arn,
					d.Reason.Message(action))
			}
		}
	}
	if az.Decision == policy.Allow {
		return nil
	}
	return sesapi.ErrAccessDenied(caller.ARN, action, res.arn, az.Reason.Message(action))
}

// authorize is policy.Authorize with every one of a resource's
// resource-based policies, an email identity having up to 20: the request
// is denied when any of them denies it, and otherwise allowed when it is
// allowed with any of them, as it would be with one policy of all their
// statements. Every one is evaluated before an Allow is returned, so a
// Deny in a later one applies. A denied request reports the first policy's
// reason, which is the same for each, since none applies a Deny.
func authorize(
	req policy.AuthorizeRequest,
	resourcePolicies, identity []*policy.Policy,
) policy.Authorization {
	if len(resourcePolicies) == 0 {
		return policy.Authorize(req, nil, identity...)
	}
	var first, allowed policy.Authorization
	found := false
	for i, rp := range resourcePolicies {
		az := policy.Authorize(req, rp, identity...)
		switch {
		case az.Decision == policy.ExplicitDeny:
			return az
		case i == 0:
			first = az
		}
		if az.Decision == policy.Allow && !found {
			allowed, found = az, true
		}
	}
	if found {
		return allowed
	}
	return first
}

// resource is one resource a request is evaluated on: its ARN, and the tags
// of what it names when that exists. denyAlso are resources an explicit
// Deny on which refuses the request as well, though it is not evaluated on
// them for an Allow: the more specific sender identities a send does not go
// through, those that do not exist, which mailbox lets a send go through
// regardless, and those an ARN passed over for a less specific one. keys
// replace the request's keys of the same names for this resource, a nil
// value removing one.
//
// account is the ID of the account that owns the resource, and policies are
// its resource-based policies, none for a resource that has none.
type resource struct {
	keys     map[string][]string
	arn      string
	account  string
	tags     []contracts.Tag
	denyAlso []denyTarget
	policies []*policy.Policy
}

// denyTarget is a resource only an explicit Deny is evaluated on: its ARN
// and, for an identity that exists, its tags and sending authorization
// policies.
type denyTarget struct {
	arn      string
	tags     []contracts.Tag
	policies []*policy.Policy
}

// denyTargets are ARNs of resources that do not exist, as deny targets.
func denyTargets(arns []string) []denyTarget {
	out := make([]denyTarget, len(arns))
	for i, arn := range arns {
		out[i] = denyTarget{arn: arn}
	}
	return out
}

// arnBase is the start of the ARNs of an account in a region:
// arn:aws:ses:<region>:<account>:. The partition is always aws.
func arnBase(region, account string) string {
	return "arn:aws:ses:" + region + ":" + account + ":"
}

// resources resolves the resources op is evaluated on for t, in the order of
// its entry; none is "*".
func (a *Authorizer) resources(
	ctx context.Context,
	op Operation,
	t Target,
	callerAccount string,
) ([]resource, error) {
	if len(op.Resources) == 0 {
		return []resource{{arn: "*", account: a.account}}, nil
	}
	out := make([]resource, 0, len(op.Resources))
	for _, r := range op.Resources {
		res, use, err := a.resolve(ctx, r, t, callerAccount)
		if err != nil {
			return nil, fmt.Errorf("authz: %s: %w", op.Name, err)
		}
		if use {
			if res.account == "" {
				// Every resource mailbox stores is the service account's.
				res.account = a.account
			}
			out = append(out, res)
		}
	}
	return out, nil
}

// resolve resolves one resource of an entry, reporting false for an
// Optional one the request does not use.
func (a *Authorizer) resolve(
	ctx context.Context,
	r Resource,
	t Target,
	callerAccount string,
) (resource, bool, error) {
	base := a.ARNPrefix()
	switch r.Type {
	case Service:
		return resource{arn: base + "*"}, true, nil
	case SenderIdentity, HeaderSenderIdentity, FeedbackIdentity:
		return a.resolveSender(ctx, r.Type, t, base+"identity/")
	case Identity:
		return named(ctx, r, CanonicalIdentity(t.Identity), base+"identity/", a.identityTags)
	case Template:
		return named(ctx, r, t.Template, base+"template/", a.templateTags)
	case ConfigurationSet:
		// Configuration sets are not stored: they have no tags. A send uses
		// the configuration sets of the account that sends, the caller's,
		// even when it sends from another account's identity: SES "doesn't
		// apply" the identity's configuration set to a delegate sender's
		// mail (SES Developer Guide, "Sending authorization overview").
		res, use, err := named(ctx, r, t.ConfigurationSet,
			arnBase(a.region, callerAccount)+"configuration-set/", noTags)
		res.account = callerAccount
		return res, use, err
	}
	return resource{}, false, fmt.Errorf("unknown resource type %d", r.Type)
}

// resolveSender resolves the identity of one of a send's addresses: its
// sender's, its raw From header's or its feedback address's, reporting
// false for an optional one the send does not have.
func (a *Authorizer) resolveSender(
	ctx context.Context,
	typ ResourceType,
	t Target,
	prefix string,
) (resource, bool, error) {
	switch typ {
	case SenderIdentity:
		if t.Sender == "" {
			return resource{}, false, errors.New("a send without a sender")
		}
		res, err := a.senderIdentity(ctx, t.Sender, prefix, t.SenderIdentityName)
		return res, true, err
	case FeedbackIdentity:
		if t.Feedback == "" {
			return resource{}, false, nil
		}
		res, err := a.senderIdentity(ctx, t.Feedback, prefix, t.FeedbackIdentityName)
		return res, true, err
	}
	if t.HeaderSender == "" {
		return resource{}, false, nil
	}
	res, err := a.senderIdentity(ctx, t.HeaderSender, prefix, t.HeaderSenderIdentityName)
	// The header's sender is evaluated as the From address.
	res.keys = map[string][]string{
		KeyFromAddress:     {t.HeaderSender},
		KeyFromDisplayName: nil,
	}
	if t.HeaderSenderDisplayName != "" {
		res.keys[KeyFromDisplayName] = []string{t.HeaderSenderDisplayName}
	}
	return res, true, err
}

// named resolves a resource the request names, its ARN prefix and the name,
// with the tags tagsOf finds for it.
func named(
	ctx context.Context,
	r Resource,
	name, prefix string,
	tagsOf func(context.Context, string) ([]contracts.Tag, error),
) (resource, bool, error) {
	switch {
	case name == "" && r.Optional:
		return resource{}, false, nil
	case name == "":
		return resource{}, false, fmt.Errorf("no name for resource type %d", r.Type)
	}
	tags, err := tagsOf(ctx, name)
	if err != nil {
		return resource{}, false, err
	}
	if err = checkStoredTags(prefix+name, tags); err != nil {
		return resource{}, false, err
	}
	return resource{arn: prefix + name, tags: tags}, true, nil
}

// The longest names a resource can have, which bound the ARNs evaluated:
// pattern matching costs the pattern's length times the ARN's.
const (
	// maxAddressLength is an email address's: a local part of 64 octets,
	// "@" and a domain of 255 (RFC 5321, 4.5.3.1.1 and 4.5.3.1.2).
	maxAddressLength = 64 + 1 + 255
	// maxDomainLength is a domain name's in text form (RFC 1035, 2.3.4).
	maxDomainLength = 253
	// maxConfigurationSetLength is a configuration set name's: "up to 64
	// alphanumeric characters" (SES Developer Guide, Service quotas).
	maxConfigurationSetLength = 64
	// maxTemplateLength is a template name's. The SES model gives a
	// template name no maximum; 256 is this service's bound.
	maxTemplateLength = 256
)

// checkNames refuses, before anything is evaluated, a resource name longer
// than a resource of its kind can have.
func checkNames(t Target) error {
	identityMax := maxDomainLength
	if strings.Contains(t.Identity, "@") {
		identityMax = maxAddressLength
	}
	for _, n := range []struct {
		field, value string
		maxLen       int
	}{
		{"EmailIdentity", t.Identity, identityMax},
		{"FromEmailAddress", t.Sender, maxAddressLength},
		{"FeedbackForwardingEmailAddress", t.Feedback, maxAddressLength},
		{"the From header", t.HeaderSender, maxAddressLength},
		{"ConfigurationSetName", t.ConfigurationSet, maxConfigurationSetLength},
		{"TemplateName", t.Template, maxTemplateLength},
	} {
		if len(n.value) > n.maxLen {
			return sesapi.ErrBadRequest(fmt.Sprintf("%s is longer than %d characters.",
				n.field, n.maxLen))
		}
	}
	return nil
}

// caseDuplicate reports a tag key of tags that another one equals without
// regard to case, which would feed one condition key twice.
func caseDuplicate(tags []contracts.Tag) (string, bool) {
	seen := make(map[string]bool, len(tags))
	for _, t := range tags {
		k := strings.ToLower(t.Key)
		if seen[k] {
			return t.Key, true
		}
		seen[k] = true
	}
	return "", false
}

// checkStoredTags fails closed on a stored resource whose tag keys differ
// only by case, which the root can create: the request is not evaluated on
// tags that would merge into one aws:ResourceTag key.
func checkStoredTags(arn string, tags []contracts.Tag) error {
	if k, dup := caseDuplicate(tags); dup {
		return fmt.Errorf("authz: %s has tag keys that differ only by case (%s)", arn, k)
	}
	return nil
}

func noTags(context.Context, string) ([]contracts.Tag, error) {
	return nil, nil
}

// senderIdentity resolves the identity a send from the address goes
// through, with prefix its ARN prefix. With chosen, the name of the identity
// a sending authorization ARN names (IdentityFromARN), it is that identity.
// Otherwise it is the first of SenderIdentityCandidates that exists. Either
// comes with its tags and its sending authorization policies, all of which
// the send is evaluated with. They are read with the identity, in one
// transaction, and the send holds the module's resource lock until it is
// stored, so the policies evaluated are the identity's when it acts.
//
// The candidates before it are its denyAlso, so a Deny written for one of
// them still applies. A chosen identity can pass over more specific ones
// that exist, such as an address identity under the domain an ARN names:
// their own policies' Deny statements apply too, with their tags. AWS does
// not document whether it evaluates the policy of an identity an ARN passes
// over; mailbox fails closed. When none exists, as mailbox sends from any address,
// the send is evaluated on the address's domain, the identity a SES account
// most often verifies, and every other candidate is its denyAlso: a Deny on
// a parent domain is not sidestepped through a subdomain no identity covers.
func (a *Authorizer) senderIdentity(
	ctx context.Context,
	address, prefix, chosen string,
) (resource, error) {
	candidates := SenderIdentityCandidates(address)
	arns := make([]string, len(candidates))
	for i, name := range candidates {
		arns[i] = prefix + name
	}
	if chosen != "" {
		i := slices.Index(candidates, chosen)
		if i < 0 {
			return resource{}, fmt.Errorf("authz: %s does not cover %s", chosen, address)
		}
		id, err := a.store.GetIdentity(ctx, chosen)
		if err != nil {
			// IdentityFromARN found it under the same lock: not finding it
			// now is a fault.
			return resource{}, fmt.Errorf("authz: identity %s: %w", chosen, err)
		}
		passed, err := a.passedOver(ctx, candidates[:i], arns[:i])
		if err != nil {
			return resource{}, err
		}
		return a.identityResource(arns[i], id, passed)
	}
	for i, name := range candidates {
		id, err := a.store.GetIdentity(ctx, name)
		switch {
		case errors.Is(err, contracts.ErrIdentityNotFound):
			continue
		case err != nil:
			return resource{}, err
		}
		return a.identityResource(arns[i], id, denyTargets(arns[:i]))
	}
	primary := min(1, len(arns)-1)
	others := append(append([]string(nil), arns[:primary]...), arns[primary+1:]...)
	return resource{arn: arns[primary], denyAlso: denyTargets(others)}, nil
}

// passedOver are the deny targets of the more specific candidates a chosen
// identity passes over, of the ARNs: each that exists with its tags and
// policies, each that does not with neither.
func (a *Authorizer) passedOver(
	ctx context.Context,
	names, arns []string,
) ([]denyTarget, error) {
	out := make([]denyTarget, len(names))
	for i, name := range names {
		out[i] = denyTarget{arn: arns[i]}
		id, err := a.store.GetIdentity(ctx, name)
		switch {
		case errors.Is(err, contracts.ErrIdentityNotFound):
			continue
		case err != nil:
			return nil, err
		}
		if err = checkStoredTags(arns[i], id.Tags); err != nil {
			return nil, err
		}
		if out[i].policies, err = a.identityPolicies(arns[i], id.Policies); err != nil {
			return nil, err
		}
		out[i].tags = id.Tags
	}
	return out, nil
}

// identityResource is the stored identity id, of ARN arn, as a resource a
// send is evaluated on, with its tags and policies.
func (a *Authorizer) identityResource(
	arn string,
	id *contracts.Identity,
	denyAlso []denyTarget,
) (resource, error) {
	if err := checkStoredTags(arn, id.Tags); err != nil {
		return resource{}, err
	}
	policies, err := a.identityPolicies(arn, id.Policies)
	if err != nil {
		return resource{}, err
	}
	return resource{arn: arn, tags: id.Tags, denyAlso: denyAlso, policies: policies}, nil
}

// identityPolicies parses an identity's stored sending authorization
// policies. Each was checked when it was stored; one that no longer parses
// fails the request closed rather than being skipped, which could drop a
// Deny.
func (a *Authorizer) identityPolicies(
	arn string,
	stored []contracts.IdentityPolicy,
) ([]*policy.Policy, error) {
	docs := make([]json.RawMessage, len(stored))
	for i, p := range stored {
		docs[i] = json.RawMessage(p.Document)
	}
	out, err := a.stored.parse(docs)
	if err != nil {
		return nil, fmt.Errorf("authz: the policies of %s: %w", arn, err)
	}
	return out, nil
}

// IdentityFromARN returns the identity a sending authorization ARN a send
// gives for the address chooses, by its canonical name. field names where
// the ARN came from: FromEmailAddressIdentityArn,
// FeedbackForwardingEmailAddressIdentityArn, or a raw message's
// X-SES-SOURCE-ARN or X-SES-FROM-ARN. The ARN is "the ARN of the identity
// that is associated with the sending authorization policy that permits you
// to use the email address" (SES API v2 Reference, SendEmail), so it
// chooses whose policies apply: the address's own identity, or one of its
// parent domains' (SES's example names example.com for
// sender@example.com). It must be an SES identity ARN (BadRequestException
// otherwise) of the service's account and region, as every identity
// mailbox holds is (NotFoundException otherwise, since SES documents no
// answer), naming an identity that covers the address (BadRequestException
// otherwise) and exists (NotFoundException otherwise). It is checked for
// every caller, the root included, before anything is evaluated.
func (a *Authorizer) IdentityFromARN(
	ctx context.Context,
	field, arn, address string,
) (string, error) {
	name, err := a.identityARNName(field, arn)
	if err != nil {
		return "", err
	}
	if len(address) > maxAddressLength {
		return "", sesapi.ErrBadRequest(fmt.Sprintf("The address is longer than %d characters.",
			maxAddressLength))
	}
	if !slices.Contains(SenderIdentityCandidates(address), name) {
		return "", sesapi.ErrBadRequest(fmt.Sprintf("%s %s names an identity that does "+
			"not cover %s.", field, arn, address))
	}
	if _, err = a.store.GetIdentity(ctx, name); err != nil {
		if errors.Is(err, contracts.ErrIdentityNotFound) {
			return "", sesapi.ErrNotFound(fmt.Sprintf("Email identity %s does not exist.", name))
		}
		return "", err
	}
	return name, nil
}

// identityARNName is the canonical name of the identity an SES identity ARN
// of the service's account and region names, as IdentityFromARN describes.
func (a *Authorizer) identityARNName(field, arn string) (string, error) {
	parts := strings.SplitN(arn, ":", 6)
	if len(parts) != 6 || parts[0] != "arn" || parts[2] != "ses" ||
		!strings.HasPrefix(parts[5], "identity/") || parts[5] == "identity/" {
		return "", sesapi.ErrBadRequest(fmt.Sprintf("Invalid %s: %s", field, arn))
	}
	if !strings.HasPrefix(arn, a.ARNPrefix()) {
		return "", sesapi.ErrNotFound(fmt.Sprintf("Email identity %s does not exist.", arn))
	}
	return CanonicalIdentity(strings.TrimPrefix(parts[5], "identity/")), nil
}

// CanonicalIdentity is the name an identity is known by: a domain in lower
// case, an email address as written. SES treats domain names without regard
// to case and email addresses with it, the domain part included ("Domain
// names are case-insensitive", "Email addresses are case sensitive", SES
// Developer Guide, "Creating and verifying identities").
func CanonicalIdentity(name string) string {
	if strings.Contains(name, "@") {
		return name
	}
	return strings.ToLower(name)
}

// SenderIdentityCandidates are the identities a send from the address can
// go through, in the order they are looked for, by their canonical names:
// the address itself, then its domain, then each parent domain of two
// labels or more. A verified domain covers its subdomains, and the most
// granular identity's settings apply (SES Developer Guide, "Creating and
// verifying identities"); which one AWS evaluates is not documented.
func SenderIdentityCandidates(address string) []string {
	_, domain, ok := strings.Cut(address, "@")
	if !ok || domain == "" {
		return []string{address}
	}
	domain = strings.ToLower(domain)
	out := []string{address, domain}
	for {
		_, parent, found := strings.Cut(domain, ".")
		if !found || !strings.Contains(parent, ".") {
			return out
		}
		out = append(out, parent)
		domain = parent
	}
}

func (a *Authorizer) identityTags(ctx context.Context, name string) ([]contracts.Tag, error) {
	id, err := a.store.GetIdentity(ctx, name)
	switch {
	case errors.Is(err, contracts.ErrIdentityNotFound):
		return nil, nil
	case err != nil:
		return nil, err
	}
	return id.Tags, nil
}

func (a *Authorizer) templateTags(ctx context.Context, name string) ([]contracts.Tag, error) {
	tmpl, err := a.store.GetTemplate(ctx, name)
	switch {
	case errors.Is(err, contracts.ErrTemplateNotFound):
		return nil, nil
	case err != nil:
		return nil, err
	}
	return tmpl.Tags, nil
}

// globalKeys are the global condition keys (IAM User Guide, "AWS global
// condition context keys") the service has for every request, which also
// fill policy variables. aws:PrincipalArn, aws:PrincipalAccount,
// aws:userid, aws:PrincipalType and aws:username are not among them:
// policy.Authorize supplies them from the caller (callerOf).
// aws:PrincipalTag/<key> is each of the principal's tags.
func globalKeys(
	r *http.Request,
	p sigv4.Principal,
	region string,
	now time.Time,
) map[string][]string {
	now = now.UTC()
	keys := map[string][]string{
		"aws:CurrentTime":     {now.Format(time.RFC3339)},
		"aws:EpochTime":       {strconv.FormatInt(now.Unix(), 10)},
		"aws:SecureTransport": {strconv.FormatBool(r.TLS != nil)},
		"aws:RequestedRegion": {region},
	}
	for k, v := range p.Tags {
		keys["aws:PrincipalTag/"+k] = []string{v}
	}
	if host, _, err := net.SplitHostPort(r.RemoteAddr); err == nil {
		keys["aws:SourceIp"] = []string{host}
	}
	return keys
}

// operationKeys are the service-specific keys op's entry lists, from t.
func operationKeys(op Operation, t Target) map[string][]string {
	keys := map[string][]string{}
	for _, k := range op.Keys {
		switch k {
		case KeyAPIVersion:
			keys[k] = []string{apiVersion}
		case KeyRequestTags:
			if len(t.Tags) == 0 {
				continue
			}
			names := make([]string, 0, len(t.Tags))
			for _, tag := range t.Tags {
				keys["aws:RequestTag/"+tag.Key] = []string{tag.Value}
				names = append(names, tag.Key)
			}
			keys["aws:TagKeys"] = names
		default:
			if v := t.values(k); len(v) > 0 {
				keys[k] = v
			}
		}
	}
	return keys
}

// values are the target's values for a send key, none when it has none.
func (t *Target) values(key string) []string {
	var v string
	switch key {
	case KeyFromAddress:
		v = t.Sender
	case KeyFromDisplayName:
		v = t.SenderDisplayName
	case KeyFeedbackAddress:
		v = t.Feedback
	case KeyRecipients:
		return t.Recipients
	}
	if v == "" {
		return nil
	}
	return []string{v}
}

// contextFor returns keys as evaluated on res: with its keys replacing the
// request's, and aws:ResourceTag/<key> for each of its tags.
func contextFor(keys map[string][]string, res resource) map[string][]string {
	if len(res.tags) == 0 && len(res.keys) == 0 {
		return keys
	}
	out := make(map[string][]string, len(keys)+len(res.tags))
	for k, v := range keys {
		out[k] = v
	}
	for k, v := range res.keys {
		if v == nil {
			delete(out, k)
			continue
		}
		out[k] = v
	}
	for _, t := range res.tags {
		out["aws:ResourceTag/"+t.Key] = []string{t.Value}
	}
	return out
}

// checkKeys holds the request context to maxKeyValues values per key and
// maxValueLength bytes per value. A request past them is refused, rather
// than evaluated on part of what it carries.
func checkKeys(keys map[string][]string) error {
	for k, vs := range keys {
		if len(vs) > maxKeyValues {
			return sesapi.ErrBadRequest(fmt.Sprintf(
				"The request has more than %d values for %s to evaluate.", maxKeyValues, k))
		}
		for _, v := range vs {
			if len(v) > maxValueLength {
				return sesapi.ErrBadRequest(fmt.Sprintf(
					"The request's value for %s is longer than %d bytes.", k, maxValueLength))
			}
		}
	}
	return nil
}

// guardWriter refuses a success the guarded handler answers without having
// been authorized: it answers InternalFailure instead, and drops the body.
type guardWriter struct {
	http.ResponseWriter
	c       *call
	wrote   bool
	refused bool
}

func (w *guardWriter) WriteHeader(code int) {
	if !w.wrote {
		w.wrote = true
		if code < http.StatusBadRequest && !w.c.authorized {
			w.refused = true
			h := w.Header()
			for k := range h {
				delete(h, k)
			}
			httpx.Logger(w.c.r.Context()).Error("a handler answered without authorizing").
				Str("operation", w.c.op.Name).Send()
			sesapi.WriteHTTPError(w.ResponseWriter, w.c.r, sesapi.ErrInternalFailure())
			return
		}
	}
	if w.refused {
		return
	}
	w.ResponseWriter.WriteHeader(code)
}

func (w *guardWriter) Write(b []byte) (int, error) {
	if !w.wrote {
		w.WriteHeader(http.StatusOK)
	}
	if w.refused {
		return len(b), nil
	}
	//nolint:wrapcheck // the writer's error is the caller's, as from any ResponseWriter
	return w.ResponseWriter.Write(b)
}

// Flush flushes the writer underneath when it can, so a handler keeps its
// http.Flusher.
func (w *guardWriter) Flush() {
	if w.refused {
		return
	}
	if f, ok := w.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}

// Unwrap lets http.ResponseController and gas reach the writer underneath.
func (w *guardWriter) Unwrap() http.ResponseWriter {
	return w.ResponseWriter
}
