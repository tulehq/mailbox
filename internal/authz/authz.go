// Package authz authorizes requests by the caller's IAM identity policies,
// as AWS authorizes them within an account: the root principal is always
// allowed, and any other principal needs an Allow for the operation's action
// on every resource the operation is evaluated on, and no Deny.
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
	"errors"
	"fmt"
	"net"
	"net/http"
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

// Authorizer evaluates requests against the caller's identity policies.
type Authorizer struct {
	store   contracts.MailboxProvider
	cache   *policyCache
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
		store: store, cache: newPolicyCache(maxCachedPolicies), now: time.Now,
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
	// Root is the root of its own account only: a root principal of
	// another account is evaluated, and refused, like any other.
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
// order of its entry, and the first that is not is the one reported.
//
// A principal of another account is then refused even when its identity
// policies allow the request: in AWS a cross-account request needs a
// resource-based policy of the resource's account as well (IAM User Guide,
// "Cross-account policy evaluation logic"), and none is enforced here, so
// nothing can grant one. One store serves every account, so allowing it
// would let any account reach the service account's mail.
func (a *Authorizer) evaluate(ctx context.Context, c *call, t Target, p sigv4.Principal) error {
	policies, err := a.cache.parse(p.Policies)
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
	resources, err := a.resources(ctx, c.op, t, a.ARNPrefix())
	if err != nil {
		return err
	}
	keys, err := a.requestKeys(c, t, p, resources)
	if err != nil {
		return err
	}
	for _, action := range c.op.actions(t) {
		for _, res := range resources {
			if err = decide(p.ARN, action, res, keys, policies); err != nil {
				return err
			}
		}
	}
	if p.AccountID != a.account {
		return sesapi.ErrNoResourcePolicy(p.ARN, c.op.Action, resources[0].arn)
	}
	return nil
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

// decide is nil when the policies allow the action on the resource, else
// its AccessDeniedException. An explicit Deny of any of the resource's
// denyAlso ARNs refuses it too.
func decide(
	principal, action string,
	res resource,
	keys map[string][]string,
	policies []*policy.Policy,
) error {
	ctxKeys := contextFor(keys, res)
	d := policy.Evaluate(policy.Request{
		Action:    action,
		Resource:  res.arn,
		Principal: principal,
		Context:   ctxKeys,
	}, policies...)
	if d.Decision != policy.ExplicitDeny {
		for _, arn := range res.denyAlso {
			also := policy.Evaluate(policy.Request{
				Action: action, Resource: arn, Principal: principal, Context: ctxKeys,
			}, policies...)
			if also.Decision == policy.ExplicitDeny {
				return sesapi.ErrExplicitlyDenied(principal, action, arn)
			}
		}
	}
	switch d.Decision {
	case policy.Allow:
		return nil
	case policy.ExplicitDeny:
		return sesapi.ErrExplicitlyDenied(principal, action, res.arn)
	default:
		return sesapi.ErrNotAllowed(principal, action, res.arn)
	}
}

// resource is one resource a request is evaluated on: its ARN, and the tags
// of what it names when that exists. denyAlso are ARNs an explicit Deny of
// which refuses the request as well, though it is not evaluated on them for
// an Allow: the sender identities that do not exist, which mailbox lets a
// send go through regardless. keys replace the request's keys of the same
// names for this resource, a nil value removing one.
type resource struct {
	keys     map[string][]string
	arn      string
	tags     []contracts.Tag
	denyAlso []string
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
	base string,
) ([]resource, error) {
	if len(op.Resources) == 0 {
		return []resource{{arn: "*"}}, nil
	}
	out := make([]resource, 0, len(op.Resources))
	for _, r := range op.Resources {
		res, use, err := a.resolve(ctx, r, t, base)
		if err != nil {
			return nil, fmt.Errorf("authz: %s: %w", op.Name, err)
		}
		if use {
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
	base string,
) (resource, bool, error) {
	switch r.Type {
	case Service:
		return resource{arn: base + "*"}, true, nil
	case SenderIdentity:
		if t.Sender == "" {
			return resource{}, false, errors.New("a send without a sender")
		}
		res, err := a.senderIdentity(ctx, t.Sender, base+"identity/")
		return res, true, err
	case HeaderSenderIdentity:
		if t.HeaderSender == "" {
			return resource{}, false, nil
		}
		res, err := a.senderIdentity(ctx, t.HeaderSender, base+"identity/")
		// The header's sender is evaluated as the From address.
		res.keys = map[string][]string{
			KeyFromAddress:     {t.HeaderSender},
			KeyFromDisplayName: nil,
		}
		if t.HeaderSenderDisplayName != "" {
			res.keys[KeyFromDisplayName] = []string{t.HeaderSenderDisplayName}
		}
		return res, true, err
	case Identity:
		return named(ctx, r, CanonicalIdentity(t.Identity), base+"identity/", a.identityTags)
	case Template:
		return named(ctx, r, t.Template, base+"template/", a.templateTags)
	case ConfigurationSet:
		// Configuration sets are not stored: they have no tags.
		return named(ctx, r, t.ConfigurationSet, base+"configuration-set/", noTags)
	}
	return resource{}, false, fmt.Errorf("unknown resource type %d", r.Type)
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
// through, with prefix its ARN prefix: the first of SenderIdentityCandidates
// that exists, with its tags. The candidates before it, which do not exist,
// are its denyAlso, so a Deny written for one of them still applies. When
// none exists, as mailbox sends from any address, the send is evaluated on
// the address's domain, the identity a SES account most often verifies,
// and every other candidate is its denyAlso: a Deny on a parent domain is
// not sidestepped through a subdomain no identity covers.
func (a *Authorizer) senderIdentity(
	ctx context.Context,
	address, prefix string,
) (resource, error) {
	candidates := SenderIdentityCandidates(address)
	arns := make([]string, len(candidates))
	for i, name := range candidates {
		arns[i] = prefix + name
	}
	for i, name := range candidates {
		id, err := a.store.GetIdentity(ctx, name)
		switch {
		case errors.Is(err, contracts.ErrIdentityNotFound):
			continue
		case err != nil:
			return resource{}, err
		}
		if err = checkStoredTags(arns[i], id.Tags); err != nil {
			return resource{}, err
		}
		return resource{arn: arns[i], tags: id.Tags, denyAlso: arns[:i]}, nil
	}
	primary := min(1, len(arns)-1)
	others := append(append([]string(nil), arns[:primary]...), arns[primary+1:]...)
	return resource{arn: arns[primary], denyAlso: others}, nil
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
// fill policy variables.
//
// aws:PrincipalArn is the caller's ARN for an IAM user, and for a role
// session its role's ARN without the role's path, which the session's ARN
// does not carry and identity does not report: a condition on a role path
// does not match it. aws:userid is left out, as identity does not report
// unique IDs; aws:PrincipalTag/<key> is left out, as it does not report
// tags.
func globalKeys(
	r *http.Request,
	p sigv4.Principal,
	region string,
	now time.Time,
) map[string][]string {
	now = now.UTC()
	keys := map[string][]string{
		"aws:PrincipalAccount": {p.AccountID},
		"aws:CurrentTime":      {now.Format(time.RFC3339)},
		"aws:EpochTime":        {strconv.FormatInt(now.Unix(), 10)},
		"aws:SecureTransport":  {strconv.FormatBool(r.TLS != nil)},
		"aws:RequestedRegion":  {region},
	}
	for k, v := range principalKeys(p.ARN) {
		keys[k] = []string{v}
	}
	if host, _, err := net.SplitHostPort(r.RemoteAddr); err == nil {
		keys["aws:SourceIp"] = []string{host}
	}
	return keys
}

// principalKeys derives aws:PrincipalArn, aws:PrincipalType and, for an IAM
// user, aws:username from the caller's ARN: arn:aws:iam::<account>:user/
// <path><name>, or arn:aws:sts::<account>:assumed-role/<role>/<session>.
func principalKeys(arn string) map[string]string {
	parts := strings.SplitN(arn, ":", 6)
	if len(parts) != 6 {
		return nil
	}
	partition, svc, account, res := parts[1], parts[2], parts[4], parts[5]
	switch {
	case svc == "iam" && strings.HasPrefix(res, "user/"):
		return map[string]string{
			"aws:PrincipalArn":  arn,
			"aws:PrincipalType": "User",
			"aws:username":      res[strings.LastIndex(res, "/")+1:],
		}
	case svc == "sts" && strings.HasPrefix(res, "assumed-role/"):
		role, _, ok := strings.Cut(strings.TrimPrefix(res, "assumed-role/"), "/")
		if !ok {
			return nil
		}
		return map[string]string{
			"aws:PrincipalArn":  "arn:" + partition + ":iam::" + account + ":role/" + role,
			"aws:PrincipalType": "AssumedRole",
		}
	}
	return map[string]string{"aws:PrincipalArn": arn}
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
