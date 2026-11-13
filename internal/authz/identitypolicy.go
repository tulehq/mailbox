package authz

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"

	"tule.dev/policy"

	"tule.dev/mailbox/internal/sesapi"
)

// MaxIdentityPolicySize is the longest sending authorization policy, in
// bytes: "The policy cannot exceed 4 KB." (SES API v2 Reference,
// CreateEmailIdentityPolicy). It also bounds what each stored policy costs
// to evaluate, as tule.dev/policy asks services to.
const MaxIdentityPolicySize = 4096

// policyNamePattern is a policy name: "The policy name cannot exceed 64
// characters and can only include alphanumeric characters, dashes, and
// underscores." (SES API v2 Reference, CreateEmailIdentityPolicy).
var policyNamePattern = regexp.MustCompile(`^[A-Za-z0-9_-]{1,64}$`)

// CheckIdentityPolicyName refuses a policy name SES does not accept.
func CheckIdentityPolicyName(name string) error {
	if !policyNamePattern.MatchString(name) {
		return sesapi.ErrBadRequest(fmt.Sprintf("Invalid policy name: %q. The policy name "+
			"must be 1 to 64 alphanumeric characters, dashes and underscores.", name))
	}
	return nil
}

// CheckIdentityPolicySize refuses a sending authorization policy over
// MaxIdentityPolicySize. It is checked again on a document once its
// principals are bound, since a unique ID can be longer than the ARN it
// replaces.
func CheckIdentityPolicySize(doc string) error {
	if len(doc) > MaxIdentityPolicySize {
		return sesapi.ErrBadRequest(fmt.Sprintf("The policy cannot exceed 4 KB: it is %d bytes.",
			len(doc)))
	}
	return nil
}

// CheckIdentityPolicy refuses a sending authorization policy for the
// identity (by its canonical name) that SES would not store: one over
// MaxIdentityPolicySize, one tule.dev/policy's ParseResource refuses (a
// statement without a Principal, an invalid principal, malformed JSON, and
// the rest of its rules), and one with a statement whose Resource is not the
// identity's ARN: "Each policy has to specify one resource, and that
// resource has to be the ARN of the identity that the policy is attached
// to." (SES Developer Guide, "Policy anatomy"). The ARN may have "*" for its
// region, as the guide's policies for a global endpoint do. The Sid is any
// string unique within the policy, as ParseResource accepts it: the guide
// gives it as "Any string." that "Uniquely identifies the statement".
func (a *Authorizer) CheckIdentityPolicy(identity, doc string) error {
	if doc == "" {
		return sesapi.ErrBadRequest("You must specify a Policy.")
	}
	if err := CheckIdentityPolicySize(doc); err != nil {
		return err
	}
	if _, err := policy.ParseResource([]byte(doc)); err != nil {
		var pe *policy.ParseError
		if errors.As(err, &pe) {
			return sesapi.ErrBadRequest("Invalid policy: " + pe.Message)
		}
		return fmt.Errorf("authz: parse a policy: %w", err)
	}
	return checkPolicyResources([]byte(doc), a.ARNPrefix()+"identity/"+identity,
		"arn:aws:ses:*:"+a.account+":identity/"+identity)
}

// checkPolicyResources refuses a parsed policy with a statement whose
// Resource is anything but arn or global, or that has none.
func checkPolicyResources(doc []byte, arn, global string) error {
	statements, err := policyResources(doc)
	if err != nil {
		return err
	}
	for _, resources := range statements {
		if len(resources) == 0 {
			return errResource(arn)
		}
		for _, r := range resources {
			if r != arn && r != global {
				return errResource(arn)
			}
		}
	}
	return nil
}

func errResource(arn string) error {
	return sesapi.ErrBadRequest("Invalid policy: the Resource of each statement must be " +
		"the ARN of the identity the policy is attached to, " + arn + ".")
}

// policyResources reads each statement's Resource values from a document
// ParseResource accepted, so its JSON is valid, its element names exact and
// unrepeated: a statement with NotResource, and none other, has no values.
// It only refuses what would be stored; evaluation reads the parsed policy.
func policyResources(doc []byte) ([][]string, error) {
	var top struct {
		Statement json.RawMessage
	}
	if err := json.Unmarshal(doc, &top); err != nil {
		return nil, fmt.Errorf("authz: decode a parsed policy: %w", err)
	}
	var raw []json.RawMessage
	if trimmed := bytes.TrimSpace(top.Statement); len(trimmed) > 0 && trimmed[0] == '{' {
		raw = []json.RawMessage{top.Statement}
	} else if err := json.Unmarshal(top.Statement, &raw); err != nil {
		return nil, fmt.Errorf("authz: decode a parsed policy's statements: %w", err)
	}
	out := make([][]string, 0, len(raw))
	for _, st := range raw {
		var s struct {
			Resource json.RawMessage
		}
		if err := json.Unmarshal(st, &s); err != nil {
			return nil, fmt.Errorf("authz: decode a parsed statement: %w", err)
		}
		values, err := stringOrList(s.Resource)
		if err != nil {
			return nil, err
		}
		out = append(out, values)
	}
	return out, nil
}

// stringOrList decodes a policy element that is one string or a list of
// them; an absent one has no values.
func stringOrList(v json.RawMessage) ([]string, error) {
	if len(v) == 0 {
		return nil, nil
	}
	var one string
	if err := json.Unmarshal(v, &one); err == nil {
		return []string{one}, nil
	}
	var list []string
	if err := json.Unmarshal(v, &list); err != nil {
		return nil, fmt.Errorf("authz: decode a parsed Resource: %w", err)
	}
	return list, nil
}
