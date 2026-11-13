package email

import (
	"github.com/gasmod/gas"

	"tule.dev/mailbox/internal/authz"
	"tule.dev/mailbox/internal/contracts"
	"tule.dev/mailbox/internal/sesapi"
)

// The sending authorization policy operations of the SES v2 API: an
// identity's resource-based policies, which authorize other principals to
// send from it.

// policyRequest is a policy operation's identity, policy name and, for a
// create or an update, document, checked.
type policyRequest struct {
	identity string
	name     string
	document string
}

// policyParams reads and checks the identity and the policy name the path
// names, and, when withDocument is set, the Policy the body holds.
func (m *Module) policyParams(ctx gas.Context, withDocument bool) (policyRequest, error) {
	var req policyRequest
	identity, err := sesapi.PathParam(ctx, "EmailIdentity")
	if err != nil {
		return req, err
	}
	if identity == "" {
		return req, sesapi.ErrBadRequest("You must specify an EmailIdentity.")
	}
	req.identity = authz.CanonicalIdentity(identity)
	if req.name, err = sesapi.PathParam(ctx, "PolicyName"); err != nil {
		return req, err
	}
	if err = authz.CheckIdentityPolicyName(req.name); err != nil {
		return req, err
	}
	if !withDocument {
		return req, nil
	}
	body, err := sesapi.Decode[sesapi.IdentityPolicyRequest](ctx)
	if err != nil {
		return req, err
	}
	req.document = deref(body.Policy)
	return req, m.authz.CheckIdentityPolicy(req.identity, req.document)
}

func (m *Module) createEmailIdentityPolicy(ctx gas.Context) error {
	req, err := m.policyParams(ctx, true)
	if err != nil {
		return err
	}
	if err = m.authz.Authorize(ctx, authz.Target{Identity: req.identity}); err != nil {
		return err
	}
	if err = m.store.CreateIdentityPolicy(ctx, req.identity, contracts.IdentityPolicy{
		Name: req.name, Document: req.document,
	}); err != nil {
		return identityNotFound(err, req.identity)
	}
	return sesapi.Write(ctx, sesapi.EmptyResponse{})
}

func (m *Module) getEmailIdentityPolicies(ctx gas.Context) error {
	name, err := m.identityParam(ctx)
	if err != nil {
		return err
	}
	id, err := m.store.GetIdentity(ctx, name)
	if err != nil {
		return identityNotFound(err, name)
	}
	return sesapi.Write(ctx, sesapi.GetEmailIdentityPoliciesResponse{
		Policies: wirePolicies(id.Policies),
	})
}

// updateEmailIdentityPolicy replaces a policy's document. "This API returns
// successfully even if a policy with the specified name does not exist"
// (SES API v2 Reference, UpdateEmailIdentityPolicy): such a policy is not
// created.
func (m *Module) updateEmailIdentityPolicy(ctx gas.Context) error {
	req, err := m.policyParams(ctx, true)
	if err != nil {
		return err
	}
	if err = m.authz.Authorize(ctx, authz.Target{Identity: req.identity}); err != nil {
		return err
	}
	if err = m.store.UpdateIdentityPolicy(ctx, req.identity, contracts.IdentityPolicy{
		Name: req.name, Document: req.document,
	}); err != nil {
		return identityNotFound(err, req.identity)
	}
	return sesapi.Write(ctx, sesapi.EmptyResponse{})
}

// deleteEmailIdentityPolicy deletes a policy, succeeding "even if a policy
// with the specified name does not exist" (SES API v2 Reference,
// DeleteEmailIdentityPolicy).
func (m *Module) deleteEmailIdentityPolicy(ctx gas.Context) error {
	req, err := m.policyParams(ctx, false)
	if err != nil {
		return err
	}
	if err = m.authz.Authorize(ctx, authz.Target{Identity: req.identity}); err != nil {
		return err
	}
	if err = m.store.DeleteIdentityPolicy(ctx, req.identity, req.name); err != nil {
		return identityNotFound(err, req.identity)
	}
	return sesapi.Write(ctx, sesapi.EmptyResponse{})
}

// wirePolicies are an identity's policies as GetEmailIdentity and
// GetEmailIdentityPolicies report them: each document by its name.
func wirePolicies(policies []contracts.IdentityPolicy) map[string]string {
	out := make(map[string]string, len(policies))
	for _, p := range policies {
		out[p.Name] = p.Document
	}
	return out
}
