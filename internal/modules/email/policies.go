package email

import (
	"context"
	"errors"
	"fmt"

	"github.com/gasmod/gas"
	"tule.dev/identity/principals"

	"tule.dev/mailbox/internal/authz"
	"tule.dev/mailbox/internal/contracts"
	"tule.dev/mailbox/internal/sesapi"
)

// The sending authorization policy operations of the SES v2 API: an
// identity's resource-based policies, which authorize other principals to
// send from it.

// policyRequest is a policy operation's identity, policy name and, for a
// create or an update, document, checked, and bound when bindErr is nil.
type policyRequest struct {
	bindErr  error
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

// bind binds the principals of a policy a create or an update stores, as
// AWS does when it saves the policy: a user or role ARN becomes the unique
// ID of the IAM user or role that has it now, which the policy is evaluated
// with. It runs before the resource lock, since it asks identity. Its
// error is returned only once the request is authorized, so a caller that
// may not write the policy learns nothing of which users and roles exist.
//
// An ARN no user or role has is BadRequestException, the error the SES v2
// API reference gives for invalid input ("The input you provided is
// invalid.", CreateEmailIdentityPolicy). A failure to ask identity fails
// the request with InternalFailure, and is logged.
func (m *Module) bind(ctx context.Context, doc string) (string, error) {
	bound, err := m.principals.Bind(ctx, doc)
	var invalid *principals.InvalidPrincipalError
	switch {
	case errors.As(err, &invalid):
		return "", sesapi.ErrBadRequest(
			`Invalid policy: Invalid principal in policy: "AWS":"` + invalid.ARN + `"`)
	case err != nil:
		return "", fmt.Errorf("email: bind the policy's principals at identity: %w", err)
	}
	return bound, nil
}

// boundPolicyParams are policyParams with the document bound, or with
// bind's error, which the caller returns once the request is authorized.
func (m *Module) boundPolicyParams(ctx gas.Context) (policyRequest, error) {
	req, err := m.policyParams(ctx, true)
	if err != nil {
		return req, err
	}
	req.document, req.bindErr = m.bind(ctx, req.document)
	return req, nil
}

func (m *Module) createEmailIdentityPolicy(
	ctx gas.Context,
	locked func(func() error) error,
) error {
	req, err := m.boundPolicyParams(ctx)
	if err != nil {
		return err
	}
	return locked(func() error {
		if err := m.authz.Authorize(ctx, authz.Target{Identity: req.identity}); err != nil {
			return err
		}
		if req.bindErr != nil {
			return req.bindErr
		}
		if err := m.store.CreateIdentityPolicy(ctx, req.identity, contracts.IdentityPolicy{
			Name: req.name, Document: req.document,
		}); err != nil {
			return identityNotFound(err, req.identity)
		}
		return sesapi.Write(ctx, sesapi.EmptyResponse{})
	})
}

func (m *Module) getEmailIdentityPolicies(
	ctx gas.Context,
	locked func(func() error) error,
) error {
	id, err := m.readIdentity(ctx, locked)
	if err != nil {
		return err
	}
	policies, err := m.showPolicies(ctx, id.Policies)
	if err != nil {
		return err
	}
	return sesapi.Write(ctx, sesapi.GetEmailIdentityPoliciesResponse{Policies: policies})
}

// updateEmailIdentityPolicy replaces a policy's document. "This API returns
// successfully even if a policy with the specified name does not exist"
// (SES API v2 Reference, UpdateEmailIdentityPolicy): such a policy is not
// created.
func (m *Module) updateEmailIdentityPolicy(
	ctx gas.Context,
	locked func(func() error) error,
) error {
	req, err := m.boundPolicyParams(ctx)
	if err != nil {
		return err
	}
	return locked(func() error {
		if err := m.authz.Authorize(ctx, authz.Target{Identity: req.identity}); err != nil {
			return err
		}
		if req.bindErr != nil {
			return req.bindErr
		}
		if err := m.store.UpdateIdentityPolicy(ctx, req.identity, contracts.IdentityPolicy{
			Name: req.name, Document: req.document,
		}); err != nil {
			return identityNotFound(err, req.identity)
		}
		return sesapi.Write(ctx, sesapi.EmptyResponse{})
	})
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

// readIdentity authorizes the request on the identity the path names and
// reads it, under the shared lock.
func (m *Module) readIdentity(
	ctx gas.Context,
	locked func(func() error) error,
) (*contracts.Identity, error) {
	var id *contracts.Identity
	err := locked(func() error {
		name, err := m.identityParam(ctx)
		if err != nil {
			return err
		}
		if id, err = m.store.GetIdentity(ctx, name); err != nil {
			return identityNotFound(err, name)
		}
		return nil
	})
	return id, err
}

// showPolicies are an identity's policies as GetEmailIdentity and
// GetEmailIdentityPolicies report them: each document by its name, as AWS
// shows a stored policy, each unique ID a user or role still has as its
// current ARN. It runs after the resource lock, since it asks identity; a
// failure to ask fails the request with InternalFailure, and is logged.
func (m *Module) showPolicies(
	ctx context.Context,
	policies []contracts.IdentityPolicy,
) (map[string]string, error) {
	out := make(map[string]string, len(policies))
	for _, p := range policies {
		doc, err := m.principals.Show(ctx, p.Document)
		if err != nil {
			return nil, fmt.Errorf("email: show the principals of policy %s at identity: %w",
				p.Name, err)
		}
		out[p.Name] = doc
	}
	return out, nil
}
