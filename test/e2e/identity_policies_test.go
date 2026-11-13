//go:build e2e

package e2e

import (
	"context"
	"fmt"
	"strings"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/sesv2"
	"github.com/aws/aws-sdk-go-v2/service/sesv2/types"
)

// sendingPolicy is a sending authorization policy of the identity that lets
// the principal send from it.
func sendingPolicy(identity, principal string) string {
	return policyDoc(statement{
		Effect: "Allow", Principal: map[string]string{"AWS": principal},
		Action: []string{"ses:SendEmail"}, Resource: []string{sesARN("identity/" + identity)},
	})
}

func createPolicy(t *testing.T, c *sesv2.Client, identity, name, doc string) {
	t.Helper()
	_, err := c.CreateEmailIdentityPolicy(t.Context(), &sesv2.CreateEmailIdentityPolicyInput{
		EmailIdentity: aws.String(identity), PolicyName: aws.String(name),
		Policy: aws.String(doc),
	})
	requireNoErr(t, err, "create policy "+name)
}

// policiesOf returns the policies of the identity example.com.
func policiesOf(ctx context.Context, t *testing.T, c *sesv2.Client) map[string]string {
	t.Helper()
	out, err := c.GetEmailIdentityPolicies(ctx, &sesv2.GetEmailIdentityPoliciesInput{
		EmailIdentity: aws.String("example.com"),
	})
	requireNoErr(t, err, "get policies")
	return out.Policies
}

func TestIdentityPoliciesAreStoredReturnedAndDeleted(t *testing.T) {
	c, _ := newClient(t)
	ctx := t.Context()
	_, err := c.CreateEmailIdentity(ctx,
		&sesv2.CreateEmailIdentityInput{EmailIdentity: aws.String("example.com")})
	requireNoErr(t, err, "create identity")

	first := sendingPolicy("example.com", "111111111111")
	second := sendingPolicy("example.com", "222222222222")
	createPolicy(t, c, "example.com", "first", first)
	// The domain is the identity whatever the case it is named in.
	createPolicy(t, c, "Example.COM", "second-one_2", second)
	got := policiesOf(ctx, t, c)
	requireEqual(t, len(got), 2, "policies")
	requireEqual(t, got["first"], first, "first policy")
	requireEqual(t, got["second-one_2"], second, "second policy")

	identity, err := c.GetEmailIdentity(ctx,
		&sesv2.GetEmailIdentityInput{EmailIdentity: aws.String("example.com")})
	requireNoErr(t, err, "get identity")
	requireEqual(t, identity.Policies["first"], first, "GetEmailIdentity's policy")

	requireAs[*types.AlreadyExistsException](t, errOf(c.CreateEmailIdentityPolicy(ctx,
		&sesv2.CreateEmailIdentityPolicyInput{
			EmailIdentity: aws.String("example.com"), PolicyName: aws.String("first"),
			Policy: aws.String(second),
		})))

	_, err = c.UpdateEmailIdentityPolicy(ctx, &sesv2.UpdateEmailIdentityPolicyInput{
		EmailIdentity: aws.String("example.com"), PolicyName: aws.String("first"),
		Policy: aws.String(second),
	})
	requireNoErr(t, err, "update")
	requireEqual(t, policiesOf(ctx, t, c)["first"], second, "updated policy")
	// Update and Delete succeed for a policy the identity does not have.
	_, err = c.UpdateEmailIdentityPolicy(ctx, &sesv2.UpdateEmailIdentityPolicyInput{
		EmailIdentity: aws.String("example.com"), PolicyName: aws.String("absent"),
		Policy: aws.String(first),
	})
	requireNoErr(t, err, "update an absent policy")
	requireEqual(t, len(policiesOf(ctx, t, c)), 2, "policies after that update")
	_, err = c.DeleteEmailIdentityPolicy(ctx, &sesv2.DeleteEmailIdentityPolicyInput{
		EmailIdentity: aws.String("example.com"), PolicyName: aws.String("absent"),
	})
	requireNoErr(t, err, "delete an absent policy")

	_, err = c.DeleteEmailIdentityPolicy(ctx, &sesv2.DeleteEmailIdentityPolicyInput{
		EmailIdentity: aws.String("example.com"), PolicyName: aws.String("first"),
	})
	requireNoErr(t, err, "delete")
	got = policiesOf(ctx, t, c)
	requireEqual(t, len(got), 1, "policies after the delete")
	requireEqual(t, got["second-one_2"], second, "the policy left")
}

func TestIdentityPoliciesAreValidated(t *testing.T) {
	c, _ := newClient(t)
	ctx := t.Context()
	create := func(identity, name, doc string) error {
		return errOf(c.CreateEmailIdentityPolicy(ctx, &sesv2.CreateEmailIdentityPolicyInput{
			EmailIdentity: aws.String(identity), PolicyName: aws.String(name),
			Policy: aws.String(doc),
		}))
	}
	valid := sendingPolicy("example.com", "111111111111")

	t.Run("an identity that does not exist", func(t *testing.T) {
		requireAs[*types.NotFoundException](t, create("example.com", "p", valid))
		requireAs[*types.NotFoundException](t, errOf(c.GetEmailIdentityPolicies(ctx,
			&sesv2.GetEmailIdentityPoliciesInput{EmailIdentity: aws.String("example.com")})))
		requireAs[*types.NotFoundException](t, errOf(c.DeleteEmailIdentityPolicy(ctx,
			&sesv2.DeleteEmailIdentityPolicyInput{
				EmailIdentity: aws.String("example.com"), PolicyName: aws.String("p"),
			})))
	})

	_, err := c.CreateEmailIdentity(ctx,
		&sesv2.CreateEmailIdentityInput{EmailIdentity: aws.String("example.com")})
	requireNoErr(t, err, "create identity")

	for name, tc := range map[string]struct{ policyName, doc string }{
		"a name with a dot":    {"a.b", valid},
		"a name of 65":         {strings.Repeat("a", 65), valid},
		"a document over 4 KB": {"p", valid + strings.Repeat(" ", 4096)},
		"malformed JSON":       {"p", `{"Statement":`},
		"no Principal":         {"p", allowPolicy("ses:SendEmail")},
		"another identity":     {"p", sendingPolicy("other.example", "111111111111")},
		"an invalid principal": {"p", sendingPolicy("example.com", "arn:aws:iam::1:user/x")},
		"a principal wildcard": {"p", sendingPolicy("example.com", "arn:aws:iam::*:root")},
		"a Resource of every resource": {"p", policyDoc(statement{
			Effect: "Deny", Action: []string{"ses:*"}, Principal: map[string]string{"AWS": "*"},
			Resource: []string{"*"},
		})},
	} {
		t.Run(name, func(t *testing.T) {
			requireAs[*types.BadRequestException](t, create("example.com", tc.policyName, tc.doc))
		})
	}

	t.Run("at most 20 per identity", func(t *testing.T) {
		for i := range 20 {
			createPolicy(t, c, "example.com", fmt.Sprintf("p%02d", i), valid)
		}
		requireAs[*types.LimitExceededException](t, create("example.com", "p20", valid))
	})

	t.Run("deleted with the identity", func(t *testing.T) {
		_, err := c.DeleteEmailIdentity(ctx,
			&sesv2.DeleteEmailIdentityInput{EmailIdentity: aws.String("example.com")})
		requireNoErr(t, err, "delete identity")
		_, err = c.CreateEmailIdentity(ctx,
			&sesv2.CreateEmailIdentityInput{EmailIdentity: aws.String("example.com")})
		requireNoErr(t, err, "create identity again")
		requireEqual(t, len(policiesOf(ctx, t, c)), 0, "policies")
	})
}

func TestThePolicyOperationsAreAuthorized(t *testing.T) {
	s := startIdentityStack(t)
	ctx := t.Context()
	root := sesClientWith(s.srv, s.rootCreds)
	for _, id := range []string{"allowed.example", "other.example"} {
		_, err := root.CreateEmailIdentity(ctx,
			&sesv2.CreateEmailIdentityInput{EmailIdentity: aws.String(id)})
		requireNoErr(t, err, "create identity "+id)
	}
	key := createUserKey(t, s.iam, "reader")
	putUserPolicy(t, s.iam, "reader", policyDoc(statement{
		Effect: "Allow", Action: []string{"ses:GetEmailIdentityPolicies"},
		Resource: []string{sesARN("identity/allowed.example")},
	}))
	c := sesClientWith(s.srv, key)
	get := func(identity string) error {
		return errOf(c.GetEmailIdentityPolicies(ctx,
			&sesv2.GetEmailIdentityPoliciesInput{EmailIdentity: aws.String(identity)}))
	}

	requireNoErr(t, get("allowed.example"), "get the allowed identity's policies")
	requireAccessDenied(t, get("other.example"), "User: arn:aws:iam::"+account+
		":user/reader is not authorized to perform: ses:GetEmailIdentityPolicies on "+
		"resource: "+sesARN("identity/other.example")+" because no identity-based policy "+
		"allows the ses:GetEmailIdentityPolicies action")
	requireAccessDenied(t, errOf(c.CreateEmailIdentityPolicy(ctx,
		&sesv2.CreateEmailIdentityPolicyInput{
			EmailIdentity: aws.String("allowed.example"), PolicyName: aws.String("p"),
			Policy: aws.String(sendingPolicy("allowed.example", "111111111111")),
		})), "User: arn:aws:iam::"+account+":user/reader is not authorized to perform: "+
		"ses:CreateEmailIdentityPolicy on resource: "+sesARN("identity/allowed.example")+
		" because no identity-based policy allows the ses:CreateEmailIdentityPolicy action")
	requireDenied(t, errOf(c.UpdateEmailIdentityPolicy(ctx,
		&sesv2.UpdateEmailIdentityPolicyInput{
			EmailIdentity: aws.String("allowed.example"), PolicyName: aws.String("p"),
			Policy: aws.String(sendingPolicy("allowed.example", "111111111111")),
		})))
	requireDenied(t, errOf(c.DeleteEmailIdentityPolicy(ctx,
		&sesv2.DeleteEmailIdentityPolicyInput{
			EmailIdentity: aws.String("allowed.example"), PolicyName: aws.String("p"),
		})))
}
