//go:build e2e

package e2e

import (
	"strings"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	"github.com/aws/aws-sdk-go-v2/service/sesv2"
	"github.com/aws/aws-sdk-go-v2/service/sesv2/types"
)

// These tests check that a sending authorization policy's user and role
// ARNs are bound to unique IDs when it is stored, as AWS binds them, so a
// user deleted and created again under the same name does not inherit the
// grant.

// identityPolicies returns the identity's policies through both reads,
// GetEmailIdentityPolicies and GetEmailIdentity, failing unless they agree.
func identityPolicies(t *testing.T, c *sesv2.Client, identity string) map[string]string {
	t.Helper()
	out, err := c.GetEmailIdentityPolicies(t.Context(),
		&sesv2.GetEmailIdentityPoliciesInput{EmailIdentity: aws.String(identity)})
	requireNoErr(t, err, "get policies of "+identity)
	id, err := c.GetEmailIdentity(t.Context(),
		&sesv2.GetEmailIdentityInput{EmailIdentity: aws.String(identity)})
	requireNoErr(t, err, "get identity "+identity)
	requireEqual(t, len(id.Policies), len(out.Policies), "policies GetEmailIdentity reports")
	for name, doc := range out.Policies {
		requireEqual(t, id.Policies[name], doc, "GetEmailIdentity's policy "+name)
	}
	return out.Policies
}

// deleteUser deletes the IAM user, its inline policy and its access keys.
func deleteUser(t *testing.T, ic *iam.Client, user string) {
	t.Helper()
	keys, err := ic.ListAccessKeys(t.Context(), &iam.ListAccessKeysInput{
		UserName: aws.String(user),
	})
	requireNoErr(t, err, "list the keys of "+user)
	for _, k := range keys.AccessKeyMetadata {
		_, err = ic.DeleteAccessKey(t.Context(), &iam.DeleteAccessKeyInput{
			UserName: aws.String(user), AccessKeyId: k.AccessKeyId,
		})
		requireNoErr(t, err, "delete a key of "+user)
	}
	_, err = ic.DeleteUser(t.Context(), &iam.DeleteUserInput{UserName: aws.String(user)})
	requireNoErr(t, err, "delete user "+user)
}

func TestARecreatedUserDoesNotInheritAGrant(t *testing.T) {
	s := startIdentityStack(t)
	s.createIdentity(t, "bound.example")
	root := sesClientWith(s.srv, s.rootCreds)
	userARN := "arn:aws:iam::" + account + ":user/granted"
	oldKey := createUserKey(t, s.iam, "granted")
	got, err := s.iam.GetUser(t.Context(), &iam.GetUserInput{UserName: aws.String("granted")})
	requireNoErr(t, err, "get user")
	oldID := aws.ToString(got.User.UserId)
	if !strings.HasPrefix(oldID, "AIDA") {
		t.Fatalf("user ID %q is not a user's unique ID", oldID)
	}
	doc := sendingPolicy("bound.example", userARN)
	createPolicy(t, root, "bound.example", "user", doc)
	mail := simpleInput("a@bound.example", "Granted", "Body.", "to@example.com")

	t.Run("while the IAM user exists the policy shows its ARN", func(t *testing.T) {
		requireEqual(t, identityPolicies(t, root, "bound.example")["user"], doc, "the policy")
		send(t, sesClientWith(s.srv, oldKey), mail)
	})

	deleteUser(t, s.iam, "granted")
	newKey := createUserKey(t, s.iam, "granted")

	t.Run("the recreated user is denied", func(t *testing.T) {
		requireAccessDenied(t, errOf(sesClientWith(s.srv, newKey).SendEmail(t.Context(), mail)),
			"User: "+userARN+" is not authorized to perform: ses:SendEmail on resource: "+
				sesARN("identity/bound.example")+" because no identity-based policy allows "+
				"the ses:SendEmail action")
	})
	t.Run("the policy shows the deleted user's unique ID", func(t *testing.T) {
		requireEqual(t, identityPolicies(t, root, "bound.example")["user"],
			sendingPolicy("bound.example", oldID), "the policy")
	})
	t.Run("saved again, it grants the recreated user", func(t *testing.T) {
		_, err := root.UpdateEmailIdentityPolicy(t.Context(),
			&sesv2.UpdateEmailIdentityPolicyInput{
				EmailIdentity: aws.String("bound.example"), PolicyName: aws.String("user"),
				Policy: aws.String(doc),
			})
		requireNoErr(t, err, "update the policy")
		send(t, sesClientWith(s.srv, newKey), mail)
		requireEqual(t, identityPolicies(t, root, "bound.example")["user"], doc, "the policy")
	})
}

func TestAPolicyNamingAUserThatDoesNotExistIsRefused(t *testing.T) {
	s := startIdentityStack(t)
	s.createIdentity(t, "bound.example")
	root := sesClientWith(s.srv, s.rootCreds)
	missing := "arn:aws:iam::" + account + ":user/missing"
	for name, put := range map[string]func(doc string) error{
		"CreateEmailIdentityPolicy": func(doc string) error {
			return errOf(root.CreateEmailIdentityPolicy(t.Context(),
				&sesv2.CreateEmailIdentityPolicyInput{
					EmailIdentity: aws.String("bound.example"), PolicyName: aws.String("p"),
					Policy: aws.String(doc),
				}))
		},
		"UpdateEmailIdentityPolicy": func(doc string) error {
			return errOf(root.UpdateEmailIdentityPolicy(t.Context(),
				&sesv2.UpdateEmailIdentityPolicyInput{
					EmailIdentity: aws.String("bound.example"), PolicyName: aws.String("p"),
					Policy: aws.String(doc),
				}))
		},
	} {
		t.Run(name, func(t *testing.T) {
			err := put(sendingPolicy("bound.example", missing))
			requireAs[*types.BadRequestException](t, err)
			if !strings.Contains(err.Error(),
				`Invalid policy: Invalid principal in policy: "AWS":"`+missing+`"`) {
				t.Fatalf("error = %v", err)
			}
		})
	}
	requireEqual(t, len(identityPolicies(t, root, "bound.example")), 0, "policies stored")
}

// TestStandaloneStoresAUserARNAsSent binds nothing without identity: a
// policy naming a user is stored and returned as it was sent, whether or
// not such a user exists anywhere.
func TestStandaloneStoresAUserARNAsSent(t *testing.T) {
	c, _ := newClient(t)
	_, err := c.CreateEmailIdentity(t.Context(),
		&sesv2.CreateEmailIdentityInput{EmailIdentity: aws.String("example.com")})
	requireNoErr(t, err, "create identity")
	doc := sendingPolicy("example.com", "arn:aws:iam::"+account+":user/anyone")
	createPolicy(t, c, "example.com", "user", doc)
	requireEqual(t, identityPolicies(t, c, "example.com")["user"], doc, "the policy")
}
