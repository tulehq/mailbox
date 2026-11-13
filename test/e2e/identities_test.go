//go:build e2e

package e2e

import (
	"net/http"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/sesv2"
	"github.com/aws/aws-sdk-go-v2/service/sesv2/types"
)

// The design: no verification can happen, so every identity is verified at
// once.

func TestIdentityLifecycle(t *testing.T) {
	c, _ := newClient(t)
	ctx := t.Context()

	tests := []struct {
		identity string
		kind     types.IdentityType
	}{
		{identity: "sender@example.com", kind: types.IdentityTypeEmailAddress},
		{identity: "example.org", kind: types.IdentityTypeDomain},
	}
	for _, tt := range tests {
		t.Run(tt.identity, func(t *testing.T) {
			created, err := c.CreateEmailIdentity(ctx, &sesv2.CreateEmailIdentityInput{
				EmailIdentity: aws.String(tt.identity),
			})
			requireNoErr(t, err, "create identity")
			requireEqual(t, created.IdentityType, tt.kind, "created identity type")
			requireEqual(t, created.VerifiedForSendingStatus, true, "created verified for sending")

			got, err := c.GetEmailIdentity(ctx, &sesv2.GetEmailIdentityInput{
				EmailIdentity: aws.String(tt.identity),
			})
			requireNoErr(t, err, "get identity")
			requireEqual(t, got.IdentityType, tt.kind, "identity type")
			requireEqual(
				t,
				got.VerificationStatus,
				types.VerificationStatusSuccess,
				"verification status",
			)
			requireEqual(t, got.VerifiedForSendingStatus, true, "verified for sending")

			_, err = c.DeleteEmailIdentity(ctx, &sesv2.DeleteEmailIdentityInput{
				EmailIdentity: aws.String(tt.identity),
			})
			requireNoErr(t, err, "delete identity")

			err = errOf(c.GetEmailIdentity(ctx, &sesv2.GetEmailIdentityInput{
				EmailIdentity: aws.String(tt.identity),
			}))
			requireAs[*types.NotFoundException](t, err)
		})
	}
}

func TestDuplicateIdentityAlreadyExists(t *testing.T) {
	// CreateEmailIdentity models AlreadyExistsException, "The resource
	// specified in your request already exists".
	c, _ := newClient(t)
	in := &sesv2.CreateEmailIdentityInput{EmailIdentity: aws.String("dup@example.com")}

	_, err := c.CreateEmailIdentity(t.Context(), in)
	requireNoErr(t, err, "create identity")
	err = errOf(c.CreateEmailIdentity(t.Context(), in))
	requireAs[*types.AlreadyExistsException](t, err)
	requireStatus(t, err, http.StatusBadRequest)
}

func TestUnknownIdentityIsNotFound(t *testing.T) {
	// GetEmailIdentity and DeleteEmailIdentity model NotFoundException,
	// HTTP 404.
	c, _ := newClient(t)
	name := aws.String("nobody@example.com")

	err := errOf(c.GetEmailIdentity(t.Context(), &sesv2.GetEmailIdentityInput{EmailIdentity: name}))
	requireAs[*types.NotFoundException](t, err)
	requireStatus(t, err, http.StatusNotFound)

	err = errOf(
		c.DeleteEmailIdentity(t.Context(), &sesv2.DeleteEmailIdentityInput{EmailIdentity: name}),
	)
	requireAs[*types.NotFoundException](t, err)
	requireStatus(t, err, http.StatusNotFound)
}

func TestListIdentitiesPaginates(t *testing.T) {
	c, _ := newClient(t)
	want := []string{
		"a@example.com",
		"b@example.com",
		"c@example.com",
		"example.net",
		"e@example.com",
	}
	for _, id := range want {
		_, err := c.CreateEmailIdentity(
			t.Context(),
			&sesv2.CreateEmailIdentityInput{EmailIdentity: aws.String(id)},
		)
		requireNoErr(t, err, "create identity "+id)
	}

	var got []string
	pages := 0
	p := sesv2.NewListEmailIdentitiesPaginator(
		c,
		&sesv2.ListEmailIdentitiesInput{PageSize: aws.Int32(2)},
	)
	for p.HasMorePages() {
		page, err := p.NextPage(t.Context())
		requireNoErr(t, err, "list identities")
		pages++
		if len(page.EmailIdentities) > 2 {
			t.Fatalf("page of %d identities, want at most 2", len(page.EmailIdentities))
		}
		for _, info := range page.EmailIdentities {
			got = append(got, aws.ToString(info.IdentityName))
			requireEqual(
				t,
				info.VerificationStatus,
				types.VerificationStatusSuccess,
				"listed verification status",
			)
			requireEqual(t, info.SendingEnabled, true, "listed sending enabled")
		}
	}
	requireSameSet(t, got, want, "identities listed")
	if pages < 3 {
		t.Fatalf("listed in %d pages of 2, want at least 3", pages)
	}
}
