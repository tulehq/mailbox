package app

import (
	"context"
	"fmt"
	"net/http"

	"tule.dev/identity/principals"

	"tule.dev/mailbox/internal/contracts"
)

// newPrincipals returns what binds the principals of the sending
// authorization policies mailbox stores. With an identity endpoint it is
// identity's principal-ID client, signed with the configured key, which
// must be identity's root key, and bounded by identityTimeout per call.
// Standalone there are no users or roles to bind to: documents are stored
// and returned as they are sent, and matched by ARN.
func newPrincipals(cfg *Config) (contracts.PrincipalBinder, error) {
	if cfg.Auth.IdentityEndpoint == "" {
		return unboundPrincipals{}, nil
	}
	c, err := principals.New(principals.Config{
		HTTPClient:      &http.Client{Timeout: identityTimeout},
		Endpoint:        cfg.Auth.IdentityEndpoint,
		AccessKeyID:     cfg.Auth.AccessKeyID,
		SecretAccessKey: cfg.Auth.SecretAccessKey,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to build the principal-ID client: %w", err)
	}
	return c, nil
}

// unboundPrincipals is the standalone PrincipalBinder: it binds nothing.
type unboundPrincipals struct{}

func (unboundPrincipals) Bind(_ context.Context, doc string) (string, error) {
	return doc, nil
}

func (unboundPrincipals) Show(_ context.Context, doc string) (string, error) {
	return doc, nil
}
