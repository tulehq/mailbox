package app

import (
	"fmt"
	"net/http"
	"time"

	"tule.dev/identity/keysource"
	"tule.dev/sigv4"

	"tule.dev/mailbox/internal/modules/health"
	"tule.dev/mailbox/internal/sesapi"
)

// maxBodySize bounds the request body the verifier buffers to hash it. The
// largest legitimate request is a SendEmail of a message at SES's 40 MiB
// limit: base64 in JSON makes that 53.4 MiB, and the rest of the request is
// small beside it, so 64 MiB leaves room for it and no more than that.
const maxBodySize = 64 << 20

// identityTimeout bounds a key lookup at identity, so an identity that hangs
// fails the request with ServiceException rather than holding it until the
// server's own timeout. A lookup is one small local request. It is a
// variable so a test can shorten it.
var identityTimeout = 10 * time.Second

// newVerifier returns the SigV4 verifier every request but the probes goes
// through, the SES API's and the retrieval API's alike. It knows the
// configured root key and, when an identity endpoint is configured, every
// key identity issued, asked of identity on each request after the root key.
// Any key it accepts may call every operation: there are no permissions.
// Requests are accepted signed for ses in any region. Host and X-Amz-Date
// must be signed, as SigV4 requires of every request; the operation is the
// method and path, which the signature covers.
func newVerifier(cfg *Config) (*sigv4.Verifier, error) {
	root, err := sigv4.NewStaticKey(sigv4.StaticKeyConfig{
		AccessKeyID:     cfg.Auth.AccessKeyID,
		SecretAccessKey: cfg.Auth.SecretAccessKey,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to build the signature verifier: %w", err)
	}
	var keys sigv4.KeySource = root
	if cfg.Auth.IdentityEndpoint != "" {
		identity, kErr := keysource.New(keysource.Config{
			HTTPClient:      &http.Client{Timeout: identityTimeout},
			Endpoint:        cfg.Auth.IdentityEndpoint,
			AccessKeyID:     cfg.Auth.AccessKeyID,
			SecretAccessKey: cfg.Auth.SecretAccessKey,
		})
		if kErr != nil {
			return nil, fmt.Errorf("failed to build the signature verifier: %w", kErr)
		}
		keys = sigv4.Chain(root, identity)
	}
	v, err := sigv4.New(
		keys,
		sigv4.WithBufferedPayload(maxBodySize),
		sigv4.WithRequiredSignedHeaders("host", "x-amz-date"),
		sigv4.WithService("ses"),
		sigv4.WithErrorMap(sigv4Error),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to build the signature verifier: %w", err)
	}
	return v, nil
}

// verifySignature rejects requests whose SigV4 signature does not verify
// against v, and serves the rest as Verify returns them, with the signer's
// principal in their context and the body the signature covered.
//
// The health probes are exempt, so a container's health check needs no
// credentials; nothing else is, because any web page the developer has open
// can reach a server on localhost, and this one hands out every message it
// holds.
func verifySignature(v *sigv4.Verifier) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if isProbe(r.URL.Path) {
				next.ServeHTTP(w, r)
				return
			}
			verified, err := v.Verify(r)
			if err != nil {
				sesapi.WriteHTTPError(w, r, err)
				return
			}
			next.ServeHTTP(w, verified)
		})
	}
}

func isProbe(path string) bool {
	return path == health.HealthPath || path == health.ReadyPath
}
