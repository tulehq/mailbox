package app

import (
	"net/http"

	"tule.dev/sigv4"

	"tule.dev/mailbox/internal/sesapi"
)

// sigv4Error maps a verification failure to the error it is answered with,
// with the codes and statuses of the SES v2 Common Errors page. The messages
// are the verifier's own, the AWS JSON services' texts.
//
// KindInvalidSessionToken and KindExpiredSessionToken come from identity,
// for role session keys, or from the root key, which takes no token. The
// Kinds this configuration cannot produce (presigned URLs, a streamed body)
// and KindKeyLookupFailed are returned as the *sigv4.Error itself: sesapi
// answers any error it does not know with InternalFailure and logs it, so
// they surface as a 500 with their cause in the log. A failed lookup at
// identity is never answered as an unknown key, so the client sees a fault
// on the server's side rather than a key to throw away.
func sigv4Error(e *sigv4.Error) error {
	switch e.Kind {
	case sigv4.KindMissingAuth:
		return sesapi.NewError(http.StatusForbidden, sesapi.TypeMissingAuthToken, e.Message)
	case sigv4.KindUnsupportedAlgorithm, sigv4.KindIncompleteAuth, sigv4.KindInvalidDate,
		sigv4.KindUnsignedHeader, sigv4.KindMalformedCredential,
		sigv4.KindCredentialDateMismatch, sigv4.KindPayloadHashNotAccepted:
		return sesapi.NewError(http.StatusForbidden, sesapi.TypeIncompleteSig, e.Message)
	case sigv4.KindRequestTimeTooSkewed, sigv4.KindSignatureMismatch, sigv4.KindWrongService:
		return sesapi.NewError(http.StatusForbidden, sesapi.TypeInvalidSignature, e.Message)
	case sigv4.KindUnknownAccessKey, sigv4.KindInvalidSessionToken:
		return sesapi.NewError(http.StatusForbidden, sesapi.TypeUnrecognizedClient, e.Message)
	case sigv4.KindExpiredSessionToken:
		return sesapi.NewError(http.StatusForbidden, sesapi.TypeExpiredToken, e.Message)
	case sigv4.KindPayloadHashMismatch, sigv4.KindBodyUnreadable:
		return sesapi.ErrBadRequest(e.Message)
	case sigv4.KindBodyTooLarge:
		return sesapi.NewError(
			http.StatusRequestEntityTooLarge,
			sesapi.TypeEntityTooLarge,
			e.Message,
		)
	default:
		return e
	}
}
