package sesapi

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"

	"github.com/gasmod/gas"

	"tule.dev/mailbox/internal/contracts"
	"tule.dev/mailbox/internal/httpx"
)

// errorTypeHeader carries the error code. restJson1 clients read the code
// from it first, and from the body only when it is absent.
const errorTypeHeader = "X-Amzn-Errortype"

// Error is an error document, of the SES API and of the retrieval API
// alike. SES sends its errors as the X-Amzn-ErrorType header and a body with
// a "message" member, which is what the SDK model gives every SES exception;
// "code" repeats the header's value in the body, so a client of the
// retrieval API reads both from one place. It implements error so handlers
// and the validation helpers can return one directly.
type Error struct {
	Type    string `json:"code"`
	Message string `json:"message"`
	Status  int    `json:"-"`
}

func (e *Error) Error() string {
	return e.Type + ": " + e.Message
}

// NewError builds an error document with the given status and type.
func NewError(status int, errType, message string) *Error {
	return &Error{Status: status, Type: errType, Message: message}
}

// The SES errors this service raises, with the statuses the SES v2 API
// reference and the SDK model give them, and the common errors beside them,
// with the statuses of the SES v2 Common Errors page.
const (
	TypeBadRequest         = "BadRequestException"
	TypeNotFound           = "NotFoundException"
	TypeAlreadyExists      = "AlreadyExistsException"
	TypeLimitExceeded      = "LimitExceededException"
	TypeMessageRejected    = "MessageRejected"
	TypeInternalFailure    = "InternalFailure"
	TypeUnknownOperation   = "UnknownOperationException"
	TypeSerialization      = "SerializationException"
	TypeEntityTooLarge     = "RequestEntityTooLargeException"
	TypeMissingAuthToken   = "MissingAuthenticationTokenException"
	TypeIncompleteSig      = "IncompleteSignature"
	TypeInvalidSignature   = "InvalidSignatureException"
	TypeUnrecognizedClient = "UnrecognizedClientException"
	TypeExpiredToken       = "ExpiredTokenException"
	TypeAccessDenied       = "AccessDeniedException"
)

// ErrBadRequest is the error for input SES calls invalid.
func ErrBadRequest(msg string) *Error {
	return NewError(http.StatusBadRequest, TypeBadRequest, msg)
}

// ErrNotFound is the error for a resource that does not exist.
func ErrNotFound(msg string) *Error {
	return NewError(http.StatusNotFound, TypeNotFound, msg)
}

// ErrMessageRejected is the error for a message SES will not send because of
// its content.
func ErrMessageRejected(msg string) *Error {
	return NewError(http.StatusBadRequest, TypeMessageRejected, msg)
}

// ErrSerialization is the error for a body that is not valid JSON, or whose
// fields have the wrong JSON types.
func ErrSerialization(msg string) *Error {
	return NewError(http.StatusBadRequest, TypeSerialization, msg)
}

// ErrNotAllowed is the AccessDeniedException of a request no identity-based
// policy allows, in the form of AWS's messages. The SES v2 SDK model has no
// AccessDeniedException; the SES v2 Common Errors page gives it, with 403.
func ErrNotAllowed(callerARN, action, resource string) *Error {
	return NewError(http.StatusForbidden, TypeAccessDenied, "User: "+callerARN+
		" is not authorized to perform: "+action+" on resource: "+resource+
		" because no identity-based policy allows the "+action+" action")
}

// ErrExplicitlyDenied is the AccessDeniedException of a request an
// identity-based policy denies, in the form of AWS's messages.
func ErrExplicitlyDenied(callerARN, action, resource string) *Error {
	return NewError(http.StatusForbidden, TypeAccessDenied, "User: "+callerARN+
		" is not authorized to perform: "+action+" on resource: "+resource+
		" with an explicit deny in an identity-based policy")
}

// ErrNoResourcePolicy is the AccessDeniedException of a cross-account
// request that its identity-based policies allow and no resource-based
// policy does, in the form of AWS's messages.
func ErrNoResourcePolicy(callerARN, action, resource string) *Error {
	return NewError(http.StatusForbidden, TypeAccessDenied, "User: "+callerARN+
		" is not authorized to perform: "+action+" on resource: "+resource+
		" because no resource-based policy allows the "+action+" action")
}

// ErrUnknownOperation is the error for a path and method no operation of
// this service is routed at.
func ErrUnknownOperation() *Error {
	return NewError(http.StatusNotFound, TypeUnknownOperation,
		"The requested operation is not recognized by this service.")
}

// ErrInternalFailure is the error every unrecognized failure becomes.
func ErrInternalFailure() *Error {
	return NewError(http.StatusInternalServerError, TypeInternalFailure,
		"The request processing has failed because of an unknown error, exception or failure.")
}

// sentinelErrors maps store-layer sentinels to the errors they become.
var sentinelErrors = []struct {
	err    error
	apiErr *Error
}{
	{contracts.ErrIdentityNotFound, ErrNotFound("Email identity does not exist.")},
	{contracts.ErrIdentityExists, NewError(http.StatusBadRequest, TypeAlreadyExists,
		"Email identity already exists.")},
	{contracts.ErrIdentityLimit, NewError(http.StatusBadRequest, TypeLimitExceeded,
		"Maximum number of email identities reached.")},
	{contracts.ErrTemplateNotFound, ErrNotFound("Email template does not exist.")},
	{contracts.ErrTemplateExists, NewError(http.StatusBadRequest, TypeAlreadyExists,
		"Email template already exists.")},
	{contracts.ErrTemplateLimit, NewError(http.StatusBadRequest, TypeLimitExceeded,
		"Maximum number of email templates reached.")},
	{contracts.ErrMessageNotFound, ErrNotFound("Message does not exist.")},
	{contracts.ErrAttachmentNotFound, ErrNotFound("Attachment does not exist.")},
	{contracts.ErrInvalidToken, ErrBadRequest("Invalid NextToken.")},
}

// ToError maps err to an error document, logging it when it maps to an
// internal error. It returns a copy, safe for the caller to fill in.
func ToError(ctx context.Context, err error) *Error {
	apiErr := toAPIError(err)
	if apiErr.Status == http.StatusInternalServerError {
		httpx.Logger(ctx).Error("request failed").Err("error", err).Send()
	}
	return apiErr
}

func toAPIError(err error) *Error {
	var apiErr *Error
	if errors.As(err, &apiErr) {
		cp := *apiErr
		return &cp
	}

	for _, se := range sentinelErrors {
		if errors.Is(err, se.err) {
			cp := *se.apiErr
			return &cp
		}
	}

	return ErrInternalFailure()
}

// WriteError renders err as an error response.
func WriteError(ctx gas.Context, err error) error {
	writeError(ctx.ResponseWriter(), ctx.Request(), err)
	return nil
}

// WriteHTTPError is WriteError for plain http.Handler middleware, which has no
// gas.Context.
func WriteHTTPError(w http.ResponseWriter, r *http.Request, err error) {
	writeError(w, r, err)
}

func writeError(w http.ResponseWriter, r *http.Request, err error) {
	apiErr := ToError(r.Context(), err)

	body, mErr := json.Marshal(apiErr)
	if mErr != nil {
		httpx.Logger(r.Context()).Error("failed to encode error response").
			Err("error", mErr).Send()
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", ContentType)
	w.Header().Set(errorTypeHeader, apiErr.Type)
	setRequestID(w, r)
	w.WriteHeader(apiErr.Status)

	if _, wErr := w.Write(body); wErr != nil {
		httpx.Logger(r.Context()).Warn("failed to write error response").
			Err("error", wErr).Send()
	}
}
