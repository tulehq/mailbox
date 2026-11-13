// Package sesapi is the SES v2 wire layer: the restJson1 envelope the SDK
// speaks, the request and response shapes, the input validation the service
// applies before a request reaches the store, and the error documents, which
// the retrieval API shares.
//
// AWS calls the service SES and its SDK package "sesv2"; this service is
// mailbox, so the wire details live here rather than spelling the AWS names
// into the store or the modules.
package sesapi

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"

	"github.com/gasmod/gas"

	"tule.dev/mailbox/internal/httpx"
)

// ContentType is the media type of every JSON request and response body.
const ContentType = "application/json"

// requestIDHeader is where AWS reports the ID of a request, which clients
// quote in bug reports.
const requestIDHeader = "X-Amzn-Requestid"

// Write sends v as the JSON body of a successful response.
func Write(ctx gas.Context, v any) error {
	body, err := json.Marshal(v)
	if err != nil {
		return WriteError(ctx, err)
	}

	w := ctx.ResponseWriter()
	w.Header().Set("Content-Type", ContentType)
	setRequestID(w, ctx.Request())
	w.WriteHeader(http.StatusOK)

	if _, wErr := w.Write(body); wErr != nil {
		httpx.Logger(ctx).Warn("failed to write response").Err("error", wErr).Send()
	}
	return nil
}

// WriteBytes sends body as a successful response of the given content type.
func WriteBytes(ctx gas.Context, contentType string, body []byte) error {
	w := ctx.ResponseWriter()
	w.Header().Set("Content-Type", contentType)
	setRequestID(w, ctx.Request())
	w.WriteHeader(http.StatusOK)

	if _, wErr := w.Write(body); wErr != nil {
		httpx.Logger(ctx).Warn("failed to write response").Err("error", wErr).Send()
	}
	return nil
}

func setRequestID(w http.ResponseWriter, r *http.Request) {
	if id := httpx.RequestIDOf(r.Context()); id != "" {
		w.Header().Set(requestIDHeader, id)
	}
}

// Decode reads a request body into T. An empty body decodes to the zero
// value, and unknown fields are ignored, as restJson1 expects.
func Decode[T any](ctx gas.Context) (T, error) {
	var body T
	err := json.NewDecoder(ctx.Request().Body).Decode(&body)
	if err != nil && !errors.Is(err, io.EOF) {
		return body, ErrSerialization("The request body is not valid JSON, " +
			"or a field has the wrong type.")
	}
	return body, nil
}

// PathParam returns a path label, decoded. The router matches the raw path
// when the request has one, as it has whenever a label holds an escaped
// character, and then hands the label over still escaped.
func PathParam(ctx gas.Context, name string) (string, error) {
	v := ctx.Param(name)
	if ctx.Request().URL.RawPath == "" {
		return v, nil
	}
	d, err := url.PathUnescape(v)
	if err != nil {
		return "", ErrBadRequest(fmt.Sprintf("The %s in the path is not "+
			"percent-encoded properly.", name))
	}
	return d, nil
}
