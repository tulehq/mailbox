// Package email serves the SES v2 API: the restJson1 routes under /v2/email
// of the operations in scope.
package email

import (
	"context"
	"fmt"
	"net/http"
	"strconv"
	"time"

	"github.com/gasmod/gas"

	"tule.dev/mailbox/internal/contracts"
	"tule.dev/mailbox/internal/sesapi"
)

const moduleName = "tule/modules/email"

// Module registers the SES routes and serves the operations behind them.
type Module struct {
	router *gas.Router
	store  contracts.MailboxProvider
	now    func() time.Time
}

// NewModule returns a Module serving from store. It registers its routes
// when the app initializes it.
func NewModule(router *gas.Router, store contracts.MailboxProvider) *Module {
	return &Module{router: router, store: store, now: time.Now}
}

// Name identifies the module to gas.
func (m *Module) Name() string {
	return moduleName
}

// handler serves one operation. Returning an error leaves the response to
// serve, which renders it as an error document.
type handler func(gas.Context) error

// Init registers the module's routes, the paths and methods of the SES v2
// API model.
func (m *Module) Init(context.Context) error {
	routes := []struct {
		h      handler
		method string
		path   string
	}{
		{m.sendEmail, http.MethodPost, "/v2/email/outbound-emails"},
		{m.sendBulkEmail, http.MethodPost, "/v2/email/outbound-bulk-emails"},
		{m.createEmailIdentity, http.MethodPost, "/v2/email/identities"},
		// The SDK model binds ListEmailIdentities to POST /list-identities
		// with a body; the botocore model the AWS CLI reads still binds it to
		// GET /identities with a query. Both are served.
		{m.listEmailIdentities, http.MethodPost, "/v2/email/list-identities"},
		{m.listEmailIdentitiesByQuery, http.MethodGet, "/v2/email/identities"},
		{m.getEmailIdentity, http.MethodGet, "/v2/email/identities/{EmailIdentity}"},
		{m.deleteEmailIdentity, http.MethodDelete, "/v2/email/identities/{EmailIdentity}"},
		{m.createEmailTemplate, http.MethodPost, "/v2/email/templates"},
		{m.listEmailTemplates, http.MethodGet, "/v2/email/templates"},
		{m.getEmailTemplate, http.MethodGet, "/v2/email/templates/{TemplateName}"},
		{m.updateEmailTemplate, http.MethodPut, "/v2/email/templates/{TemplateName}"},
		{m.deleteEmailTemplate, http.MethodDelete, "/v2/email/templates/{TemplateName}"},
		{m.testRenderEmailTemplate, http.MethodPost, "/v2/email/templates/{TemplateName}/render"},
		{m.getAccount, http.MethodGet, "/v2/email/account"},
	}
	for _, r := range routes {
		m.router.Handle(m, r.method, r.path, serve(r.h))
	}
	return nil
}

// Close releases nothing; the module holds no resources of its own.
func (m *Module) Close(context.Context) error {
	return nil
}

func serve(h handler) func(gas.Context) error {
	return func(ctx gas.Context) error {
		if err := h(ctx); err != nil {
			return sesapi.WriteError(ctx, err)
		}
		return nil
	}
}

// pageOf reads a list operation's NextToken and PageSize from the query.
func pageOf(ctx gas.Context, minSize, maxSize int) (contracts.PageInput, error) {
	var size *int
	if v := ctx.Query("PageSize"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil {
			return contracts.PageInput{}, errPageSize(minSize, maxSize)
		}
		size = &n
	}
	return pageInput(ctx.Query("NextToken"), size, minSize, maxSize)
}

// pageInput checks a page size, which must be from minSize to maxSize;
// without one, or with 0, the page is defaultPageSize long.
func pageInput(token string, size *int, minSize, maxSize int) (contracts.PageInput, error) {
	page := contracts.PageInput{Token: token, Size: defaultPageSize}
	if size == nil {
		return page, nil
	}
	if *size < minSize || *size > maxSize {
		return page, errPageSize(minSize, maxSize)
	}
	if *size > 0 {
		page.Size = *size
	}
	return page, nil
}

func errPageSize(minSize, maxSize int) error {
	return sesapi.ErrBadRequest(fmt.Sprintf("PageSize must be a number from %d to %d.",
		minSize, maxSize))
}

// defaultPageSize is the page size of a list request without PageSize: the
// ten the ListEmailTemplates reference says a NextToken fetches.
const defaultPageSize = 10

func wireTags(tags []contracts.Tag) []sesapi.ResponseTag {
	out := make([]sesapi.ResponseTag, 0, len(tags))
	for _, t := range tags {
		out = append(out, sesapi.ResponseTag{Key: t.Key, Value: t.Value})
	}
	return out
}

func storeTags(tags []sesapi.Tag) []contracts.Tag {
	out := make([]contracts.Tag, 0, len(tags))
	for _, t := range tags {
		out = append(out, contracts.Tag{Key: *t.Key, Value: *t.Value})
	}
	return out
}

func deref(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}
