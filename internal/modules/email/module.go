// Package email serves the SES v2 API: the restJson1 routes under /v2/email
// of the operations in scope.
package email

import (
	"context"
	"fmt"
	"net/http"
	"strconv"
	"sync"
	"time"

	"github.com/gasmod/gas"

	"tule.dev/mailbox/internal/authz"
	"tule.dev/mailbox/internal/contracts"
	"tule.dev/mailbox/internal/sesapi"
)

const moduleName = "tule/modules/email"

// Module registers the SES routes and serves the operations behind them.
type Module struct {
	router *gas.Router
	store  contracts.MailboxProvider
	authz  *authz.Authorizer
	now    func() time.Time
	// resources orders the operations on identities and templates; see
	// serve.
	resources sync.RWMutex
}

// NewModule returns a Module serving from store, its requests authorized by
// az. It registers its routes when the app initializes it.
func NewModule(
	router *gas.Router,
	store contracts.MailboxProvider,
	az *authz.Authorizer,
) *Module {
	return &Module{router: router, store: store, authz: az, now: time.Now}
}

// Name identifies the module to gas.
func (m *Module) Name() string {
	return moduleName
}

// handler serves one operation. Returning an error leaves the response to
// serve, which renders it as an error document.
type handler func(gas.Context) error

// Init registers the module's routes, the paths and methods of the SES v2
// API model, each guarded by its authorization entry.
func (m *Module) Init(context.Context) error {
	routes := []struct {
		h      handler
		method string
		path   string
		// writes marks an operation that creates, changes or deletes an
		// identity, an identity's policy or a template.
		writes bool
	}{
		{m.sendEmail, http.MethodPost, "/v2/email/outbound-emails", false},
		{m.sendBulkEmail, http.MethodPost, "/v2/email/outbound-bulk-emails", false},
		{m.createEmailIdentity, http.MethodPost, "/v2/email/identities", true},
		// The SDK model binds ListEmailIdentities to POST /list-identities
		// with a body; the botocore model the AWS CLI reads still binds it to
		// GET /identities with a query. Both are served.
		{m.listEmailIdentities, http.MethodPost, "/v2/email/list-identities", false},
		{m.listEmailIdentitiesByQuery, http.MethodGet, "/v2/email/identities", false},
		{m.getEmailIdentity, http.MethodGet, "/v2/email/identities/{EmailIdentity}", false},
		{m.deleteEmailIdentity, http.MethodDelete, "/v2/email/identities/{EmailIdentity}", true},
		{
			m.createEmailIdentityPolicy,
			http.MethodPost,
			"/v2/email/identities/{EmailIdentity}/policies/{PolicyName}",
			true,
		},
		{
			m.getEmailIdentityPolicies,
			http.MethodGet,
			"/v2/email/identities/{EmailIdentity}/policies",
			false,
		},
		{
			m.updateEmailIdentityPolicy,
			http.MethodPut,
			"/v2/email/identities/{EmailIdentity}/policies/{PolicyName}",
			true,
		},
		{
			m.deleteEmailIdentityPolicy,
			http.MethodDelete,
			"/v2/email/identities/{EmailIdentity}/policies/{PolicyName}",
			true,
		},
		{m.createEmailTemplate, http.MethodPost, "/v2/email/templates", true},
		{m.listEmailTemplates, http.MethodGet, "/v2/email/templates", false},
		{m.getEmailTemplate, http.MethodGet, "/v2/email/templates/{TemplateName}", false},
		{m.updateEmailTemplate, http.MethodPut, "/v2/email/templates/{TemplateName}", true},
		{m.deleteEmailTemplate, http.MethodDelete, "/v2/email/templates/{TemplateName}", true},
		{
			m.testRenderEmailTemplate,
			http.MethodPost,
			"/v2/email/templates/{TemplateName}/render",
			false,
		},
		{m.getAccount, http.MethodGet, "/v2/email/account", false},
	}
	for _, r := range routes {
		op, ok := authz.Lookup(r.method, r.path)
		if !ok {
			return fmt.Errorf("email: %s %s has no authorization entry", r.method, r.path)
		}
		m.router.Handle(m, r.method, r.path, m.serve(r.h, r.writes),
			gas.MiddlewareFuncWithName("authz "+op.Name, m.authz.Guard(op)))
	}
	return nil
}

// Close releases nothing; the module holds no resources of its own.
func (m *Module) Close(context.Context) error {
	return nil
}

// serve runs h under the resource lock: shared, or exclusive for an
// operation that writes an identity, an identity's policy or a template. An
// operation is authorized on the identities and templates it looks up, with
// the policies of the identities it sends from, and then acts on them;
// holding the lock from one to the other keeps a concurrent create, update
// or delete from making it act on a resource other than the one evaluated,
// or under policies other than the ones evaluated.
// Nothing changes a resource's tags, so they cannot go stale in between.
func (m *Module) serve(h handler, writes bool) func(gas.Context) error {
	return func(ctx gas.Context) error {
		if writes {
			m.resources.Lock()
			defer m.resources.Unlock()
		} else {
			m.resources.RLock()
			defer m.resources.RUnlock()
		}
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
