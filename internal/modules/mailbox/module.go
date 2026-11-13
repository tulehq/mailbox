// Package mailbox serves the retrieval API under /_mailbox: the messages
// mailbox accepted, listed, filtered, read back and deleted. It is not an
// AWS API; its errors take the SES API's shape.
package mailbox

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/gasmod/gas"

	"tule.dev/mailbox/internal/authz"
	"tule.dev/mailbox/internal/contracts"
	"tule.dev/mailbox/internal/mailmime"
	"tule.dev/mailbox/internal/sesapi"
)

const moduleName = "tule/modules/mailbox"

// The page sizes of GET /_mailbox/messages.
const (
	defaultLimit = 20
	maxLimit     = 100
)

// Module registers the retrieval routes and serves them.
type Module struct {
	router *gas.Router
	store  contracts.MailboxProvider
	authz  *authz.Authorizer
}

// NewModule returns a Module serving from store, its requests authorized by
// az. It registers its routes when the app initializes it.
func NewModule(
	router *gas.Router,
	store contracts.MailboxProvider,
	az *authz.Authorizer,
) *Module {
	return &Module{router: router, store: store, authz: az}
}

// Name identifies the module to gas.
func (m *Module) Name() string {
	return moduleName
}

// Init registers the module's routes, each guarded by its authorization
// entry: tule:Inspect on the whole service, which the guard evaluates before
// the handler runs.
func (m *Module) Init(context.Context) error {
	routes := []struct {
		h      func(gas.Context) error
		method string
		path   string
	}{
		{m.list, http.MethodGet, "/_mailbox/messages"},
		{m.reset, http.MethodDelete, "/_mailbox/messages"},
		{m.get, http.MethodGet, "/_mailbox/messages/{id}"},
		{m.delete, http.MethodDelete, "/_mailbox/messages/{id}"},
		{m.raw, http.MethodGet, "/_mailbox/messages/{id}/raw"},
		{m.attachment, http.MethodGet, "/_mailbox/messages/{id}/attachments/{index}"},
		{m.failures, http.MethodGet, "/_mailbox/rendering-failures"},
	}
	for _, r := range routes {
		op, ok := authz.Lookup(r.method, r.path)
		if !ok {
			return fmt.Errorf("mailbox: %s %s has no authorization entry", r.method, r.path)
		}
		h := r.h
		m.router.Handle(m, r.method, r.path, func(ctx gas.Context) error {
			if err := h(ctx); err != nil {
				return sesapi.WriteError(ctx, err)
			}
			return nil
		}, gas.MiddlewareFuncWithName("authz "+op.Name, m.authz.Guard(op)))
	}
	return nil
}

// Close releases nothing; the module holds no resources of its own.
func (m *Module) Close(context.Context) error {
	return nil
}

// Tag is a message tag.
type Tag struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

// Header is a message header, its value decoded.
type Header struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

// Attachment describes an attachment; Size is its decoded length.
type Attachment struct {
	Name        string `json:"name"`
	ContentType string `json:"contentType"`
	Size        int    `json:"size"`
}

// Summary is a listed message.
type Summary struct {
	ID               string   `json:"id"`
	Time             string   `json:"time"`
	From             string   `json:"from"`
	Subject          string   `json:"subject"`
	ConfigurationSet string   `json:"configurationSet"`
	To               []string `json:"to"`
	Cc               []string `json:"cc"`
	Bcc              []string `json:"bcc"`
	Tags             []Tag    `json:"tags"`
	Size             int      `json:"size"`
	AttachmentCount  int      `json:"attachmentCount"`
}

// Detail is a message read back whole: its summary, its headers, bodies and
// attachments.
type Detail struct {
	Text        string       `json:"text"`
	HTML        string       `json:"html"`
	Headers     []Header     `json:"headers"`
	Attachments []Attachment `json:"attachments"`
	Summary
}

// Page is one page of a listing; NextCursor is absent on the last.
type Page struct {
	NextCursor string    `json:"nextCursor,omitempty"`
	Items      []Summary `json:"items"`
}

// timeFormat is how times are written: RFC 3339 in UTC, to the millisecond.
const timeFormat = "2006-01-02T15:04:05.000Z07:00"

func summaryOf(msg *contracts.Message) Summary {
	s := Summary{
		ID:               msg.ID,
		Time:             msg.Time.UTC().Format(timeFormat),
		From:             msg.From,
		To:               nonNil(msg.To),
		Cc:               nonNil(msg.Cc),
		Bcc:              nonNil(msg.Bcc),
		Subject:          msg.Subject,
		Tags:             make([]Tag, 0, len(msg.Tags)),
		ConfigurationSet: msg.ConfigurationSet,
		Size:             msg.Size,
		AttachmentCount:  len(msg.Attachments),
	}
	for _, t := range msg.Tags {
		s.Tags = append(s.Tags, Tag{Name: t.Name, Value: t.Value})
	}
	return s
}

func nonNil(s []string) []string {
	if s == nil {
		return []string{}
	}
	return s
}

func (m *Module) list(ctx gas.Context) error {
	f, page, err := filterOf(ctx.Request())
	if err != nil {
		return err
	}
	out, err := m.store.ListMessages(ctx, f, page)
	if err != nil {
		return err
	}
	resp := Page{Items: make([]Summary, 0, len(out.Items)), NextCursor: out.NextToken}
	for i := range out.Items {
		resp.Items = append(resp.Items, summaryOf(&out.Items[i]))
	}
	return sesapi.Write(ctx, resp)
}

// filterOf reads the filters and the page of a listing from the query.
func filterOf(r *http.Request) (contracts.MessageFilter, contracts.PageInput, error) {
	q := r.URL.Query()
	f := contracts.MessageFilter{
		From:             q.Get("from"),
		To:               q.Get("to"),
		Subject:          q.Get("subject"),
		Query:            strings.TrimSpace(q.Get("q")),
		ConfigurationSet: q.Get("configurationSet"),
		MessageID:        q.Get("messageId"),
	}
	page, err := pageOf(q)
	if err != nil {
		return f, page, err
	}
	if f.Since, f.Until, err = timesOf(q); err != nil {
		return f, page, err
	}
	for _, t := range q["tag"] {
		name, value, ok := strings.Cut(t, ":")
		if !ok || name == "" {
			return f, page, sesapi.ErrBadRequest(fmt.Sprintf(
				"The tag filter %q is not name:value.", t))
		}
		f.Tags = append(f.Tags, contracts.MessageTag{Name: name, Value: value})
	}
	return f, page, nil
}

// pageOf reads a listing's limit and cursor, and refuses a query whose
// values hold a NUL, which no stored value has and SQLite's full-text
// search cannot take.
func pageOf(q url.Values) (contracts.PageInput, error) {
	page := contracts.PageInput{Token: q.Get("cursor"), Size: defaultLimit}
	for name, vs := range q {
		for _, v := range vs {
			if strings.ContainsRune(v, 0) {
				return page, sesapi.ErrBadRequest(fmt.Sprintf(
					"The %s parameter contains a NUL character.", name))
			}
		}
	}
	if v := q.Get("limit"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n < 1 || n > maxLimit {
			return page, sesapi.ErrBadRequest(fmt.Sprintf(
				"limit must be a number from 1 to %d.", maxLimit))
		}
		page.Size = n
	}
	return page, nil
}

// timesOf reads a listing's since and until.
func timesOf(q url.Values) (*time.Time, *time.Time, error) {
	since, err := timeParam(q.Get("since"), "since")
	if err != nil {
		return nil, nil, err
	}
	until, err := timeParam(q.Get("until"), "until")
	return since, until, err
}

func timeParam(v, name string) (*time.Time, error) {
	if v == "" {
		return nil, nil
	}
	t, err := time.Parse(time.RFC3339, v)
	if err != nil {
		return nil, sesapi.ErrBadRequest(fmt.Sprintf("%s must be an RFC 3339 time.", name))
	}
	return &t, nil
}

func (m *Module) get(ctx gas.Context) error {
	id, err := sesapi.PathParam(ctx, "id")
	if err != nil {
		return err
	}
	msg, err := m.store.GetMessage(ctx, id)
	if err != nil {
		return err
	}
	d := Detail{
		Summary:     summaryOf(msg),
		Headers:     make([]Header, 0, len(msg.Headers)),
		Text:        msg.Text,
		HTML:        msg.HTML,
		Attachments: make([]Attachment, 0, len(msg.Attachments)),
	}
	for _, h := range msg.Headers {
		d.Headers = append(d.Headers, Header{Name: h.Name, Value: h.Value})
	}
	for _, a := range msg.Attachments {
		d.Attachments = append(d.Attachments, Attachment{
			Name: a.Name, ContentType: a.ContentType, Size: a.Size,
		})
	}
	return sesapi.Write(ctx, d)
}

func (m *Module) raw(ctx gas.Context) error {
	id, err := sesapi.PathParam(ctx, "id")
	if err != nil {
		return err
	}
	b, err := m.store.GetMessageMIME(ctx, id)
	if err != nil {
		return err
	}
	return sesapi.WriteBytes(ctx, "message/rfc822", b)
}

func (m *Module) attachment(ctx gas.Context) error {
	id, err := sesapi.PathParam(ctx, "id")
	if err != nil {
		return err
	}
	index, err := strconv.Atoi(ctx.Param("index"))
	if err != nil || index < 0 {
		return sesapi.ErrBadRequest("The attachment index must be a number from 0.")
	}
	b, err := m.store.GetMessageMIME(ctx, id)
	if err != nil {
		return err
	}
	parsed, err := mailmime.Parse(b)
	if err != nil {
		return fmt.Errorf("parse stored message %s: %w", id, err)
	}
	if index >= len(parsed.Attachments) {
		return contracts.ErrAttachmentNotFound
	}
	a := parsed.Attachments[index]
	return sesapi.WriteBytes(ctx, a.ContentType, a.Content)
}

func (m *Module) delete(ctx gas.Context) error {
	id, err := sesapi.PathParam(ctx, "id")
	if err != nil {
		return err
	}
	if err = m.store.DeleteMessage(ctx, id); err != nil {
		return err
	}
	return noContent(ctx)
}

func (m *Module) reset(ctx gas.Context) error {
	if err := m.store.DeleteMessages(ctx); err != nil {
		return err
	}
	return noContent(ctx)
}

func noContent(ctx gas.Context) error {
	ctx.ResponseWriter().WriteHeader(http.StatusNoContent)
	return nil
}

// Failure is a recorded rendering failure: a templated message accepted and
// then dropped. Template is "" for inline template content.
type Failure struct {
	MessageID        string   `json:"messageId"`
	Time             string   `json:"time"`
	Source           string   `json:"source"`
	Template         string   `json:"template"`
	From             string   `json:"from"`
	ConfigurationSet string   `json:"configurationSet"`
	Error            string   `json:"error"`
	To               []string `json:"to"`
	Cc               []string `json:"cc"`
	Bcc              []string `json:"bcc"`
	Tags             []Tag    `json:"tags"`
}

// FailurePage is one page of rendering failures; NextCursor is absent on
// the last.
type FailurePage struct {
	NextCursor string    `json:"nextCursor,omitempty"`
	Items      []Failure `json:"items"`
}

func (m *Module) failures(ctx gas.Context) error {
	q := ctx.Request().URL.Query()
	page, err := pageOf(q)
	if err != nil {
		return err
	}
	f := contracts.FailureFilter{MessageID: q.Get("messageId"), Template: q.Get("template")}
	if f.Since, f.Until, err = timesOf(q); err != nil {
		return err
	}
	out, err := m.store.ListRenderingFailures(ctx, f, page)
	if err != nil {
		return err
	}
	resp := FailurePage{Items: make([]Failure, 0, len(out.Items)), NextCursor: out.NextToken}
	for _, rf := range out.Items {
		item := Failure{
			MessageID:        rf.MessageID,
			Time:             rf.Time.UTC().Format(timeFormat),
			Source:           rf.Source,
			Template:         rf.Template,
			From:             rf.From,
			ConfigurationSet: rf.ConfigurationSet,
			Error:            rf.Error,
			To:               nonNil(rf.To),
			Cc:               nonNil(rf.Cc),
			Bcc:              nonNil(rf.Bcc),
			Tags:             make([]Tag, 0, len(rf.Tags)),
		}
		for _, t := range rf.Tags {
			item.Tags = append(item.Tags, Tag{Name: t.Name, Value: t.Value})
		}
		resp.Items = append(resp.Items, item)
	}
	return sesapi.Write(ctx, resp)
}
