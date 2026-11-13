//go:build e2e

package e2e

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	v4 "github.com/aws/aws-sdk-go-v2/aws/signer/v4"
)

// mailbox is a client of the retrieval API under /_mailbox/, which is not an
// AWS API: each request is signed SigV4 for service ses, as the SES API is.
type mailbox struct {
	srv     *server
	signer  *v4.Signer
	creds   aws.Credentials
	service string
}

// mailboxFor returns a retrieval client for srv signing with test/test.
func mailboxFor(srv *server) *mailbox {
	return mailboxWith(srv, aws.Credentials{AccessKeyID: "test", SecretAccessKey: "test"})
}

// mailboxWith returns a retrieval client for srv signing with creds.
func mailboxWith(srv *server, creds aws.Credentials) *mailbox {
	return &mailbox{srv: srv, signer: v4.NewSigner(), creds: creds, service: "ses"}
}

// response is what the retrieval API answered.
type response struct {
	Header http.Header
	Body   []byte
	Status int
}

// summary is a listed message: id, time (RFC 3339 UTC with milliseconds),
// from as sent, to, cc and bcc (always arrays), subject, tags (name and
// value, in sent order), configurationSet ("" when none), size (bytes of the
// stored MIME) and attachment count.
type summary struct {
	Time             string      `json:"time"`
	ID               string      `json:"id"`
	From             string      `json:"from"`
	Subject          string      `json:"subject"`
	ConfigurationSet string      `json:"configurationSet"`
	To               []string    `json:"to"`
	Cc               []string    `json:"cc"`
	Bcc              []string    `json:"bcc"`
	Tags             []nameValue `json:"tags"`
	Size             int64       `json:"size"`
	AttachmentCount  int         `json:"attachmentCount"`
}

// nameValue is a tag or a header.
type nameValue struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

// message is a message in full: the summary fields plus headers (in message
// order, values decoded from RFC 2047), text and HTML ("" when absent) and
// the attachments' metadata.
type message struct {
	Text        string       `json:"text"`
	HTML        string       `json:"html"`
	Headers     []nameValue  `json:"headers"`
	Attachments []attachment `json:"attachments"`
	summary
}

// attachment is an attachment's metadata; size is its decoded bytes.
type attachment struct {
	Name        string `json:"name"`
	ContentType string `json:"contentType"`
	Size        int64  `json:"size"`
}

// page is a page of the message list; nextCursor is omitted on the last.
type page struct {
	NextCursor string    `json:"nextCursor"`
	Items      []summary `json:"items"`
}

// timeFormat is the shape of the time field: RFC 3339, UTC, milliseconds.
var timeFormat = regexp.MustCompile(`^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$`)

// at returns the summary's time, failing unless it has the pinned shape.
func (s summary) at(t *testing.T) time.Time {
	t.Helper()
	requireMatch(t, timeFormat, s.Time, "time of "+s.ID)
	v, err := time.Parse(time.RFC3339Nano, s.Time)
	requireNoErr(t, err, "parse time "+s.Time)
	return v
}

// apiError is the retrieval API's error body: a code and a message.
type apiError struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}

// do sends a signed request and returns the response, failing the test only
// when the request cannot be sent.
func (m *mailbox) do(t *testing.T, method, path string, query url.Values) response {
	t.Helper()

	req := m.request(t, method, path, query)
	sum := sha256.Sum256(nil)
	err := m.signer.SignHTTP(context.Background(), m.creds, req, hex.EncodeToString(sum[:]),
		m.service, region, time.Now())
	requireNoErr(t, err, "sign "+method+" "+path)
	return m.send(t, req)
}

// doUnsigned sends a request with no signature.
func (m *mailbox) doUnsigned(t *testing.T, method, path string) response {
	t.Helper()
	return m.send(t, m.request(t, method, path, nil))
}

func (m *mailbox) request(t *testing.T, method, path string, query url.Values) *http.Request {
	t.Helper()

	u := m.srv.URL + path
	if len(query) > 0 {
		u += "?" + query.Encode()
	}
	req, err := http.NewRequestWithContext(context.Background(), method, u, http.NoBody)
	requireNoErr(t, err, "build "+method+" "+path)
	return req
}

func (m *mailbox) send(t *testing.T, req *http.Request) response {
	t.Helper()

	res, err := m.srv.Client().Do(req)
	requireNoErr(t, err, req.Method+" "+req.URL.Path)
	defer func() { _ = res.Body.Close() }()

	body, err := io.ReadAll(res.Body)
	requireNoErr(t, err, "read "+req.Method+" "+req.URL.Path)
	return response{Status: res.StatusCode, Header: res.Header, Body: body}
}

// list lists messages with the given filters and returns the page, failing
// unless the API answered 200.
func (m *mailbox) list(t *testing.T, query url.Values) page {
	t.Helper()

	res := m.do(t, http.MethodGet, "/_mailbox/messages", query)
	requireOK(t, res, "list messages")
	var p page
	decode(t, res, &p)
	var shape struct {
		NextCursor *string           `json:"nextCursor"`
		Items      []json.RawMessage `json:"items"`
	}
	decode(t, res, &shape)
	if shape.NextCursor != nil && *shape.NextCursor == "" {
		t.Fatalf("nextCursor is present but empty, want it omitted: %s", res.Body)
	}
	for _, item := range shape.Items {
		requireArrays(t, item, "to", "cc", "bcc", "tags")
	}
	return p
}

// listAll lists every message matching query, following the cursor.
func (m *mailbox) listAll(t *testing.T, query url.Values) []summary {
	t.Helper()

	var all []summary
	q := url.Values{}
	for k, v := range query {
		q[k] = v
	}
	for range 1000 {
		p := m.list(t, q)
		all = append(all, p.Items...)
		if p.NextCursor == "" {
			return all
		}
		q.Set("cursor", p.NextCursor)
	}
	t.Fatal("the cursor did not end after 1000 pages")
	return nil
}

// byMessageID returns the one stored message with the SES message ID id,
// found through the messageId filter.
func (m *mailbox) byMessageID(t *testing.T, id string) summary {
	t.Helper()

	p := m.list(t, url.Values{"messageId": {id}})
	if len(p.Items) != 1 {
		t.Fatalf("messages with message ID %s: got %d, want 1", id, len(p.Items))
	}
	return p.Items[0]
}

// get returns the message in full.
func (m *mailbox) get(t *testing.T, id string) message {
	t.Helper()

	res := m.do(t, http.MethodGet, "/_mailbox/messages/"+url.PathEscape(id), nil)
	requireOK(t, res, "get message "+id)
	var msg message
	decode(t, res, &msg)
	requireArrays(t, res.Body, "to", "cc", "bcc", "tags", "headers", "attachments")
	return msg
}

// raw returns the message's MIME, checking it is served as message/rfc822.
func (m *mailbox) raw(t *testing.T, id string) []byte {
	t.Helper()

	res := m.do(t, http.MethodGet, "/_mailbox/messages/"+url.PathEscape(id)+"/raw", nil)
	requireOK(t, res, "get raw message "+id)
	requireMediaType(t, res, "message/rfc822")
	return res.Body
}

// attachmentAt returns the response for the attachment at index.
func (m *mailbox) attachmentAt(t *testing.T, id string, index int) response {
	t.Helper()
	return m.do(t, http.MethodGet,
		"/_mailbox/messages/"+url.PathEscape(id)+"/attachments/"+strconv.Itoa(index), nil)
}

// remove deletes one message.
func (m *mailbox) remove(t *testing.T, id string) {
	t.Helper()
	res := m.do(t, http.MethodDelete, "/_mailbox/messages/"+url.PathEscape(id), nil)
	requireSuccess(t, res, "delete message "+id)
}

// reset deletes every message.
func (m *mailbox) reset(t *testing.T) {
	t.Helper()
	res := m.do(t, http.MethodDelete, "/_mailbox/messages", nil)
	requireSuccess(t, res, "reset")
}

// stored returns the full message and its MIME for the SES message ID id.
func (m *mailbox) stored(t *testing.T, messageID string) (message, *parsedMIME) {
	t.Helper()
	s := m.byMessageID(t, messageID)
	return m.get(t, s.ID), parseMIME(t, m.raw(t, s.ID))
}

func decode(t *testing.T, res response, v any) {
	t.Helper()
	if err := json.Unmarshal(res.Body, v); err != nil {
		t.Fatalf("decode %s: %v", res.Body, err)
	}
}

func requireOK(t *testing.T, res response, what string) {
	t.Helper()
	if res.Status != http.StatusOK {
		t.Fatalf("%s: status %d, want 200: %s", what, res.Status, res.Body)
	}
}

// requireSuccess accepts any 2xx: the design does not say whether a
// delete answers 200 or 204.
func requireSuccess(t *testing.T, res response, what string) {
	t.Helper()
	if res.Status < 200 || res.Status > 299 {
		t.Fatalf("%s: status %d, want 2xx: %s", what, res.Status, res.Body)
	}
}

// requireAPIErrorBody fails unless res has the given status, an
// X-Amzn-ErrorType header and a JSON body {code, message} with the same
// code. An empty code accepts any code, for refusals whose code is not
// pinned.
func requireAPIErrorBody(t *testing.T, res response, status int, code, what string) {
	t.Helper()
	if res.Status != status {
		t.Fatalf("%s: status %d, want %d: %s", what, res.Status, status, res.Body)
	}
	var e apiError
	if err := json.Unmarshal(res.Body, &e); err != nil {
		t.Fatalf("%s: error body is not JSON: %v: %s", what, err, res.Body)
	}
	if e.Code == "" || e.Message == "" {
		t.Fatalf("%s: error body lacks a code or a message: %s", what, res.Body)
	}
	header, _, _ := strings.Cut(res.Header.Get("X-Amzn-ErrorType"), ":")
	if header == "" {
		t.Fatalf("%s: no X-Amzn-ErrorType header", what)
	}
	requireEqual(t, header, e.Code, what+": X-Amzn-ErrorType against the body's code")
	if code != "" {
		requireEqual(t, e.Code, code, what+": error code")
	}
}

// requireArrays fails unless each field of the JSON object raw is an array,
// never null or absent.
func requireArrays(t *testing.T, raw []byte, fields ...string) {
	t.Helper()
	var obj map[string]json.RawMessage
	if err := json.Unmarshal(raw, &obj); err != nil {
		t.Fatalf("not a JSON object: %v: %s", err, raw)
	}
	for _, f := range fields {
		if v := bytes.TrimSpace(obj[f]); len(v) == 0 || v[0] != '[' {
			t.Fatalf("field %s is %s, want an array: %s", f, obj[f], raw)
		}
	}
}

func requireMediaType(t *testing.T, res response, want string) {
	t.Helper()
	got, _, _ := strings.Cut(res.Header.Get("Content-Type"), ";")
	requireEqual(t, strings.ToLower(strings.TrimSpace(got)), want, "Content-Type")
}

// ids returns the ids of items, in order.
func ids(items []summary) []string {
	out := make([]string, 0, len(items))
	for _, s := range items {
		out = append(out, s.ID)
	}
	return out
}

// tagsOf returns tags as a map.
func tagsOf(tags []nameValue) map[string]string {
	out := make(map[string]string, len(tags))
	for _, tag := range tags {
		out[tag.Name] = tag.Value
	}
	return out
}

// headerValues returns the values of the header name, in message order,
// matching the name without regard to case.
func headerValues(headers []nameValue, name string) []string {
	var out []string
	for _, h := range headers {
		if strings.EqualFold(h.Name, name) {
			out = append(out, h.Value)
		}
	}
	return out
}

// requireBytes fails unless got equals want.
func requireBytes(t *testing.T, got, want []byte, what string) {
	t.Helper()
	if !bytes.Equal(got, want) {
		t.Fatalf(
			"%s: got %d bytes %.200q, want %d bytes %.200q",
			what,
			len(got),
			got,
			len(want),
			want,
		)
	}
}
