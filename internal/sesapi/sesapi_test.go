package sesapi

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"tule.dev/mailbox/internal/contracts"
)

var errUnmapped = errors.New("something the store did not model")

func TestWriteHTTPErrorSendsTheRestJSONShape(t *testing.T) {
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/v2/email/account", http.NoBody)
	WriteHTTPError(w, r, ErrBadRequest("bad input"))

	if w.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", w.Code)
	}
	if got := w.Header().Get("X-Amzn-ErrorType"); got != TypeBadRequest {
		t.Fatalf("X-Amzn-ErrorType = %q, want %s", got, TypeBadRequest)
	}
	if got := w.Header().Get("Content-Type"); got != ContentType {
		t.Fatalf("Content-Type = %q", got)
	}
	var body map[string]string
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode %q: %v", w.Body.String(), err)
	}
	if body["message"] != "bad input" || body["code"] != TypeBadRequest || len(body) != 2 {
		t.Fatalf("body = %v, want code and message", body)
	}
}

func TestToErrorMapsSentinelsAndTheRest(t *testing.T) {
	tests := []struct {
		err    error
		typ    string
		status int
	}{
		{contracts.ErrTemplateNotFound, TypeNotFound, http.StatusNotFound},
		{contracts.ErrIdentityExists, TypeAlreadyExists, http.StatusBadRequest},
		{contracts.ErrTemplateLimit, TypeLimitExceeded, http.StatusBadRequest},
		{contracts.ErrMessageNotFound, TypeNotFound, http.StatusNotFound},
		{contracts.ErrInvalidToken, TypeBadRequest, http.StatusBadRequest},
		{
			fmt.Errorf("wrapped: %w", contracts.ErrIdentityNotFound),
			TypeNotFound,
			http.StatusNotFound,
		},
		{ErrMessageRejected("no"), TypeMessageRejected, http.StatusBadRequest},
		{errUnmapped, TypeInternalFailure, http.StatusInternalServerError},
	}
	for _, tt := range tests {
		t.Run(tt.err.Error(), func(t *testing.T) {
			got := ToError(t.Context(), tt.err)
			if got.Type != tt.typ || got.Status != tt.status {
				t.Fatalf("mapped to %d %s, want %d %s", got.Status, got.Type, tt.status, tt.typ)
			}
		})
	}
}

func TestEpochSecondsKeepsMilliseconds(t *testing.T) {
	b, err := json.Marshal(EpochSeconds(time.UnixMilli(1763028000123)))
	if err != nil || string(b) != "1763028000.123" {
		t.Fatalf("marshal = %s, %v", b, err)
	}
}

func TestAddress(t *testing.T) {
	tests := []struct {
		in, want, err string
	}{
		{in: "a@example.com", want: "a@example.com"},
		{in: "Name <a@example.com>", want: "a@example.com"},
		{in: "=?utf-8?q?N=C3=A9?= <a@example.com>", want: "a@example.com"},
		{in: "nodomain", err: "Missing final '@domain'"},
		{in: "a@@example.com", err: "Illegal address"},
		{in: "é@example.com", err: "7-bit ASCII"},
		{in: "a@example.com (x\r\nBcc: evil@example.com)", err: "control character"},
		{in: "Name\x00 <a@example.com>", err: "control character"},
	}
	for _, tt := range tests {
		t.Run(tt.in, func(t *testing.T) {
			got, err := Address("To", tt.in)
			if tt.err == "" {
				if err != nil || got != tt.want {
					t.Fatalf("address = %q, %v, want %q", got, err, tt.want)
				}
				return
			}
			var apiErr *Error
			if !errors.As(err, &apiErr) || apiErr.Type != TypeBadRequest ||
				!strings.Contains(apiErr.Message, tt.err) {
				t.Fatalf("address = %v, want BadRequestException with %q", err, tt.err)
			}
		})
	}
}

func ptr(s string) *string { return &s }

func TestMessageHeaders(t *testing.T) {
	ok := []MessageHeader{{Name: ptr("X-Thing"), Value: ptr("v")}}
	if err := MessageHeaders("Headers", ok); err != nil {
		t.Fatalf("valid headers: %v", err)
	}
	for name, hs := range map[string][]MessageHeader{
		"reserved":           {{Name: ptr("Subject"), Value: ptr("v")}},
		"reserved, any case": {{Name: ptr("message-id"), Value: ptr("v")}},
		"colon in name":      {{Name: ptr("X:Y"), Value: ptr("v")}},
		"non-ASCII value":    {{Name: ptr("X-A"), Value: ptr("é")}},
		"empty value":        {{Name: ptr("X-A"), Value: ptr("")}},
		"too many":           make([]MessageHeader, MaxMessageHeaders+1),
	} {
		if err := MessageHeaders("Headers", hs); err == nil {
			t.Errorf("%s: headers accepted", name)
		}
	}
}

func TestMessageTags(t *testing.T) {
	if err := MessageTags(
		"EmailTags",
		[]MessageTag{{Name: ptr("a_b-1"), Value: ptr("")}},
	); err != nil {
		t.Fatalf("valid tags: %v", err)
	}
	for _, tag := range []MessageTag{
		{Name: ptr(""), Value: ptr("v")},
		{Name: ptr("a b"), Value: ptr("v")},
		{Name: ptr("a"), Value: ptr("v.w")},
		{Name: ptr(strings.Repeat("a", 257)), Value: ptr("v")},
		{Name: ptr("a")},
	} {
		if err := MessageTags("EmailTags", []MessageTag{tag}); err == nil {
			t.Errorf("tag %v accepted", tag)
		}
	}
}

func TestTags(t *testing.T) {
	if err := Tags([]Tag{{Key: ptr("env"), Value: ptr("dev test/1")}}); err != nil {
		t.Fatalf("valid tags: %v", err)
	}
	for name, tags := range map[string][]Tag{
		"aws prefix": {{Key: ptr("aws:x"), Value: ptr("v")}},
		"duplicate":  {{Key: ptr("k"), Value: ptr("1")}, {Key: ptr("k"), Value: ptr("2")}},
		"empty key":  {{Key: ptr(""), Value: ptr("v")}},
		"bad char":   {{Key: ptr("k*"), Value: ptr("v")}},
		"too many":   make([]Tag, MaxResourceTags+1),
	} {
		if err := Tags(tags); err == nil {
			t.Errorf("%s: tags accepted", name)
		}
	}
}

func TestSingleHeaders(t *testing.T) {
	if err := SingleHeaders([]string{"Received", "received", "Subject"}); err != nil {
		t.Fatalf("a repeatable header refused: %v", err)
	}
	err := SingleHeaders([]string{"Subject", "subject"})
	var apiErr *Error
	if !errors.As(err, &apiErr) || apiErr.Type != TypeMessageRejected {
		t.Fatalf("two Subject headers = %v, want MessageRejected", err)
	}
}

func TestAttachmentName(t *testing.T) {
	if err := AttachmentName("report.pdf"); err != nil {
		t.Fatalf("pdf refused: %v", err)
	}
	for _, name := range []string{"setup.exe", "SCRIPT.JS", "a.b.vbs"} {
		var apiErr *Error
		if err := AttachmentName(name); !errors.As(err, &apiErr) ||
			apiErr.Type != TypeMessageRejected {
			t.Errorf("%s = %v, want MessageRejected", name, err)
		}
	}
}

func TestAttachmentFieldsGoSafelyIntoHeaders(t *testing.T) {
	att := func(f func(*Attachment)) []Attachment {
		a := Attachment{FileName: ptr("f.txt"), RawContent: []byte("x")}
		f(&a)
		return []Attachment{a}
	}
	if err := Attachments("Attachments", att(func(a *Attachment) {
		a.ContentType, a.ContentID, a.ContentDescription = ptr("text/csv; charset=utf-8"),
			ptr("logo1"), ptr("Ünïcode is fine here")
	})); err != nil {
		t.Fatalf("valid attachment: %v", err)
	}
	for name, as := range map[string][]Attachment{
		"CRLF in the description": att(func(a *Attachment) { a.ContentDescription = ptr("d\r\n\r\nx") }),
		"CRLF in the content ID":  att(func(a *Attachment) { a.ContentID = ptr("c\r\nX-Evil: 1") }),
		"non-ASCII content ID":    att(func(a *Attachment) { a.ContentID = ptr("é") }),
		"CRLF in the file name":   att(func(a *Attachment) { a.FileName = ptr("f\r\n.txt") }),
		"type without subtype":    att(func(a *Attachment) { a.ContentType = ptr("text") }),
		"empty subtype":           att(func(a *Attachment) { a.ContentType = ptr("text/") }),
	} {
		var apiErr *Error
		if err := Attachments("Attachments", as); !errors.As(err, &apiErr) ||
			apiErr.Type != TypeBadRequest {
			t.Errorf("%s = %v, want BadRequestException", name, err)
		}
	}
}
