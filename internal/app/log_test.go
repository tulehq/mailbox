package app

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gasmod/gas"

	"tule.dev/mailbox/internal/sesapi"
)

func TestARequestWithoutALoggerFailsAsAnInternalError(t *testing.T) {
	// A request scope whose container has no request logger registered, so
	// resolving one fails. The request must fail visibly rather than answer
	// an empty 200.
	ctx := t.Context()
	scope := gas.NewServiceContainer().NewScope(ctx)
	t.Cleanup(func() {
		if err := scope.Close(ctx); err != nil {
			t.Errorf("close scope: %v", err)
		}
	})
	req := httptest.NewRequest(http.MethodPost, "/v2/email/outbound-emails", http.NoBody)
	req = req.WithContext(gas.WithRequestScope(ctx, scope))

	called := false
	h := withRequestLogger(&gas.NopLogger{})(http.HandlerFunc(
		func(http.ResponseWriter, *http.Request) { called = true }))

	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)

	if called {
		t.Fatal("the handler ran without a request logger")
	}
	if w.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500", w.Code)
	}
	var body sesapi.Error
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode body %q: %v", w.Body.String(), err)
	}
	if body.Type != sesapi.TypeInternalFailure {
		t.Fatalf("error type = %s, want %s", body.Type, sesapi.TypeInternalFailure)
	}
}
