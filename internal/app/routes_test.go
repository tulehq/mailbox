package app

import (
	"context"
	"path/filepath"
	"testing"

	"github.com/gasmod/gas"

	"tule.dev/mailbox/internal/authz"
	"tule.dev/mailbox/internal/modules/health"
)

// TestEveryRouteHasAnAuthorizationEntry holds the routes the app serves and
// the authorization table to each other: every route but the health probes
// has an entry, and every entry is routed.
func TestEveryRouteHasAnAuthorizationEntry(t *testing.T) {
	routed := map[string]bool{}
	for owner, routes := range appRoutes(t) {
		for _, r := range routes {
			if r.Path == health.HealthPath || r.Path == health.ReadyPath {
				continue
			}
			routed[r.Method+" "+r.Path] = true
			if _, ok := authz.Lookup(r.Method, r.Path); !ok {
				t.Errorf("%s routes %s %s, which has no authorization entry", owner, r.Method,
					r.Path)
			}
		}
	}
	for _, op := range authz.Operations() {
		if !routed[op.Method+" "+op.Path] {
			t.Errorf("%s (%s %s) has an entry but no route", op.Name, op.Method, op.Path)
		}
	}
	if len(routed) == 0 {
		t.Fatal("the app routes nothing")
	}
}

// appRoutes starts the app and returns the routes it serves, by owner.
func appRoutes(t *testing.T) map[string][]gas.RegisteredRoute {
	t.Helper()
	t.Setenv("TULE_Store_Path", filepath.Join(t.TempDir(), "mailbox.db"))
	cfg, err := loadEnvConfig(t, "test", "test")
	if err != nil {
		t.Fatalf("load config: %v", err)
	}
	a, err := New(cfg)
	if err != nil {
		t.Fatalf("new app: %v", err)
	}
	if err = a.Start(context.Background()); err != nil {
		t.Fatalf("start app: %v", err)
	}
	t.Cleanup(func() {
		if sErr := a.Shutdown(context.Background()); sErr != nil {
			t.Errorf("shutdown: %v", sErr)
		}
	})

	return a.Router().Routes()
}
