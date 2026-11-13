package email

import (
	"context"
	"net/http"
	"net/http/httptest"
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/gasmod/gas"
)

func gasContext() gas.Context {
	return gas.NewContext(context.Background(), httptest.NewRecorder(),
		httptest.NewRequest(http.MethodGet, "/", nil))
}

// TestAWriteWaitsForTheOperationInFlight holds an operation that has
// looked its resources up, and been authorized on them, to act on those
// resources: a create or delete cannot run in between.
func TestAWriteWaitsForTheOperationInFlight(t *testing.T) {
	m := &Module{}
	var (
		mu    sync.Mutex
		order []string
	)
	record := func(s string) {
		mu.Lock()
		defer mu.Unlock()
		order = append(order, s)
	}
	authorized, release := make(chan struct{}), make(chan struct{})
	read := m.serve(whole(func(gas.Context) error {
		close(authorized)
		<-release
		record("act")
		return nil
	}), false)
	write := m.serve(whole(func(gas.Context) error {
		record("write")
		return nil
	}), true)

	readDone := make(chan struct{})
	go func() {
		_ = read(gasContext())
		close(readDone)
	}()
	<-authorized
	writeDone := make(chan struct{})
	go func() {
		_ = write(gasContext())
		close(writeDone)
	}()
	select {
	case <-writeDone:
		t.Fatal("a write ran between authorization and the act")
	case <-time.After(50 * time.Millisecond):
	}
	close(release)
	<-readDone
	<-writeDone
	if !slices.Equal(order, []string{"act", "write"}) {
		t.Fatalf("order = %v", order)
	}
}
