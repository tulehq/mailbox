//go:build e2e

package e2e

import (
	"context"
	"errors"
	"net"
	"net/http"
	"path/filepath"
	"regexp"
	"slices"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	awshttp "github.com/aws/aws-sdk-go-v2/aws/transport/http"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/sesv2"
	"github.com/aws/aws-sdk-go-v2/service/sesv2/types"
	"github.com/aws/smithy-go"
	"github.com/gasmod/gas"
	"github.com/gasmod/gas/config"

	"tule.dev/mailbox/internal/app"
)

// server is the app under test, served by the app's own *http.Server over a
// real TCP listener: the listener is created here because gas.App.Serve
// exposes neither the listener nor its port, and everything else is the
// server gas built from the bound configuration, reached over the network
// and shut down through gas.App.Stop.
type server struct {
	app      *gas.App
	listener net.Listener
	client   *http.Client
	served   chan error
	URL      string
	Addr     string
	stopped  bool
}

// clientTimeout bounds a test's own requests, so a hung server fails the test
// instead of the suite's timeout.
const clientTimeout = 60 * time.Second

// region is the region every client signs for.
const region = "us-east-1"

// newClient starts the app on a fresh store and returns an SES client and a
// retrieval client pointed at it.
func newClient(t *testing.T) (*sesv2.Client, *mailbox) {
	t.Helper()
	srv := startServer(t, nil)
	return clientFor(srv), mailboxFor(srv)
}

// startServer starts the app on a fresh store, with env setting extra TULE_
// variables. It accepts the test/test credentials clientFor signs with unless
// env changes them.
func startServer(t *testing.T, env map[string]string) *server {
	t.Helper()

	setEnv(t, env)

	cfg, err := app.LoadConfigFrom(config.NewEnvProvider(
		config.WithEnvSeparator("_"),
		config.WithEnvPrefix("TULE_"),
	))
	if err != nil {
		t.Fatalf("load config: %v", err)
	}

	a, err := app.New(cfg)
	if err != nil {
		t.Fatalf("new app: %v", err)
	}

	// Start binds the configuration and initializes the services, so the
	// server built after it carries the configured timeouts.
	if err = a.Start(context.Background()); err != nil {
		t.Fatalf("start app: %v", err)
	}

	srv := serve(t, a)
	t.Cleanup(func() { srv.Stop(t) })
	return srv
}

func setEnv(t *testing.T, env map[string]string) {
	t.Helper()

	t.Setenv("TULE_GasEnv", "testing")
	t.Setenv("TULE_Store_Path", filepath.Join(t.TempDir(), "mailbox.db"))
	t.Setenv("TULE_Auth_AccessKeyID", "test")
	t.Setenv("TULE_Auth_SecretAccessKey", "test")
	for k, v := range env {
		t.Setenv(k, v)
	}
}

// serve puts the app's own server on a loopback listener on a free port.
func serve(t *testing.T, a *gas.App) *server {
	t.Helper()

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}

	srv := &server{
		app:      a,
		listener: listener,
		client:   &http.Client{Timeout: clientTimeout},
		served:   make(chan error, 1),
		Addr:     listener.Addr().String(),
		URL:      "http://" + listener.Addr().String(),
	}

	go func() {
		srv.served <- a.Server().Serve(listener)
	}()

	return srv
}

// Client returns an HTTP client for the server.
func (s *server) Client() *http.Client {
	return s.client
}

// Stop shuts the app down the way a signal does, through gas.App.Stop, and
// fails the test if the shutdown or the server itself reported an error. It
// is idempotent, so a test can stop the server early and let the cleanup run
// anyway.
func (s *server) Stop(t *testing.T) {
	t.Helper()

	if s.stopped {
		return
	}
	s.stopped = true

	// Close the client's spare connections first; the server would otherwise
	// wait for them to age out during the shutdown.
	s.client.CloseIdleConnections()

	if err := s.app.Stop(context.Background()); err != nil {
		t.Errorf("stop app: %v", err)
	}

	select {
	case err := <-s.served:
		if err != nil && !errors.Is(err, http.ErrServerClosed) {
			t.Errorf("serve: %v", err)
		}
	case <-time.After(clientTimeout):
		t.Error("serve did not return after shutdown")
	}
}

// clientFor returns an SES v2 client for srv, with the test/test credentials
// unless opts change them. It does not retry, so a refused request fails at
// once.
func clientFor(srv *server, opts ...func(*sesv2.Options)) *sesv2.Client {
	return sesv2.New(sesv2.Options{
		Region:           region,
		BaseEndpoint:     aws.String(srv.URL),
		Credentials:      credentials.NewStaticCredentialsProvider("test", "test", ""),
		HTTPClient:       srv.Client(),
		RetryMaxAttempts: 1,
	}, opts...)
}

// sesClientWith returns an SES v2 client for srv signing with creds.
func sesClientWith(srv *server, creds aws.Credentials) *sesv2.Client {
	return clientFor(srv, func(o *sesv2.Options) {
		o.Credentials = credentials.StaticCredentialsProvider{Value: creds}
	})
}

// send sends a SendEmail request and returns the message ID SES answered,
// failing the test on any error.
func send(t *testing.T, c *sesv2.Client, in *sesv2.SendEmailInput) string {
	t.Helper()

	out, err := c.SendEmail(t.Context(), in)
	requireNoErr(t, err, "send email")
	id := aws.ToString(out.MessageId)
	if id == "" {
		t.Fatal("send email returned no message ID")
	}
	return id
}

// simpleInput returns a SendEmail input with Simple content: a text body,
// from from to the To addresses.
func simpleInput(from, subject, text string, to ...string) *sesv2.SendEmailInput {
	return &sesv2.SendEmailInput{
		FromEmailAddress: aws.String(from),
		Destination:      &types.Destination{ToAddresses: to},
		Content: &types.EmailContent{Simple: &types.Message{
			Subject: &types.Content{Data: aws.String(subject)},
			Body:    &types.Body{Text: &types.Content{Data: aws.String(text)}},
		}},
	}
}

// errOf returns the error of an SDK call and drops its output, for tests that
// call an operation only for the error it reports.
func errOf[T any](_ T, err error) error {
	return err
}

func requireNoErr(t *testing.T, err error, what string) {
	t.Helper()
	if err != nil {
		t.Fatalf("%s: %v", what, err)
	}
}

func requireEqual[T comparable](t *testing.T, got, want T, what string) {
	t.Helper()
	if got != want {
		t.Fatalf("%s: got %v, want %v", what, got, want)
	}
}

func requireSameSet(t *testing.T, got, want []string, what string) {
	t.Helper()
	g, w := slices.Sorted(slices.Values(got)), slices.Sorted(slices.Values(want))
	if !slices.Equal(g, w) {
		t.Fatalf("%s: got %q, want %q", what, got, want)
	}
}

func requireMatch(t *testing.T, re *regexp.Regexp, got, what string) {
	t.Helper()
	if !re.MatchString(got) {
		t.Fatalf("%s: %q does not match %s", what, got, re)
	}
}

// requireAs fails unless err matches the modeled SDK error type T.
func requireAs[T error](t *testing.T, err error) {
	t.Helper()
	var want T
	if !errors.As(err, &want) {
		t.Fatalf("want error of type %T, got %v", want, err)
	}
}

// requireRejected fails unless err is one of the modeled errors SES v2
// answers invalid input of a send with, BadRequestException ("The input you
// provided is invalid") or MessageRejected ("The message can't be sent
// because it contains invalid content"), with HTTP 400 (SendEmail API
// reference, Errors). Which of the two SES answers for a given fault is not
// documented, so either is accepted.
func requireRejected(t *testing.T, err error) {
	t.Helper()
	var badRequest *types.BadRequestException
	var rejected *types.MessageRejected
	if !errors.As(err, &badRequest) && !errors.As(err, &rejected) {
		t.Fatalf("want BadRequestException or MessageRejected, got %v", err)
	}
	requireStatus(t, err, http.StatusBadRequest)
}

// requireStatus fails unless err came with the given HTTP status.
func requireStatus(t *testing.T, err error, status int) {
	t.Helper()
	var re *awshttp.ResponseError
	if !errors.As(err, &re) {
		t.Fatalf("want an HTTP response error with status %d, got %v", status, err)
	}
	requireEqual(t, re.HTTPStatusCode(), status, "HTTP status")
}

// requireAPIError fails unless err is an API error the server answered,
// rather than a client-side failure.
func requireAPIError(t *testing.T, err error) {
	t.Helper()
	var apiErr smithy.APIError
	if !errors.As(err, &apiErr) {
		t.Fatalf("want an API error, got %v", err)
	}
}
