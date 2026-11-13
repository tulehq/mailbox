package app

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	v4 "github.com/aws/aws-sdk-go-v2/aws/signer/v4"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/sesv2"
	"github.com/aws/aws-sdk-go-v2/service/sesv2/types"
)

// startApp starts the app on a store in dir and returns an SDK client for
// its handler, and the server. The full server, over TCP, is what test/e2e
// drives; this only checks the wiring, the protocol and the store meet as
// the SDK expects.
func startApp(t *testing.T, dir string) (*sesv2.Client, *httptest.Server) {
	t.Helper()
	t.Setenv("TULE_Store_Path", filepath.Join(dir, "nested", "mailbox.db"))

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
	srv := httptest.NewServer(a.Handler())
	t.Cleanup(func() {
		srv.Close()
		if sErr := a.Shutdown(context.Background()); sErr != nil {
			t.Errorf("shutdown: %v", sErr)
		}
	})

	return sesv2.New(sesv2.Options{
		Region:           "us-east-1",
		BaseEndpoint:     aws.String(srv.URL),
		Credentials:      credentials.NewStaticCredentialsProvider("test", "test", ""),
		HTTPClient:       srv.Client(),
		RetryMaxAttempts: 1,
	}), srv
}

func TestTheSDKSendsAMessageAndSeesItCounted(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	c, _ := startApp(t, dir)

	out, err := c.SendEmail(ctx, &sesv2.SendEmailInput{
		FromEmailAddress: aws.String("sender@example.com"),
		Destination: &types.Destination{
			ToAddresses:  []string{"a@example.com"},
			BccAddresses: []string{"b@example.com"},
		},
		Content: &types.EmailContent{Simple: &types.Message{
			Subject: &types.Content{Data: aws.String("Hello")},
			Body:    &types.Body{Text: &types.Content{Data: aws.String("Hi.")}},
		}},
	})
	if err != nil {
		t.Fatalf("send email: %v", err)
	}
	if aws.ToString(out.MessageId) == "" {
		t.Fatal("send email answered no MessageId")
	}

	acct, err := c.GetAccount(ctx, &sesv2.GetAccountInput{})
	if err != nil {
		t.Fatalf("get account: %v", err)
	}
	if !acct.ProductionAccessEnabled || !acct.SendingEnabled ||
		acct.SendQuota.SentLast24Hours != 2 {
		t.Fatalf("account = %+v, want production access, sending, and 2 sent", acct)
	}

	// The store is the SQLite file under the configured path, created with
	// the directory it sits in.
	if _, err = os.Stat(filepath.Join(dir, "nested", "mailbox.db")); err != nil {
		t.Fatalf("store file: %v", err)
	}
}

func TestTheSDKDecodesErrors(t *testing.T) {
	ctx := context.Background()
	c, _ := startApp(t, t.TempDir())

	_, err := c.GetEmailTemplate(
		ctx,
		&sesv2.GetEmailTemplateInput{TemplateName: aws.String("none")},
	)
	var notFound *types.NotFoundException
	if !errors.As(err, &notFound) || aws.ToString(notFound.Message) == "" {
		t.Fatalf("get missing template = %v, want NotFoundException with a message", err)
	}

	_, err = c.SendEmail(ctx, &sesv2.SendEmailInput{
		FromEmailAddress: aws.String("not-an-address"),
		Content: &types.EmailContent{Simple: &types.Message{
			Subject: &types.Content{Data: aws.String("x")}, Body: &types.Body{},
		}},
	})
	var bad *types.BadRequestException
	if !errors.As(err, &bad) {
		t.Fatalf("send from a bad address = %v, want BadRequestException", err)
	}
}

func TestAnIdentityWithEscapedCharactersRoundTrips(t *testing.T) {
	ctx := context.Background()
	c, _ := startApp(t, t.TempDir())
	name := "first+last@example.com"

	if _, err := c.CreateEmailIdentity(ctx, &sesv2.CreateEmailIdentityInput{
		EmailIdentity: aws.String(name),
	}); err != nil {
		t.Fatalf("create identity: %v", err)
	}
	got, err := c.GetEmailIdentity(
		ctx,
		&sesv2.GetEmailIdentityInput{EmailIdentity: aws.String(name)},
	)
	if err != nil {
		t.Fatalf("get identity: %v", err)
	}
	if got.IdentityType != types.IdentityTypeEmailAddress || !got.VerifiedForSendingStatus {
		t.Fatalf("identity = %+v, want a verified email address", got)
	}
}

// signedRequest signs a request with the root key for ses, as an SDK would.
func signedRequest(t *testing.T, method, url string) *http.Request {
	t.Helper()
	req, err := http.NewRequestWithContext(t.Context(), method, url, http.NoBody)
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	empty := sha256.Sum256(nil)
	err = v4.NewSigner().SignHTTP(t.Context(),
		aws.Credentials{AccessKeyID: "test", SecretAccessKey: "test"}, req,
		hex.EncodeToString(empty[:]), "ses", "us-east-1", time.Now())
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	return req
}

func TestRequestsTheServiceDoesNotRoute(t *testing.T) {
	_, srv := startApp(t, t.TempDir())

	res, err := srv.Client().Do(signedRequest(t, http.MethodGet, srv.URL+"/v2/email/no-such-thing"))
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	defer func() { _ = res.Body.Close() }()
	var body struct{ Code, Message string }
	if err = json.NewDecoder(res.Body).Decode(&body); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if res.StatusCode != http.StatusNotFound ||
		res.Header.Get("X-Amzn-ErrorType") != "UnknownOperationException" ||
		body.Code != "UnknownOperationException" {
		t.Fatalf("unrouted = %d %s %+v, want 404 UnknownOperationException", res.StatusCode,
			res.Header.Get("X-Amzn-ErrorType"), body)
	}
}

func TestTheRetrievalAPIIsSignedAndTheProbesAreNot(t *testing.T) {
	_, srv := startApp(t, t.TempDir())

	for path, want := range map[string]int{
		"/_health":           http.StatusOK,
		"/_ready":            http.StatusOK,
		"/_mailbox/messages": http.StatusForbidden,
	} {
		req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, srv.URL+path,
			http.NoBody)
		if err != nil {
			t.Fatalf("new request: %v", err)
		}
		res, err := srv.Client().Do(req)
		if err != nil {
			t.Fatalf("unsigned %s: %v", path, err)
		}
		_ = res.Body.Close()
		if res.StatusCode != want {
			t.Errorf("unsigned %s = %d, want %d", path, res.StatusCode, want)
		}
	}

	res, err := srv.Client().Do(signedRequest(t, http.MethodGet, srv.URL+"/_mailbox/messages"))
	if err != nil {
		t.Fatalf("signed list: %v", err)
	}
	defer func() { _ = res.Body.Close() }()
	var page struct {
		Items []json.RawMessage `json:"items"`
	}
	if err = json.NewDecoder(res.Body).
		Decode(&page); err != nil ||
		res.StatusCode != http.StatusOK ||
		page.Items == nil {
		t.Fatalf("signed list = %d, %+v, %v; want 200 with an empty items list",
			res.StatusCode, page, err)
	}
}
