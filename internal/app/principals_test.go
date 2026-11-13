package app

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/sesv2"
	_ "modernc.org/sqlite" // the store's driver, to read what it stored
	"tule.dev/identity/keysource"
	"tule.dev/identity/principals"
	"tule.dev/sigv4"

	"tule.dev/mailbox/internal/authz"
	"tule.dev/mailbox/internal/modules/health"
)

// The IAM user the fake identity knows, and its unique ID.
const (
	senderARN = "arn:aws:iam::000000000000:user/sender"
	senderID  = "AIDAEXAMPLESENDER001"
	// goneARN is a user ARN no user has.
	goneARN = "arn:aws:iam::000000000000:user/gone"
	// longARN is a user whose unique ID is as long as IAM allows, 128
	// characters, longer than its ARN.
	longARN = "arn:aws:iam::000000000000:user/long"
)

// longID is longARN's unique ID.
var longID = "AIDA" + strings.Repeat("L", 124)

// The key of an IAM user with no policies, which the fake identity issues.
const (
	plainKeyID  = "AKIAEXAMPLEPLAIN001"
	plainSecret = "plain-secret"
)

// principalIdentity is a fake identity: its principal-ID endpoint knows
// one user, senderARN, and its signing-key endpoint one key, of a user with
// no policies. It counts the calls that bind and the calls that show, and
// fails every principal-ID call while failing is set. A bind waits for
// release while hold is set, having sent on held.
type principalIdentity struct {
	held    chan struct{}
	release chan struct{}
	url     string
	binds   atomic.Int32
	shows   atomic.Int32
	failing atomic.Bool
	hold    atomic.Bool
}

func startPrincipalIdentity(t *testing.T) *principalIdentity {
	t.Helper()
	f := &principalIdentity{held: make(chan struct{}, 1), release: make(chan struct{})}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case principals.Path:
			f.principalIDs(t, w, r)
		case keysource.Path:
			signingKey(t, w, r)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	t.Cleanup(srv.Close)
	f.url = srv.URL
	return f
}

func (f *principalIdentity) principalIDs(t *testing.T, w http.ResponseWriter, r *http.Request) {
	var req principals.Request
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		t.Errorf("decode a principal-ID request: %v", err)
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	if len(req.ARNs) > 0 {
		f.binds.Add(1)
		if f.hold.Load() {
			f.held <- struct{}{}
			<-f.release
		}
	}
	if len(req.IDs) > 0 {
		f.shows.Add(1)
	}
	if f.failing.Load() {
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = io.WriteString(w, `{"Code":"InternalFailure","Message":"the store failed"}`)
		return
	}
	out := principals.Response{IDs: map[string]string{}, ARNs: map[string]string{}}
	known := map[string]string{senderARN: senderID, longARN: longID}
	for _, arn := range req.ARNs {
		if id, ok := known[arn]; ok {
			out.IDs[arn] = id
		}
	}
	for _, id := range req.IDs {
		if id == senderID {
			out.ARNs[id] = senderARN
		}
	}
	_ = json.NewEncoder(w).Encode(out)
}

// signingKey answers the signing-key endpoint for plainKeyID: an IAM user
// of the service's account with no policies.
func signingKey(t *testing.T, w http.ResponseWriter, r *http.Request) {
	var req keysource.Request
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.AccessKeyID != plainKeyID {
		w.WriteHeader(http.StatusBadRequest)
		_, _ = io.WriteString(w, `{"Code":"UnknownAccessKey","Message":"unknown"}`)
		return
	}
	const arn = "arn:aws:iam::000000000000:user/plain"
	err := json.NewEncoder(w).Encode(keysource.Response{
		SigningKey: sigv4.DeriveSigningKey(plainSecret, req.Date, req.Region, req.Service),
		Principal: keysource.Principal{
			AccountID: "000000000000", ARN: arn, PrincipalARN: arn,
			UserID: "AIDAEXAMPLEPLAIN0001", AccessKeyID: plainKeyID, PrincipalType: "User",
		},
		Version: keysource.Version,
	})
	if err != nil {
		t.Errorf("encode a signing key: %v", err)
	}
}

// startBoundApp starts the app pointed at a fake identity, with an
// identity example.com, and returns the fake, the SES client of the root
// key, the server and the store's file.
func startBoundApp(t *testing.T) (*principalIdentity, *sesv2.Client, *httptest.Server, string) {
	t.Helper()
	f := startPrincipalIdentity(t)
	t.Setenv("TULE_Auth_IdentityEndpoint", f.url)
	dir := t.TempDir()
	c, srv := startApp(t, dir)
	_, err := c.CreateEmailIdentity(context.Background(),
		&sesv2.CreateEmailIdentityInput{EmailIdentity: aws.String("example.com")})
	if err != nil {
		t.Fatalf("create identity: %v", err)
	}
	return f, c, srv, filepath.Join(dir, "nested", "mailbox.db")
}

// grantPolicy is a sending authorization policy of example.com granting
// the principal, with the Sid.
func grantPolicy(sid, principal string) string {
	return `{"Version":"2012-10-17","Statement":[{"Sid":"` + sid + `","Effect":"Allow",` +
		`"Principal":{"AWS":"` + principal + `"},"Action":"ses:SendEmail",` +
		`"Resource":"arn:aws:ses:us-east-1:000000000000:identity/example.com"}]}`
}

// storedDocuments are the documents of every policy the store holds.
func storedDocuments(t *testing.T, path string) []string {
	t.Helper()
	db, err := sql.Open("sqlite", "file:"+path+"?mode=ro")
	if err != nil {
		t.Fatalf("open the store: %v", err)
	}
	defer func() { _ = db.Close() }()
	rows, err := db.QueryContext(t.Context(), `SELECT document FROM identity_policies`)
	if err != nil {
		t.Fatalf("read the policies: %v", err)
	}
	defer func() { _ = rows.Close() }()
	var docs []string
	for rows.Next() {
		var d string
		if err = rows.Scan(&d); err != nil {
			t.Fatalf("scan a policy: %v", err)
		}
		docs = append(docs, d)
	}
	if err = rows.Err(); err != nil {
		t.Fatalf("read the policies: %v", err)
	}
	return docs
}

// TestEveryPolicyWriteIsBound writes a policy naming a user through every
// operation that stores one, and requires that the store holds only bound
// documents: the IAM user's unique ID, never its ARN.
func TestEveryPolicyWriteIsBound(t *testing.T) {
	f, c, _, db := startBoundApp(t)
	ctx := context.Background()

	writes := map[string]func() error{
		"CreateEmailIdentityPolicy": func() error {
			return errOf(c.CreateEmailIdentityPolicy(ctx, &sesv2.CreateEmailIdentityPolicyInput{
				EmailIdentity: aws.String("example.com"), PolicyName: aws.String("send"),
				Policy: aws.String(grantPolicy("Created", senderARN)),
			}))
		},
		"UpdateEmailIdentityPolicy": func() error {
			return errOf(c.UpdateEmailIdentityPolicy(ctx, &sesv2.UpdateEmailIdentityPolicyInput{
				EmailIdentity: aws.String("example.com"), PolicyName: aws.String("send"),
				Policy: aws.String(grantPolicy("Updated", senderARN)),
			}))
		},
	}
	for _, name := range []string{"CreateEmailIdentityPolicy", "UpdateEmailIdentityPolicy"} {
		before := f.binds.Load()
		if err := writes[name](); err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if f.binds.Load() != before+1 {
			t.Errorf("%s asked identity to bind %d times, want 1", name, f.binds.Load()-before)
		}
		docs := storedDocuments(t, db)
		if len(docs) != 1 {
			t.Fatalf("after %s the store holds %d policies, want 1", name, len(docs))
		}
		sid := strings.TrimSuffix(name, "EmailIdentityPolicy") + "d"
		if !strings.Contains(docs[0], `"`+sid+`"`) || !strings.Contains(docs[0], senderID) ||
			strings.Contains(docs[0], senderARN) {
			t.Errorf("after %s the store holds %s, want its document bound to %s", name, docs[0],
				senderID)
		}
	}
}

// TestEveryPolicyReadIsShown reads every route the app serves with GET
// once the store holds a bound policy, and requires that none answers the
// unique ID a user still has, and that the identity reads show its ARN, so
// a read added without Show fails here.
func TestEveryPolicyReadIsShown(t *testing.T) {
	f, c, srv, _ := startBoundApp(t)
	_, err := c.CreateEmailIdentityPolicy(context.Background(),
		&sesv2.CreateEmailIdentityPolicyInput{
			EmailIdentity: aws.String("example.com"), PolicyName: aws.String("send"),
			Policy: aws.String(grantPolicy("Send", senderARN)),
		})
	if err != nil {
		t.Fatalf("create policy: %v", err)
	}

	showing := 0
	for _, routes := range appRoutes(t) {
		for _, r := range routes {
			if r.Method == http.MethodGet && r.Path != health.HealthPath &&
				r.Path != health.ReadyPath && f.requireShown(t, srv, r.Path) {
				showing++
			}
		}
	}
	// GetEmailIdentity and GetEmailIdentityPolicies.
	if showing != 2 {
		t.Fatalf("%d reads show the policy, want 2", showing)
	}
}

// requireShown reads the GET route and fails if it answers the bound ID,
// or the ARN without having asked identity. It reports whether it answered
// the ARN.
func (f *principalIdentity) requireShown(t *testing.T, srv *httptest.Server, route string) bool {
	t.Helper()
	if _, ok := authz.Lookup(http.MethodGet, route); !ok {
		t.Fatalf("GET %s has no authorization entry", route)
	}
	path := strings.NewReplacer("{EmailIdentity}", "example.com",
		"{TemplateName}", "Greeting", "{id}", "none", "{index}", "0").Replace(route)
	before := f.shows.Load()
	body := getBody(t, srv, path)
	if strings.Contains(body, senderID) {
		t.Errorf("GET %s answers the bound ID: %s", route, body)
	}
	if !strings.Contains(body, senderARN) {
		return false
	}
	if f.shows.Load() == before {
		t.Errorf("GET %s answers the ARN without asking identity", route)
	}
	return true
}

// errOf is the error of a call's two results.
func errOf[T any](_ T, err error) error {
	return err
}

func getBody(t *testing.T, srv *httptest.Server, path string) string {
	t.Helper()
	res, err := srv.Client().Do(signedRequest(t, http.MethodGet, srv.URL+path))
	if err != nil {
		t.Fatalf("GET %s: %v", path, err)
	}
	defer func() { _ = res.Body.Close() }()
	b, err := io.ReadAll(res.Body)
	if err != nil {
		t.Fatalf("read GET %s: %v", path, err)
	}
	return string(b)
}

// TestAPolicyIsBoundOutsideTheLock holds a policy write while identity
// binds it: the operations that take the resource lock, shared or
// exclusive, are served in the meantime.
func TestAPolicyIsBoundOutsideTheLock(t *testing.T) {
	f, c, _, _ := startBoundApp(t)
	ctx := context.Background()
	f.hold.Store(true)
	done := make(chan error, 1)
	go func() {
		_, err := c.CreateEmailIdentityPolicy(ctx, &sesv2.CreateEmailIdentityPolicyInput{
			EmailIdentity: aws.String("example.com"), PolicyName: aws.String("send"),
			Policy: aws.String(grantPolicy("Send", senderARN)),
		})
		done <- err
	}()
	<-f.held
	if _, err := c.ListEmailTemplates(ctx, &sesv2.ListEmailTemplatesInput{}); err != nil {
		t.Errorf("a read while a policy is bound: %v", err)
	}
	_, err := c.CreateEmailIdentity(ctx,
		&sesv2.CreateEmailIdentityInput{EmailIdentity: aws.String("other.example")})
	if err != nil {
		t.Errorf("a write while a policy is bound: %v", err)
	}
	close(f.release)
	if err = <-done; err != nil {
		t.Fatalf("create policy: %v", err)
	}
}

// TestABoundPolicyIsHeldToTheSizeLimit refuses a policy within 4 KB as
// sent whose bound document, with longer unique IDs in place of its ARNs,
// is over it, as an oversized policy is refused.
func TestABoundPolicyIsHeldToTheSizeLimit(t *testing.T) {
	_, c, _, db := startBoundApp(t)
	statements := make([]string, 20)
	for i := range statements {
		statements[i] = fmt.Sprintf(`{"Sid":"S%02d","Effect":"Allow","Principal":{"AWS":"%s"},`+
			`"Action":"ses:SendEmail",`+
			`"Resource":"arn:aws:ses:us-east-1:000000000000:identity/example.com"}`, i, longARN)
	}
	doc := `{"Version":"2012-10-17","Statement":[` + strings.Join(statements, ",") + `]}`
	if len(doc) > authz.MaxIdentityPolicySize {
		t.Fatalf("the policy as sent is %d bytes, over the limit", len(doc))
	}
	_, err := c.CreateEmailIdentityPolicy(context.Background(),
		&sesv2.CreateEmailIdentityPolicyInput{
			EmailIdentity: aws.String("example.com"), PolicyName: aws.String("send"),
			Policy: aws.String(doc),
		})
	requireAPIError(t, err, "BadRequestException", http.StatusBadRequest)
	if !strings.Contains(err.Error(), "The policy cannot exceed 4 KB") {
		t.Fatalf("error = %v", err)
	}
	if docs := storedDocuments(t, db); len(docs) != 0 {
		t.Fatalf("the store holds %v", docs)
	}
}

func TestAPolicyNamingAUserNoOneHasIsRefused(t *testing.T) {
	_, c, _, db := startBoundApp(t)
	_, err := c.CreateEmailIdentityPolicy(context.Background(),
		&sesv2.CreateEmailIdentityPolicyInput{
			EmailIdentity: aws.String("example.com"), PolicyName: aws.String("send"),
			Policy: aws.String(grantPolicy("Send", goneARN)),
		})
	requireAPIError(t, err, "BadRequestException", http.StatusBadRequest)
	if !strings.Contains(err.Error(),
		`Invalid policy: Invalid principal in policy: "AWS":"`+goneARN+`"`) {
		t.Fatalf("error = %v", err)
	}
	if docs := storedDocuments(t, db); len(docs) != 0 {
		t.Fatalf("the store holds %v", docs)
	}
}

// TestAnUnauthorizedWriteLearnsNothingOfThePrincipals answers a caller
// that may not write the policy with AccessDenied, whether or not the
// users it names exist, without asking identity to bind them.
func TestAnUnauthorizedWriteLearnsNothingOfThePrincipals(t *testing.T) {
	f, _, srv, _ := startBoundApp(t)
	plain := sesv2.New(sesv2.Options{
		Region:           "us-east-1",
		BaseEndpoint:     aws.String(srv.URL),
		Credentials:      credentials.NewStaticCredentialsProvider(plainKeyID, plainSecret, ""),
		HTTPClient:       srv.Client(),
		RetryMaxAttempts: 1,
	})
	for _, principal := range []string{senderARN, goneARN} {
		_, err := plain.CreateEmailIdentityPolicy(context.Background(),
			&sesv2.CreateEmailIdentityPolicyInput{
				EmailIdentity: aws.String("example.com"), PolicyName: aws.String("send"),
				Policy: aws.String(grantPolicy("Send", principal)),
			})
		requireAPIError(t, err, "AccessDeniedException", http.StatusForbidden)
	}
	if n := f.binds.Load(); n != 0 {
		t.Fatalf("a denied caller made %d bind calls to identity, want 0", n)
	}
}

// TestIdentityUnreachableFailsPolicyWritesAndReads fails a write with
// InternalFailure, storing nothing, and a read of a bound policy too.
func TestIdentityUnreachableFailsPolicyWritesAndReads(t *testing.T) {
	f, c, _, db := startBoundApp(t)
	ctx := context.Background()
	create := func(name string) error {
		return errOf(c.CreateEmailIdentityPolicy(ctx, &sesv2.CreateEmailIdentityPolicyInput{
			EmailIdentity: aws.String("example.com"), PolicyName: aws.String(name),
			Policy: aws.String(grantPolicy("Send", senderARN)),
		}))
	}
	if err := create("send"); err != nil {
		t.Fatalf("create policy: %v", err)
	}
	f.failing.Store(true)

	requireAPIError(t, create("other"), "InternalFailure", http.StatusInternalServerError)
	_, err := c.UpdateEmailIdentityPolicy(ctx, &sesv2.UpdateEmailIdentityPolicyInput{
		EmailIdentity: aws.String("example.com"), PolicyName: aws.String("send"),
		Policy: aws.String(grantPolicy("Changed", senderARN)),
	})
	requireAPIError(t, err, "InternalFailure", http.StatusInternalServerError)
	if docs := storedDocuments(t, db); len(docs) != 1 || strings.Contains(docs[0], "Changed") {
		t.Fatalf("the store holds %v, want the first policy only", docs)
	}

	_, err = c.GetEmailIdentityPolicies(ctx,
		&sesv2.GetEmailIdentityPoliciesInput{EmailIdentity: aws.String("example.com")})
	requireAPIError(t, err, "InternalFailure", http.StatusInternalServerError)
	_, err = c.GetEmailIdentity(ctx,
		&sesv2.GetEmailIdentityInput{EmailIdentity: aws.String("example.com")})
	requireAPIError(t, err, "InternalFailure", http.StatusInternalServerError)
}

// TestStandaloneStoresAPolicyAsSent binds nothing without identity: the
// document is stored and returned as it was sent.
func TestStandaloneStoresAPolicyAsSent(t *testing.T) {
	dir := t.TempDir()
	c, _ := startApp(t, dir)
	ctx := context.Background()
	_, err := c.CreateEmailIdentity(ctx,
		&sesv2.CreateEmailIdentityInput{EmailIdentity: aws.String("example.com")})
	if err != nil {
		t.Fatalf("create identity: %v", err)
	}
	doc := grantPolicy("Send", goneARN)
	_, err = c.CreateEmailIdentityPolicy(ctx, &sesv2.CreateEmailIdentityPolicyInput{
		EmailIdentity: aws.String("example.com"), PolicyName: aws.String("send"),
		Policy: aws.String(doc),
	})
	if err != nil {
		t.Fatalf("create policy: %v", err)
	}
	if docs := storedDocuments(t, filepath.Join(dir, "nested", "mailbox.db")); len(docs) != 1 ||
		docs[0] != doc {
		t.Fatalf("the store holds %v, want %s", docs, doc)
	}
	out, err := c.GetEmailIdentityPolicies(ctx,
		&sesv2.GetEmailIdentityPoliciesInput{EmailIdentity: aws.String("example.com")})
	if err != nil || out.Policies["send"] != doc {
		t.Fatalf("policies = %v, %v; want the document as sent", out, err)
	}
}
