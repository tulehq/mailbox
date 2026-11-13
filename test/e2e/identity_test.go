//go:build e2e

package e2e

import (
	"bytes"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	iamtypes "github.com/aws/aws-sdk-go-v2/service/iam/types"
)

// These tests run mailbox against a real identity service: identity is
// built from its checkout and run as a process with the same root key, and
// mailbox is pointed at it through TULE_Auth_IdentityEndpoint.

// identityDirEnv names the identity checkout to build, for a layout where it
// is not mailbox's sibling.
const identityDirEnv = "TULE_E2E_IDENTITY_DIR"

// The root key both services are configured with: the AWS documentation's
// example key, since identity holds an access key ID to at least 16
// characters.
const (
	identityRootKeyID  = "AKIAIOSFODNN7EXAMPLE"
	identityRootSecret = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
)

// identityStack is the mailbox app under test with a running identity it
// accepts keys from, and clients for both.
type identityStack struct {
	srv       *server
	identity  *identityProcess
	iam       *iam.Client
	rootCreds aws.Credentials
}

func TestIdentityIssuedKeys(t *testing.T) {
	s := startIdentityStack(t)
	userKey := createUserKey(t, s.iam, "dev")
	// An identity-issued key is evaluated against its policies: this one
	// may send and read the mailbox.
	putUserPolicy(t, s.iam, "dev", allowPolicy("ses:SendEmail", "tule:Inspect"))

	t.Run("a user key sends mail", func(t *testing.T) {
		id := send(t, sesClientWith(s.srv, userKey),
			simpleInput("app@example.com", "From a user key", "Body.", "to@example.com"))
		got := mailboxWith(s.srv, userKey).byMessageID(t, id)
		requireEqual(t, got.Subject, "From a user key", "subject")
	})
	t.Run("a user key reads the mailbox", func(t *testing.T) {
		mb := mailboxWith(s.srv, userKey)
		requireOK(t, mb.do(t, http.MethodGet, "/_mailbox/messages", nil), "list with the user key")
		items := mb.listAll(t, nil)
		if len(items) == 0 {
			t.Fatal("the user key lists no messages")
		}
		mb.raw(t, items[0].ID)
	})
	t.Run("the root key keeps working", func(t *testing.T) {
		send(t, sesClientWith(s.srv, s.rootCreds),
			simpleInput("root@example.com", "From the root key", "Body.", "to@example.com"))
		mailboxWith(s.srv, s.rootCreds).listAll(t, nil)
	})
	t.Run("an inactive key is refused", s.testInactiveKey)
	t.Run("a deleted key is refused", s.testDeletedKey)
}

func startIdentityStack(t *testing.T) *identityStack {
	t.Helper()

	port := identityFreePort(t)
	identityURL := "http://127.0.0.1:" + strconv.Itoa(port)
	s := &identityStack{
		rootCreds: aws.Credentials{
			AccessKeyID:     identityRootKeyID,
			SecretAccessKey: identityRootSecret,
		},
	}
	s.identity = startIdentity(t, port)
	s.srv = startServer(t, map[string]string{
		"TULE_Auth_AccessKeyID":      identityRootKeyID,
		"TULE_Auth_SecretAccessKey":  identityRootSecret,
		"TULE_Auth_IdentityEndpoint": identityURL,
	})
	s.iam = iamClient(identityURL, s.rootCreds)
	return s
}

func (s *identityStack) testInactiveKey(t *testing.T) {
	key := createUserKey(t, s.iam, "inactive")
	_, err := s.iam.UpdateAccessKey(t.Context(), &iam.UpdateAccessKeyInput{
		UserName:    aws.String("inactive"),
		AccessKeyId: aws.String(key.AccessKeyID),
		Status:      iamtypes.StatusTypeInactive,
	})
	requireNoErr(t, err, "deactivate the key")

	s.requireRefused(t, key)
}

func (s *identityStack) testDeletedKey(t *testing.T) {
	key := createUserKey(t, s.iam, "deleted")
	putUserPolicy(t, s.iam, "deleted", allowPolicy("ses:SendEmail"))
	send(
		t,
		sesClientWith(s.srv, key),
		simpleInput("a@example.com", "Before", "Body.", "to@example.com"),
	)

	_, err := s.iam.DeleteAccessKey(t.Context(), &iam.DeleteAccessKeyInput{
		UserName:    aws.String("deleted"),
		AccessKeyId: aws.String(key.AccessKeyID),
	})
	requireNoErr(t, err, "delete the key")

	s.requireRefused(t, key)
}

// requireRefused fails unless both the SES API and the retrieval API refuse
// key with 403, and the refused send stored nothing.
func (s *identityStack) requireRefused(t *testing.T, key aws.Credentials) {
	t.Helper()

	root := mailboxWith(s.srv, s.rootCreds)
	before := len(root.listAll(t, nil))

	err := errOf(sesClientWith(s.srv, key).SendEmail(t.Context(),
		simpleInput("a@example.com", "Refused", "Body.", "to@example.com")))
	requireAPIError(t, err)
	requireStatus(t, err, http.StatusForbidden)

	requireAPIErrorBody(t, mailboxWith(s.srv, key).do(t, http.MethodGet, "/_mailbox/messages", nil),
		http.StatusForbidden, "", "list with a refused key")
	requireEqual(t, len(root.listAll(t, nil)), before, "messages after the refused send")
}

func iamClient(url string, creds aws.Credentials) *iam.Client {
	return iam.New(iam.Options{
		Region:           region,
		BaseEndpoint:     aws.String(url),
		Credentials:      credentials.StaticCredentialsProvider{Value: creds},
		HTTPClient:       &http.Client{Timeout: clientTimeout},
		RetryMaxAttempts: 1,
	})
}

// createUserKey creates an IAM user and an access key for it, and returns
// the key as credentials.
func createUserKey(t *testing.T, ic *iam.Client, user string) aws.Credentials {
	t.Helper()
	_, err := ic.CreateUser(t.Context(), &iam.CreateUserInput{UserName: aws.String(user)})
	requireNoErr(t, err, "create user "+user)
	out, err := ic.CreateAccessKey(
		t.Context(),
		&iam.CreateAccessKeyInput{UserName: aws.String(user)},
	)
	requireNoErr(t, err, "create access key for "+user)
	return aws.Credentials{
		AccessKeyID:     aws.ToString(out.AccessKey.AccessKeyId),
		SecretAccessKey: aws.ToString(out.AccessKey.SecretAccessKey),
	}
}

// identityProcess is a running identity service.
type identityProcess struct {
	cmd     *exec.Cmd
	exited  chan error
	out     *identityOutput
	stopped bool
}

// identityOutput collects the process's output, safe to write from the
// process's copying goroutines and read from the test.
type identityOutput struct {
	buf bytes.Buffer
	mu  sync.Mutex
}

func (b *identityOutput) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p) //nolint:wrapcheck // bytes.Buffer.Write never fails
}

func (b *identityOutput) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

// startIdentity builds the identity service from its checkout and runs it
// on port with a fresh store and the root key mailbox has. The process is
// stopped when the test ends.
func startIdentity(t *testing.T, port int) *identityProcess {
	t.Helper()

	bin := buildIdentity(t)
	dir := t.TempDir()

	cmd := exec.Command(bin) //nolint:gosec // G204: the binary this test just built
	cmd.Dir = dir
	cmd.Env = append(envWithoutTule(),
		"TULE_GasEnv=testing",
		"TULE_Server_Port="+strconv.Itoa(port),
		"TULE_Store_Path="+filepath.Join(dir, "identity.db"),
		"TULE_Auth_AccessKeyID="+identityRootKeyID,
		"TULE_Auth_SecretAccessKey="+identityRootSecret,
	)
	p := &identityProcess{cmd: cmd, exited: make(chan error, 1), out: &identityOutput{}}
	cmd.Stdout = p.out
	cmd.Stderr = p.out
	if err := cmd.Start(); err != nil {
		t.Fatalf("start identity: %v", err)
	}
	go func() { p.exited <- cmd.Wait() }()
	t.Cleanup(func() { p.Stop(t) })

	p.waitReady(t, "http://127.0.0.1:"+strconv.Itoa(port))
	return p
}

// buildIdentity builds the identity binary into a temporary directory.
func buildIdentity(t *testing.T) string {
	t.Helper()

	// The test runs in mailbox/test/e2e; by default identity is mailbox's
	// sibling. CI sets the directory. A missing checkout fails the test, so
	// the cross-service test is never silently left out.
	src, from := os.Getenv(identityDirEnv), identityDirEnv
	if src == "" {
		src, from = filepath.Join("..", "..", "..", "identity"), "the default sibling path"
	}
	src, err := filepath.Abs(src)
	requireNoErr(t, err, "identity directory")
	//nolint:gosec // G703: the checkout the test is told to build
	if _, err = os.Stat(filepath.Join(src, "go.mod")); err != nil {
		t.Fatalf("no identity checkout at %s (from %s); set %s to an identity checkout: %v",
			src, from, identityDirEnv, err)
	}

	bin := filepath.Join(t.TempDir(), "tule-identity")
	//nolint:gosec // G204: go build of the checkout into this test's directory
	build := exec.CommandContext(t.Context(), "go", "build", "-o", bin, "./cmd")
	build.Dir = src
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build identity: %v\n%s", err, out)
	}
	return bin
}

// envWithoutTule is this process's environment minus the TULE_ variables the
// tests set for mailbox, so the identity process gets only its own.
func envWithoutTule() []string {
	var env []string
	for _, kv := range os.Environ() {
		if !strings.HasPrefix(kv, "TULE_") {
			env = append(env, kv)
		}
	}
	return env
}

func identityFreePort(t *testing.T) int {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	requireNoErr(t, err, "find a free port")
	port := l.Addr().(*net.TCPAddr).Port
	requireNoErr(t, l.Close(), "release the free port")
	return port
}

// waitReady polls identity's readiness probe until it answers 200.
func (p *identityProcess) waitReady(t *testing.T, url string) {
	t.Helper()

	client := &http.Client{Timeout: time.Second}
	deadline := time.Now().Add(clientTimeout)
	for time.Now().Before(deadline) {
		select {
		case err := <-p.exited:
			t.Fatalf("identity exited before it was ready: %v\n%s", err, p.out.String())
		default:
		}
		req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, url+"/_ready", nil)
		requireNoErr(t, err, "build readiness request")
		if res, err := client.Do(req); err == nil {
			_ = res.Body.Close()
			if res.StatusCode == http.StatusOK {
				return
			}
		}
		time.Sleep(100 * time.Millisecond)
	}
	t.Fatalf("identity was not ready within %v\n%s", clientTimeout, p.out.String())
}

// Stop interrupts the process, as a signal stops the service, and kills it
// if it does not exit in time. It is idempotent.
func (p *identityProcess) Stop(t *testing.T) {
	t.Helper()

	if p.stopped {
		return
	}
	p.stopped = true

	_ = p.cmd.Process.Signal(os.Interrupt)
	select {
	case err := <-p.exited:
		if err != nil {
			t.Logf("identity exited: %v", err)
		}
	case <-time.After(clientTimeout):
		_ = p.cmd.Process.Kill()
		err := <-p.exited
		t.Errorf("identity did not stop on interrupt (%v)\n%s", err, p.out.String())
	}
}
