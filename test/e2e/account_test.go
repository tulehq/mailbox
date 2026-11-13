//go:build e2e

package e2e

import (
	"net/http"
	"testing"

	"github.com/aws/aws-sdk-go-v2/service/sesv2"
)

func TestGetAccountAllowsSending(t *testing.T) {
	// The design: production access and sending enabled, with generous
	// quotas, so clients that check before sending proceed.
	c, _ := newClient(t)

	out, err := c.GetAccount(t.Context(), &sesv2.GetAccountInput{})
	requireNoErr(t, err, "get account")
	requireEqual(t, out.ProductionAccessEnabled, true, "production access enabled")
	requireEqual(t, out.SendingEnabled, true, "sending enabled")
	if out.SendQuota == nil {
		t.Fatal("no send quota")
	}
	// Max24HourSend of -1 is unlimited (types.SendQuota). Assumption:
	// "generous" means unlimited or at least SES's sandbox 200 a day and 1
	// a second, which a sandboxed account already has.
	if q := out.SendQuota.Max24HourSend; q != -1 && q < 200 {
		t.Fatalf("Max24HourSend %v is neither unlimited nor generous", q)
	}
	if out.SendQuota.MaxSendRate < 1 {
		t.Fatalf("MaxSendRate %v, want at least 1", out.SendQuota.MaxSendRate)
	}
}

func TestProbesNeedNoCredentials(t *testing.T) {
	srv := startServer(t, nil)
	mb := mailboxFor(srv)

	for _, path := range []string{"/_health", "/_ready"} {
		res := mb.doUnsigned(t, http.MethodGet, path)
		requireEqual(t, res.Status, http.StatusOK, "unsigned "+path)
	}
}
