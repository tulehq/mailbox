package email

import (
	"time"

	"github.com/gasmod/gas"

	"tule.dev/mailbox/internal/sesapi"
)

// The quotas GetAccount reports: far above anything a local test sends, so
// a client that checks its quota before sending always proceeds. Nothing
// enforces them.
const (
	max24HourSend = 1_000_000
	maxSendRate   = 1_000
)

// getAccount answers as an account out of the sandbox with sending enabled.
// SentLast24Hours counts the recipients of the messages stored in the last
// 24 hours.
func (m *Module) getAccount(ctx gas.Context) error {
	sent, err := m.store.RecipientsSince(ctx, m.now().Add(-24*time.Hour))
	if err != nil {
		return err
	}
	return sesapi.Write(ctx, sesapi.GetAccountResponse{
		EnforcementStatus:       "HEALTHY",
		ProductionAccessEnabled: true,
		SendingEnabled:          true,
		SendQuota: sesapi.SendQuota{
			Max24HourSend:   max24HourSend,
			MaxSendRate:     maxSendRate,
			SentLast24Hours: float64(sent),
		},
	})
}
