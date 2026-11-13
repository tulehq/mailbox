package mailmime

import (
	"crypto/rand"
	"fmt"
	"time"
)

// messageIDDomain is the domain of the Message-ID header SES gives the
// messages it sends from us-east-1.
const messageIDDomain = "email.amazonses.com"

// NewMessageID returns a MessageId in SES's shape: 16 hex digits, "0100"
// and the acceptance time in Unix milliseconds, then a random UUID, then
// "-000000".
func NewMessageID(now time.Time) (string, error) {
	var u [16]byte
	if _, err := rand.Read(u[:]); err != nil {
		return "", fmt.Errorf("failed to generate a message ID: %w", err)
	}
	u[6] = u[6]&0x0f | 0x40 // version 4
	u[8] = u[8]&0x3f | 0x80 // RFC 4122 variant
	return fmt.Sprintf("0100%012x-%x-%x-%x-%x-%x-000000",
		now.UnixMilli(), u[0:4], u[4:6], u[6:8], u[8:10], u[10:16]), nil
}

// HeaderMessageID is the Message-ID header value of the message with the
// given MessageId.
func HeaderMessageID(id string) string {
	return "<" + id + "@" + messageIDDomain + ">"
}

// HeaderDate is the Date header value for t: the time in UTC, as SES sets
// it.
func HeaderDate(t time.Time) string {
	return t.UTC().Format("Mon, 2 Jan 2006 15:04:05 -0700")
}
