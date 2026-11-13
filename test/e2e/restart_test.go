//go:build e2e

package e2e

import (
	"path/filepath"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/sesv2"
)

func TestDataSurvivesARestart(t *testing.T) {
	// The design: messages, identities and templates live in the SQLite
	// store at TULE_Store_Path.
	env := map[string]string{"TULE_Store_Path": filepath.Join(t.TempDir(), "kept.db")}

	srv := startServer(t, env)
	c, mb := clientFor(srv), mailboxFor(srv)
	sesID := send(
		t,
		c,
		simpleInput("sender@example.com", "Survivor", "Still here.", "to@example.com"),
	)
	_, err := c.CreateEmailIdentity(t.Context(), &sesv2.CreateEmailIdentityInput{
		EmailIdentity: aws.String("kept@example.com"),
	})
	requireNoErr(t, err, "create identity")
	createTemplate(t, c, "Kept", greeting)

	before := mb.byMessageID(t, sesID)
	rawBefore := mb.raw(t, before.ID)
	srv.Stop(t)

	srv = startServer(t, env)
	c, mb = clientFor(srv), mailboxFor(srv)

	after := mb.byMessageID(t, sesID)
	requireEqual(t, after.ID, before.ID, "id after restart")
	requireEqual(t, after.Subject, "Survivor", "subject after restart")
	requireBytes(t, mb.raw(t, after.ID), rawBefore, "raw after restart")

	_, err = c.GetEmailIdentity(
		t.Context(),
		&sesv2.GetEmailIdentityInput{EmailIdentity: aws.String("kept@example.com")},
	)
	requireNoErr(t, err, "get identity after restart")
	got, err := c.GetEmailTemplate(
		t.Context(),
		&sesv2.GetEmailTemplateInput{TemplateName: aws.String("Kept")},
	)
	requireNoErr(t, err, "get template after restart")
	requireContent(t, got.TemplateContent, greeting)

	// A send after the restart gets a new ID and both are listed.
	next := send(t, c, simpleInput("sender@example.com", "Next", "New.", "to@example.com"))
	if next == sesID {
		t.Fatalf("message ID %s reused after restart", next)
	}
	requireEqual(t, len(mb.listAll(t, nil)), 2, "messages after restart")
}
