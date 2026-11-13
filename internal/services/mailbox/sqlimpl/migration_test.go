package sqlimpl

import (
	"context"
	"database/sql"
	"fmt"
	"path/filepath"
	"strings"
	"testing"

	"github.com/gasmod/gas"
	"github.com/gasmod/gas/database"
	"github.com/gasmod/gas/migrate"

	"tule.dev/mailbox/internal/contracts"
)

// storeBefore0003 opens a database with the schema of the migrations before
// 0003 and the identities rows, as a store of an earlier release holds them,
// then applies every migration. It returns the store, a function that
// applies every migration again after running the SQL it is given, and the
// error of the first run.
func storeBefore0003(
	t *testing.T,
	names ...string,
) (*Service, func(repair string) error, error) {
	t.Helper()
	ctx := context.Background()
	logger := &gas.NopLogger{}
	cfg := database.DefaultConfig()
	cfg.Database.Dialect = database.DialectSQLite
	cfg.Database.DSN = gas.Secret("file:" + filepath.Join(t.TempDir(), "mailbox.db"))
	cfg.Database.MaxOpenConns = 1
	cfg.Database.MaxIdleConns = 1
	db, err := database.New(database.WithConfig(cfg))(nil, logger)
	must(t, err, "new database")
	must(t, db.Init(ctx), "init database")
	t.Cleanup(func() { _ = db.Close(ctx) })

	run := func(ms []gas.Migration) (*Service, error) {
		mm, mErr := migrate.New()(db, logger)
		must(t, mErr, "new migrate")
		must(t, mm.Init(ctx), "init migrate")
		s := NewService(db, mm)
		mm.RegisterSlice(s, ms)
		return s, mm.RunPendingContext(ctx)
	}
	_, err = run(migrations[:2])
	must(t, err, "apply 0001 and 0002")
	must(t, db.WithTx(ctx, nil, func(tx *sql.Tx) error {
		for _, n := range names {
			typ := contracts.IdentityTypeDomain
			if strings.Contains(n, "@") {
				typ = contracts.IdentityTypeEmail
			}
			if _, xErr := tx.ExecContext(ctx, `INSERT INTO identities
				(name, type, configuration_set, dkim, tags, created_at)
				VALUES (?, ?, '', '{}', '[{"Key":"env","Value":"prod"}]', 0)`, n, typ); xErr != nil {
				return fmt.Errorf("insert %s: %w", n, xErr)
			}
		}
		return nil
	}), "insert identities")
	s, err := run(migrations)
	again := func(repair string) error {
		if xErr := db.WithTx(ctx, nil, func(tx *sql.Tx) error {
			if _, eErr := tx.ExecContext(ctx, repair); eErr != nil {
				return fmt.Errorf("exec: %w", eErr)
			}
			return nil
		}); xErr != nil {
			return fmt.Errorf("repair: %w", xErr)
		}
		_, rErr := run(migrations)
		return rErr
	}
	return s, again, err
}

func TestMigration0003LowerCasesDomainIdentities(t *testing.T) {
	s, _, err := storeBefore0003(t, "Example.COM", "Sender@EXAMPLE.org", "lower.example")
	must(t, err, "apply 0003")
	ctx := context.Background()
	id, err := s.GetIdentity(ctx, "example.com")
	must(t, err, "get the lower-cased domain")
	check(t, len(id.Tags) == 1 && id.Tags[0].Value == "prod", "tags kept: %+v", id.Tags)
	_, err = s.GetIdentity(ctx, "Sender@EXAMPLE.org")
	must(t, err, "an email address identity keeps its case")
	_, err = s.GetIdentity(ctx, "lower.example")
	must(t, err, "a lower-case domain is unchanged")
}

func TestMigration0003FailsOnDomainsThatDifferOnlyByCase(t *testing.T) {
	s, again, err := storeBefore0003(t, "Example.com", "example.COM", "other.example")
	if err == nil || !strings.Contains(err.Error(), "differ only by case") ||
		!strings.Contains(err.Error(), "Example.com") {
		t.Fatalf("got %v, want the migration to fail naming the identities", err)
	}
	// The repair the README gives.
	must(t, again(`DELETE FROM identities WHERE name = 'Example.com';
		DELETE FROM __gas_migrations WHERE version = '0003' AND dirty;`), "repair and migrate")
	_, err = s.GetIdentity(context.Background(), "example.com")
	must(t, err, "get the kept identity")
}
