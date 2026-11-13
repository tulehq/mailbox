package sqlimpl

import (
	"context"
	"database/sql"
	"errors"
	"fmt"

	"tule.dev/mailbox/internal/contracts"
)

// CreateIdentity stores a new identity, as long as its name is not taken
// and fewer than contracts.MaxIdentities exist.
func (s *Service) CreateIdentity(ctx context.Context, in contracts.Identity) error {
	return s.inTx(ctx, func(tx *sql.Tx) error {
		taken, err := exists(ctx, tx, `SELECT 1 FROM identities WHERE name = ? LIMIT 1`, in.Name)
		if err != nil {
			return err
		}
		if taken {
			return contracts.ErrIdentityExists
		}
		n, err := count(ctx, tx, `SELECT count(*) FROM identities`)
		if err != nil {
			return err
		}
		if n >= contracts.MaxIdentities {
			return contracts.ErrIdentityLimit
		}

		dkim, err := toJSON(in.DKIM)
		if err != nil {
			return err
		}
		tags, err := toJSON(in.Tags)
		if err != nil {
			return err
		}
		_, err = exec(ctx, tx,
			`INSERT INTO identities (name, type, configuration_set, dkim, tags, created_at)
			 VALUES (?, ?, ?, ?, ?, ?)`,
			in.Name, in.Type, in.ConfigurationSet, dkim, tags, stamp(in.CreatedAt))
		return err
	})
}

const identityColumns = `rowid, name, type, configuration_set, dkim, tags, created_at`

func scanIdentity(r scanner) (rowed[contracts.Identity], error) {
	var (
		out        rowed[contracts.Identity]
		dkim, tags string
		created    int64
	)
	if err := r.Scan(&out.row, &out.item.Name, &out.item.Type, &out.item.ConfigurationSet,
		&dkim, &tags, &created); err != nil {
		return out, err
	}
	out.item.CreatedAt = unstamp(created)
	if err := fromJSON(dkim, &out.item.DKIM); err != nil {
		return out, err
	}
	return out, fromJSON(tags, &out.item.Tags)
}

// GetIdentity returns the identity with the given name.
func (s *Service) GetIdentity(ctx context.Context, name string) (*contracts.Identity, error) {
	var out *contracts.Identity
	err := s.inTx(ctx, func(tx *sql.Tx) error {
		r, err := scanIdentity(tx.QueryRowContext(ctx,
			`SELECT `+identityColumns+` FROM identities WHERE name = ?`, name))
		switch {
		case errors.Is(err, sql.ErrNoRows):
			return contracts.ErrIdentityNotFound
		case err != nil:
			return fmt.Errorf("query: %w", err)
		}
		out = &r.item
		return nil
	})
	return out, err
}

// ListIdentities pages through the identities matching f in creation order.
func (s *Service) ListIdentities(
	ctx context.Context,
	f contracts.IdentityFilter,
	page contracts.PageInput,
) (*contracts.Page[contracts.Identity], error) {
	var out *contracts.Page[contracts.Identity]
	err := s.inTx(ctx, func(tx *sql.Tx) error {
		after, err := decodeToken(page.Token, listIdentities)
		if err != nil {
			return err
		}
		rows, err := queryAll(ctx, tx, scanIdentity,
			`SELECT `+identityColumns+` FROM identities WHERE rowid > ?
			 AND (? = '' OR instr(lower(name), lower(?)) > 0) AND (? = '' OR type = ?)
			 ORDER BY rowid LIMIT ?`,
			after, f.NameContains, f.NameContains, f.Type, f.Type, page.Size+1)
		if err != nil {
			return err
		}
		out = paginate(rows, page.Size, listIdentities)
		return nil
	})
	return out, err
}

// DeleteIdentity deletes the identity with the given name.
func (s *Service) DeleteIdentity(ctx context.Context, name string) error {
	return s.inTx(ctx, func(tx *sql.Tx) error {
		return deleteOne(ctx, tx, `DELETE FROM identities WHERE name = ?`, name,
			contracts.ErrIdentityNotFound)
	})
}

// deleteOne runs a DELETE of at most one row, failing with notFound when it
// deletes none.
func deleteOne(ctx context.Context, tx *sql.Tx, query, key string, notFound error) error {
	res, err := exec(ctx, tx, query, key)
	if err != nil {
		return err
	}
	n, err := res.RowsAffected()
	if err != nil {
		return fmt.Errorf("rows affected: %w", err)
	}
	if n == 0 {
		return notFound
	}
	return nil
}
