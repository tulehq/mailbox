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
		out.Policies, err = queryAll(ctx, tx, scanPolicy,
			`SELECT name, document FROM identity_policies WHERE identity = ? ORDER BY name`,
			name)
		return err
	})
	return out, err
}

func scanPolicy(r scanner) (contracts.IdentityPolicy, error) {
	var p contracts.IdentityPolicy
	return p, r.Scan(&p.Name, &p.Document)
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

// DeleteIdentity deletes the identity with the given name, and its
// policies.
func (s *Service) DeleteIdentity(ctx context.Context, name string) error {
	return s.inTx(ctx, func(tx *sql.Tx) error {
		if err := deleteOne(ctx, tx, `DELETE FROM identities WHERE name = ?`, name,
			contracts.ErrIdentityNotFound); err != nil {
			return err
		}
		_, err := exec(ctx, tx, `DELETE FROM identity_policies WHERE identity = ?`, name)
		return err
	})
}

// CreateIdentityPolicy adds a policy to an identity that exists, has no
// policy of the name and fewer than contracts.MaxIdentityPolicies.
func (s *Service) CreateIdentityPolicy(
	ctx context.Context,
	identity string,
	p contracts.IdentityPolicy,
) error {
	return s.inTx(ctx, func(tx *sql.Tx) error {
		if err := identityExists(ctx, tx, identity); err != nil {
			return err
		}
		taken, err := exists(ctx, tx,
			`SELECT 1 FROM identity_policies WHERE identity = ? AND name = ? LIMIT 1`,
			identity, p.Name)
		if err != nil {
			return err
		}
		if taken {
			return contracts.ErrIdentityPolicyExists
		}
		n, err := count(ctx, tx, `SELECT count(*) FROM identity_policies WHERE identity = ?`,
			identity)
		if err != nil {
			return err
		}
		if n >= contracts.MaxIdentityPolicies {
			return contracts.ErrIdentityPolicyLimit
		}
		_, err = exec(ctx, tx,
			`INSERT INTO identity_policies (identity, name, document) VALUES (?, ?, ?)`,
			identity, p.Name, p.Document)
		return err
	})
}

// UpdateIdentityPolicy replaces the document of a policy the identity has.
func (s *Service) UpdateIdentityPolicy(
	ctx context.Context,
	identity string,
	p contracts.IdentityPolicy,
) error {
	return s.inTx(ctx, func(tx *sql.Tx) error {
		if err := identityExists(ctx, tx, identity); err != nil {
			return err
		}
		_, err := exec(ctx, tx,
			`UPDATE identity_policies SET document = ? WHERE identity = ? AND name = ?`,
			p.Document, identity, p.Name)
		return err
	})
}

// DeleteIdentityPolicy deletes a policy of the identity, if it has one.
func (s *Service) DeleteIdentityPolicy(ctx context.Context, identity, name string) error {
	return s.inTx(ctx, func(tx *sql.Tx) error {
		if err := identityExists(ctx, tx, identity); err != nil {
			return err
		}
		_, err := exec(ctx, tx,
			`DELETE FROM identity_policies WHERE identity = ? AND name = ?`, identity, name)
		return err
	})
}

// identityExists is nil when the identity exists, else
// contracts.ErrIdentityNotFound.
func identityExists(ctx context.Context, tx *sql.Tx, name string) error {
	found, err := exists(ctx, tx, `SELECT 1 FROM identities WHERE name = ? LIMIT 1`, name)
	switch {
	case err != nil:
		return err
	case !found:
		return contracts.ErrIdentityNotFound
	}
	return nil
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
