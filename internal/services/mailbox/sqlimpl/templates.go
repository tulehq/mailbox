package sqlimpl

import (
	"context"
	"database/sql"
	"errors"
	"fmt"

	"tule.dev/mailbox/internal/contracts"
)

// CreateTemplate stores a new template, as long as its name is not taken and
// fewer than contracts.MaxTemplates exist.
func (s *Service) CreateTemplate(ctx context.Context, in contracts.Template) error {
	return s.inTx(ctx, func(tx *sql.Tx) error {
		taken, err := exists(ctx, tx, `SELECT 1 FROM templates WHERE name = ? LIMIT 1`, in.Name)
		if err != nil {
			return err
		}
		if taken {
			return contracts.ErrTemplateExists
		}
		n, err := count(ctx, tx, `SELECT count(*) FROM templates`)
		if err != nil {
			return err
		}
		if n >= contracts.MaxTemplates {
			return contracts.ErrTemplateLimit
		}

		tags, err := toJSON(in.Tags)
		if err != nil {
			return err
		}
		_, err = exec(ctx, tx,
			`INSERT INTO templates (name, subject, text_part, html_part, tags, created_at)
			 VALUES (?, ?, ?, ?, ?, ?)`,
			in.Name, in.Content.Subject, in.Content.Text, in.Content.HTML, tags,
			stamp(in.CreatedAt))
		return err
	})
}

const templateColumns = `rowid, name, subject, text_part, html_part, tags, created_at`

func scanTemplate(r scanner) (rowed[contracts.Template], error) {
	var (
		out     rowed[contracts.Template]
		tags    string
		created int64
	)
	c := &out.item.Content
	if err := r.Scan(&out.row, &out.item.Name, &c.Subject, &c.Text, &c.HTML,
		&tags, &created); err != nil {
		return out, err
	}
	out.item.CreatedAt = unstamp(created)
	return out, fromJSON(tags, &out.item.Tags)
}

// GetTemplate returns the template with the given name.
func (s *Service) GetTemplate(ctx context.Context, name string) (*contracts.Template, error) {
	var out *contracts.Template
	err := s.inTx(ctx, func(tx *sql.Tx) error {
		r, err := scanTemplate(tx.QueryRowContext(ctx,
			`SELECT `+templateColumns+` FROM templates WHERE name = ?`, name))
		switch {
		case errors.Is(err, sql.ErrNoRows):
			return contracts.ErrTemplateNotFound
		case err != nil:
			return fmt.Errorf("query: %w", err)
		}
		out = &r.item
		return nil
	})
	return out, err
}

// ListTemplates pages through the templates in creation order.
func (s *Service) ListTemplates(
	ctx context.Context,
	page contracts.PageInput,
) (*contracts.Page[contracts.Template], error) {
	var out *contracts.Page[contracts.Template]
	err := s.inTx(ctx, func(tx *sql.Tx) error {
		after, err := decodeToken(page.Token, listTemplates)
		if err != nil {
			return err
		}
		rows, err := queryAll(ctx, tx, scanTemplate,
			`SELECT `+templateColumns+` FROM templates WHERE rowid > ?
			 ORDER BY rowid LIMIT ?`, after, page.Size+1)
		if err != nil {
			return err
		}
		out = paginate(rows, page.Size, listTemplates)
		return nil
	})
	return out, err
}

// UpdateTemplate replaces the content of the template with the given name.
func (s *Service) UpdateTemplate(
	ctx context.Context,
	name string,
	content contracts.TemplateContent,
) error {
	return s.inTx(ctx, func(tx *sql.Tx) error {
		res, err := exec(ctx, tx,
			`UPDATE templates SET subject = ?, text_part = ?, html_part = ? WHERE name = ?`,
			content.Subject, content.Text, content.HTML, name)
		if err != nil {
			return err
		}
		n, err := res.RowsAffected()
		if err != nil {
			return fmt.Errorf("rows affected: %w", err)
		}
		if n == 0 {
			return contracts.ErrTemplateNotFound
		}
		return nil
	})
}

// DeleteTemplate deletes the template with the given name.
func (s *Service) DeleteTemplate(ctx context.Context, name string) error {
	return s.inTx(ctx, func(tx *sql.Tx) error {
		return deleteOne(ctx, tx, `DELETE FROM templates WHERE name = ?`, name,
			contracts.ErrTemplateNotFound)
	})
}
