package sqlimpl

import (
	"context"
	"database/sql"
	"strings"

	"tule.dev/mailbox/internal/contracts"
)

func putFailure(ctx context.Context, tx *sql.Tx, f *contracts.RenderingFailure) error {
	cols := make([]string, 0, 4)
	for _, v := range []any{nonNil(f.To), nonNil(f.Cc), nonNil(f.Bcc), nonNil(f.Tags)} {
		s, err := toJSON(v)
		if err != nil {
			return err
		}
		cols = append(cols, s)
	}
	_, err := exec(ctx, tx,
		`INSERT INTO rendering_failures (message_id, failed_at, source, template,
			from_display, to_list, cc_list, bcc_list, tags, configuration_set, error)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		f.MessageID, stamp(f.Time), f.Source, f.Template, f.From,
		cols[0], cols[1], cols[2], cols[3], f.ConfigurationSet, f.Error)
	return err
}

func scanFailure(r scanner) (rowed[contracts.RenderingFailure], error) {
	var (
		out               rowed[contracts.RenderingFailure]
		failed            int64
		to, cc, bcc, tags string
	)
	f := &out.item
	if err := r.Scan(&out.row, &f.MessageID, &failed, &f.Source, &f.Template, &f.From,
		&to, &cc, &bcc, &tags, &f.ConfigurationSet, &f.Error); err != nil {
		return out, err
	}
	f.Time = unstamp(failed)
	for _, c := range []struct {
		dst any
		src string
	}{{&f.To, to}, {&f.Cc, cc}, {&f.Bcc, bcc}, {&f.Tags, tags}} {
		if err := fromJSON(c.src, c.dst); err != nil {
			return out, err
		}
	}
	return out, nil
}

// ListRenderingFailures pages through the rendering failures matching f,
// newest first.
func (s *Service) ListRenderingFailures(
	ctx context.Context,
	f contracts.FailureFilter,
	page contracts.PageInput,
) (*contracts.Page[contracts.RenderingFailure], error) {
	var out *contracts.Page[contracts.RenderingFailure]
	err := s.inTx(ctx, func(tx *sql.Tx) error {
		before, err := decodeToken(page.Token, listFailures)
		if err != nil {
			return err
		}
		var (
			where []string
			args  []any
		)
		add := func(cond string, a any) {
			where = append(where, cond)
			args = append(args, a)
		}
		if f.MessageID != "" {
			add(`message_id = ?`, f.MessageID)
		}
		if f.Template != "" {
			add(`template = ?`, f.Template)
		}
		if f.Since != nil {
			add(`failed_at >= ?`, stamp(*f.Since))
		}
		if f.Until != nil {
			add(`failed_at <= ?`, stamp(*f.Until))
		}
		if before > 0 {
			add(`seq < ?`, before)
		}
		query := `SELECT seq, message_id, failed_at, source, template, from_display, to_list,
			cc_list, bcc_list, tags, configuration_set, error FROM rendering_failures`
		if len(where) > 0 {
			query += ` WHERE ` + strings.Join(where, ` AND `)
		}
		query += ` ORDER BY seq DESC LIMIT ?`
		args = append(args, page.Size+1)

		rows, err := queryAll(ctx, tx, scanFailure, query, args...)
		if err != nil {
			return err
		}
		out = paginate(rows, page.Size, listFailures)
		return nil
	})
	return out, err
}
