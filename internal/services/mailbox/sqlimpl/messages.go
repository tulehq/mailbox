package sqlimpl

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"

	"tule.dev/mailbox/internal/contracts"
)

// PutSend stores the messages and rendering failures of one send in one
// transaction.
func (s *Service) PutSend(
	ctx context.Context,
	msgs []contracts.Message,
	failures []contracts.RenderingFailure,
) error {
	return s.inTx(ctx, func(tx *sql.Tx) error {
		for i := range msgs {
			if err := putMessage(ctx, tx, &msgs[i]); err != nil {
				return err
			}
		}
		for i := range failures {
			if err := putFailure(ctx, tx, &failures[i]); err != nil {
				return err
			}
		}
		return nil
	})
}

func putMessage(ctx context.Context, tx *sql.Tx, m *contracts.Message) error {
	cols, err := messageJSON(m)
	if err != nil {
		return err
	}
	res, err := exec(ctx, tx,
		`INSERT INTO messages (id, sent_at, source, kind, from_display, from_address,
			to_list, cc_list, bcc_list, reply_to, feedback_forwarding, subject,
			configuration_set, tags, headers, text_body, html_body, attachments,
			attachment_count, recipient_count, size)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		m.ID, stamp(m.Time), m.Source, m.Kind, m.From, m.FromAddress,
		cols.to, cols.cc, cols.bcc, cols.replyTo, m.FeedbackForwarding, m.Subject,
		m.ConfigurationSet, cols.tags, cols.headers, m.Text, m.HTML, cols.attachments,
		len(m.Attachments), len(m.Recipients), len(m.MIME))
	if err != nil {
		return err
	}
	seq, err := res.LastInsertId()
	if err != nil {
		return fmt.Errorf("last insert id: %w", err)
	}
	if _, err = exec(ctx, tx, `INSERT INTO message_mime (seq, mime) VALUES (?, ?)`,
		seq, m.MIME); err != nil {
		return err
	}
	for _, a := range m.Recipients {
		if _, err = exec(ctx, tx,
			`INSERT INTO message_recipients (seq, address) VALUES (?, ?)`, seq, a); err != nil {
			return err
		}
	}
	for _, t := range m.Tags {
		if _, err = exec(ctx, tx,
			`INSERT INTO message_tags (seq, name, value) VALUES (?, ?, ?)`,
			seq, t.Name, t.Value); err != nil {
			return err
		}
	}
	return nil
}

// jsonColumns are a message's JSON-encoded columns.
type jsonColumns struct {
	to, cc, bcc, replyTo, tags, headers, attachments string
}

func messageJSON(m *contracts.Message) (jsonColumns, error) {
	var c jsonColumns
	for _, f := range []struct {
		dst *string
		v   any
	}{
		{&c.to, nonNil(m.To)},
		{&c.cc, nonNil(m.Cc)},
		{&c.bcc, nonNil(m.Bcc)},
		{&c.replyTo, nonNil(m.ReplyTo)},
		{&c.tags, nonNil(m.Tags)},
		{&c.headers, nonNil(m.Headers)},
		{&c.attachments, nonNil(m.Attachments)},
	} {
		s, err := toJSON(f.v)
		if err != nil {
			return c, err
		}
		*f.dst = s
	}
	return c, nil
}

// nonNil returns s, or an empty slice for a nil one, so the column holds []
// rather than null.
func nonNil[T any](s []T) []T {
	if s == nil {
		return []T{}
	}
	return s
}

// summaryColumns are the columns of a listed message; detailColumns add the
// headers and the bodies.
const (
	summaryColumns = `m.seq, m.id, m.sent_at, m.source, m.kind, m.from_display,
		m.from_address, m.to_list, m.cc_list, m.bcc_list, m.reply_to,
		m.feedback_forwarding, m.subject, m.configuration_set, m.tags, m.attachments,
		m.size`
	detailColumns = summaryColumns + `, m.headers, m.text_body, m.html_body`
)

func scanSummary(r scanner) (rowed[contracts.Message], error) {
	var out rowed[contracts.Message]
	return out, scanInto(r, &out)
}

func scanDetail(r scanner) (rowed[contracts.Message], error) {
	var (
		out     rowed[contracts.Message]
		headers string
	)
	if err := scanInto(r, &out, &headers, &out.item.Text, &out.item.HTML); err != nil {
		return out, err
	}
	return out, fromJSON(headers, &out.item.Headers)
}

// scanInto scans the summary columns into out, and the rest into extra.
func scanInto(r scanner, out *rowed[contracts.Message], extra ...any) error {
	var (
		sent                                    int64
		to, cc, bcc, replyTo, tags, attachments string
	)
	m := &out.item
	dest := append([]any{
		&out.row, &m.ID, &sent, &m.Source, &m.Kind, &m.From, &m.FromAddress,
		&to, &cc, &bcc, &replyTo, &m.FeedbackForwarding, &m.Subject,
		&m.ConfigurationSet, &tags, &attachments, &m.Size,
	}, extra...)
	if err := r.Scan(dest...); err != nil {
		return err
	}
	m.Time = unstamp(sent)
	for _, f := range []struct {
		dst any
		src string
	}{
		{&m.To, to},
		{&m.Cc, cc},
		{&m.Bcc, bcc},
		{&m.ReplyTo, replyTo},
		{&m.Tags, tags},
		{&m.Attachments, attachments},
	} {
		if err := fromJSON(f.src, f.dst); err != nil {
			return err
		}
	}
	return nil
}

// ListMessages pages through the messages matching f, newest first.
func (s *Service) ListMessages(
	ctx context.Context,
	f contracts.MessageFilter,
	page contracts.PageInput,
) (*contracts.Page[contracts.Message], error) {
	var out *contracts.Page[contracts.Message]
	err := s.inTx(ctx, func(tx *sql.Tx) error {
		before, err := decodeToken(page.Token, listMessages)
		if err != nil {
			return err
		}
		where, args := filterClause(f)
		if before > 0 {
			where = append(where, `m.seq < ?`)
			args = append(args, before)
		}
		query := `SELECT ` + summaryColumns + ` FROM messages m`
		if len(where) > 0 {
			query += ` WHERE ` + strings.Join(where, ` AND `)
		}
		query += ` ORDER BY m.seq DESC LIMIT ?`
		args = append(args, page.Size+1)

		rows, err := queryAll(ctx, tx, scanSummary, query, args...)
		if err != nil {
			return err
		}
		out = paginate(rows, page.Size, listMessages)
		return nil
	})
	return out, err
}

// filterClause returns the WHERE conditions of f, to be joined with AND, and
// their arguments.
func filterClause(f contracts.MessageFilter) ([]string, []any) {
	var (
		where []string
		args  []any
	)
	add := func(cond string, a ...any) {
		where = append(where, cond)
		args = append(args, a...)
	}
	if f.MessageID != "" {
		add(`m.id = ?`, f.MessageID)
	}
	if f.From != "" {
		add(`m.from_address = ?`, f.From)
	}
	if f.To != "" {
		add(`EXISTS (SELECT 1 FROM message_recipients r WHERE r.seq = m.seq AND r.address = ?)`,
			f.To)
	}
	if f.Subject != "" {
		add(`instr(lower(m.subject), lower(?)) > 0`, f.Subject)
	}
	if f.Query != "" {
		add(`m.seq IN (SELECT rowid FROM messages_fts WHERE messages_fts MATCH ?)`,
			ftsQuery(f.Query))
	}
	if f.Since != nil {
		add(`m.sent_at >= ?`, stamp(*f.Since))
	}
	if f.Until != nil {
		add(`m.sent_at <= ?`, stamp(*f.Until))
	}
	if f.ConfigurationSet != "" {
		add(`m.configuration_set = ?`, f.ConfigurationSet)
	}
	for _, t := range f.Tags {
		add(`EXISTS (SELECT 1 FROM message_tags t
			WHERE t.seq = m.seq AND t.name = ? AND t.value = ?)`, t.Name, t.Value)
	}
	return where, args
}

// ftsQuery turns free text into an FTS5 query that every word of it must
// match. Each word is quoted as an FTS5 string, so no word is read as FTS5
// syntax and no input makes the query invalid.
func ftsQuery(q string) string {
	words := strings.Fields(q)
	for i, w := range words {
		words[i] = `"` + strings.ReplaceAll(w, `"`, `""`) + `"`
	}
	return strings.Join(words, " ")
}

// GetMessage returns the message with the given ID, without its MIME.
func (s *Service) GetMessage(ctx context.Context, id string) (*contracts.Message, error) {
	var out *contracts.Message
	err := s.inTx(ctx, func(tx *sql.Tx) error {
		r, err := scanDetail(tx.QueryRowContext(ctx,
			`SELECT `+detailColumns+` FROM messages m WHERE m.id = ?`, id))
		switch {
		case errors.Is(err, sql.ErrNoRows):
			return contracts.ErrMessageNotFound
		case err != nil:
			return fmt.Errorf("query: %w", err)
		}
		out = &r.item
		return nil
	})
	return out, err
}

// GetMessageMIME returns the MIME of the message with the given ID.
func (s *Service) GetMessageMIME(ctx context.Context, id string) ([]byte, error) {
	var out []byte
	err := s.inTx(ctx, func(tx *sql.Tx) error {
		err := tx.QueryRowContext(ctx,
			`SELECT b.mime FROM messages m JOIN message_mime b ON b.seq = m.seq
			 WHERE m.id = ?`, id).Scan(&out)
		switch {
		case errors.Is(err, sql.ErrNoRows):
			return contracts.ErrMessageNotFound
		case err != nil:
			return fmt.Errorf("query: %w", err)
		}
		return nil
	})
	return out, err
}

// DeleteMessage deletes the message with the given ID and its rows in the
// tables beside it.
func (s *Service) DeleteMessage(ctx context.Context, id string) error {
	return s.inTx(ctx, func(tx *sql.Tx) error {
		var seq int64
		err := tx.QueryRowContext(ctx, `SELECT seq FROM messages WHERE id = ?`, id).Scan(&seq)
		switch {
		case errors.Is(err, sql.ErrNoRows):
			return contracts.ErrMessageNotFound
		case err != nil:
			return fmt.Errorf("query: %w", err)
		}
		for _, q := range []string{
			`DELETE FROM message_mime WHERE seq = ?`,
			`DELETE FROM message_recipients WHERE seq = ?`,
			`DELETE FROM message_tags WHERE seq = ?`,
			`DELETE FROM messages WHERE seq = ?`,
		} {
			if _, err = exec(ctx, tx, q, seq); err != nil {
				return err
			}
		}
		return nil
	})
}

// DeleteMessages deletes every message and rendering failure. Identities
// and templates stay.
func (s *Service) DeleteMessages(ctx context.Context) error {
	return s.inTx(ctx, func(tx *sql.Tx) error {
		for _, q := range []string{
			`DELETE FROM message_mime`,
			`DELETE FROM message_recipients`,
			`DELETE FROM message_tags`,
			`DELETE FROM messages`,
			`DELETE FROM rendering_failures`,
		} {
			if _, err := exec(ctx, tx, q); err != nil {
				return err
			}
		}
		return nil
	})
}

// RecipientsSince counts the recipients of the messages stored at or after
// t.
func (s *Service) RecipientsSince(ctx context.Context, t time.Time) (int, error) {
	var n int
	err := s.inTx(ctx, func(tx *sql.Tx) error {
		var err error
		n, err = count(ctx, tx,
			`SELECT coalesce(sum(recipient_count), 0) FROM messages WHERE sent_at >= ?`,
			stamp(t))
		return err
	})
	return n, err
}
