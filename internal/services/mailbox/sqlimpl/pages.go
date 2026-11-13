package sqlimpl

import (
	"context"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"

	"tule.dev/mailbox/internal/contracts"
)

// A pagination token names the listing it belongs to and the rowid of the
// last item it returned, encoded to keep it opaque to clients. A token is
// only accepted back by the listing that issued it.
const tokenSeparator = "\x00"

// The listings a token can belong to.
const (
	listIdentities = "identities"
	listTemplates  = "templates"
	listMessages   = "messages"
	listFailures   = "rendering-failures"
)

func encodeToken(list string, row int64) string {
	raw := list + tokenSeparator + strconv.FormatInt(row, 10)
	return base64.RawURLEncoding.EncodeToString([]byte(raw))
}

// decodeToken returns the rowid a listing resumes after, or 0 for an empty
// token.
func decodeToken(token, list string) (int64, error) {
	if token == "" {
		return 0, nil
	}
	raw, err := base64.RawURLEncoding.DecodeString(token)
	if err != nil {
		return 0, contracts.ErrInvalidToken
	}
	name, cursor, ok := strings.Cut(string(raw), tokenSeparator)
	if !ok || name != list {
		return 0, contracts.ErrInvalidToken
	}
	row, err := strconv.ParseInt(cursor, 10, 64)
	if err != nil || row <= 0 {
		return 0, contracts.ErrInvalidToken
	}
	return row, nil
}

// rowed is one item of a listing with the rowid that resumes after it.
type rowed[T any] struct {
	item T
	row  int64
}

// paginate makes a page of up to size items from rows, which the query
// fetched with one more than size: when that extra row is there, the page has
// a token for the next.
func paginate[T any](rows []rowed[T], size int, list string) *contracts.Page[T] {
	page := &contracts.Page[T]{Items: make([]T, 0, min(len(rows), size))}
	for i, r := range rows {
		if i == size {
			page.NextToken = encodeToken(list, rows[size-1].row)
			break
		}
		page.Items = append(page.Items, r.item)
	}
	return page
}

// scanner is a row to scan: an *sql.Rows positioned on a row, or an
// *sql.Row.
type scanner interface {
	Scan(dest ...any) error
}

// queryAll runs query in tx and scans every row with scan.
func queryAll[T any](
	ctx context.Context,
	tx *sql.Tx,
	scan func(scanner) (T, error),
	query string,
	args ...any,
) ([]T, error) {
	rows, err := tx.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("query: %w", err)
	}
	// Every error of the iteration is reported by rows.Err below; Close
	// after a full iteration has nothing left to report.
	defer func() { _ = rows.Close() }()

	var out []T
	for rows.Next() {
		v, sErr := scan(rows)
		if sErr != nil {
			return nil, fmt.Errorf("scan: %w", sErr)
		}
		out = append(out, v)
	}
	if err = rows.Err(); err != nil {
		return nil, fmt.Errorf("rows: %w", err)
	}
	return out, nil
}

// exists reports whether query, a SELECT 1 ... LIMIT 1, returns a row.
func exists(ctx context.Context, tx *sql.Tx, query string, args ...any) (bool, error) {
	var one int
	err := tx.QueryRowContext(ctx, query, args...).Scan(&one)
	switch {
	case err == nil:
		return true, nil
	case errors.Is(err, sql.ErrNoRows):
		return false, nil
	default:
		return false, fmt.Errorf("query: %w", err)
	}
}

func exec(ctx context.Context, tx *sql.Tx, query string, args ...any) (sql.Result, error) {
	res, err := tx.ExecContext(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("exec: %w", err)
	}
	return res, nil
}

// count runs query, a SELECT count(*), and returns the count.
func count(ctx context.Context, tx *sql.Tx, query string, args ...any) (int, error) {
	var n int
	if err := tx.QueryRowContext(ctx, query, args...).Scan(&n); err != nil {
		return 0, fmt.Errorf("query: %w", err)
	}
	return n, nil
}

// toJSON encodes a value for a JSON column.
func toJSON(v any) (string, error) {
	b, err := json.Marshal(v)
	if err != nil {
		return "", fmt.Errorf("encode: %w", err)
	}
	return string(b), nil
}

// fromJSON decodes a JSON column into dst.
func fromJSON(s string, dst any) error {
	if err := json.Unmarshal([]byte(s), dst); err != nil {
		return fmt.Errorf("decode: %w", err)
	}
	return nil
}
