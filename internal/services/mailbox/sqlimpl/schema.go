package sqlimpl

import "github.com/gasmod/gas"

// migrations is the store's schema, applied by gas/migrate in version order.
//
// Times are Unix milliseconds. Lists that are only ever read back whole
// (tags, recipients as sent, headers, attachment metadata) are JSON text;
// what the retrieval filters match on is in tables of its own: the bare
// recipient addresses and the message tags, and the FTS5 index over the
// subject and text body, an external-content table kept in step by
// triggers. The tables beside messages have no foreign keys, since SQLite
// enforces them only per connection when asked to; the store deletes a
// message's rows from each of them itself. A message's MIME is a blob in a table of its own, so listing
// messages never reads it; it is at most 40 MiB, SES's message size limit,
// well inside SQLite's default 1 GB blob limit, and keeping it in the
// database keeps each send and each reset one transaction over one file.
var migrations = []gas.Migration{
	{
		Version:     "0001",
		Description: "create the mailbox schema",
		Up: `
CREATE TABLE identities (
	name              TEXT PRIMARY KEY,
	type              TEXT NOT NULL,
	configuration_set TEXT NOT NULL,
	dkim              TEXT NOT NULL,
	tags              TEXT NOT NULL,
	created_at        INTEGER NOT NULL
);

CREATE TABLE templates (
	name       TEXT PRIMARY KEY,
	subject    TEXT NOT NULL,
	text_part  TEXT NOT NULL,
	html_part  TEXT NOT NULL,
	tags       TEXT NOT NULL,
	created_at INTEGER NOT NULL
);

CREATE TABLE messages (
	seq                 INTEGER PRIMARY KEY AUTOINCREMENT,
	id                  TEXT NOT NULL UNIQUE,
	sent_at             INTEGER NOT NULL,
	source              TEXT NOT NULL,
	kind                TEXT NOT NULL,
	from_display        TEXT NOT NULL,
	from_address        TEXT NOT NULL COLLATE NOCASE,
	to_list             TEXT NOT NULL,
	cc_list             TEXT NOT NULL,
	bcc_list            TEXT NOT NULL,
	reply_to            TEXT NOT NULL,
	feedback_forwarding TEXT NOT NULL,
	subject             TEXT NOT NULL,
	configuration_set   TEXT NOT NULL,
	tags                TEXT NOT NULL,
	headers             TEXT NOT NULL,
	text_body           TEXT NOT NULL,
	html_body           TEXT NOT NULL,
	attachments         TEXT NOT NULL,
	attachment_count    INTEGER NOT NULL,
	recipient_count     INTEGER NOT NULL,
	size                INTEGER NOT NULL
);
CREATE INDEX messages_sent_at ON messages (sent_at);
CREATE INDEX messages_from ON messages (from_address);

CREATE TABLE message_mime (
	seq  INTEGER PRIMARY KEY,
	mime BLOB NOT NULL
);

CREATE TABLE message_recipients (
	seq     INTEGER NOT NULL,
	address TEXT NOT NULL COLLATE NOCASE
);
CREATE INDEX message_recipients_address ON message_recipients (address, seq);
CREATE INDEX message_recipients_seq ON message_recipients (seq);

CREATE TABLE message_tags (
	seq   INTEGER NOT NULL,
	name  TEXT NOT NULL,
	value TEXT NOT NULL
);
CREATE INDEX message_tags_tag ON message_tags (name, value, seq);
CREATE INDEX message_tags_seq ON message_tags (seq);

CREATE VIRTUAL TABLE messages_fts USING fts5 (
	subject, text_body, content = 'messages', content_rowid = 'seq'
);
CREATE TRIGGER messages_fts_insert AFTER INSERT ON messages BEGIN
	INSERT INTO messages_fts (rowid, subject, text_body)
		VALUES (new.seq, new.subject, new.text_body);
END;
CREATE TRIGGER messages_fts_delete AFTER DELETE ON messages BEGIN
	INSERT INTO messages_fts (messages_fts, rowid, subject, text_body)
		VALUES ('delete', old.seq, old.subject, old.text_body);
END;
`,
		Down: `
DROP TRIGGER messages_fts_delete;
DROP TRIGGER messages_fts_insert;
DROP TABLE messages_fts;
DROP TABLE message_tags;
DROP TABLE message_recipients;
DROP TABLE message_mime;
DROP TABLE messages;
DROP TABLE templates;
DROP TABLE identities;
`,
	},
	{
		Version:     "0002",
		Description: "record rendering failures",
		Up: `
CREATE TABLE rendering_failures (
	seq               INTEGER PRIMARY KEY AUTOINCREMENT,
	message_id        TEXT NOT NULL,
	failed_at         INTEGER NOT NULL,
	source            TEXT NOT NULL,
	template          TEXT NOT NULL,
	from_display      TEXT NOT NULL,
	to_list           TEXT NOT NULL,
	cc_list           TEXT NOT NULL,
	bcc_list          TEXT NOT NULL,
	tags              TEXT NOT NULL,
	configuration_set TEXT NOT NULL,
	error             TEXT NOT NULL
);
CREATE INDEX rendering_failures_message_id ON rendering_failures (message_id);
CREATE INDEX rendering_failures_failed_at ON rendering_failures (failed_at);
`,
		Down: `
DROP TABLE rendering_failures;
`,
	},
}
