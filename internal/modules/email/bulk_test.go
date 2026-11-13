package email

import (
	"fmt"
	"testing"

	"tule.dev/mailbox/internal/sesapi"
)

func header(name, value string) sesapi.MessageHeader {
	return sesapi.MessageHeader{Name: &name, Value: &value}
}

func TestMergeHeadersLetsTheEntryWinPerName(t *testing.T) {
	got := mergeHeaders(
		[]sesapi.MessageHeader{header("X-Shared", "template"), header("X-Override", "template")},
		[]sesapi.MessageHeader{header("x-override", "entry"), header("X-Entry", "entry")},
	)
	out := make([]string, 0, len(got))
	for _, h := range got {
		out = append(out, *h.Name+"="+*h.Value)
	}
	want := "[X-Shared=template x-override=entry X-Entry=entry]"
	if fmt.Sprint(out) != want {
		t.Fatalf("merged = %v, want %s", out, want)
	}
}

func TestEntryDataFallsBackToTheDefault(t *testing.T) {
	data := func(d string) *sesapi.BulkEmailEntry {
		return &sesapi.BulkEmailEntry{ReplacementEmailContent: &sesapi.ReplacementEmailContent{
			ReplacementTemplate: &sesapi.ReplacementTemplate{ReplacementTemplateData: &d},
		}}
	}
	for _, tt := range []struct {
		entry *sesapi.BulkEmailEntry
		want  string
	}{
		{&sesapi.BulkEmailEntry{}, "default"},
		{data("{}"), "default"},
		{data(" {} "), "default"},
		{data(`{"a":1}`), `{"a":1}`},
	} {
		if got := entryData(tt.entry, "default"); got != tt.want {
			t.Errorf("entry data = %q, want %q", got, tt.want)
		}
	}
}
