package email

import (
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/gasmod/gas"

	"tule.dev/mailbox/internal/authz"
	"tule.dev/mailbox/internal/contracts"
	"tule.dev/mailbox/internal/mailmime"
	"tule.dev/mailbox/internal/sesapi"
)

// sendBulkEmail renders the default template once per entry and stores one
// message per entry. A request-level fault (no template, a template that
// does not exist, a bad sender) fails the whole request; a fault of one
// entry fails that entry alone, and the others are sent.
func (m *Module) sendBulkEmail(ctx gas.Context) error {
	req, err := sesapi.Decode[sesapi.SendBulkEmailRequest](ctx)
	if err != nil {
		return err
	}
	d, err := m.checkBulk(ctx, &req)
	if err != nil {
		return err
	}

	results := make([]sesapi.BulkEmailEntryResult, 0, len(req.BulkEmailEntries))
	var (
		msgs     []contracts.Message
		failures []contracts.RenderingFailure
	)
	for i := range req.BulkEmailEntries {
		res, eErr := m.bulkEntry(d, &req.BulkEmailEntries[i])
		if eErr != nil {
			return eErr
		}
		results = append(results, res.result)
		if res.msg != nil {
			msgs = append(msgs, *res.msg)
		}
		if res.failure != nil {
			failures = append(failures, *res.failure)
		}
	}
	if err = m.store.PutSend(ctx, msgs, failures); err != nil {
		return err
	}
	return sesapi.Write(ctx, sesapi.SendBulkEmailResponse{BulkEmailEntryResults: results})
}

// bulkDefaults is what every entry of a SendBulkEmail shares: the
// envelope, the default template and its content, and the default data.
type bulkDefaults struct {
	name     string
	template *sesapi.Template
	data     string
	content  contracts.TemplateContent
	env      envelope
}

// checkBulk checks a SendBulkEmail's request-level members and resolves
// its template.
func (m *Module) checkBulk(
	ctx gas.Context,
	req *sesapi.SendBulkEmailRequest,
) (*bulkDefaults, error) {
	if req.DefaultContent == nil || req.DefaultContent.Template == nil {
		return nil, sesapi.ErrBadRequest("You must specify the DefaultContent's Template.")
	}
	if n := len(req.BulkEmailEntries); n == 0 || n > sesapi.MaxBulkEntries {
		return nil, sesapi.ErrBadRequest(fmt.Sprintf(
			"BulkEmailEntries must have 1 to %d entries.", sesapi.MaxBulkEntries))
	}
	t := req.DefaultContent.Template
	env, err := envelopeOf(req.FromEmailAddress, req.ReplyToAddresses,
		req.FeedbackForwardingEmailAddress, req.ConfigurationSetName, "DefaultEmailTags",
		req.DefaultEmailTags)
	if err != nil {
		return nil, err
	}
	if env.from == "" {
		return nil, sesapi.ErrBadRequest("You must specify a FromEmailAddress.")
	}
	if err = checkTemplateParts("DefaultContent.Template", t); err != nil {
		return nil, err
	}
	d := &bulkDefaults{template: t, data: templateData(t.TemplateData), env: env}
	if err = checkTemplateData(d.data); err != nil {
		return nil, err
	}
	if d.name, d.content, err = m.bulkTemplate(ctx, env, t); err != nil {
		return nil, err
	}
	return d, nil
}

// bulkTemplate authorizes a SendBulkEmail and returns the name and content
// of its template. The resources it is evaluated on are the request's,
// shared by every entry: the reference lists no recipient or sender keys for
// SendBulkEmail.
func (m *Module) bulkTemplate(
	ctx gas.Context,
	env envelope,
	t *sesapi.Template,
) (string, contracts.TemplateContent, error) {
	name, content, err := m.templateSource(t)
	if err != nil {
		return "", content, err
	}
	if err = m.authz.Authorize(ctx, authz.Target{
		Sender:           env.fromAddress,
		ConfigurationSet: env.configSet,
		Template:         name,
	}); err != nil {
		return "", content, err
	}
	if name != "" {
		content, err = m.storedTemplate(ctx, name)
	}
	return name, content, err
}

// entryOutcome is what one bulk entry produced: its result, and the message
// it stored or the rendering failure it recorded, if either.
type entryOutcome struct {
	msg     *contracts.Message
	failure *contracts.RenderingFailure
	result  sesapi.BulkEmailEntryResult
}

// bulkEntry renders and builds one entry's message. Its faults become its
// result; the error is for a failure of the service itself.
func (m *Module) bulkEntry(d *bulkDefaults, e *sesapi.BulkEmailEntry) (entryOutcome, error) {
	now := m.now()
	id, err := mailmime.NewMessageID(now)
	if err != nil {
		return entryOutcome{}, err
	}
	success := sesapi.BulkEmailEntryResult{Status: sesapi.BulkStatusSuccess, MessageID: id}
	msg, err := renderEntry(d, e, now, id)
	var (
		failed *renderFailed
		apiErr *sesapi.Error
	)
	switch {
	case errors.As(err, &failed):
		// Accepted and then dropped, as SendEmail's are.
		failed.failure.Source = contracts.SourceSendBulkEmail
		return entryOutcome{result: success, failure: &failed.failure}, nil
	case errors.As(err, &apiErr):
		status := sesapi.BulkStatusInvalidParameter
		if apiErr.Type == sesapi.TypeMessageRejected {
			status = sesapi.BulkStatusMessageRejected
		}
		return entryOutcome{result: sesapi.BulkEmailEntryResult{
			Status: status, Error: apiErr.Message,
		}}, nil
	case err != nil:
		return entryOutcome{}, err
	}
	msg.Source = contracts.SourceSendBulkEmail
	return entryOutcome{result: success, msg: msg}, nil
}

// renderEntry renders one entry. The entry's replacement data and tags
// replace the defaults when it has them; replacement data of {} is none, as
// the SES developer guide describes it. Its replacement headers are merged
// into the template's.
func renderEntry(
	d *bulkDefaults,
	e *sesapi.BulkEmailEntry,
	now time.Time,
	id string,
) (*contracts.Message, error) {
	rcpt, err := recipientsOf(e.Destination)
	if err != nil {
		return nil, err
	}
	env := d.env
	data := entryData(e, d.data)
	if err = checkTemplateData(data); err != nil {
		return nil, err
	}
	if len(e.ReplacementTags) > 0 {
		if env.tags, err = messageTags("ReplacementTags", e.ReplacementTags); err != nil {
			return nil, err
		}
	}
	if err = sesapi.MessageHeaders("ReplacementHeaders", e.ReplacementHeaders); err != nil {
		return nil, err
	}
	headers := mergeHeaders(d.template.Headers, e.ReplacementHeaders)
	if err = sesapi.MessageHeaders("ReplacementHeaders", headers); err != nil {
		return nil, err
	}
	return renderMessage(env, rcpt, rendering{
		template: d.name, content: d.content, data: data,
		headers: headers, attachments: d.template.Attachments,
	}, now, id)
}

// entryData is an entry's replacement template data, or the default data
// when it has none or has {}.
func entryData(e *sesapi.BulkEmailEntry, defaultData string) string {
	c := e.ReplacementEmailContent
	if c == nil || c.ReplacementTemplate == nil ||
		c.ReplacementTemplate.ReplacementTemplateData == nil {
		return defaultData
	}
	if d := *c.ReplacementTemplate.ReplacementTemplateData; strings.TrimSpace(d) != "{}" {
		return d
	}
	return defaultData
}

// mergeHeaders adds the entry's headers to the template's, as the model
// describes BulkEmailEntry.ReplacementHeaders: an entry header replaces the
// value of the template's headers of the same name, compared without regard
// to case, and is added when the template has none.
func mergeHeaders(template, entry []sesapi.MessageHeader) []sesapi.MessageHeader {
	out := make([]sesapi.MessageHeader, 0, len(template)+len(entry))
	replaced := make(map[string]bool, len(entry))
	for _, h := range template {
		r := findHeader(entry, *h.Name)
		if r == nil {
			out = append(out, h)
			continue
		}
		key := strings.ToLower(*h.Name)
		if !replaced[key] {
			out = append(out, *r)
			replaced[key] = true
		}
	}
	for _, h := range entry {
		if !replaced[strings.ToLower(*h.Name)] {
			out = append(out, h)
		}
	}
	return out
}

func findHeader(hs []sesapi.MessageHeader, name string) *sesapi.MessageHeader {
	for i := range hs {
		if strings.EqualFold(*hs[i].Name, name) {
			return &hs[i]
		}
	}
	return nil
}

// checkTemplateParts checks the headers and attachments Template content
// adds.
func checkTemplateParts(field string, t *sesapi.Template) error {
	if err := sesapi.MessageHeaders(field+".Headers", t.Headers); err != nil {
		return err
	}
	return sesapi.Attachments(field+".Attachments", t.Attachments)
}
