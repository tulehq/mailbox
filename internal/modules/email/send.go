package email

import (
	"errors"
	"fmt"
	"net/mail"
	"strings"
	"time"

	"github.com/gasmod/gas"

	"tule.dev/mailbox/internal/contracts"
	"tule.dev/mailbox/internal/mailmime"
	"tule.dev/mailbox/internal/render"
	"tule.dev/mailbox/internal/sesapi"
)

// envelope is what every message of one send shares.
type envelope struct {
	from        string
	fromAddress string
	feedback    string
	configSet   string
	replyTo     []string
	tags        []contracts.MessageTag
}

// envelopeOf checks the sender, reply-to and feedback addresses, and the
// tags, of a send.
func envelopeOf(
	from *string,
	replyTo []string,
	feedback *string,
	configSet *string,
	tagsField string,
	tags []sesapi.MessageTag,
) (envelope, error) {
	env := envelope{
		replyTo:   replyTo,
		configSet: deref(configSet),
		feedback:  deref(feedback),
	}
	if from != nil {
		a, err := sesapi.Address("FromEmailAddress", *from)
		if err != nil {
			return env, err
		}
		env.from, env.fromAddress = *from, a
	}
	if _, err := sesapi.Addresses("ReplyToAddresses", replyTo); err != nil {
		return env, err
	}
	if feedback != nil {
		if _, err := sesapi.Address("FeedbackForwardingEmailAddress", *feedback); err != nil {
			return env, err
		}
	}
	var err error
	env.tags, err = messageTags(tagsField, tags)
	return env, err
}

func messageTags(field string, tags []sesapi.MessageTag) ([]contracts.MessageTag, error) {
	if err := sesapi.MessageTags(field, tags); err != nil {
		return nil, err
	}
	out := make([]contracts.MessageTag, 0, len(tags))
	for _, t := range tags {
		out = append(out, contracts.MessageTag{Name: *t.Name, Value: *t.Value})
	}
	return out, nil
}

// recipients are a message's To, Cc and Bcc as sent, and the bare address
// of each.
type recipients struct {
	to, cc, bcc []string
	addresses   []string
}

// recipientsOf checks a destination: valid addresses, 1 to
// sesapi.MaxRecipients of them.
func recipientsOf(d *sesapi.Destination) (recipients, error) {
	var r recipients
	if d != nil {
		r.to, r.cc, r.bcc = d.ToAddresses, d.CcAddresses, d.BccAddresses
	}
	for _, l := range []struct {
		field string
		addrs []string
	}{
		{"ToAddresses", r.to}, {"CcAddresses", r.cc}, {"BccAddresses", r.bcc},
	} {
		a, err := sesapi.Addresses("Destination."+l.field, l.addrs)
		if err != nil {
			return r, err
		}
		r.addresses = append(r.addresses, a...)
	}
	return r, checkRecipientCount(len(r.addresses))
}

func checkRecipientCount(n int) error {
	switch {
	case n == 0:
		return sesapi.ErrBadRequest(
			"The message has no recipients: specify at least one To, Cc or Bcc address.",
		)
	case n > sesapi.MaxRecipients:
		return sesapi.ErrBadRequest(fmt.Sprintf("Recipient count exceeds %d.",
			sesapi.MaxRecipients))
	}
	return nil
}

func (m *Module) sendEmail(ctx gas.Context) error {
	req, err := sesapi.Decode[sesapi.SendEmailRequest](ctx)
	if err != nil {
		return err
	}
	c := req.Content
	if c == nil || kinds(c) != 1 {
		return sesapi.ErrBadRequest("Content must have exactly one of Simple, Raw and Template.")
	}
	env, err := envelopeOf(req.FromEmailAddress, req.ReplyToAddresses,
		req.FeedbackForwardingEmailAddress, req.ConfigurationSetName, "EmailTags", req.EmailTags)
	if err != nil {
		return err
	}
	now := m.now()
	id, err := mailmime.NewMessageID(now)
	if err != nil {
		return err
	}

	msg, err := m.message(ctx, env, req.Destination, c, now, id)
	var failed *renderFailed
	switch {
	case errors.As(err, &failed):
		// SES accepts a templated message whose rendering fails, and then
		// drops it: the MessageId is answered and nothing is sent. The
		// failure is recorded for the retrieval API.
		err = m.store.PutSend(ctx, nil, []contracts.RenderingFailure{failed.failure})
	case err == nil:
		err = m.store.PutSend(ctx, []contracts.Message{*msg}, nil)
	}
	if err != nil {
		return err
	}
	return sesapi.Write(ctx, sesapi.SendEmailResponse{MessageID: id})
}

// message makes the stored message of SendEmail's one kind of content.
func (m *Module) message(
	ctx gas.Context,
	env envelope,
	dest *sesapi.Destination,
	c *sesapi.EmailContent,
	now time.Time,
	id string,
) (*contracts.Message, error) {
	switch {
	case c.Simple != nil:
		return m.simple(env, dest, c.Simple, now, id)
	case c.Template != nil:
		return m.templated(ctx, env, dest, c.Template, now, id)
	default:
		return m.raw(env, dest, c.Raw, now, id)
	}
}

func kinds(c *sesapi.EmailContent) int {
	n := 0
	for _, set := range []bool{c.Simple != nil, c.Raw != nil, c.Template != nil} {
		if set {
			n++
		}
	}
	return n
}

func (m *Module) simple(
	env envelope,
	dest *sesapi.Destination,
	s *sesapi.Message,
	now time.Time,
	id string,
) (*contracts.Message, error) {
	if s.Subject == nil || s.Subject.Data == nil {
		return nil, sesapi.ErrBadRequest("You must specify the Subject of the message.")
	}
	if s.Body == nil {
		return nil, sesapi.ErrBadRequest("You must specify the Body of the message.")
	}
	rcpt, err := m.checkSend(env, dest, "Content.Simple", s.Headers, s.Attachments)
	if err != nil {
		return nil, err
	}
	msg := baseMessage(env, rcpt, now, id, s.Headers, s.Attachments)
	msg.Subject = text(s.Subject)
	if s.Body.Text != nil {
		t := text(s.Body.Text)
		msg.Text = &t
	}
	if s.Body.Html != nil {
		h := text(s.Body.Html)
		msg.HTML = &h
	}
	return build(contracts.KindSimple, env, rcpt, msg)
}

// checkSend checks what Simple and Template content share: a sender, the
// recipients, the headers and the attachments.
func (m *Module) checkSend(
	env envelope,
	dest *sesapi.Destination,
	field string,
	headers []sesapi.MessageHeader,
	attachments []sesapi.Attachment,
) (recipients, error) {
	if env.from == "" {
		return recipients{}, sesapi.ErrBadRequest("You must specify a FromEmailAddress.")
	}
	rcpt, err := recipientsOf(dest)
	if err != nil {
		return rcpt, err
	}
	if err = sesapi.MessageHeaders(field+".Headers", headers); err != nil {
		return rcpt, err
	}
	return rcpt, sesapi.Attachments(field+".Attachments", attachments)
}

func text(c *sesapi.Content) mailmime.Text {
	return mailmime.Text{Data: deref(c.Data), Charset: deref(c.Charset)}
}

// baseMessage is the message to build, without its subject and bodies.
func baseMessage(
	env envelope,
	rcpt recipients,
	now time.Time,
	id string,
	headers []sesapi.MessageHeader,
	attachments []sesapi.Attachment,
) *mailmime.Message {
	msg := &mailmime.Message{
		Date:      now,
		MessageID: id,
		From:      env.from,
		ReplyTo:   env.replyTo,
		To:        rcpt.to,
		Cc:        rcpt.cc,
	}
	for _, h := range headers {
		msg.Headers = append(msg.Headers, mailmime.Header{Name: *h.Name, Value: *h.Value})
	}
	for _, a := range attachments {
		msg.Attachments = append(msg.Attachments, mailmime.Attachment{
			Content:     a.RawContent,
			FileName:    *a.FileName,
			ContentType: deref(a.ContentType),
			Disposition: deref(a.ContentDisposition),
			Description: deref(a.ContentDescription),
			ContentID:   deref(a.ContentID),
			Encoding:    deref(a.ContentTransferEncoding),
		})
	}
	return msg
}

// build assembles msg and makes the stored message of it.
func build(
	kind string,
	env envelope,
	rcpt recipients,
	msg *mailmime.Message,
) (*contracts.Message, error) {
	b, err := mailmime.Build(msg)
	if err != nil {
		return nil, sesapi.ErrBadRequest(err.Error())
	}
	return stored(kind, env, rcpt, b, msg.Date, msg.MessageID)
}

// stored makes the stored message of a message as SES sends it: it must be
// within SES's size limit and attach no file type SES refuses.
func stored(
	kind string,
	env envelope,
	rcpt recipients,
	b []byte,
	now time.Time,
	id string,
) (*contracts.Message, error) {
	if len(b) > sesapi.MaxMessageSize {
		return nil, sesapi.ErrMessageRejected(fmt.Sprintf(
			"Message length is more than %d bytes long: '%d'.", sesapi.MaxMessageSize, len(b)))
	}
	parsed, err := mailmime.Parse(b)
	if err != nil {
		return nil, sesapi.ErrMessageRejected(err.Error())
	}
	msg := &contracts.Message{
		Time:               now,
		ID:                 id,
		Source:             contracts.SourceSendEmail,
		Kind:               kind,
		From:               env.from,
		FromAddress:        env.fromAddress,
		FeedbackForwarding: env.feedback,
		Subject:            parsed.Subject,
		ConfigurationSet:   env.configSet,
		Text:               parsed.Text,
		HTML:               parsed.HTML,
		To:                 rcpt.to,
		Cc:                 rcpt.cc,
		Bcc:                rcpt.bcc,
		ReplyTo:            env.replyTo,
		Recipients:         rcpt.addresses,
		Tags:               env.tags,
		MIME:               b,
		Size:               len(b),
	}
	names := make([]string, 0, len(parsed.Headers))
	for _, h := range parsed.Headers {
		names = append(names, h.Name)
		msg.Headers = append(msg.Headers, contracts.Header{Name: h.Name, Value: h.Value})
	}
	if err = sesapi.SingleHeaders(names); err != nil {
		return nil, err
	}
	for _, a := range parsed.Attachments {
		if err = sesapi.AttachmentName(a.Name); err != nil {
			return nil, err
		}
		msg.Attachments = append(msg.Attachments, contracts.AttachmentInfo{
			Name:        a.Name,
			ContentType: a.ContentType,
			Size:        len(a.Content),
		})
	}
	return msg, nil
}

// renderFailed is a templated message whose rendering failed after SES
// would have accepted it, with the record of the failure.
type renderFailed struct {
	failure contracts.RenderingFailure
}

func (e *renderFailed) Error() string {
	return "email: the template did not render: " + e.failure.Error
}

func (m *Module) templated(
	ctx gas.Context,
	env envelope,
	dest *sesapi.Destination,
	t *sesapi.Template,
	now time.Time,
	id string,
) (*contracts.Message, error) {
	name, content, err := m.resolveTemplate(ctx, t)
	if err != nil {
		return nil, err
	}
	rcpt, err := m.checkSend(env, dest, "Content.Template", t.Headers, t.Attachments)
	if err != nil {
		return nil, err
	}
	data := templateData(t.TemplateData)
	if err = checkTemplateData(data); err != nil {
		return nil, err
	}
	return renderMessage(env, rcpt, rendering{
		template: name, content: content, data: data,
		headers: t.Headers, attachments: t.Attachments,
	}, now, id)
}

// rendering is what a templated message is rendered from: the template's
// name ("" for inline content) and content, the data, and the headers and
// attachments the message adds.
type rendering struct {
	template    string
	content     contracts.TemplateContent
	data        string
	headers     []sesapi.MessageHeader
	attachments []sesapi.Attachment
}

// templateData is the data a template renders with: an absent TemplateData
// is an empty object.
func templateData(v *string) string {
	if v == nil {
		return "{}"
	}
	return *v
}

// renderMessage renders a template into a message. Data that is not a JSON
// object is refused; a rendering that fails, as render.Failure has it,
// returns a *renderFailed recording it, from SendEmail.
func renderMessage(
	env envelope,
	rcpt recipients,
	r rendering,
	now time.Time,
	id string,
) (*contracts.Message, error) {
	rendered, err := render.Render(renderContent(r.content), r.data)
	var f *render.Failure
	if errors.As(err, &f) {
		return nil, &renderFailed{failure: contracts.RenderingFailure{
			Time:             now,
			MessageID:        id,
			Source:           contracts.SourceSendEmail,
			Template:         r.template,
			From:             env.from,
			ConfigurationSet: env.configSet,
			Error:            f.Message,
			To:               rcpt.to,
			Cc:               rcpt.cc,
			Bcc:              rcpt.bcc,
			Tags:             env.tags,
		}}
	}
	if err != nil {
		return nil, renderError(err)
	}
	msg := baseMessage(env, rcpt, now, id, r.headers, r.attachments)
	rm := renderedMessage(rendered, now, id)
	msg.Subject, msg.Text, msg.HTML = rm.Subject, rm.Text, rm.HTML
	return build(contracts.KindTemplate, env, rcpt, msg)
}

// resolveTemplate returns the name and content of Template content: given
// inline, with no name, or the stored template it names by name or ARN.
func (m *Module) resolveTemplate(
	ctx gas.Context,
	t *sesapi.Template,
) (string, contracts.TemplateContent, error) {
	if t.TemplateContent != nil {
		if t.TemplateName != nil || t.TemplateArn != nil {
			return "", contracts.TemplateContent{}, sesapi.ErrBadRequest(
				"Specify either TemplateContent or a TemplateName or TemplateArn, not both.")
		}
		content, err := templateContent(t.TemplateContent)
		return "", content, err
	}
	name, err := templateName(t)
	if err != nil {
		return "", contracts.TemplateContent{}, err
	}
	tmpl, err := m.store.GetTemplate(ctx, name)
	if err != nil {
		return "", contracts.TemplateContent{}, templateNotFound(err, name)
	}
	return name, tmpl.Content, nil
}

// templateName is the name of the stored template Template content names,
// by its TemplateName or, without one, by its TemplateArn.
func templateName(t *sesapi.Template) (string, error) {
	switch {
	case t.TemplateName != nil && *t.TemplateName != "":
		return *t.TemplateName, nil
	case t.TemplateArn != nil && *t.TemplateArn != "":
		_, name, ok := strings.Cut(*t.TemplateArn, ":template/")
		if !ok || name == "" {
			return "", sesapi.ErrBadRequest(fmt.Sprintf("Invalid TemplateArn: %s",
				*t.TemplateArn))
		}
		return name, nil
	default:
		return "", sesapi.ErrBadRequest(
			"You must specify a TemplateName, a TemplateArn or the TemplateContent.")
	}
}

// raw prepares Raw content as SES sends it. The sender, recipients,
// configuration set and tags the request gives take precedence over the
// message's own From, To, Cc and Bcc headers and its X-SES headers.
func (m *Module) raw(
	env envelope,
	dest *sesapi.Destination,
	r *sesapi.RawMessage,
	now time.Time,
	id string,
) (*contracts.Message, error) {
	if len(r.Data) == 0 {
		return nil, sesapi.ErrBadRequest("You must specify the Data of the raw message.")
	}
	prepared, err := mailmime.PrepareRaw(r.Data, id, now)
	if err != nil {
		return nil, sesapi.ErrMessageRejected(err.Error())
	}

	if env.from == "" {
		if env.from, env.fromAddress, err = rawSender(prepared.From); err != nil {
			return nil, err
		}
	}
	rcpt, err := rawRecipients(dest, prepared)
	if err != nil {
		return nil, err
	}
	if env.configSet == "" {
		env.configSet = prepared.ConfigurationSet
	}
	if len(env.tags) == 0 && prepared.Tags != "" {
		if env.tags, err = headerTags(prepared.Tags); err != nil {
			return nil, err
		}
	}
	return stored(contracts.KindRaw, env, rcpt, prepared.MIME, now, id)
}

// rawSender is the sender of a raw message sent without FromEmailAddress:
// its From header, as written, and that header's address.
func rawSender(from string) (string, string, error) {
	if from == "" {
		return "", "", sesapi.ErrBadRequest(
			"You must specify a FromEmailAddress or a From header in the raw message.")
	}
	a, err := headerAddress(from)
	if err != nil {
		return "", "", err
	}
	return from, a.Address, nil
}

// rawRecipients are the destination's addresses when it has any, and
// otherwise the message's To, Cc and Bcc headers'.
func rawRecipients(dest *sesapi.Destination, prepared *mailmime.Raw) (recipients, error) {
	if dest != nil && len(dest.ToAddresses)+len(dest.CcAddresses)+len(dest.BccAddresses) > 0 {
		return recipientsOf(dest)
	}
	var r recipients
	for _, l := range []struct {
		dst   *[]string
		value string
	}{{&r.to, prepared.To}, {&r.cc, prepared.Cc}, {&r.bcc, prepared.Bcc}} {
		if l.value == "" {
			continue
		}
		list, err := mail.ParseAddressList(l.value)
		if err != nil {
			return r, sesapi.ErrBadRequest(fmt.Sprintf("Illegal address: %s", l.value))
		}
		for _, a := range list {
			if _, err = sesapi.Address("the raw message", a.Address); err != nil {
				return r, err
			}
			*l.dst = append(*l.dst, displayAddress(a))
			r.addresses = append(r.addresses, a.Address)
		}
	}
	return r, checkRecipientCount(len(r.addresses))
}

func headerAddress(v string) (*mail.Address, error) {
	a, err := mail.ParseAddress(v)
	if err != nil {
		return nil, sesapi.ErrBadRequest(fmt.Sprintf("Illegal address: %s", v))
	}
	if _, err = sesapi.Address("the raw message", a.Address); err != nil {
		return nil, err
	}
	return a, nil
}

// headerTags parses an X-SES-MESSAGE-TAGS header: name=value pairs
// separated by commas.
func headerTags(v string) ([]contracts.MessageTag, error) {
	var tags []sesapi.MessageTag
	for pair := range strings.SplitSeq(v, ",") {
		name, value, ok := strings.Cut(strings.TrimSpace(pair), "=")
		if !ok {
			return nil, sesapi.ErrBadRequest(fmt.Sprintf(
				"Invalid X-SES-MESSAGE-TAGS header: %s", v))
		}
		name, value = strings.TrimSpace(name), strings.TrimSpace(value)
		tags = append(tags, sesapi.MessageTag{Name: &name, Value: &value})
	}
	return messageTags("the X-SES-MESSAGE-TAGS header", tags)
}

// displayAddress writes a header address the way a request gives one: bare
// when it has no display name.
func displayAddress(a *mail.Address) string {
	if a.Name == "" {
		return a.Address
	}
	return a.String()
}
