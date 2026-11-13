package email

import (
	"errors"
	"fmt"
	"net/http"
	"time"
	"unicode/utf8"

	"github.com/gasmod/gas"

	"tule.dev/mailbox/internal/authz"
	"tule.dev/mailbox/internal/contracts"
	"tule.dev/mailbox/internal/mailmime"
	"tule.dev/mailbox/internal/render"
	"tule.dev/mailbox/internal/sesapi"
)

// templateContent checks a template's content: present, at most
// sesapi.MaxTemplateSize all told, and valid Handlebars.
func templateContent(c *sesapi.EmailTemplateContent) (contracts.TemplateContent, error) {
	if c == nil {
		return contracts.TemplateContent{}, sesapi.ErrBadRequest(
			"You must specify the TemplateContent.")
	}
	out := contracts.TemplateContent{
		Subject: deref(c.Subject),
		Text:    deref(c.Text),
		HTML:    deref(c.Html),
	}
	if len(out.Subject)+len(out.Text)+len(out.HTML) > sesapi.MaxTemplateSize {
		return out, sesapi.ErrBadRequest(fmt.Sprintf(
			"The template is larger than %d bytes.", sesapi.MaxTemplateSize))
	}
	if err := render.Check(renderContent(out)); err != nil {
		return out, sesapi.ErrBadRequest(err.Error())
	}
	return out, nil
}

func renderContent(c contracts.TemplateContent) render.Content {
	return render.Content{Subject: c.Subject, Text: c.Text, HTML: c.HTML}
}

func wireContent(c contracts.TemplateContent) sesapi.EmailTemplateContent {
	var out sesapi.EmailTemplateContent
	if c.Subject != "" {
		out.Subject = &c.Subject
	}
	if c.Text != "" {
		out.Text = &c.Text
	}
	if c.HTML != "" {
		out.Html = &c.HTML
	}
	return out
}

func templateNotFound(err error, name string) error {
	if errors.Is(err, contracts.ErrTemplateNotFound) {
		return sesapi.ErrNotFound(fmt.Sprintf("Template %s does not exist.", name))
	}
	return err
}

// templateParam returns the template the path names, once the request is
// authorized for it.
func (m *Module) templateParam(ctx gas.Context) (string, error) {
	name, err := sesapi.PathParam(ctx, "TemplateName")
	if err != nil {
		return "", err
	}
	if name == "" {
		return "", sesapi.ErrBadRequest("You must specify a TemplateName.")
	}
	return name, m.authz.Authorize(ctx, authz.Target{Template: name})
}

func (m *Module) createEmailTemplate(ctx gas.Context) error {
	req, err := sesapi.Decode[sesapi.CreateEmailTemplateRequest](ctx)
	if err != nil {
		return err
	}
	if req.TemplateName == "" {
		return sesapi.ErrBadRequest("You must specify a TemplateName.")
	}
	content, err := templateContent(req.TemplateContent)
	if err != nil {
		return err
	}
	if err = sesapi.Tags(req.Tags); err != nil {
		return err
	}
	if err = m.authz.Authorize(ctx, authz.Target{
		Template: req.TemplateName, Tags: storeTags(req.Tags),
	}); err != nil {
		return err
	}
	err = m.store.CreateTemplate(ctx, contracts.Template{
		CreatedAt: m.now(),
		Name:      req.TemplateName,
		Content:   content,
		Tags:      storeTags(req.Tags),
	})
	if errors.Is(err, contracts.ErrTemplateExists) {
		return sesapi.NewError(http.StatusBadRequest, sesapi.TypeAlreadyExists,
			fmt.Sprintf("Template %s already exists.", req.TemplateName))
	}
	if err != nil {
		return err
	}
	return sesapi.Write(ctx, sesapi.EmptyResponse{})
}

func (m *Module) getEmailTemplate(ctx gas.Context) error {
	name, err := m.templateParam(ctx)
	if err != nil {
		return err
	}
	t, err := m.store.GetTemplate(ctx, name)
	if err != nil {
		return templateNotFound(err, name)
	}
	return sesapi.Write(ctx, sesapi.GetEmailTemplateResponse{
		TemplateName:    t.Name,
		TemplateContent: wireContent(t.Content),
		Tags:            wireTags(t.Tags),
	})
}

func (m *Module) listEmailTemplates(ctx gas.Context) error {
	page, err := pageOf(ctx, 1, 100)
	if err != nil {
		return err
	}
	out, err := m.store.ListTemplates(ctx, page)
	if err != nil {
		return err
	}
	resp := sesapi.ListEmailTemplatesResponse{
		TemplatesMetadata: make([]sesapi.EmailTemplateMetadata, 0, len(out.Items)),
		NextToken:         out.NextToken,
	}
	for _, t := range out.Items {
		resp.TemplatesMetadata = append(resp.TemplatesMetadata, sesapi.EmailTemplateMetadata{
			TemplateName:     t.Name,
			CreatedTimestamp: sesapi.EpochSeconds(t.CreatedAt),
		})
	}
	return sesapi.Write(ctx, resp)
}

func (m *Module) updateEmailTemplate(ctx gas.Context) error {
	name, err := m.templateParam(ctx)
	if err != nil {
		return err
	}
	req, err := sesapi.Decode[sesapi.UpdateEmailTemplateRequest](ctx)
	if err != nil {
		return err
	}
	content, err := templateContent(req.TemplateContent)
	if err != nil {
		return err
	}
	if err = m.store.UpdateTemplate(ctx, name, content); err != nil {
		return templateNotFound(err, name)
	}
	return sesapi.Write(ctx, sesapi.EmptyResponse{})
}

func (m *Module) deleteEmailTemplate(ctx gas.Context) error {
	name, err := m.templateParam(ctx)
	if err != nil {
		return err
	}
	if err = m.store.DeleteTemplate(ctx, name); err != nil {
		return templateNotFound(err, name)
	}
	return sesapi.Write(ctx, sesapi.EmptyResponse{})
}

func (m *Module) testRenderEmailTemplate(ctx gas.Context) error {
	name, err := m.templateParam(ctx)
	if err != nil {
		return err
	}
	req, err := sesapi.Decode[sesapi.TestRenderEmailTemplateRequest](ctx)
	if err != nil {
		return err
	}
	if req.TemplateData == nil {
		return sesapi.ErrBadRequest("You must specify the TemplateData.")
	}
	if err = checkTemplateData(*req.TemplateData); err != nil {
		return err
	}
	t, err := m.store.GetTemplate(ctx, name)
	if err != nil {
		return templateNotFound(err, name)
	}
	rendered, err := render.Render(renderContent(t.Content), *req.TemplateData)
	if err != nil {
		return renderError(err)
	}

	now := m.now()
	id, err := mailmime.NewMessageID(now)
	if err != nil {
		return err
	}
	msg, err := mailmime.Build(renderedMessage(rendered, now, id))
	if err != nil {
		return sesapi.ErrBadRequest(err.Error())
	}
	return sesapi.Write(ctx, sesapi.TestRenderEmailTemplateResponse{RenderedTemplate: string(msg)})
}

// checkTemplateData holds template data to the model's length limit.
func checkTemplateData(data string) error {
	if utf8.RuneCountInString(data) > sesapi.MaxTemplateData {
		return sesapi.ErrBadRequest(fmt.Sprintf("TemplateData can be at most %d characters.",
			sesapi.MaxTemplateData))
	}
	return nil
}

// renderError is the error a failed rendering is answered with.
func renderError(err error) error {
	var f *render.Failure
	switch {
	case errors.As(err, &f):
		return sesapi.ErrBadRequest(f.Message)
	case errors.Is(err, render.ErrInvalidData):
		return sesapi.ErrBadRequest("Invalid TemplateData: it must be a JSON object.")
	default:
		return sesapi.ErrBadRequest(err.Error())
	}
}

// renderedMessage is the message SES assembles from a rendered template,
// before it has a sender and recipients.
func renderedMessage(r render.Content, now time.Time, id string) *mailmime.Message {
	msg := &mailmime.Message{
		Date:      now,
		MessageID: id,
		Subject:   mailmime.Text{Data: r.Subject},
	}
	if r.Text != "" {
		msg.Text = &mailmime.Text{Data: r.Text}
	}
	if r.HTML != "" {
		msg.HTML = &mailmime.Text{Data: r.HTML}
	}
	return msg
}
