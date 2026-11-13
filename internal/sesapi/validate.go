package sesapi

import (
	"fmt"
	"mime"
	"net/mail"
	"regexp"
	"slices"
	"strings"
	"unicode/utf8"
)

// The limits of the SES v2 API model and the SES quotas that the in-scope
// operations are held to.
const (
	// MaxRecipients is how many To, Cc and Bcc addresses one message may
	// have.
	MaxRecipients = 50
	// MaxMessageSize is the largest message SES v2 sends, in bytes, after
	// base64 encoding: 40 MB, read as MiB.
	MaxMessageSize = 40 << 20
	// MaxBulkEntries is how many entries one SendBulkEmail may have.
	MaxBulkEntries = 50
	// MaxTemplateSize is the largest template, its parts together: 500 KB,
	// read as KiB.
	MaxTemplateSize = 500 << 10
	// MaxTemplateData is the longest TemplateData, in characters.
	MaxTemplateData = 262144
	// MaxMessageHeaders is how many headers Simple or Template content may
	// add.
	MaxMessageHeaders = 15
	// MaxResourceTags is how many tags an identity or template may carry.
	MaxResourceTags = 50
)

// Address checks one email address of a request, which may carry a display
// name, and returns its bare address. SES takes 7-bit ASCII addresses only.
// The messages are the ones SES answers with, from its address parser.
func Address(field, v string) (string, error) {
	// A control character, CR and LF among them, is legal inside an address
	// comment to net/mail, and would end the header line the address is
	// written in.
	if hasControl(v) {
		return "", ErrBadRequest(fmt.Sprintf("Illegal address in %s: it contains a control "+
			"character.", field))
	}
	a, err := mail.ParseAddress(v)
	if err != nil {
		if !strings.Contains(v, "@") {
			return "", ErrBadRequest(fmt.Sprintf("Missing final '@domain' in %s: %s", field, v))
		}
		return "", ErrBadRequest(fmt.Sprintf("Illegal address in %s: %s", field, v))
	}
	for i := range len(a.Address) {
		if a.Address[i] > 0x7e || a.Address[i] < 0x21 {
			return "", ErrBadRequest(fmt.Sprintf(
				"Illegal address in %s: %s; the address must be 7-bit ASCII, its domain in "+
					"Punycode", field, v))
		}
	}
	return a.Address, nil
}

// Addresses checks a list of addresses and returns their bare addresses.
func Addresses(field string, vs []string) ([]string, error) {
	out := make([]string, 0, len(vs))
	for _, v := range vs {
		a, err := Address(field, v)
		if err != nil {
			return nil, err
		}
		out = append(out, a)
	}
	return out, nil
}

var tagNamePattern = regexp.MustCompile(`^[A-Za-z0-9_-]{0,256}$`)

// MessageTags checks a message's tags: names of 1 to 256 and values of up to
// 256 ASCII letters, digits, underscores and dashes.
func MessageTags(field string, tags []MessageTag) error {
	for _, t := range tags {
		if t.Name == nil || *t.Name == "" {
			return ErrBadRequest(fmt.Sprintf("You must specify a Name for each of %s.", field))
		}
		if t.Value == nil {
			return ErrBadRequest(fmt.Sprintf("You must specify a Value for each of %s.", field))
		}
		if !tagNamePattern.MatchString(*t.Name) || !tagNamePattern.MatchString(*t.Value) {
			return ErrBadRequest(fmt.Sprintf("Invalid tag in %s: names and values may only "+
				"contain ASCII letters, numbers, underscores and dashes, and be up to 256 "+
				"characters long.", field))
		}
	}
	return nil
}

var (
	headerNamePattern  = regexp.MustCompile(`^[!-9;-@A-~]{1,126}$`)
	headerValuePattern = regexp.MustCompile(`^[ -~]{1,995}$`)
)

// reservedHeaders are the headers SES sets itself, which Simple and Template
// content may not add.
var reservedHeaders = []string{
	"bcc", "cc", "content-disposition", "content-type", "date", "from", "message-id",
	"mime-version", "reply-to", "return-path", "subject", "to",
}

// MessageHeaders checks the headers Simple or Template content adds.
func MessageHeaders(field string, hs []MessageHeader) error {
	if len(hs) > MaxMessageHeaders {
		return ErrBadRequest(fmt.Sprintf("%s can have at most %d headers.", field,
			MaxMessageHeaders))
	}
	for _, h := range hs {
		if h.Name == nil || h.Value == nil {
			return ErrBadRequest(fmt.Sprintf("You must specify a Name and a Value for each "+
				"of %s.", field))
		}
		if !headerNamePattern.MatchString(*h.Name) {
			return ErrBadRequest(fmt.Sprintf("Invalid header name in %s: %s", field, *h.Name))
		}
		if !headerValuePattern.MatchString(*h.Value) {
			return ErrBadRequest(fmt.Sprintf("Invalid value for header %s in %s.", *h.Name,
				field))
		}
		if slices.Contains(reservedHeaders, strings.ToLower(*h.Name)) {
			return ErrBadRequest(fmt.Sprintf("The header %s is set by SES and cannot be "+
				"specified in %s.", *h.Name, field))
		}
	}
	return nil
}

// Attachments checks the attachments Simple or Template content adds, by
// the model's lengths and enumerations.
func Attachments(field string, as []Attachment) error {
	for _, a := range as {
		if a.FileName == nil || a.RawContent == nil {
			return ErrBadRequest(fmt.Sprintf("You must specify a FileName and RawContent for "+
				"each of %s.", field))
		}
		checks := []struct {
			v    *string
			name string
			min  int
			max  int
		}{
			{a.FileName, "FileName", 0, 255},
			{a.ContentDescription, "ContentDescription", 0, 1000},
			{a.ContentID, "ContentId", 1, 78},
			{a.ContentType, "ContentType", 1, 78},
		}
		for _, c := range checks {
			if err := attachmentField(field, c.name, c.v, c.min, c.max); err != nil {
				return err
			}
		}
		if err := attachmentContentType(field, a.ContentType); err != nil {
			return err
		}
		if err := Enum(field+".ContentDisposition", a.ContentDisposition,
			"ATTACHMENT", "INLINE"); err != nil {
			return err
		}
		if err := Enum(field+".ContentTransferEncoding", a.ContentTransferEncoding,
			"BASE64", "QUOTED_PRINTABLE", "SEVEN_BIT"); err != nil {
			return err
		}
	}
	return nil
}

// attachmentField checks one of an attachment's string fields: its length,
// and no control character, since each goes into a header. A ContentId
// goes into one as it is, so it must be printable ASCII.
func attachmentField(field, name string, v *string, minLen, maxLen int) error {
	if v == nil {
		return nil
	}
	if n := utf8.RuneCountInString(*v); n < minLen || n > maxLen {
		return ErrBadRequest(fmt.Sprintf("%s.%s must be %d to %d characters long.",
			field, name, minLen, maxLen))
	}
	if hasControl(*v) {
		return ErrBadRequest(fmt.Sprintf("%s.%s contains a control character.", field, name))
	}
	if name == "ContentId" && !isPrintableASCII(*v) {
		return ErrBadRequest(fmt.Sprintf("%s.ContentId must be printable ASCII.", field))
	}
	return nil
}

// attachmentContentType checks an attachment's ContentType is a
// type/subtype media type.
func attachmentContentType(field string, v *string) error {
	if v == nil {
		return nil
	}
	mediaType, _, err := mime.ParseMediaType(*v)
	typ, sub, ok := strings.Cut(mediaType, "/")
	if err != nil || !ok || typ == "" || sub == "" {
		return ErrBadRequest(fmt.Sprintf("%s.ContentType %q is not a type/subtype media type.",
			field, *v))
	}
	return nil
}

func hasControl(s string) bool {
	return strings.ContainsFunc(s, func(r rune) bool { return r < 0x20 || r == 0x7f })
}

func isPrintableASCII(s string) bool {
	for i := range len(s) {
		if s[i] < 0x20 || s[i] > 0x7e {
			return false
		}
	}
	return true
}

// Enum checks that v, when present, is one of values.
func Enum(field string, v *string, values ...string) error {
	if v == nil || slices.Contains(values, *v) {
		return nil
	}
	return ErrBadRequest(fmt.Sprintf("%s must be one of %s.", field, strings.Join(values, ", ")))
}

// unsupportedExtensions are the attachment file extensions SES refuses, from
// the SES developer guide's list of unsupported attachment types.
var unsupportedExtensions = strings.Fields(`
	ade adp app asp bas bat cer chm cmd com cpl crt csh der exe fxp gadget hlp
	hta inf ins isp its js jse ksh lib lnk mad maf mag mam maq mar mas mat
	mau mav maw mda mdb mde mdt mdw mdz msc msh msh1 msh2 mshxml msh1xml msh2xml msi msp
	mst ops pcd pif plg prf prg reg scf scr sct shb shs sys ps1 ps1xml ps2 ps2xml
	psc1 psc2 tmp url vb vbe vbs vps vsmacros vss vst vsw vxd ws wsc wsf wsh xnk`)

// AttachmentName refuses an attachment whose file name has an extension SES
// does not accept.
func AttachmentName(name string) error {
	i := strings.LastIndexByte(name, '.')
	if i < 0 {
		return nil
	}
	if slices.Contains(unsupportedExtensions, strings.ToLower(name[i+1:])) {
		return ErrMessageRejected(fmt.Sprintf("Illegal filename '%s'", name))
	}
	return nil
}

var resourceTagPattern = regexp.MustCompile(`^[\p{L}\p{Z}\p{N}_.:/=+\-]*$`)

// Tags checks a resource's tags: at most MaxResourceTags, keys of 1 to 128
// and values of up to 256 Unicode letters, digits, white space and _ . : / =
// + -, unique keys, and no aws: prefix.
func Tags(tags []Tag) error {
	if len(tags) > MaxResourceTags {
		return ErrBadRequest(fmt.Sprintf("A resource can have at most %d tags.",
			MaxResourceTags))
	}
	seen := make(map[string]bool, len(tags))
	for _, t := range tags {
		if t.Key == nil || t.Value == nil {
			return ErrBadRequest("You must specify a Key and a Value for each tag.")
		}
		k := *t.Key
		if err := tag(k, *t.Value); err != nil {
			return err
		}
		if seen[k] {
			return ErrBadRequest(fmt.Sprintf("Duplicate tag key: %s", k))
		}
		seen[k] = true
	}
	return nil
}

// tag checks one tag's key and value.
func tag(k, v string) error {
	if n := utf8.RuneCountInString(k); n < 1 || n > 128 || !resourceTagPattern.MatchString(k) {
		return ErrBadRequest(fmt.Sprintf("Invalid tag key: %s", k))
	}
	if utf8.RuneCountInString(v) > 256 || !resourceTagPattern.MatchString(v) {
		return ErrBadRequest(fmt.Sprintf("Invalid value for tag %s.", k))
	}
	if strings.HasPrefix(strings.ToLower(k), "aws:") ||
		strings.HasPrefix(strings.ToLower(v), "aws:") {
		return ErrBadRequest("The aws: prefix is reserved for use by AWS.")
	}
	return nil
}

// onceOnlyHeaders are the header fields SES refuses to see more than once in
// a message, from the SES developer guide's header fields page, lowercased.
var onceOnlyHeaders = strings.Fields(`
	accept-language acceptlanguage archived-at auto-submitted bounces-to comments
	content-alternative content-base content-class content-description
	content-disposition content-duration content-id content-language content-length
	content-location content-md5 content-transfer-encoding content-type date
	delivered-to disposition-notification-options disposition-notification-to
	dkim-signature domainkey-signature errors-to from importance in-reply-to keywords
	list-archive list-help list-id list-owner list-post list-subscribe list-unsubscribe
	list-unsubscribe-post message-context message-id mime-version organization
	original-from original-message-id original-recipient original-subject precedence
	priority references reply-to return-path return-receipt-to sender solicitation
	sensitivity subject thread-index thread-topic user-agent vbr-info`)

// SingleHeaders refuses a message whose header has one of the fields SES
// allows once more than once.
func SingleHeaders(names []string) error {
	seen := make(map[string]bool, len(names))
	for _, n := range names {
		k := strings.ToLower(n)
		if seen[k] && slices.Contains(onceOnlyHeaders, k) {
			return ErrMessageRejected(fmt.Sprintf("Duplicate header '%s'.", n))
		}
		seen[k] = true
	}
	return nil
}
