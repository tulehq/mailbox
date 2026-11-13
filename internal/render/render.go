// Package render renders SES email templates: Handlebars, through
// github.com/mailgun/raymond/v2, with what SES's renderer, Handlebars.js,
// does on top:
//
//   - HTML is not escaped, as SES documents.
//   - JSON objects keep their key order, so #each over an object visits
//     the keys in the order the data gives them.
//   - Numbers print as JavaScript prints them.
//   - Rendering an attribute the data lacks, or calling a helper that does
//     not exist, fails the rendering.
//
// Before raymond renders a template, a walk over its syntax tree follows
// the branches and contexts the rendering takes. It reports the failures
// above, and bounds the rendering: the output it would produce and the work
// it would take, so no template and data can hold the service.
package render

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"reflect"
	"strconv"
	"strings"

	"github.com/mailgun/raymond/v2"
	"github.com/mailgun/raymond/v2/ast"
	"github.com/mailgun/raymond/v2/parser"
)

// The bounds of one rendering, all parts together: the output is at most
// MaxOutput bytes, SES's 40 MB message limit read as MiB, and the walk
// visits at most MaxSteps template nodes, each #each iteration visiting its
// block's nodes again.
const (
	MaxOutput = 40 << 20
	MaxSteps  = 1_000_000
)

// ErrInvalidData is returned for template data that is not a JSON object.
var ErrInvalidData = errors.New("render: template data is not a JSON object")

// Failure is a rendering that fails after SES would have accepted the send:
// the data lacks an attribute the template renders, the template calls a
// helper that does not exist, or the rendering exceeds its bounds. Message
// is the text SES, or Handlebars.js under it, reports.
type Failure struct {
	Message string
}

func (e *Failure) Error() string {
	return e.Message
}

func missingAttribute(name string) *Failure {
	return &Failure{Message: fmt.Sprintf("Attribute '%s' is not present in the rendering data.",
		name)}
}

func missingHelper(name string) *Failure {
	return &Failure{Message: fmt.Sprintf("Missing helper: %q", name)}
}

var (
	errTooLarge = &Failure{Message: fmt.Sprintf(
		"The rendered template is larger than %d bytes.", MaxOutput)}
	errTooComplex = &Failure{Message: fmt.Sprintf(
		"The template takes more than %d steps to render.", MaxSteps)}
)

// SyntaxError is returned for a template part that is not valid Handlebars.
type SyntaxError struct {
	Err  error
	Part string
}

func (e *SyntaxError) Error() string {
	return fmt.Sprintf("The %s part of the template is not valid: %v", e.Part, e.Err)
}

func (e *SyntaxError) Unwrap() error {
	return e.Err
}

// Content is a template's parts, or their rendering. An empty part is
// absent and renders empty.
type Content struct {
	Subject string
	Text    string
	HTML    string
}

// Check reports the first part of c that does not parse.
func Check(c Content) error {
	for _, p := range parts(&c) {
		if _, err := parser.Parse(*p.src); err != nil {
			return &SyntaxError{Part: p.name, Err: err}
		}
	}
	return nil
}

// Render renders every part of c with data, a JSON object. It returns
// ErrInvalidData for data that is not one, a *SyntaxError for a part that
// does not parse, and a *Failure for a rendering that fails.
func Render(c Content, data string) (Content, error) {
	d, err := decodeData(data)
	if err != nil {
		return Content{}, err
	}
	w := &walker{data: d}
	out := c
	for _, p := range parts(&out) {
		if *p.src == "" {
			continue
		}
		tpl, pErr := raymond.Parse(*p.src)
		if pErr != nil {
			return Content{}, &SyntaxError{Part: p.name, Err: pErr}
		}
		prog, pErr := parser.Parse(*p.src)
		if pErr != nil {
			return Content{}, &SyntaxError{Part: p.name, Err: pErr}
		}
		if wErr := w.program(prog, []frame{{ctx: d.root}}); wErr != nil {
			return Content{}, wErr
		}
		tpl.RegisterHelper("each", d.each)
		rendered, rErr := tpl.Exec(d.root)
		if rErr != nil {
			// A failure at render time, such as a partial that is not
			// there, is Handlebars.js's runtime error, a rendering failure.
			return Content{}, &Failure{Message: rErr.Error()}
		}
		*p.src = rendered
	}
	if len(out.Subject)+len(out.Text)+len(out.HTML) > MaxOutput {
		return Content{}, errTooLarge
	}
	return out, nil
}

type part struct {
	src  *string
	name string
}

func parts(c *Content) []part {
	return []part{{&c.Subject, "subject"}, {&c.Text, "text"}, {&c.HTML, "HTML"}}
}

// data is decoded template data: JSON objects as map[string]any, with
// their key order kept beside them, keyed by map identity, since a Go map
// has none.
type data struct {
	root  map[string]any
	order map[uintptr][]string
}

// keys returns an object's keys in the order the data gives them.
func (d *data) keys(m map[string]any) []string {
	return d.order[reflect.ValueOf(m).Pointer()]
}

// decodeData decodes template data. Strings become raymond.SafeString,
// which raymond writes unescaped, and numbers become what prints as
// JavaScript prints them.
func decodeData(s string) (*data, error) {
	d := &data{order: map[uintptr][]string{}}
	dec := json.NewDecoder(strings.NewReader(s))
	dec.UseNumber()
	v, err := d.decode(dec)
	if err != nil {
		return nil, ErrInvalidData
	}
	if _, err = dec.Token(); !errors.Is(err, io.EOF) {
		return nil, ErrInvalidData
	}
	root, ok := v.(map[string]any)
	if !ok {
		return nil, ErrInvalidData
	}
	d.root = root
	return d, nil
}

func (d *data) decode(dec *json.Decoder) (any, error) {
	tok, err := dec.Token()
	if err != nil {
		return nil, fmt.Errorf("decode: %w", err)
	}
	switch t := tok.(type) {
	case json.Delim:
		if t == '[' {
			return d.decodeArray(dec)
		}
		if t == '{' {
			return d.decodeObject(dec)
		}
		return nil, fmt.Errorf("decode: unexpected %v", t)
	case string:
		return raymond.SafeString(t), nil
	case json.Number:
		return jsNumber(t)
	default: // bool or nil
		return t, nil
	}
}

func (d *data) decodeArray(dec *json.Decoder) (any, error) {
	out := []any{}
	for dec.More() {
		v, err := d.decode(dec)
		if err != nil {
			return nil, err
		}
		out = append(out, v)
	}
	if _, err := dec.Token(); err != nil {
		return nil, fmt.Errorf("decode: %w", err)
	}
	return out, nil
}

func (d *data) decodeObject(dec *json.Decoder) (any, error) {
	out := map[string]any{}
	var keys []string
	for dec.More() {
		tok, err := dec.Token()
		if err != nil {
			return nil, fmt.Errorf("decode: %w", err)
		}
		k, _ := tok.(string) // an object key is always a string
		v, err := d.decode(dec)
		if err != nil {
			return nil, err
		}
		if _, dup := out[k]; !dup {
			keys = append(keys, k)
		}
		out[k] = v
	}
	if _, err := dec.Token(); err != nil {
		return nil, fmt.Errorf("decode: %w", err)
	}
	d.order[reflect.ValueOf(out).Pointer()] = keys
	return out, nil
}

// jsNumber returns a JSON number as the value that renders as JavaScript's
// Number toString renders it. Within 1e-6 to 1e21 that is a float64, which
// raymond prints in the same shortest decimal form, and which stays falsy at
// zero for #if. Outside that range JavaScript uses an exponent, so the
// number is that text, which is truthy, as a nonzero number is.
func jsNumber(n json.Number) (any, error) {
	f, err := strconv.ParseFloat(string(n), 64)
	if err != nil && !errors.Is(err, strconv.ErrRange) {
		return nil, fmt.Errorf("decode number: %w", err)
	}
	if f == 0 {
		return float64(0), nil // -0 prints as 0 in JavaScript
	}
	if a := math.Abs(f); a >= 1e-6 && a < 1e21 {
		return f, nil
	}
	if math.IsInf(f, 0) {
		if f > 0 {
			return raymond.SafeString("Infinity"), nil
		}
		return raymond.SafeString("-Infinity"), nil
	}
	mantissa, exp, _ := strings.Cut(strconv.FormatFloat(f, 'e', -1, 64), "e")
	e, _ := strconv.Atoi(exp) // FormatFloat writes a valid exponent
	sign := "+"
	if e < 0 {
		sign, e = "-", -e
	}
	return raymond.SafeString(mantissa + "e" + sign + strconv.Itoa(e)), nil
}

// each is the each helper, rendering arrays in order and objects in their
// keys' order, with @index, @key, @first and @last. raymond's own iterates
// a Go map, in no order. A second block parameter (as |item key|) is not
// bound: raymond offers a helper no way to bind it.
func (d *data) each(context any, options *raymond.Options) any {
	if !raymond.IsTrue(context) {
		return options.Inverse()
	}
	var b strings.Builder
	iter := func(n, i int, key, item any) {
		f := options.NewDataFrame()
		f.Set("index", i)
		f.Set("key", key)
		f.Set("first", i == 0)
		f.Set("last", i == n-1)
		b.WriteString(options.FnCtxData(item, f))
	}
	switch v := context.(type) {
	case []any:
		for i, item := range v {
			iter(len(v), i, i, item)
		}
	case map[string]any:
		keys := d.keys(v)
		for i, k := range keys {
			iter(len(keys), i, k, v[k])
		}
	}
	return b.String()
}

// helpers are Handlebars.js's built-in helpers. raymond also has equal,
// which Handlebars.js does not: a call to it is a missing helper, as on SES.
var helpers = map[string]bool{
	"if": true, "unless": true, "each": true, "with": true, "lookup": true, "log": true,
}

// frame is one context of the walk: the context value and the block
// parameters bound in it. An unbound parameter is known but has no value
// the walk can follow.
type frame struct {
	ctx     any
	params  map[string]any
	unbound map[string]bool
}

// walker follows a rendering through the syntax tree, as raymond will
// render it, counting the nodes it visits and the bytes it would write.
type walker struct {
	data  *data
	steps int
	size  int
}

func (w *walker) step() error {
	w.steps++
	if w.steps > MaxSteps {
		return errTooComplex
	}
	return nil
}

func (w *walker) write(n int) error {
	w.size += n
	if w.size > MaxOutput {
		return errTooLarge
	}
	return nil
}

func (w *walker) program(prog *ast.Program, frames []frame) error {
	if prog == nil {
		return nil
	}
	for _, node := range prog.Body {
		if err := w.step(); err != nil {
			return err
		}
		var err error
		switch n := node.(type) {
		case *ast.ContentStatement:
			err = w.write(len(n.Value))
		case *ast.MustacheStatement:
			err = w.mustache(n.Expression, frames)
		case *ast.BlockStatement:
			err = w.block(n, frames)
		}
		if err != nil {
			return err
		}
	}
	return nil
}

// mustache checks {{...}}: a helper call must name a helper, and an
// attribute must be in the data.
func (w *walker) mustache(expr *ast.Expression, frames []frame) error {
	path, ok := expr.Path.(*ast.PathExpression)
	if !ok {
		s, _ := expr.LiteralStr()
		return w.write(len(s))
	}
	name := expr.HelperName()
	if len(expr.Params) > 0 || expr.Hash != nil {
		v, err := w.call(expr, frames)
		if err != nil {
			return err
		}
		return w.write(strLen(v))
	}
	if helpers[name] {
		return nil
	}
	if path.Data {
		return w.write(len(path.Original))
	}
	v, st := resolve(path, frames)
	switch {
	case st == unknown:
		return nil
	case st == missing || v == nil:
		return missingAttribute(path.Original)
	}
	return w.write(strLen(v))
}

// call evaluates a helper call with arguments: lookup's value, nothing for
// the other helpers, and a failure for a helper that does not exist.
func (w *walker) call(expr *ast.Expression, frames []frame) (any, error) {
	name := expr.HelperName()
	if !helpers[name] {
		return nil, missingHelper(callee(expr))
	}
	args := make([]any, 0, len(expr.Params))
	for _, p := range expr.Params {
		v, err := w.param(p, frames)
		if err != nil {
			return nil, err
		}
		args = append(args, v)
	}
	if name == "lookup" && len(args) == 2 {
		return lookup(args[0], args[1]), nil
	}
	return nil, nil
}

// param evaluates a helper's argument.
func (w *walker) param(node ast.Node, frames []frame) (any, error) {
	switch n := node.(type) {
	case *ast.PathExpression:
		if n.Data {
			return nil, nil
		}
		v, _ := resolve(n, frames)
		return v, nil
	case *ast.SubExpression:
		return w.call(n.Expression, frames)
	case *ast.StringLiteral:
		return n.Value, nil
	case *ast.NumberLiteral:
		return n.Number(), nil
	case *ast.BooleanLiteral:
		return n.Value, nil
	}
	return nil, nil
}

// block follows a block the way it renders: if and unless into the branch
// their condition takes, each into every item, with into its value, and a
// block over an attribute, as Handlebars.js renders one, like each for an
// array, like with for any other true value, and its else otherwise.
func (w *walker) block(b *ast.BlockStatement, frames []frame) error {
	expr := b.Expression
	name := expr.HelperName()
	if len(expr.Params) == 0 && expr.Hash == nil && !helpers[name] {
		return w.section(b, frames)
	}
	if !helpers[name] {
		return missingHelper(callee(expr))
	}
	if len(expr.Params) == 0 {
		return nil
	}
	v, err := w.param(expr.Params[0], frames)
	if err != nil {
		return err
	}
	return w.helperBlock(name, b, v, frames)
}

// helperBlock follows a built-in block helper called with v.
func (w *walker) helperBlock(name string, b *ast.BlockStatement, v any, frames []frame) error {
	switch name {
	case "if":
		return w.program(branch(b, raymond.IsTrue(v)), frames)
	case "unless":
		return w.program(branch(b, !raymond.IsTrue(v)), frames)
	case "with":
		if !raymond.IsTrue(v) {
			return w.program(b.Inverse, frames)
		}
		return w.program(b.Program, push(frames, b.Program, v))
	case "each":
		return w.each(b, w.iterate(v), frames)
	}
	return nil
}

func (w *walker) section(b *ast.BlockStatement, frames []frame) error {
	path, ok := b.Expression.Path.(*ast.PathExpression)
	if !ok {
		return nil
	}
	v, st := resolve(path, frames)
	if st == unknown {
		return nil
	}
	if items, isArray := v.([]any); isArray {
		return w.each(b, items, frames)
	}
	if !raymond.IsTrue(v) {
		return w.program(b.Inverse, frames)
	}
	return w.program(b.Program, push(frames, b.Program, v))
}

func (w *walker) each(b *ast.BlockStatement, items []any, frames []frame) error {
	if len(items) == 0 {
		return w.program(b.Inverse, frames)
	}
	for _, item := range items {
		if err := w.program(b.Program, push(frames, b.Program, item)); err != nil {
			return err
		}
	}
	return nil
}

// iterate returns what each iterates over in v: an array's items or an
// object's values, in the data's key order.
func (w *walker) iterate(v any) []any {
	switch t := v.(type) {
	case []any:
		return t
	case map[string]any:
		keys := w.data.keys(t)
		out := make([]any, 0, len(keys))
		for _, k := range keys {
			out = append(out, t[k])
		}
		return out
	}
	return nil
}

// push adds the context of a block's program: its value, bound to the
// first block parameter, the second being unbound.
func push(frames []frame, prog *ast.Program, ctx any) []frame {
	f := frame{ctx: ctx}
	if prog != nil && len(prog.BlockParams) > 0 {
		f.params = map[string]any{prog.BlockParams[0]: ctx}
		if len(prog.BlockParams) > 1 {
			f.unbound = map[string]bool{prog.BlockParams[1]: true}
		}
	}
	return append(frames[:len(frames):len(frames)], f)
}

func branch(b *ast.BlockStatement, cond bool) *ast.Program {
	if cond {
		return b.Program
	}
	return b.Inverse
}

type status int

const (
	found status = iota
	missing
	unknown
)

// resolve looks a path up: in the block parameters when its first part
// names one, and otherwise in the context it names, the innermost one or the
// one path.Depth levels out for a ../ path.
func resolve(path *ast.PathExpression, frames []frame) (any, status) {
	parts := path.Parts
	var v any
	switch p, st := blockParam(path, frames); st {
	case found:
		v, parts = p, parts[1:]
	case unknown:
		return nil, unknown
	default:
		i := len(frames) - 1 - path.Depth
		if i < 0 {
			return nil, missing
		}
		v = frames[i].ctx
	}
	for _, p := range parts {
		m, ok := v.(map[string]any)
		if !ok {
			return nil, missing
		}
		if v, ok = m[p]; !ok {
			return nil, missing
		}
	}
	return v, found
}

// blockParam returns the block parameter a path starts with, missing when
// it starts with none.
func blockParam(path *ast.PathExpression, frames []frame) (any, status) {
	if path.Depth > 0 || path.Scoped || len(path.Parts) == 0 {
		return nil, missing
	}
	for i := len(frames) - 1; i >= 0; i-- {
		if v, ok := frames[i].params[path.Parts[0]]; ok {
			return v, found
		}
		if frames[i].unbound[path.Parts[0]] {
			return nil, unknown
		}
	}
	return nil, missing
}

// lookup is the lookup helper: an object's member or an array's item.
func lookup(obj, key any) any {
	k := raymond.Str(key)
	switch o := obj.(type) {
	case map[string]any:
		return o[k]
	case []any:
		if i, err := strconv.Atoi(k); err == nil && i >= 0 && i < len(o) {
			return o[i]
		}
	}
	return nil
}

// strLen is how many bytes raymond writes for v.
func strLen(v any) int {
	return len(raymond.Str(v))
}

// callee is the name a helper call is written with.
func callee(expr *ast.Expression) string {
	if p, ok := expr.Path.(*ast.PathExpression); ok {
		return p.Original
	}
	return expr.Canonical()
}
