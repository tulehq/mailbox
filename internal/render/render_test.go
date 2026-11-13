package render

import (
	"errors"
	"strings"
	"testing"
)

func TestRenderFollowsSESHandlebars(t *testing.T) {
	tests := []struct {
		name, tmpl, data, want string
	}{
		{"variable", "Hello {{name}}!", `{"name":"Alejandro"}`, "Hello Alejandro!"},
		{"nested", "{{contact.firstName}}", `{"contact":{"firstName":"Anaya"}}`, "Anaya"},
		{
			"each", "{{#each subscription}}[{{interest}}]{{/each}}",
			`{"subscription":[{"interest":"Sports"},{"interest":"Travel"}]}`, "[Sports][Travel]",
		},
		{"if", "{{#if a}}yes{{else}}no{{/if}}", `{"a":true}`, "yes"},
		{"if on a missing attribute", "{{#if a}}yes{{else}}no{{/if}}", `{}`, "no"},
		{"unless", "{{#unless a}}none{{/unless}}", `{"a":[]}`, "none"},
		{"with", "{{#with c}}{{x}}{{/with}}", `{"c":{"x":"in"}}`, "in"},
		{
			"parent path",
			"{{#each l}}{{this}}{{../sep}}{{/each}}",
			`{"l":["a","b"],"sep":","}`,
			"a,b,",
		},
		{"index", "{{#each l}}{{@index}}{{/each}}", `{"l":["a","b"]}`, "01"},
		{"numbers as written", "{{n}} {{f}}", `{"n":51806220607,"f":1.5}`, "51806220607 1.5"},
		{"HTML is not escaped", "<p>{{x}}</p>", `{"x":"<b>a & b</b>"}`, "<p><b>a & b</b></p>"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := Render(Content{HTML: tt.tmpl}, tt.data)
			if err != nil {
				t.Fatalf("render: %v", err)
			}
			if got.HTML != tt.want {
				t.Fatalf("rendered %q, want %q", got.HTML, tt.want)
			}
		})
	}
}

func TestRenderReportsAMissingAttribute(t *testing.T) {
	tests := []struct {
		name, tmpl, data, missing string
	}{
		{"absent", "Hi {{name}}", `{}`, "name"},
		{"null", "Hi {{name}}", `{"name":null}`, "name"},
		{"nested", "{{a.b}}", `{"a":{}}`, "a.b"},
		{"in an each item", "{{#each l}}{{x}}{{/each}}", `{"l":[{"x":1},{}]}`, "x"},
		{"in the branch taken", "{{#if a}}{{b}}{{/if}}", `{"a":1}`, "b"},
		{"through a block parameter", "{{#each l as |it|}}{{it.x}}{{/each}}", `{"l":[{}]}`, "it.x"},
		{"in a section over an object", "{{#c}}{{y}}{{/c}}", `{"c":{"x":1}}`, "y"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := Render(Content{Text: tt.tmpl}, tt.data)
			want := "Attribute '" + tt.missing + "' is not present in the rendering data."
			var f *Failure
			if !errors.As(err, &f) || f.Message != want {
				t.Fatalf("render = %v, want the failure %q", err, want)
			}
		})
	}

	// The branch not taken is not rendered, so what it lacks does not count.
	if _, err := Render(Content{Text: "{{#if a}}{{b}}{{/if}}"}, `{}`); err != nil {
		t.Fatalf("render with the branch not taken: %v", err)
	}
}

func TestRenderFailsOnAMissingHelper(t *testing.T) {
	for _, tmpl := range []string{
		"{{eq 1 1}}",
		"{{#eq a 1}}x{{/eq}}",
		"{{lookup (eq a b) 1}}",
		"{{equal a a}}", // raymond's own, which Handlebars.js does not have
	} {
		_, err := Render(Content{HTML: tmpl}, `{"a":1,"b":2}`)
		var f *Failure
		if !errors.As(err, &f) || !strings.HasPrefix(f.Message, "Missing helper: ") {
			t.Errorf("render %s = %v, want a missing helper failure", tmpl, err)
		}
	}
}

func TestEachOverAnObjectKeepsTheDataKeyOrder(t *testing.T) {
	data := `{"o":{"zeta":1,"alpha":2,"mid":3,"beta":4}}`
	tmpl := "{{#each o}}{{@key}}={{this}};{{/each}}"
	for range 20 {
		got, err := Render(Content{Text: tmpl}, data)
		if err != nil {
			t.Fatalf("render: %v", err)
		}
		if got.Text != "zeta=1;alpha=2;mid=3;beta=4;" {
			t.Fatalf("rendered %q, want the data's key order", got.Text)
		}
	}
}

func TestNumbersRenderAsJavaScriptPrintsThem(t *testing.T) {
	tests := map[string]string{
		"1.5e21":   "1.5e+21",
		"1e21":     "1e+21",
		"1e-7":     "1e-7",
		"0.000001": "0.000001",
		"-0":       "0",
		"123.450":  "123.45",
		"1e400":    "Infinity",
	}
	for in, want := range tests {
		got, err := Render(Content{Text: "{{n}}"}, `{"n":`+in+`}`)
		if err != nil || got.Text != want {
			t.Errorf("%s rendered %q, %v; want %q", in, got.Text, err, want)
		}
	}
	if got, _ := Render(Content{Text: "{{#if n}}y{{else}}n{{/if}}"}, `{"n":0}`); got.Text != "n" {
		t.Errorf("#if 0 rendered %q, want the else branch", got.Text)
	}
}

func TestRenderIsBounded(t *testing.T) {
	// 1000 items nested three deep is a billion iterations.
	items := "[" + strings.Repeat("1,", 999) + "1]"
	_, err := Render(Content{Text: "{{#each l}}{{#each ../l}}{{#each ../../l}}x{{/each}}" +
		"{{/each}}{{/each}}"}, `{"l":`+items+`}`)
	var f *Failure
	if !errors.As(err, &f) || f != errTooComplex {
		t.Fatalf("nested each = %v, want the steps failure", err)
	}

	// A 100 KiB string written 500 times is 50 MiB, over the output bound.
	big := strings.Repeat("a", 100<<10)
	_, err = Render(Content{Text: strings.Repeat("{{s}}", 500)}, `{"s":"`+big+`"}`)
	if !errors.As(err, &f) || f != errTooLarge {
		t.Fatalf("large output = %v, want the size failure", err)
	}
}

func TestRenderRefusesDataThatIsNotAnObject(t *testing.T) {
	for _, data := range []string{``, `[]`, `"x"`, `{`, `{} {}`} {
		if _, err := Render(Content{Subject: "s"}, data); !errors.Is(err, ErrInvalidData) {
			t.Fatalf("render with data %q = %v, want ErrInvalidData", data, err)
		}
	}
}

func TestCheckRefusesInvalidHandlebars(t *testing.T) {
	err := Check(Content{Subject: "ok", HTML: "{{#if a}}unclosed"})
	var syntax *SyntaxError
	if !errors.As(err, &syntax) || syntax.Part != "HTML" {
		t.Fatalf("check = %v, want a syntax error in the HTML part", err)
	}
	if err = Check(Content{Subject: "{{a}}", Text: "{{#each l}}{{this}}{{/each}}"}); err != nil {
		t.Fatalf("check valid template: %v", err)
	}
}
