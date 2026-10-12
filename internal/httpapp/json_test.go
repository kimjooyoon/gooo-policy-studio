package httpapp

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"

	"github.com/kimjooyoon/gooo-policy-studio/internal/policy"
)

func TestStrictJSONRejectsAliasesAndUnicodeLoss(t *testing.T) {
	for name, raw := range map[string]string{
		"case alias":        strings.Replace(validInput, `"amount":750000`, `"amount":750000,"Amount":0`, 1),
		"escaped duplicate": strings.Replace(validInput, `"amount":750000`, `"amount":750000,"\u0061mount":0`, 1),
		"low surrogate":     strings.Replace(validInput, `"R1"`, `"\uDC00"`, 1),
		"high surrogate":    strings.Replace(validInput, `"R1"`, `"\uD800x"`, 1),
		"invalid UTF-8":     strings.Replace(validInput, `R1`, string([]byte{0xff}), 1),
		"nested unknown":    strings.Replace(validInput, `"team":"product"`, `"team":"product","extra":[`+strings.Repeat(`[`, 17)+`0`+strings.Repeat(`]`, 17)+`]`, 1),
	} {
		t.Run(name, func(t *testing.T) {
			if w := call("POST", "/api/simulate", raw); w.Code != 400 {
				t.Fatalf("ambiguous input admitted: %d %s", w.Code, w.Body.String())
			}
		})
	}
	for _, text := range []string{`\uD83D\uDE00`, `\ufffd`, `\\uD800`, `escaped\"quote`, "한국어"} {
		raw := strings.Replace(validInput, `"R1"`, `"`+text+`"`, 1)
		if w := call("POST", "/api/simulate", raw); w.Code != 200 {
			t.Fatalf("valid string rejected: %q: %d %s", text, w.Code, w.Body.String())
		}
	}
}

func TestStrictJSONValidatesEveryArrayElement(t *testing.T) {
	type envelope struct {
		Cases []policy.Input `json:"cases"`
	}
	for _, bad := range []string{
		`null`, `{}`, strings.Replace(validInput, `"submitted":true`, `"submitted":null`, 1),
		strings.Replace(validInput, `,"submitted":true`, ``, 1),
		strings.Replace(validInput, `"amount":750000`, `"amount":750000,"Amount":0`, 1),
	} {
		// Put the invalid case after a valid one; validating only the first row is insufficient.
		raw := []byte(`{"cases":[` + validInput + `,` + bad + `]}`)
		if err := completeJSON(raw, reflect.TypeFor[envelope]()); err == nil {
			t.Fatalf("invalid second element accepted: %s", bad)
		}
	}
	var in policy.Input
	if err := json.Unmarshal([]byte(validInput), &in); err != nil {
		t.Fatal(err)
	}
	cases := make([]policy.Input, 256)
	for i := range cases {
		cases[i] = in
	}
	raw, _ := json.Marshal(envelope{cases})
	if err := completeJSON(raw, reflect.TypeFor[envelope]()); err != nil {
		t.Fatal(err)
	}
	raw, _ = json.Marshal(envelope{append(cases, in)})
	if err := completeJSON(raw, reflect.TypeFor[envelope]()); err == nil {
		t.Fatal("257 array entries admitted")
	}
}
