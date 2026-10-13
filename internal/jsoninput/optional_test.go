package jsoninput

import "testing"

func TestOptionalPointerStillRejectsAmbiguousOrIncompleteObjects(t *testing.T) {
	type nested struct {
		Required string `json:"required"`
	}
	type document struct {
		Schema string  `json:"schema"`
		Nested *nested `json:"nested,omitempty"`
	}
	for _, raw := range []string{`{"schema":"v1"}`, `{"schema":"v2","nested":{"required":"value"}}`} {
		var out document
		if err := Decode([]byte(raw), &out, 1024); err != nil {
			t.Fatalf("valid document rejected: %v", err)
		}
	}
	for _, raw := range []string{
		`{"schema":"v2","nested":null}`,
		`{"schema":"v2","nested":{}}`,
		`{"schema":"v2","nested":{"Required":"value"}}`,
		`{"schema":"v2","nested":{"required":"a","required":"b"}}`,
		`{"schema":"v2","nested":{"required":"a","extra":true}}`,
		`{"nested":{"required":"value"}}`,
	} {
		var out document
		if err := Decode([]byte(raw), &out, 1024); err == nil {
			t.Fatalf("ambiguous or incomplete document accepted: %s", raw)
		}
	}
}
