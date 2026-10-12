package main

import (
	"encoding/json"
	"os"
	"reflect"
	"testing"
)

func TestStableReceiptRetainsProvenance(t *testing.T) {
	raw, err := os.ReadFile("../../internal/completion/generation.json")
	if err != nil {
		t.Fatal(err)
	}
	var saved generation
	if err := json.Unmarshal(raw, &saved); err != nil {
		t.Fatal(err)
	}
	original := saved.Activities["CompletionStep"]
	base, err := stableReceipt(original)
	if err != nil {
		t.Fatal(err)
	}
	for _, field := range []string{"compiler_source_sha", "source_digest", "generated_digest", "input_type", "output_type", "typecheck_passed", "record_types"} {
		t.Run(field, func(t *testing.T) {
			var receipt map[string]any
			if err := json.Unmarshal(original, &receipt); err != nil {
				t.Fatal(err)
			}
			receipt["report"].(map[string]any)[field] = "changed"
			changed, _ := json.Marshal(receipt)
			got, err := stableReceipt(changed)
			if err == nil && reflect.DeepEqual(base, got) {
				t.Fatal("provenance mutation disappeared")
			}
		})
	}
	var timed map[string]any
	if err := json.Unmarshal(original, &timed); err != nil {
		t.Fatal(err)
	}
	timed["report"].(map[string]any)["route_decision_latency_ms"] = 123.5
	changed, _ := json.Marshal(timed)
	got, err := stableReceipt(changed)
	if err != nil || !reflect.DeepEqual(base, got) {
		t.Fatal("only observed latency should be exempt", err)
	}
}

func TestCompleteCompilerIdentity(t *testing.T) {
	raw, err := os.ReadFile("../../internal/completion/generation.json")
	if err != nil {
		t.Fatal(err)
	}
	var saved generation
	if err := json.Unmarshal(raw, &saved); err != nil {
		t.Fatal(err)
	}
	base, err := rawValue(saved.Compiler)
	if err != nil {
		t.Fatal(err)
	}
	for _, field := range []string{"decision_runtime", "module"} {
		t.Run(field, func(t *testing.T) {
			value, err := rawValue(saved.Compiler)
			if err != nil {
				t.Fatal(err)
			}
			value[field].(map[string]any)["version"] = "changed"
			if reflect.DeepEqual(base, value) {
				t.Fatal("nested compiler metadata disappeared")
			}
		})
	}
	for _, invalid := range []string{`{"a":1,"a":2}`, `{"a":"\ud800"}`, `{} {}`} {
		if _, err := rawValue([]byte(invalid)); err == nil {
			t.Fatal("ambiguous JSON accepted")
		}
	}
}
