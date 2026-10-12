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

func TestPinnedCompilerInstallationLabels(t *testing.T) {
	raw, err := os.ReadFile("../../internal/completion/generation.json")
	if err != nil {
		t.Fatal(err)
	}
	var saved generation
	if err := json.Unmarshal(raw, &saved); err != nil {
		t.Fatal(err)
	}
	base, err := compilerIdentity(saved.Compiler)
	if err != nil {
		t.Fatal(err)
	}
	tagged, _ := rawValue(saved.Compiler)
	tagged["module_version"] = "v0.6.32-dev"
	tagged["module"].(map[string]any)["version"] = "v0.6.32-dev"
	changed, _ := json.Marshal(tagged)
	got, err := compilerIdentity(changed)
	if err != nil || !reflect.DeepEqual(base, got) {
		t.Fatal("exact known installation labels should match", err)
	}
	for _, label := range []string{"(devel)", "v0.6.33-dev", "v0.0.0-20261011201109-83928fa45383"} {
		tagged["module_version"] = label
		tagged["module"].(map[string]any)["version"] = label
		changed, _ = json.Marshal(tagged)
		if _, err := compilerIdentity(changed); err == nil {
			t.Fatal("unrecognized module label accepted", label)
		}
	}
	tagged, _ = rawValue(saved.Compiler)
	tagged["module"].(map[string]any)["path"] = "changed"
	changed, _ = json.Marshal(tagged)
	if _, err := compilerIdentity(changed); err == nil {
		t.Fatal("module path mutation accepted")
	}
	for _, field := range []string{"decision_runtime", "module"} {
		value, _ := rawValue(saved.Compiler)
		value[field].(map[string]any)["replaced"] = true
		changed, _ = json.Marshal(value)
		got, err := compilerIdentity(changed)
		if err == nil && reflect.DeepEqual(base, got) {
			t.Fatal("nested identity mutation accepted")
		}
	}
}

func TestObservedGenerationPlatforms(t *testing.T) {
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
	value, _ := rawValue(original)
	scope := value["report"].(map[string]any)["completeness_receipt"].(map[string]any)["scope"].(map[string]any)
	scope["execution_environment"] = "linux/amd64"
	changed, _ := json.Marshal(value)
	got, err := stableReceipt(changed)
	if err != nil || !reflect.DeepEqual(base, got) {
		t.Fatal("observed generation host labels should match", err)
	}
	for _, platform := range []string{"unknown", "linux/arm64", "windows/amd64", "darwin/amd64"} {
		scope["execution_environment"] = platform
		changed, _ = json.Marshal(value)
		if _, err := stableReceipt(changed); err == nil {
			t.Fatal("unobserved generation platform accepted", platform)
		}
	}
	scope["execution_environment"] = "linux/amd64"
	scope["compiler_source_sha"] = "changed"
	changed, _ = json.Marshal(value)
	got, err = stableReceipt(changed)
	if err == nil && reflect.DeepEqual(base, got) {
		t.Fatal("other scope mutation disappeared")
	}
}
