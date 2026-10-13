package main

import (
	"bytes"
	"encoding/json"
	"os"
	"reflect"
	"strings"
	"testing"
)

// These tests inspect this new generator's retained metadata validation only.
// They do not invoke a compiler, generated activity, executable or old suite.
func numericGeneration(t *testing.T) (generation, []byte) {
	t.Helper()
	raw, err := os.ReadFile("../../internal/artifactnumeric/generation.json")
	if err != nil {
		t.Fatal(err)
	}
	var record generation
	if json.Unmarshal(raw, &record) != nil {
		t.Fatal("numeric generation JSON invalid")
	}
	source, err := os.ReadFile("../../internal/artifactnumeric/source.gooo")
	if err != nil {
		t.Fatal(err)
	}
	return record, source
}

func TestArtifactBoundsGeneratorCompleteCompilerIdentity(t *testing.T) {
	record, _ := numericGeneration(t)
	original, err := checkedCompiler(record.Compiler)
	if err != nil {
		t.Fatal(err)
	}
	for _, mutate := range []func(map[string]any){
		func(v map[string]any) { delete(v, "compiler_source_sha") },
		func(v map[string]any) { v["unexpected"] = true },
		func(v map[string]any) { v["vcs_modified"] = "true" },
		func(v map[string]any) { v["source_status"] = "UNKNOWN" },
		func(v map[string]any) { v["go_version"] = "go1.27.1" },
		func(v map[string]any) { v["module"].(map[string]any)["path"] = "untrusted/compiler" },
		func(v map[string]any) { v["decision_runtime"].(map[string]any)["replaced"] = true },
	} {
		value, err := object(record.Compiler)
		if err != nil {
			t.Fatal(err)
		}
		mutate(value)
		raw, err := json.Marshal(value)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := checkedCompiler(raw); err == nil {
			t.Fatal("incomplete or mismatching actual compiler accepted")
		}
	}
	for _, label := range []string{"v0.6.32-dev", "v0.0.0-20261011201109-83928fa45382"} {
		value, err := object(record.Compiler)
		if err != nil {
			t.Fatal(err)
		}
		value["module_version"] = label
		value["module"].(map[string]any)["version"] = label
		raw, err := json.Marshal(value)
		if err != nil {
			t.Fatal(err)
		}
		got, err := checkedCompiler(raw)
		if err != nil || !reflect.DeepEqual(got, original) {
			t.Fatal("fixed clean compiler module labels differ after declared normalization")
		}
	}
}

func TestArtifactBoundsGeneratorExactProjectionTransport(t *testing.T) {
	record, source := numericGeneration(t)
	actual, err := checkedProjection(record.Activity, source)
	if err != nil {
		t.Fatal(err)
	}
	saved, err := os.ReadFile("../../internal/artifactnumeric/rules_generated.go")
	if err != nil || !bytes.Equal(actual, saved) {
		t.Fatal("actual projection differs from checked native source")
	}
	for _, mutate := range []func(map[string]any){
		func(v map[string]any) { v["unknown"] = true },
		func(v map[string]any) { v["report"].(map[string]any)["input_type"] = "(Integer,Integer,Text)" },
		func(v map[string]any) {
			v["report"].(map[string]any)["input_parameters"].([]any)[0].(map[string]any)["type"] = "float64"
		},
		func(v map[string]any) {
			v["report"].(map[string]any)["record_types"].([]any)[0].(map[string]any)["fields"].([]any)[0].(map[string]any)["type_id"] = "urn:gooo:type:string"
		},
		func(v map[string]any) { v["report"].(map[string]any)["deterministic_replay"] = false },
		func(v map[string]any) { v["report"].(map[string]any)["repository_writes"] = json.Number("1") },
	} {
		value, err := object(record.Activity)
		if err != nil {
			t.Fatal(err)
		}
		mutate(value)
		raw, err := json.Marshal(value)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := checkedProjection(raw, source); err == nil {
			t.Fatal("incomplete native transport metadata accepted")
		}
	}
	value, err := object(record.Activity)
	if err != nil {
		t.Fatal(err)
	}
	text := value["source"].(string) + "\nfunc HiddenEffect() {}\n"
	value["source"] = text
	report := value["report"].(map[string]any)
	report["generated_digest"] = hash([]byte(text))
	report["replay_digest"] = hash([]byte(text))
	raw, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := checkedProjection(raw, source); err == nil {
		t.Fatal("coherently rehashed extra generated function accepted")
	}
}

func TestArtifactBoundsGeneratorDeclaredObservationNormalization(t *testing.T) {
	record, source := numericGeneration(t)
	baseline, err := stableReceipt(record.Activity, source)
	if err != nil {
		t.Fatal(err)
	}
	value, err := object(record.Activity)
	if err != nil {
		t.Fatal(err)
	}
	report := value["report"].(map[string]any)
	report["route_decision_latency_ms"] = json.Number("0.25")
	report["completeness_receipt"].(map[string]any)["scope"].(map[string]any)["execution_environment"] = "linux/amd64"
	raw, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	normalized, err := stableReceipt(raw, source)
	if err != nil || !reflect.DeepEqual(baseline, normalized) {
		t.Fatal("declared generating-host observations differ")
	}
	report["completeness_receipt"].(map[string]any)["scope"].(map[string]any)["domain_scope"] = "changed semantic scope"
	raw, err = json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	changed, err := stableReceipt(raw, source)
	if err != nil {
		t.Fatal(err)
	}
	if reflect.DeepEqual(baseline, changed) {
		t.Fatal("normalization hid undeclared completeness scope change")
	}
}

func TestArtifactBoundsGeneratorBoundsOutputAndStrictJSON(t *testing.T) {
	buffer := boundedBuffer{limit: 4}
	if n, err := buffer.Write([]byte("abc")); n != 3 || err != nil {
		t.Fatal("bounded buffer rejected bounded compiler output")
	}
	if n, err := buffer.Write([]byte("def")); n != 1 || err == nil || buffer.String() != "abcd" {
		t.Fatal("bounded buffer read past configured output cap")
	}
	for _, raw := range []string{`{"a":1,"a":2}`, `{"a":1} {}`, `null`, `{"a":"\ud800"}`} {
		if _, err := object([]byte(raw)); err == nil {
			t.Fatal("invalid provenance JSON accepted")
		}
	}
	if _, err := object([]byte(strings.Repeat(" ", maxOutput+1))); err == nil {
		t.Fatal("overbound provenance JSON accepted")
	}
}
