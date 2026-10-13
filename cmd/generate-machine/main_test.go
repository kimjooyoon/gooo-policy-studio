package main

import (
	"encoding/json"
	"os"
	"reflect"
	"testing"
)

func loadRecord(t *testing.T) generation {
	t.Helper()
	raw, err := os.ReadFile("../../internal/machinerules/generation.json")
	if err != nil {
		t.Fatal(err)
	}
	var record generation
	if err := json.Unmarshal(raw, &record); err != nil {
		t.Fatal(err)
	}
	return record
}
func encoded(t *testing.T, value any) []byte {
	t.Helper()
	raw, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}
func TestGenerationMetadataHasOnlyNarrowDeclaredObservations(t *testing.T) {
	record := loadRecord(t)
	raw := record.Projections["final"].Metadata
	original, err := stableReceipt(raw)
	if err != nil {
		t.Fatal(err)
	}
	accepted := []struct {
		Name   string
		Mutate func(map[string]any)
	}{
		{"latency", func(d map[string]any) {
			d["report"].(map[string]any)["route_decision_latency_ms"] = json.Number("123.5")
		}},
		{"generating_host", func(d map[string]any) {
			d["report"].(map[string]any)["completeness_receipt"].(map[string]any)["scope"].(map[string]any)["execution_environment"] = "linux/amd64"
		}},
	}
	for _, tc := range accepted {
		t.Run(tc.Name, func(t *testing.T) {
			d, err := rawValue(raw)
			if err != nil {
				t.Fatal(err)
			}
			tc.Mutate(d)
			changed, err := stableReceipt(encoded(t, d))
			if err != nil || !reflect.DeepEqual(original, changed) {
				t.Fatalf("declared observation differs: %v", err)
			}
		})
	}
	rejected := []struct {
		Name   string
		Mutate func(map[string]any)
	}{
		{"invalid_latency_type", func(d map[string]any) { d["report"].(map[string]any)["route_decision_latency_ms"] = "123" }},
		{"negative_latency", func(d map[string]any) { d["report"].(map[string]any)["route_decision_latency_ms"] = json.Number("-1") }},
		{"unknown_host", func(d map[string]any) {
			d["report"].(map[string]any)["completeness_receipt"].(map[string]any)["scope"].(map[string]any)["execution_environment"] = "darwin/amd64"
		}},
	}
	for _, tc := range rejected {
		t.Run(tc.Name, func(t *testing.T) {
			d, err := rawValue(raw)
			if err != nil {
				t.Fatal(err)
			}
			tc.Mutate(d)
			if _, err := stableReceipt(encoded(t, d)); err == nil {
				t.Fatal("invalid observation accepted")
			}
		})
	}
	preserved := []struct {
		Name   string
		Mutate func(map[string]any)
	}{
		{"source_digest", func(d map[string]any) { d["report"].(map[string]any)["source_digest"] = "changed" }},
		{"new_key", func(d map[string]any) { d["report"].(map[string]any)["unrecognized_metadata"] = true }},
		{"nested_decision", func(d map[string]any) {
			d["report"].(map[string]any)["completeness_receipt"].(map[string]any)["decision"] = "changed"
		}},
		{"record_roster", func(d map[string]any) { d["report"].(map[string]any)["record_types"] = []any{} }},
		{"native_source", func(d map[string]any) { d["source"] = "changed" }},
	}
	for _, tc := range preserved {
		t.Run(tc.Name, func(t *testing.T) {
			d, err := rawValue(raw)
			if err != nil {
				t.Fatal(err)
			}
			tc.Mutate(d)
			changed, err := stableReceipt(encoded(t, d))
			if err == nil && reflect.DeepEqual(original, changed) {
				t.Fatal("semantic metadata change was hidden")
			}
		})
	}
}
func TestCompleteCompilerIdentityPreservesAllOtherFields(t *testing.T) {
	record := loadRecord(t)
	original, err := compilerIdentity(record.Compiler)
	if err != nil {
		t.Fatal(err)
	}
	d, err := rawValue(record.Compiler)
	if err != nil {
		t.Fatal(err)
	}
	d["module_version"] = "v0.0.0-20261011201109-83928fa45382"
	d["module"].(map[string]any)["version"] = "v0.0.0-20261011201109-83928fa45382"
	equivalent, err := compilerIdentity(encoded(t, d))
	if err != nil || !reflect.DeepEqual(original, equivalent) {
		t.Fatalf("exact installed label rejected: %v", err)
	}
	d["go_version"] = "changed"
	changed, err := compilerIdentity(encoded(t, d))
	if err == nil && reflect.DeepEqual(original, changed) {
		t.Fatal("compiler identity change hidden")
	}
	d, err = rawValue(record.Compiler)
	if err != nil {
		t.Fatal(err)
	}
	d["module_version"] = "v0.6.33"
	d["module"].(map[string]any)["version"] = "v0.6.33"
	if _, err := compilerIdentity(encoded(t, d)); err == nil {
		t.Fatal("unrecognized compiler label accepted")
	}
}
func TestWorkspaceReceiptRejectsSourceRuntimeAndInputMutation(t *testing.T) {
	old, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chdir("../.."); err != nil {
		t.Fatal(err)
	}
	defer os.Chdir(old)
	raw, err := os.ReadFile(example + "receipts/evidence-workspace.json")
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := validateWorkspace(raw, "evidence"); err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		Name   string
		Mutate func(map[string]any)
	}{
		{"original_source", func(d map[string]any) {
			d["result"].(map[string]any)["program"].(map[string]any)["workspace_image"].(map[string]any)["packages"].([]any)[0].(map[string]any)["sources"].([]any)[0].(map[string]any)["source_digest"] = "changed"
		}},
		{"producer", func(d map[string]any) {
			d["result"].(map[string]any)["runtime"].(map[string]any)["producer_source_sha"] = "changed"
		}},
		{"native_exit", func(d map[string]any) {
			d["result"].(map[string]any)["runtime"].(map[string]any)["runs"].([]any)[0].(map[string]any)["exit_code"] = json.Number("1")
		}},
		{"actual_input", func(d map[string]any) {
			d["result"].(map[string]any)["runtime"].(map[string]any)["traces"].([]any)[0].(map[string]any)["deliveries"].([]any)[0].(map[string]any)["input"].(map[string]any)["provider_verified"] = false
		}},
		{"projection", func(d map[string]any) {
			d["result"].(map[string]any)["composition"].(map[string]any)["source"] = "changed"
		}},
		{"manifest", func(d map[string]any) { d["manifest_digest"] = "changed" }},
		{"runtime_replay", func(d map[string]any) {
			d["result"].(map[string]any)["runtime"].(map[string]any)["runtime_replayed"] = false
		}},
		{"actual_result", func(d map[string]any) {
			d["result"].(map[string]any)["runtime"].(map[string]any)["traces"].([]any)[0].(map[string]any)["deliveries"].([]any)[0].(map[string]any)["actual"].(map[string]any)["admissible"] = false
		}},
		{"actual_activity", func(d map[string]any) {
			d["result"].(map[string]any)["runtime"].(map[string]any)["traces"].([]any)[0].(map[string]any)["deliveries"].([]any)[0].(map[string]any)["activity_id"] = "changed"
		}},
	}
	for _, tc := range tests {
		t.Run(tc.Name, func(t *testing.T) {
			d, err := rawValue(raw)
			if err != nil {
				t.Fatal(err)
			}
			tc.Mutate(d)
			if _, _, err := validateWorkspace(encoded(t, d), "evidence"); err == nil {
				t.Fatal("changed native closure receipt accepted")
			}
		})
	}
}
func TestRawMetadataRejectsDuplicateKeysAndBrokenUnicode(t *testing.T) {
	for _, raw := range []string{`{"schema":"a","schema":"b"}`, `{"a":"\ud800"}`, `{"a":1} {"b":2}`} {
		if _, err := rawValue([]byte(raw)); err == nil {
			t.Fatalf("malformed metadata accepted: %s", raw)
		}
	}
}

func TestRetainedWorkspaceWholeGenerationTypedTraceAndStreams(t *testing.T) {
	record := loadRecord(t)
	old, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chdir("../.."); err != nil {
		t.Fatal(err)
	}
	defer os.Chdir(old)
	for _, kind := range []string{"evidence", "effects"} {
		raw, err := os.ReadFile(example + "receipts/" + kind + "-workspace.json")
		if err != nil {
			t.Fatal(err)
		}
		validate := func(raw []byte) error {
			if _, _, err := validateWorkspace(raw, kind); err != nil {
				return err
			}
			return validateWorkspaceProjection(raw, record.Projections[kind].Metadata)
		}
		if err := validate(raw); err != nil {
			t.Fatal(kind, err)
		}
		result := func(d map[string]any) map[string]any { return d["result"].(map[string]any) }
		composition := func(d map[string]any) map[string]any { return result(d)["composition"].(map[string]any) }
		step := func(d map[string]any) map[string]any { return composition(d)["steps"].([]any)[0].(map[string]any) }
		generation := func(d map[string]any) map[string]any { return step(d)["generation"].(map[string]any) }
		runtime := func(d map[string]any) map[string]any { return result(d)["runtime"].(map[string]any) }
		delivery := func(d map[string]any) map[string]any {
			return runtime(d)["traces"].([]any)[0].(map[string]any)["deliveries"].([]any)[0].(map[string]any)
		}
		inputFields := func(d map[string]any) []any {
			if kind == "evidence" {
				return delivery(d)["input_fields"].([]any)
			}
			return delivery(d)["inputs"].([]any)[0].(map[string]any)["fields"].([]any)
		}
		actualFields := func(d map[string]any) []any { return delivery(d)["actual_fields"].([]any) }
		tests := []struct {
			Name   string
			Mutate func(map[string]any)
		}{
			{"gooo_source", func(d map[string]any) { composition(d)["gooo_source"] = "changed" }},
			{"step_input_source", func(d map[string]any) { step(d)["input_source_sha256"] = "changed" }},
			{"extra_step", func(d map[string]any) { composition(d)["steps"] = append(composition(d)["steps"].([]any), step(d)) }},
			{"nested_source", func(d map[string]any) { generation(d)["source"] = "changed" }},
			{"nested_decision", func(d map[string]any) { generation(d)["report"].(map[string]any)["decision"] = "PROGRESS" }},
			{"nested_metadata_extra", func(d map[string]any) {
				generation(d)["report"].(map[string]any)["unrecognized_native_metadata"] = true
			}},
			{"nested_metadata_field_type", func(d map[string]any) {
				generation(d)["report"].(map[string]any)["record_types"].([]any)[0].(map[string]any)["fields"].([]any)[0].(map[string]any)["type_id"] = "changed"
			}},
			{"typed_input_id", func(d map[string]any) { inputFields(d)[0].(map[string]any)["id"] = "changed" }},
			{"typed_input_name", func(d map[string]any) { inputFields(d)[0].(map[string]any)["name"] = "changed" }},
			{"typed_input_value", func(d map[string]any) { inputFields(d)[0].(map[string]any)["value"] = json.Number("0") }},
			{"typed_input_order", func(d map[string]any) { f := inputFields(d); f[0], f[1] = f[1], f[0] }},
			{"typed_output_id", func(d map[string]any) { actualFields(d)[0].(map[string]any)["id"] = "changed" }},
			{"typed_output_name", func(d map[string]any) { actualFields(d)[0].(map[string]any)["name"] = "changed" }},
			{"typed_output_value", func(d map[string]any) { actualFields(d)[0].(map[string]any)["value"] = "true" }},
			{"typed_output_duplicate", func(d map[string]any) { delivery(d)["actual_fields"] = append(actualFields(d), actualFields(d)[0]) }},
			{"typed_output_order", func(d map[string]any) { f := actualFields(d); f[0], f[1] = f[1], f[0] }},
			{"second_stdout_sha", func(d map[string]any) {
				runtime(d)["runs"].([]any)[1].(map[string]any)["stdout_sha256"] = "sha256:0000000000000000000000000000000000000000000000000000000000000000"
			}},
			{"stdout_sha_syntax", func(d map[string]any) { runtime(d)["runs"].([]any)[0].(map[string]any)["stdout_sha256"] = "changed" }},
			{"stderr_sha", func(d map[string]any) { runtime(d)["runs"].([]any)[1].(map[string]any)["stderr_sha256"] = "changed" }},
			{"native_build_sha", func(d map[string]any) { runtime(d)["executable_sha256"] = "changed" }},
			{"native_build_stdout", func(d map[string]any) {
				runtime(d)["build"].(map[string]any)["stdout_sha256"] = "sha256:0000000000000000000000000000000000000000000000000000000000000000"
			}},
			{"producer_module", func(d map[string]any) { runtime(d)["producer_module"].(map[string]any)["version"] = "changed" }},
		}
		if kind == "effects" {
			tests = append(tests, []struct {
				Name   string
				Mutate func(map[string]any)
			}{
				{"slot_port", func(d map[string]any) { delivery(d)["inputs"].([]any)[0].(map[string]any)["port"] = "input1" }},
				{"slot_entity", func(d map[string]any) { delivery(d)["inputs"].([]any)[0].(map[string]any)["entity_id"] = "changed" }},
				{"slot_order", func(d map[string]any) {
					slots := delivery(d)["inputs"].([]any)
					slots[0], slots[1] = slots[1], slots[0]
				}},
				{"budget_slot_fields", func(d map[string]any) {
					delivery(d)["inputs"].([]any)[1].(map[string]any)["fields"].([]any)[0].(map[string]any)["value"] = "true"
				}},
			}...)
		}
		for _, tc := range tests {
			t.Run(kind+"/"+tc.Name, func(t *testing.T) {
				d, err := rawValue(raw)
				if err != nil {
					t.Fatal(err)
				}
				tc.Mutate(d)
				if err := validate(encoded(t, d)); err == nil {
					t.Fatal("changed retained native proof accepted")
				}
			})
		}
		// Only generation-comparison observations use the declared exceptions;
		// native runtime, input, field, output, and stream checks remain exact.
		t.Run(kind+"/narrow_generation_observations", func(t *testing.T) {
			d, err := rawValue(raw)
			if err != nil {
				t.Fatal(err)
			}
			report := generation(d)["report"].(map[string]any)
			report["route_decision_latency_ms"] = json.Number("123.5")
			report["completeness_receipt"].(map[string]any)["scope"].(map[string]any)["execution_environment"] = "linux/amd64"
			if err := validate(encoded(t, d)); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestGenerationDecodeRejectsErasedUnknownOrMissingProvenance(t *testing.T) {
	raw, err := os.ReadFile("../../internal/machinerules/generation.json")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := decodeGeneration(raw); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		Name   string
		Mutate func(map[string]any)
	}{
		{"unknown_root", func(d map[string]any) { d["unknown_provenance"] = true }},
		{"missing_root", func(d map[string]any) { delete(d, "schema") }},
		{"unknown_projection", func(d map[string]any) {
			d["projections"].(map[string]any)["evidence"].(map[string]any)["unknown_projection_provenance"] = true
		}},
		{"missing_projection", func(d map[string]any) {
			delete(d["projections"].(map[string]any)["evidence"].(map[string]any), "workspace_receipt_sha256")
		}},
		{"extra_projection", func(d map[string]any) {
			d["projections"].(map[string]any)["extra"] = d["projections"].(map[string]any)["evidence"]
		}},
	} {
		t.Run(tc.Name, func(t *testing.T) {
			d, err := rawValue(raw)
			if err != nil {
				t.Fatal(err)
			}
			tc.Mutate(d)
			if _, err := decodeGeneration(encoded(t, d)); err == nil {
				t.Fatal("unknown or missing provenance was silently discarded")
			}
		})
	}
}
