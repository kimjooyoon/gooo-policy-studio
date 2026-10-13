// generate-machine compiles checked workspace closures and the final Gooo relation.
// Workspace native observations are retained; --check does not execute them again.
package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"flag"
	"fmt"
	"github.com/kimjooyoon/gooo-policy-studio/internal/jsoninput"
	"go/format"
	"go/parser"
	"go/token"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"sort"
	"strconv"
	"strings"
	"time"
)

const example = "examples/artifact-gate/"
const destination = "internal/machinerules/"
const pin = "83928fa4538245abe33b08549da47f8cbdc50ed2"

type generation struct {
	Schema      string                `json:"schema"`
	Compiler    json.RawMessage       `json:"compiler"`
	Sources     map[string]string     `json:"sources"`
	Projections map[string]projection `json:"projections"`
}
type projection struct {
	Source           string          `json:"source_sha256"`
	Generated        string          `json:"generated_sha256"`
	Bridge           string          `json:"bridge_sha256"`
	WorkspaceReceipt string          `json:"workspace_receipt_sha256"`
	Metadata         json.RawMessage `json:"metadata"`
}
type codegen struct {
	Source string `json:"source"`
	Report struct {
		Decision   string `json:"decision"`
		InputType  string `json:"input_type"`
		OutputType string `json:"output_type"`
		Parameters []struct {
			Name string `json:"name"`
			Type string `json:"type"`
		} `json:"input_parameters"`
		Records []struct {
			Name   string `json:"name"`
			GoName string `json:"go_name"`
		} `json:"record_types"`
	} `json:"report"`
}

func main() {
	compiler := flag.String("compiler", "gooo", "Pinned compiler executable")
	check := flag.Bool("check", false, "Check all source and projection bindings without native execution")
	flag.Parse()
	if flag.NArg() != 0 {
		fmt.Fprintln(os.Stderr, "unexpected arguments")
		os.Exit(1)
	}
	if err := generate(*compiler, *check); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
func generate(compiler string, check bool) error {
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	identityRaw, err := run(ctx, compiler, "version", "--build", "--json")
	if err != nil {
		return err
	}
	identity, err := rawValue(identityRaw)
	if err != nil {
		return err
	}
	for key, value := range map[string]any{"schema": "gooo/build-identity/v1", "compiler_source_sha": pin, "version": "0.6.32-dev", "go_version": "go1.27.2", "native_go_required": "go1.27.2", "source_status": "CLEAN_VCS", "vcs_revision": pin, "vcs_modified": "false"} {
		if !reflect.DeepEqual(identity[key], value) {
			return fmt.Errorf("compiler identity differs: %s", key)
		}
	}
	if _, err := compilerIdentity(identityRaw); err != nil {
		return err
	}
	files := map[string][]byte{}
	sources := map[string]string{}
	copySource := func(path, name string) error {
		raw, e := os.ReadFile(path)
		if e != nil {
			return e
		}
		sources[path] = digest(raw)
		files["assets/"+name] = raw
		return nil
	}
	originalCopies := map[string]string{"admission.gooo": "examples/evidence-admission/admission.gooo", "proof_authority.gooo": "examples/evidence-admission/proof_authority.gooo", "tool_effects.gooo": "examples/tool-effects/tool_effects.gooo", "effect_budget.gooo": "examples/tool-effects/effect_budget.gooo"}
	for name, path := range originalCopies {
		a, e := os.ReadFile(path)
		if e != nil {
			return e
		}
		b, e := os.ReadFile(example + name)
		if e != nil {
			return e
		}
		if !bytes.Equal(a, b) {
			return fmt.Errorf("copied source differs: %s", name)
		}
		if e := copySource(path, "original-"+name); e != nil {
			return e
		}
	}
	for _, name := range []string{"admission.gooo", "proof_authority.gooo", "tool_effects.gooo", "effect_budget.gooo", "machine.gooo", "LICENSE-REA", "compiler-version.txt", "evidence.workspace.json", "effects.workspace.json", "admission.workspace.json", "evidence.inputs.json", "effects.inputs.json", "receipts/evidence-workspace.json", "receipts/effects-workspace.json"} {
		if e := copySource(example+name, strings.ReplaceAll(name, "/", "-")); e != nil {
			return e
		}
	}
	if e := copySource("cmd/generate-machine/main.go", "generator.go.txt"); e != nil {
		return e
	}
	if e := copySource(destination+"rules.go", "host-transport.go.txt"); e != nil {
		return e
	}
	if e := copySource(destination+"bindings.go", "host-bindings.go.txt"); e != nil {
		return e
	}
	projections := map[string]projection{}
	for _, kind := range []string{"evidence", "effects", "final"} {
		var source []byte
		var activity, receiptDigest string
		if kind == "final" {
			source = files["assets/machine.gooo"]
			activity = "ArtifactGateAdmits"
		} else {
			raw := files["assets/receipts-"+kind+"-workspace.json"]
			source, activity, err = validateWorkspace(raw, kind)
			if err != nil {
				return fmt.Errorf("%s closure: %w", kind, err)
			}
			receiptDigest = digest(raw)
		}
		sourcePath := example + kind + "-lowered.gooo"
		if kind == "final" {
			sourcePath = example + "machine.gooo"
		} else {
			if check {
				old, e := os.ReadFile(sourcePath)
				if e != nil {
					return e
				}
				if !bytes.Equal(old, source) {
					return fmt.Errorf("stale lowered source: %s", kind)
				}
			} else {
				if e := os.WriteFile(sourcePath, source, 0644); e != nil {
					return e
				}
			}
		}
		raw, e := run(ctx, compiler, "body-codegen", "--json", "--activity", activity, sourcePath)
		if e != nil {
			return e
		}
		if kind != "final" {
			retained := files["assets/receipts-"+kind+"-workspace.json"]
			if e := validateWorkspaceProjection(retained, raw); e != nil {
				return fmt.Errorf("%s retained generation: %w", kind, e)
			}
		}
		var result codegen
		if e := json.Unmarshal(raw, &result); e != nil {
			return e
		}
		if result.Report.Decision != "PASS" || result.Source == "" {
			return fmt.Errorf("projection rejected %s", kind)
		}
		file, e := parser.ParseFile(token.NewFileSet(), kind+".go", result.Source, 0)
		if e != nil {
			return e
		}
		if len(file.Imports) != 0 {
			return fmt.Errorf("unexpected generated imports")
		}
		compiled := strings.Replace(result.Source, "package "+file.Name.Name, "package "+kind, 1)
		generated, e := format.Source([]byte(compiled))
		if e != nil {
			return e
		}
		records := map[string]string{}
		for _, r := range result.Report.Records {
			if !token.IsIdentifier(r.GoName) {
				return fmt.Errorf("invalid record metadata")
			}
			if old, ok := records[r.Name]; ok && old != r.GoName {
				return fmt.Errorf("conflicting record metadata")
			}
			records[r.Name] = r.GoName
		}
		types := []string{result.Report.InputType}
		if len(result.Report.Parameters) > 0 {
			types = nil
			for _, p := range result.Report.Parameters {
				types = append(types, p.Type)
			}
		}
		var signature, declarations, arguments []string
		for i, name := range types {
			native := records[name]
			if native == "" {
				return fmt.Errorf("missing native input record: %s", name)
			}
			signature = append(signature, fmt.Sprintf("in%d []byte", i))
			declarations = append(declarations, fmt.Sprintf("var a%d %s; if err:=json.Unmarshal(in%d,&a%d);err!=nil{return nil,err}", i, native, i, i))
			arguments = append(arguments, fmt.Sprintf("a%d", i))
		}
		bridge := fmt.Sprintf("// Code generated from complete Gooo record metadata; DO NOT EDIT.\npackage %s\nimport \"encoding/json\"\nfunc Evaluate(%s)([]byte,error){%s;return json.Marshal(%s(%s))}\n", kind, strings.Join(signature, ","), strings.Join(declarations, ";"), activity, strings.Join(arguments, ","))
		bridgeBytes, e := format.Source([]byte(bridge))
		if e != nil {
			return e
		}
		files[kind+"/source.gooo"] = source
		files[kind+"/rules_generated.go"] = generated
		files[kind+"/generated.txt"] = generated
		files[kind+"/bridge_generated.go"] = bridgeBytes
		files[kind+"/bridge.txt"] = bridgeBytes
		projections[kind] = projection{digest(source), digest(generated), digest(bridgeBytes), receiptDigest, raw}
	}
	record := generation{"policy-studio/machine-generation/v1", identityRaw, sources, projections}
	savedRaw, e := json.MarshalIndent(record, "", "  ")
	if e != nil {
		return e
	}
	savedRaw = append(savedRaw, '\n')
	if check {
		for name, raw := range files {
			old, e := os.ReadFile(destination + name)
			if e != nil {
				return e
			}
			if !bytes.Equal(old, raw) {
				return fmt.Errorf("stale generated asset: %s", name)
			}
		}
		old, e := os.ReadFile(destination + "generation.json")
		if e != nil {
			return e
		}
		saved, e := decodeGeneration(old)
		if e != nil {
			return e
		}
		if saved.Schema != record.Schema || !reflect.DeepEqual(saved.Sources, record.Sources) || len(saved.Projections) != 3 {
			return fmt.Errorf("stale source roster")
		}
		a, e := compilerIdentity(saved.Compiler)
		if e != nil {
			return e
		}
		b, e := compilerIdentity(record.Compiler)
		if e != nil {
			return e
		}
		if !reflect.DeepEqual(a, b) {
			return fmt.Errorf("stale complete compiler identity: %s", strings.Join(differencePaths(a, b, "$"), ","))
		}
		for kind, p := range record.Projections {
			s, ok := saved.Projections[kind]
			if !ok || s.Source != p.Source || s.Generated != p.Generated || s.Bridge != p.Bridge || s.WorkspaceReceipt != p.WorkspaceReceipt {
				return fmt.Errorf("stale projection bytes: %s", kind)
			}
			a, e := stableReceipt(s.Metadata)
			if e != nil {
				return e
			}
			b, e := stableReceipt(p.Metadata)
			if e != nil {
				return e
			}
			if !reflect.DeepEqual(a, b) {
				return fmt.Errorf("stale complete %s metadata: %s", kind, strings.Join(differencePaths(a, b, "$"), ","))
			}
		}
	} else {
		files["generation.json"] = savedRaw
		for name, raw := range files {
			if e := os.MkdirAll(filepath.Dir(destination+name), 0755); e != nil {
				return e
			}
			if e := os.WriteFile(destination+name, raw, 0644); e != nil {
				return e
			}
		}
	}
	fmt.Println("EvidenceAdmission + EffectBudgetAccepts + ArtifactGateAdmits source closures and projections accepted.")
	return nil
}
func validateWorkspace(raw []byte, kind string) ([]byte, string, error) {
	d, err := rawValue(raw)
	if err != nil {
		return nil, "", err
	}
	fail := func(message string) ([]byte, string, error) { return nil, "", fmt.Errorf("%s", message) }
	if d["schema"] != "gooo/workspace-body-execution-receipt/v1" || d["decision"] != "OBSERVED" {
		return fail("unexpected workspace observation")
	}
	manifest, err := os.ReadFile(example + kind + ".workspace.json")
	if err != nil {
		return nil, "", err
	}
	inputs, err := os.ReadFile(example + kind + ".inputs.json")
	if err != nil {
		return nil, "", err
	}
	if d["manifest_digest"] != digest(manifest) || d["inputs_digest"] != digest(inputs) {
		return fail("workspace/input byte binding differs")
	}
	// Typed JSON re-encoding here is only for structural inspection. The complete
	// original receipt and original inputs remain embedded and hashed unchanged.
	var receipt struct {
		Result struct {
			Program struct {
				Entry struct {
					Package  string `json:"package_path"`
					Activity string `json:"activity"`
					Lowered  string `json:"lowered_name"`
				} `json:"entry"`
				Source    string `json:"lowered_gooo_source"`
				Workspace struct {
					Entry struct {
						Package  string `json:"package_path"`
						Activity string `json:"activity"`
					} `json:"entry"`
					Packages []struct {
						Path    string `json:"path"`
						Sources []struct {
							Filename string `json:"filename"`
							Digest   string `json:"source_digest"`
						} `json:"sources"`
					} `json:"packages"`
				} `json:"workspace_image"`
			} `json:"program"`
			Composition struct {
				Stage        string `json:"stage"`
				Source       string `json:"source"`
				Driver       string `json:"driver_source"`
				Original     string `json:"original_source_sha256"`
				Selected     string `json:"selected_source_sha256"`
				Generated    string `json:"generated_sha256"`
				DriverDigest string `json:"driver_sha256"`
				GoooSource   string `json:"gooo_source"`
				Steps        []struct {
					InputSource string          `json:"input_source_sha256"`
					Generation  json.RawMessage `json:"generation"`
				} `json:"steps"`
			} `json:"composition"`
			Runtime struct {
				Stage           string            `json:"stage"`
				Producer        string            `json:"producer_source_sha"`
				GoTool          string            `json:"go_tool_sha256"`
				GoVersion       string            `json:"go_version"`
				Original        string            `json:"original_source_sha256"`
				Selected        string            `json:"selected_source_sha256"`
				Generated       string            `json:"generated_sha256"`
				Driver          string            `json:"driver_sha256"`
				ModelCalls      int               `json:"model_calls"`
				Total           int               `json:"finite_total"`
				Replayed        bool              `json:"projection_replayed"`
				RuntimeReplayed bool              `json:"runtime_replayed"`
				Toolchain       json.RawMessage   `json:"toolchain"`
				Build           json.RawMessage   `json:"build"`
				Runs            []json.RawMessage `json:"runs"`
				Traces          []json.RawMessage `json:"traces"`
			} `json:"runtime"`
			ExecutionSource string `json:"execution_source_sha256"`
		} `json:"result"`
	}
	if err := json.Unmarshal(raw, &receipt); err != nil {
		return nil, "", err
	}
	r := receipt.Result
	p := r.Program
	c := r.Composition
	runtime := r.Runtime
	if c.Stage != "COMPLETE" || runtime.Stage != "COMPLETE" || runtime.Producer != pin || runtime.ModelCalls != 0 || runtime.Total != 0 || !runtime.Replayed || !runtime.RuntimeReplayed || len(runtime.Runs) != 2 || len(runtime.Traces) != 1 || runtime.GoTool != "sha256:516c1fbb53b5f8f4852f0c3c379d45bcff53a1032e5cd1a9ca1738f03ba07cb1" || runtime.GoVersion != "go version go1.27.2 darwin/arm64" {
		return fail("workspace native execution bindings differ")
	}
	lowered := digest([]byte(p.Source))
	if c.GoooSource != p.Source || len(c.Steps) != 1 || c.Steps[0].InputSource != lowered {
		return fail("retained source or native generation step binding differs")
	}
	if r.ExecutionSource != lowered || c.Original != lowered || c.Selected != lowered || runtime.Original != lowered || runtime.Selected != lowered || c.Generated != digest([]byte(c.Source)) || runtime.Generated != c.Generated || c.DriverDigest != digest([]byte(c.Driver)) || runtime.Driver != c.DriverDigest {
		return fail("workspace lowering/projection bindings differ")
	}
	var stdoutDigests []string
	for i, command := range append([]json.RawMessage{runtime.Toolchain, runtime.Build}, runtime.Runs...) {
		v, e := rawValue(command)
		if e != nil {
			return nil, "", e
		}
		if v["started"] != true || v["completed"] != true || v["exit_code"] != json.Number("0") || v["canceled"] != false || v["timed_out"] != false || v["output_truncated"] != false || v["diagnostics_bytes"] != json.Number("0") {
			return fail("workspace native command was not successful")
		}
		stdout, ok := v["stdout_sha256"].(string)
		if !ok || !validSHA256(stdout) || v["stderr_sha256"] != digest(nil) {
			return fail("workspace native command stream binding differs")
		}
		if i == 1 && stdout != digest(nil) {
			return fail("native build stdout differs")
		}
		if i >= 2 {
			stdoutDigests = append(stdoutDigests, stdout)
		}
	}
	if len(stdoutDigests) != 2 || stdoutDigests[0] != stdoutDigests[1] {
		return fail("native run stdout differs across replay")
	}
	resultMap := d["result"].(map[string]any)
	runtimeMap := resultMap["runtime"].(map[string]any)
	if runtimeMap["schema"] != "gooo/body-composition-runtime/v1" || runtimeMap["go_tool_selection"] != "explicit" || runtimeMap["finite_passed"] != json.Number("0") {
		return fail("retained native runtime identity differs")
	}
	for _, key := range []string{"composition_sha256", "typed_plan_sha256", "runtime_suite_sha256", "executable_sha256"} {
		value, ok := runtimeMap[key].(string)
		if !ok || !validSHA256(value) {
			return fail("retained native build/source digest differs")
		}
	}
	producer, ok := runtimeMap["producer_module"].(map[string]any)
	if !ok || len(producer) != 2 || producer["path"] != "github.com/kimjooyoon/meta-ontology-go" || producer["version"] != "v0.0.0-20261011201109-83928fa45382" {
		return fail("retained native producer module differs")
	}

	var m struct {
		Entry struct {
			Package  string `json:"package_path"`
			Activity string `json:"activity"`
		} `json:"entry"`
		Packages []struct {
			Path    string   `json:"path"`
			Sources []string `json:"sources"`
		} `json:"packages"`
	}
	if err := json.Unmarshal(manifest, &m); err != nil {
		return nil, "", err
	}
	if p.Entry.Package != m.Entry.Package || p.Entry.Activity != m.Entry.Activity || p.Workspace.Entry != m.Entry || !token.IsIdentifier(p.Entry.Lowered) || len(p.Workspace.Packages) != len(m.Packages) {
		return fail("workspace entry or package roster differs")
	}
	expected := map[string]map[string]string{}
	for _, pkg := range m.Packages {
		expected[pkg.Path] = map[string]string{}
		for _, filename := range pkg.Sources {
			source, e := os.ReadFile(example + filename)
			if e != nil {
				return nil, "", e
			}
			encoded, e := json.Marshal(string(source))
			if e != nil {
				return nil, "", e
			}
			expected[pkg.Path][filename] = digest(encoded)
		}
	}
	seen := map[string]bool{}
	for _, pkg := range p.Workspace.Packages {
		want, ok := expected[pkg.Path]
		if !ok || seen[pkg.Path] || len(want) != len(pkg.Sources) {
			return fail("workspace source roster differs")
		}
		seen[pkg.Path] = true
		actual := map[string]string{}
		for _, source := range pkg.Sources {
			if _, exists := actual[source.Filename]; exists {
				return fail("duplicate workspace source")
			}
			actual[source.Filename] = source.Digest
		}
		if !reflect.DeepEqual(actual, want) {
			return fail("workspace original source image differs")
		}
	}
	trace, err := rawValue(runtime.Traces[0])
	if err != nil {
		return nil, "", err
	}
	if trace["case_index"] != json.Number("0") {
		return fail("workspace trace order differs")
	}
	deliveries, ok := trace["deliveries"].([]any)
	if !ok || len(deliveries) != 1 {
		return fail("workspace trace roster differs")
	}
	delivery, ok := deliveries[0].(map[string]any)
	if !ok {
		return fail("missing workspace delivery")
	}
	inputDocument, err := rawValue(inputs)
	if err != nil {
		return nil, "", err
	}
	inputRows, ok := inputDocument["inputs"].([]any)
	if !ok || len(inputRows) != 1 {
		return fail("input roster differs")
	}
	row := inputRows[0].(map[string]any)
	entry := m.Entry.Package + ":" + m.Entry.Activity
	if kind == "evidence" {
		if !reflect.DeepEqual(row[entry], delivery["input"]) {
			return fail("workspace actual input differs")
		}
	} else {
		slots, ok := delivery["inputs"].([]any)
		if !ok || len(slots) != 2 {
			return fail("workspace input slots differ")
		}
		for i, slot := range slots {
			v, ok := slot.(map[string]any)
			if !ok || !reflect.DeepEqual(row[fmt.Sprintf("%s.input%d", entry, i)], v["value"]) {
				return fail("workspace actual input differs")
			}
		}
	}

	expectedOutput := map[string]any{"admissible": true}
	expectedActivity := "gooo://evidence/admission"
	fields := []string{"provider_ok", "evidence_ok", "authority_ok", "binding_ok", "artifact_ok", "policy_ok", "freshness_ok", "deadline_ok"}
	expectedOutput["reason"] = "ADMISSIBLE"
	if kind == "effects" {
		expectedActivity = "gooo://automation/effect-budget-accepts"
		expectedOutput["reason"] = "WITHIN_EFFECT_BUDGET"
		fields = []string{"target_ok", "session_ok", "filesystem_ok", "process_ok", "network_ok", "ui_ok", "discard_ok", "foreign_code_ok", "device_ok", "idempotency_ok"}
	}
	for _, field := range fields {
		expectedOutput[field] = true
	}
	if delivery["activity_id"] != expectedActivity || !reflect.DeepEqual(delivery["actual"], expectedOutput) {
		return fail("workspace actual entry result differs")
	}
	if err := validateRetainedTypedFields(d, kind); err != nil {
		return nil, "", err
	}
	return []byte(p.Source), p.Entry.Lowered, nil
}

// decodeGeneration prevents typed decoding from erasing undeclared provenance.
func decodeGeneration(raw []byte) (generation, error) {
	value, err := rawValue(raw)
	if err != nil {
		return generation{}, err
	}
	if err := exactKeys(value, []string{"schema", "compiler", "sources", "projections"}); err != nil {
		return generation{}, err
	}
	projections, ok := value["projections"].(map[string]any)
	if !ok {
		return generation{}, fmt.Errorf("missing projections")
	}
	if err := exactKeys(projections, []string{"evidence", "effects", "final"}); err != nil {
		return generation{}, err
	}
	for name, rawProjection := range projections {
		p, ok := rawProjection.(map[string]any)
		if !ok {
			return generation{}, fmt.Errorf("invalid projection: %s", name)
		}
		if err := exactKeys(p, []string{"source_sha256", "generated_sha256", "bridge_sha256", "workspace_receipt_sha256", "metadata"}); err != nil {
			return generation{}, err
		}
	}
	var result generation
	err = json.Unmarshal(raw, &result)
	return result, err
}
func exactKeys(value map[string]any, keys []string) error {
	if len(value) != len(keys) {
		return fmt.Errorf("unknown or missing generation provenance field")
	}
	for _, key := range keys {
		if _, ok := value[key]; !ok {
			return fmt.Errorf("missing generation provenance field: %s", key)
		}
	}
	return nil
}
func validSHA256(value string) bool {
	if len(value) != 71 || value[:7] != "sha256:" {
		return false
	}
	for _, b := range []byte(value[7:]) {
		if !((b >= '0' && b <= '9') || (b >= 'a' && b <= 'f')) {
			return false
		}
	}
	return true
}
func nativeStep(value map[string]any) (map[string]any, error) {
	result, ok := value["result"].(map[string]any)
	if !ok {
		return nil, fmt.Errorf("missing retained result")
	}
	composition, ok := result["composition"].(map[string]any)
	if !ok {
		return nil, fmt.Errorf("missing retained composition")
	}
	steps, ok := composition["steps"].([]any)
	if !ok || len(steps) != 1 {
		return nil, fmt.Errorf("retained composition requires exactly one generation step")
	}
	step, ok := steps[0].(map[string]any)
	if !ok {
		return nil, fmt.Errorf("invalid retained generation step")
	}
	return step, nil
}
func validateWorkspaceProjection(retained, fresh []byte) error {
	value, err := rawValue(retained)
	if err != nil {
		return err
	}
	step, err := nativeStep(value)
	if err != nil {
		return err
	}
	native, ok := step["generation"].(map[string]any)
	if !ok {
		return fmt.Errorf("missing retained generation")
	}
	raw, err := json.Marshal(native)
	if err != nil {
		return err
	}
	a, err := stableReceipt(raw)
	if err != nil {
		return err
	}
	b, err := stableReceipt(fresh)
	if err != nil {
		return err
	}
	if !reflect.DeepEqual(a, b) {
		return fmt.Errorf("retained complete native generation differs: %s", strings.Join(differencePaths(a, b, "$"), ","))
	}
	return nil
}
func validateRetainedTypedFields(value map[string]any, kind string) error {
	step, err := nativeStep(value)
	if err != nil {
		return err
	}
	native, ok := step["generation"].(map[string]any)
	if !ok {
		return fmt.Errorf("missing retained generation")
	}
	report, ok := native["report"].(map[string]any)
	if !ok {
		return fmt.Errorf("missing retained generation metadata")
	}
	result := value["result"].(map[string]any)
	program := result["program"].(map[string]any)
	source := program["lowered_gooo_source"].(string)
	if report["decision"] != "PASS" || report["compiler_source_sha"] != pin || report["source_digest"] != digest([]byte(source)) || report["typecheck_passed"] != true || report["deterministic_replay"] != true || report["repository_writes"] != json.Number("0") {
		return fmt.Errorf("retained native generation provenance differs")
	}
	generated, ok := native["source"].(string)
	if !ok || report["generated_digest"] != digest([]byte(generated)) {
		return fmt.Errorf("retained native generation source digest differs")
	}
	records, ok := report["record_types"].([]any)
	if !ok {
		return fmt.Errorf("missing retained record metadata")
	}
	byName := map[string]map[string]any{}
	for _, raw := range records {
		record, ok := raw.(map[string]any)
		if !ok {
			return fmt.Errorf("invalid record metadata")
		}
		name, ok := record["name"].(string)
		if !ok {
			return fmt.Errorf("missing record name")
		}
		if _, duplicate := byName[name]; duplicate {
			return fmt.Errorf("duplicate record metadata")
		}
		byName[name] = record
	}
	runtime := result["runtime"].(map[string]any)
	trace := runtime["traces"].([]any)[0].(map[string]any)
	delivery := trace["deliveries"].([]any)[0].(map[string]any)
	checkFields := func(recordName string, values, fields any) error {
		record, ok := byName[recordName]
		if !ok {
			return fmt.Errorf("missing typed record: %s", recordName)
		}
		sourceFields, ok := record["fields"].([]any)
		if !ok {
			return fmt.Errorf("missing typed record fields")
		}
		actual, ok := values.(map[string]any)
		if !ok || len(sourceFields) != len(actual) {
			return fmt.Errorf("typed value field roster differs")
		}
		expected := make([]any, 0, len(sourceFields))
		names := map[string]bool{}
		for _, raw := range sourceFields {
			field, ok := raw.(map[string]any)
			if !ok {
				return fmt.Errorf("invalid typed field metadata")
			}
			name, ok := field["name"].(string)
			if !ok || names[name] {
				return fmt.Errorf("invalid or duplicate typed field name")
			}
			names[name] = true
			v, ok := actual[name]
			if !ok {
				return fmt.Errorf("missing typed value")
			}
			switch field["type_id"] {
			case "urn:gooo:type:string":
				if _, ok := v.(string); !ok {
					return fmt.Errorf("typed string value differs")
				}
			case "urn:gooo:type:boolean":
				if _, ok := v.(bool); !ok {
					return fmt.Errorf("typed Boolean value differs")
				}
			case "urn:gooo:type:integer":
				n, ok := v.(json.Number)
				if !ok {
					return fmt.Errorf("typed integer value differs")
				}
				if _, err := strconv.ParseInt(string(n), 10, 64); err != nil {
					return fmt.Errorf("typed int64 value differs")
				}
			default:
				return fmt.Errorf("unsupported typed field metadata")
			}
			id, ok := field["id"].(string)
			if !ok || id == "" {
				return fmt.Errorf("missing typed field identity")
			}
			expected = append(expected, map[string]any{"id": id, "name": name, "value": v})
		}
		if !reflect.DeepEqual(expected, fields) {
			return fmt.Errorf("complete ordered typed fields differ for %s", recordName)
		}
		return nil
	}
	outputName := "EvidenceDecision"
	if kind == "evidence" {
		if err := checkFields("ObservationFacts", delivery["input"], delivery["input_fields"]); err != nil {
			return err
		}
	} else {
		outputName = "EffectBudgetDecision"
		slots := delivery["inputs"].([]any)
		for i, name := range []string{"ToolEffects", "EffectBudget"} {
			slot := slots[i].(map[string]any)
			if slot["port"] != fmt.Sprintf("input%d", i) || slot["entity_id"] != byName[name]["id"] {
				return fmt.Errorf("ordered typed input slot identity differs")
			}
			if err := checkFields(name, slot["value"], slot["fields"]); err != nil {
				return err
			}
		}
	}
	return checkFields(outputName, delivery["actual"], delivery["actual_fields"])
}

func run(ctx context.Context, compiler string, args ...string) ([]byte, error) {
	cmd := exec.CommandContext(ctx, compiler, args...)
	for _, e := range os.Environ() {
		if !strings.HasPrefix(e, "GOOO_LAYA_URL=") && !strings.HasPrefix(e, "GOOO_LAYA_API_KEY=") {
			cmd.Env = append(cmd.Env, e)
		}
	}
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	b, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("compiler: %w: %s", err, stderr.String())
	}
	return b, nil
}
func digest(b []byte) string { return fmt.Sprintf("sha256:%x", sha256.Sum256(b)) }

// The exact timing and known generating-host observations are retained in the
// raw record, separately from semantic bindings. All other keys and types match.
func stableReceipt(raw []byte) (any, error) {
	value, err := rawValue(raw)
	if err != nil {
		return nil, err
	}
	report, ok := value["report"].(map[string]any)
	if !ok {
		return nil, fmt.Errorf("missing compiler report")
	}
	latency, ok := report["route_decision_latency_ms"].(json.Number)
	if !ok {
		return nil, fmt.Errorf("missing numeric route latency")
	}
	f, err := latency.Float64()
	if err != nil || f < 0 {
		return nil, fmt.Errorf("invalid route latency")
	}
	delete(report, "route_decision_latency_ms")
	// Generation is byte-identical across these two observed hosts. This field
	// records the generating host, not the safety/execution facts of a request.
	completeness, ok := report["completeness_receipt"].(map[string]any)
	if !ok {
		return nil, fmt.Errorf("missing completeness receipt")
	}
	scope, ok := completeness["scope"].(map[string]any)
	if !ok {
		return nil, fmt.Errorf("missing generation scope")
	}
	platform, ok := scope["execution_environment"].(string)
	if !ok || (platform != "darwin/arm64" && platform != "linux/amd64") {
		return nil, fmt.Errorf("unsupported generation observation platform")
	}
	scope["execution_environment"] = "observed-generation-host"
	return value, nil
}

func rawValue(raw []byte) (map[string]any, error) {
	if err := jsoninput.Validate(raw, reflect.TypeOf(map[string]any{})); err != nil {
		return nil, err
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	var value map[string]any
	if err := decoder.Decode(&value); err != nil {
		return nil, err
	}
	return value, nil
}

// Go reports the pinned source under its release tag when built in the clean
// checkout, and under its exact pseudo-version when installed from that source.
// Preserve both raw identities in provenance. Only these two observed labels
// are equivalent for this fixed pin; every other identity field stays exact.
func compilerIdentity(raw []byte) (map[string]any, error) {
	value, err := rawValue(raw)
	if err != nil {
		return nil, err
	}
	const pin = "83928fa4538245abe33b08549da47f8cbdc50ed2"
	const installed = "v0.0.0-20261011201109-83928fa45382"
	module, ok := value["module"].(map[string]any)
	if !ok {
		return nil, fmt.Errorf("missing compiler module")
	}
	label, ok := value["module_version"].(string)
	if !ok || value["compiler_source_sha"] != pin || module["path"] != "github.com/kimjooyoon/meta-ontology-go" || module["version"] != label || (label != "v0.6.32-dev" && label != installed) {
		return nil, fmt.Errorf("unrecognized compiler module identity for pinned source")
	}
	value["module_version"] = pin
	module["version"] = pin
	return value, nil
}

func differencePaths(a, b any, path string) []string {
	if reflect.DeepEqual(a, b) {
		return nil
	}
	if am, ok := a.(map[string]any); ok {
		if bm, ok := b.(map[string]any); ok {
			keys := map[string]bool{}
			for k := range am {
				keys[k] = true
			}
			for k := range bm {
				keys[k] = true
			}
			ordered := make([]string, 0, len(keys))
			for k := range keys {
				ordered = append(ordered, k)
			}
			sort.Strings(ordered)
			out := []string{}
			for _, k := range ordered {
				av, aok := am[k]
				bv, bok := bm[k]
				if !aok || !bok {
					out = append(out, path+"."+k)
				} else {
					out = append(out, differencePaths(av, bv, path+"."+k)...)
				}
				if len(out) >= 8 {
					return out[:8]
				}
			}
			return out
		}
	}
	if aa, ok := a.([]any); ok {
		if bb, ok := b.([]any); ok && len(aa) == len(bb) {
			out := []string{}
			for i := range aa {
				out = append(out, differencePaths(aa[i], bb[i], fmt.Sprintf("%s[%d]", path, i))...)
				if len(out) >= 8 {
					return out[:8]
				}
			}
			return out
		}
	}
	return []string{path}
}
