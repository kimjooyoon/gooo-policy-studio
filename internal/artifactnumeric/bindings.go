package artifactnumeric

import (
	"bytes"
	"crypto/sha256"
	_ "embed"
	"encoding/json"
	"errors"
	"fmt"
	"go/format"
	"reflect"
	"strings"

	"github.com/kimjooyoon/gooo-policy-studio/internal/jsoninput"
)

// Generated assets are intentionally absent during the source-first phase.
// Only the approved generator creates them from the pinned actual compiler.
//
//go:embed source.gooo
var sourceBytes []byte

//go:embed rules_generated.go
var rulesBytes []byte

//go:embed generated.txt
var generatedBytes []byte

//go:embed bridge.go
var bridgeSource []byte

//go:embed bridge.txt
var bridgeBytes []byte

//go:embed model.go
var modelSource []byte

//go:embed bindings.go
var bindingsSource []byte

//go:embed generator.txt
var generatorBytes []byte

//go:embed generation.json
var generationBytes []byte

//go:embed compiler-version.txt
var compilerPin string

const generatedHeader = "// Code generated from internal/artifactnumeric/source.gooo by Gooo; DO NOT EDIT.\n"

// SourceBindings rechecks immutable embedded assets each time. In particular,
// configuration validation calls this before reserving or acquiring any file;
// an unavailable native projection is an error even for a legacy recipe.
func SourceBindings() (Bindings, error) {
	return checkBindings(sourceBytes, rulesBytes, generatedBytes, bridgeSource, bridgeBytes, modelSource, bindingsSource, generatorBytes, generationBytes, compilerPin)
}

func checkBindings(source, rules, generated, bridge, bridgeCopy, model, host, generator, raw []byte, pinText string) (Bindings, error) {
	invalid := errors.New("numeric source bindings unavailable or inconsistent")
	if len(source) == 0 || len(rules) == 0 || len(bridge) == 0 || len(model) == 0 || len(host) == 0 || len(generator) == 0 || !bytes.Equal(rules, generated) || !bytes.Equal(bridge, bridgeCopy) || strings.TrimSpace(pinText) != CompilerSourcePin {
		return Bindings{}, invalid
	}
	value, err := object(raw)
	if err != nil || !keys(value, "schema", "source_sha256", "generated_sha256", "bridge_sha256", "model_sha256", "bindings_sha256", "generator_sha256", "compiler", "activity") {
		return Bindings{}, invalid
	}
	if value["schema"] != GenerationSchema || value["source_sha256"] != hash(source) || value["generated_sha256"] != hash(rules) || value["bridge_sha256"] != hash(bridge) || value["model_sha256"] != hash(model) || value["bindings_sha256"] != hash(host) || value["generator_sha256"] != hash(generator) {
		return Bindings{}, invalid
	}
	var record struct {
		Compiler json.RawMessage `json:"compiler"`
		Activity json.RawMessage `json:"activity"`
	}
	if json.Unmarshal(raw, &record) != nil {
		return Bindings{}, invalid
	}
	if _, err := checkedCompiler(record.Compiler); err != nil {
		return Bindings{}, invalid
	}
	activity, err := object(record.Activity)
	if err != nil || !keys(activity, "source", "report") {
		return Bindings{}, invalid
	}
	projection, ok := activity["source"].(string)
	if !ok || projection == "" {
		return Bindings{}, invalid
	}
	formatted, err := format.Source([]byte(generatedHeader + projection))
	if err != nil || !bytes.Equal(formatted, rules) {
		return Bindings{}, invalid
	}
	report, ok := activity["report"].(map[string]any)
	if !ok || report["schema"] != "gooo/body-codegen-report/v3" || report["decision"] != "PASS" || report["activity"] != "Int64BoundDecision" || report["activity_id"] != "gooo://artifact/int64-bound-decision" || report["input_type"] != "(int64,int64,string)" || report["output_type"] != "BoundDecision" || report["compiler_source_sha"] != CompilerSourcePin || report["source_digest"] != hash(source) || report["generated_digest"] != hash([]byte(projection)) || report["replay_digest"] != hash([]byte(projection)) || report["typecheck_passed"] != true || report["deterministic_replay"] != true || report["repository_writes"] != json.Number("0") {
		return Bindings{}, invalid
	}
	return Bindings{Schema: BindingsSchema, SourceSHA256: hash(source), GeneratedSHA256: hash(rules), BridgeSHA256: hash(bridge), ModelSHA256: hash(model), BindingsSHA256: hash(host), GeneratorSHA256: hash(generator), GenerationSHA256: hash(raw), CompilerIdentitySHA256: hash(record.Compiler), ActivityReceiptSHA256: hash(record.Activity), CompilerSourceSHA: CompilerSourcePin, JSONInputSHA256: jsoninput.SourceIdentity()}, nil
}

func object(raw []byte) (map[string]any, error) {
	if len(raw) == 0 || len(raw) > 4*1024*1024 || jsoninput.Validate(raw, reflect.TypeOf(map[string]any{})) != nil {
		return nil, errors.New("numeric binding JSON invalid")
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	var out map[string]any
	if decoder.Decode(&out) != nil || out == nil {
		return nil, errors.New("numeric binding JSON invalid")
	}
	return out, nil
}

func keys(value map[string]any, names ...string) bool {
	if len(value) != len(names) {
		return false
	}
	for _, name := range names {
		if _, ok := value[name]; !ok {
			return false
		}
	}
	return true
}

func checkedCompiler(raw []byte) (map[string]any, error) {
	value, err := object(raw)
	invalid := errors.New("numeric compiler identity invalid")
	if err != nil || !keys(value, "schema", "language", "version", "status", "build_info_observed", "go_version", "module_version", "module", "compiler_source_sha", "source_status", "vcs_revision", "vcs_modified", "decision_runtime", "native_go_required") {
		return nil, invalid
	}
	if value["schema"] != "gooo/build-identity/v1" || value["language"] != "gooo" || value["version"] != "0.6.32-dev" || value["status"] != "development" || value["build_info_observed"] != true || value["go_version"] != "go1.27.2" || value["native_go_required"] != "go1.27.2" || value["compiler_source_sha"] != CompilerSourcePin || value["source_status"] != "CLEAN_VCS" || value["vcs_revision"] != CompilerSourcePin || value["vcs_modified"] != "false" {
		return nil, invalid
	}
	module, ok := value["module"].(map[string]any)
	label, okLabel := value["module_version"].(string)
	if !ok || !okLabel || !keys(module, "path", "version") || module["path"] != "github.com/kimjooyoon/meta-ontology-go" || module["version"] != label || (label != "v0.6.32-dev" && label != "v0.0.0-20261011201109-83928fa45382") {
		return nil, invalid
	}
	runtime, ok := value["decision_runtime"].(map[string]any)
	if !ok || !keys(runtime, "module_path", "version", "replaced") || runtime["module_path"] != "github.com/kimjooyoon/gooo-decision-runtime" || runtime["version"] != "v0.2.41-experimental" || runtime["replaced"] != false {
		return nil, invalid
	}
	// These two observed module labels identify the same fixed clean compiler.
	// Raw bytes remain retained and hashed; nothing else is normalized.
	value["module_version"] = CompilerSourcePin
	module["version"] = CompilerSourcePin
	return value, nil
}

func hash(raw []byte) string { return fmt.Sprintf("sha256:%x", sha256.Sum256(raw)) }
