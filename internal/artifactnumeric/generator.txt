// generate-artifact-bounds projects only the original Int64BoundDecision
// activity through the already installed pinned compiler. It never builds or
// downloads a compiler, executes the generated predicate, or runs old suites.
package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"go/ast"
	"go/format"
	"go/parser"
	"go/token"
	"io"
	"os"
	"os/exec"
	"reflect"
	"strconv"
	"strings"
	"time"

	"github.com/kimjooyoon/gooo-policy-studio/internal/jsoninput"
)

const destination = "internal/artifactnumeric/"
const compilerPin = "83928fa4538245abe33b08549da47f8cbdc50ed2"
const generatedHeader = "// Code generated from internal/artifactnumeric/source.gooo by Gooo; DO NOT EDIT.\n"
const generationSchema = "policy-studio/artifact-int64-generation/v1"
const maxOutput = 4 * 1024 * 1024

type generation struct {
	Schema    string          `json:"schema"`
	Source    string          `json:"source_sha256"`
	Generated string          `json:"generated_sha256"`
	Bridge    string          `json:"bridge_sha256"`
	Model     string          `json:"model_sha256"`
	Bindings  string          `json:"bindings_sha256"`
	Generator string          `json:"generator_sha256"`
	Compiler  json.RawMessage `json:"compiler"`
	Activity  json.RawMessage `json:"activity"`
}

func main() {
	compiler := flag.String("compiler", "gooo", "Existing clean pinned Gooo compiler executable")
	check := flag.Bool("check", false, "Regenerate and compare new numeric assets without writing")
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
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()
	version, err := run(ctx, compiler, "version", "--build", "--json")
	if err != nil {
		return err
	}
	if _, err := checkedCompiler(version); err != nil {
		return err
	}
	files := map[string][]byte{}
	for _, name := range []string{"source.gooo", "bridge.go", "model.go", "bindings.go"} {
		raw, err := readSource(destination + name)
		if err != nil {
			return err
		}
		files[name] = raw
	}
	generator, err := readSource("cmd/generate-artifact-bounds/main.go")
	if err != nil {
		return err
	}
	activity, err := run(ctx, compiler, "body-codegen", "--json", "--activity", "Int64BoundDecision", destination+"source.gooo")
	if err != nil {
		return err
	}
	generated, err := checkedProjection(activity, files["source.gooo"])
	if err != nil {
		return err
	}
	assets := map[string][]byte{
		"rules_generated.go": generated, "generated.txt": generated,
		"bridge.txt": files["bridge.go"], "generator.txt": generator,
		"compiler-version.txt": []byte(compilerPin + "\n"),
	}
	record := generation{generationSchema, hash(files["source.gooo"]), hash(generated), hash(files["bridge.go"]), hash(files["model.go"]), hash(files["bindings.go"]), hash(generator), version, activity}
	encoded, err := json.MarshalIndent(record, "", "  ")
	if err != nil {
		return errors.New("numeric generation encoding failed")
	}
	encoded = append(encoded, '\n')
	if check {
		for name, want := range assets {
			got, err := readSource(destination + name)
			if err != nil || !bytes.Equal(got, want) {
				return fmt.Errorf("stale numeric asset: %s", name)
			}
		}
		savedRaw, err := readSource(destination + "generation.json")
		if err != nil {
			return err
		}
		value, err := object(savedRaw)
		if err != nil || !keys(value, "schema", "source_sha256", "generated_sha256", "bridge_sha256", "model_sha256", "bindings_sha256", "generator_sha256", "compiler", "activity") {
			return errors.New("saved numeric generation invalid")
		}
		var saved generation
		if json.Unmarshal(savedRaw, &saved) != nil {
			return errors.New("saved numeric generation invalid")
		}
		if saved.Schema != record.Schema || saved.Source != record.Source || saved.Generated != record.Generated || saved.Bridge != record.Bridge || saved.Model != record.Model || saved.Bindings != record.Bindings || saved.Generator != record.Generator {
			return errors.New("stale numeric generation bindings")
		}
		oldCompiler, err := checkedCompiler(saved.Compiler)
		if err != nil {
			return err
		}
		freshCompiler, err := checkedCompiler(version)
		if err != nil {
			return err
		}
		oldActivity, err := stableReceipt(saved.Activity, files["source.gooo"])
		if err != nil {
			return err
		}
		freshActivity, err := stableReceipt(activity, files["source.gooo"])
		if err != nil {
			return err
		}
		if !reflect.DeepEqual(oldCompiler, freshCompiler) || !reflect.DeepEqual(oldActivity, freshActivity) {
			return errors.New("stale complete numeric compiler or activity receipt")
		}
	} else {
		assets["generation.json"] = encoded
		// Deterministic write order. Every write is confined to this new package.
		for _, name := range []string{"rules_generated.go", "generated.txt", "bridge.txt", "generator.txt", "compiler-version.txt", "generation.json"} {
			if err := os.WriteFile(destination+name, assets[name], 0644); err != nil {
				return errors.New("numeric asset write failed")
			}
		}
	}
	fmt.Println("Int64BoundDecision projection and complete source bindings accepted.")
	return nil
}

func checkedProjection(raw, source []byte) ([]byte, error) {
	value, err := object(raw)
	invalid := errors.New("numeric compiler projection rejected")
	if err != nil || !keys(value, "source", "report") {
		return nil, invalid
	}
	text, ok := value["source"].(string)
	if !ok || text == "" {
		return nil, invalid
	}
	report, ok := value["report"].(map[string]any)
	if !ok || report["schema"] != "gooo/body-codegen-report/v3" || report["decision"] != "PASS" || report["activity"] != "Int64BoundDecision" || report["activity_id"] != "gooo://artifact/int64-bound-decision" || report["input_type"] != "(int64,int64,string)" || report["output_type"] != "BoundDecision" || report["compiler_source_sha"] != compilerPin || report["source_digest"] != hash(source) || report["generated_digest"] != hash([]byte(text)) || report["replay_digest"] != hash([]byte(text)) || report["typecheck_passed"] != true || report["deterministic_replay"] != true || report["repository_writes"] != json.Number("0") {
		return nil, invalid
	}
	parameters, ok := report["input_parameters"].([]any)
	if !ok || len(parameters) != 3 {
		return nil, invalid
	}
	for i, expected := range []string{"int64", "int64", "string"} {
		p, ok := parameters[i].(map[string]any)
		if !ok || !keys(p, "name", "type") || p["name"] != fmt.Sprintf("input%d", i) || p["type"] != expected {
			return nil, invalid
		}
	}
	records, ok := report["record_types"].([]any)
	if !ok || len(records) != 1 {
		return nil, invalid
	}
	r, ok := records[0].(map[string]any)
	if !ok || !keys(r, "name", "id", "go_name", "fields") || r["name"] != "BoundDecision" || r["id"] != "gooo://artifact/int64-bound-decision/v1" {
		return nil, invalid
	}
	recordName, ok := r["go_name"].(string)
	if !ok || !token.IsIdentifier(recordName) {
		return nil, invalid
	}
	fields, ok := r["fields"].([]any)
	if !ok || len(fields) != 5 {
		return nil, invalid
	}
	names := []string{"at_most", "at_least", "operator_ok", "matched", "reason"}
	ids := []string{"at-most", "at-least", "operator-ok", "matched", "reason"}
	goFields := make([]string, 5)
	for i, name := range names {
		f, ok := fields[i].(map[string]any)
		if !ok || !keys(f, "name", "id", "type_id", "go_name") {
			return nil, invalid
		}
		typeID := "urn:gooo:type:boolean"
		if i == 4 {
			typeID = "urn:gooo:type:string"
		}
		goName, ok := f["go_name"].(string)
		if !ok || !token.IsIdentifier(goName) || f["name"] != name || f["id"] != "gooo://artifact/int64-bound-decision/"+ids[i] || f["type_id"] != typeID {
			return nil, invalid
		}
		goFields[i] = goName
	}
	parsed, err := parser.ParseFile(token.NewFileSet(), "numeric.go", text, 0)
	if err != nil || parsed.Name.Name != "artifactnumeric" || len(parsed.Imports) != 0 || len(parsed.Decls) != 2 {
		return nil, invalid
	}
	types, ok := parsed.Decls[0].(*ast.GenDecl)
	if !ok || types.Tok != token.TYPE || len(types.Specs) != 1 {
		return nil, invalid
	}
	spec, ok := types.Specs[0].(*ast.TypeSpec)
	if !ok || spec.Name.Name != recordName {
		return nil, invalid
	}
	structure, ok := spec.Type.(*ast.StructType)
	if !ok || len(structure.Fields.List) != 5 {
		return nil, invalid
	}
	for i, f := range structure.Fields.List {
		typeName := "bool"
		if i == 4 {
			typeName = "string"
		}
		t, ok := f.Type.(*ast.Ident)
		if !ok || t.Name != typeName || len(f.Names) != 1 || f.Names[0].Name != goFields[i] || f.Tag == nil {
			return nil, invalid
		}
		tag, err := strconv.Unquote(f.Tag.Value)
		if err != nil || tag != "json:\""+names[i]+"\"" {
			return nil, invalid
		}
	}
	fn, ok := parsed.Decls[1].(*ast.FuncDecl)
	if !ok || fn.Name.Name != "Int64BoundDecision" || fn.Recv != nil || fn.Body == nil || fn.Type.Params == nil || len(fn.Type.Params.List) != 3 || fn.Type.Results == nil || len(fn.Type.Results.List) != 1 {
		return nil, invalid
	}
	for i, f := range fn.Type.Params.List {
		name := "int64"
		if i == 2 {
			name = "string"
		}
		t, ok := f.Type.(*ast.Ident)
		if !ok || t.Name != name || len(f.Names) != 1 || f.Names[0].Name != fmt.Sprintf("input%d", i) {
			return nil, invalid
		}
	}
	result, ok := fn.Type.Results.List[0].Type.(*ast.Ident)
	if !ok || result.Name != recordName {
		return nil, invalid
	}
	pure := true
	ast.Inspect(fn.Body, func(node ast.Node) bool {
		switch node.(type) {
		case *ast.CallExpr, *ast.GoStmt, *ast.DeferStmt, *ast.SendStmt, *ast.RangeStmt, *ast.ForStmt:
			pure = false
		}
		return true
	})
	if !pure {
		return nil, invalid
	}
	formatted, err := format.Source([]byte(generatedHeader + text))
	if err != nil {
		return nil, invalid
	}
	return formatted, nil
}

func stableReceipt(raw, source []byte) (map[string]any, error) {
	if _, err := checkedProjection(raw, source); err != nil {
		return nil, err
	}
	value, err := object(raw)
	if err != nil {
		return nil, err
	}
	report := value["report"].(map[string]any)
	latency, ok := report["route_decision_latency_ms"].(json.Number)
	if !ok {
		return nil, errors.New("numeric route latency unavailable")
	}
	observed, err := latency.Float64()
	if err != nil || observed < 0 {
		return nil, errors.New("numeric route latency invalid")
	}
	delete(report, "route_decision_latency_ms")
	complete, ok := report["completeness_receipt"].(map[string]any)
	if !ok {
		return nil, errors.New("numeric completeness receipt unavailable")
	}
	scope, ok := complete["scope"].(map[string]any)
	if !ok {
		return nil, errors.New("numeric generation scope unavailable")
	}
	platform, ok := scope["execution_environment"].(string)
	if !ok || (platform != "darwin/arm64" && platform != "linux/amd64") {
		return nil, errors.New("numeric generating host unsupported")
	}
	scope["execution_environment"] = "observed-generation-host"
	return value, nil
}

func checkedCompiler(raw []byte) (map[string]any, error) {
	value, err := object(raw)
	invalid := errors.New("numeric compiler identity rejected")
	if err != nil || !keys(value, "schema", "language", "version", "status", "build_info_observed", "go_version", "module_version", "module", "compiler_source_sha", "source_status", "vcs_revision", "vcs_modified", "decision_runtime", "native_go_required") {
		return nil, invalid
	}
	if value["schema"] != "gooo/build-identity/v1" || value["language"] != "gooo" || value["version"] != "0.6.32-dev" || value["status"] != "development" || value["build_info_observed"] != true || value["go_version"] != "go1.27.2" || value["native_go_required"] != "go1.27.2" || value["compiler_source_sha"] != compilerPin || value["source_status"] != "CLEAN_VCS" || value["vcs_revision"] != compilerPin || value["vcs_modified"] != "false" {
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
	value["module_version"] = compilerPin
	module["version"] = compilerPin
	return value, nil
}

func object(raw []byte) (map[string]any, error) {
	if len(raw) == 0 || len(raw) > maxOutput || jsoninput.Validate(raw, reflect.TypeOf(map[string]any{})) != nil {
		return nil, errors.New("numeric provenance JSON invalid")
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	var result map[string]any
	if decoder.Decode(&result) != nil || result == nil {
		return nil, errors.New("numeric provenance JSON invalid")
	}
	return result, nil
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
func hash(raw []byte) string { return fmt.Sprintf("sha256:%x", sha256.Sum256(raw)) }

func readSource(path string) ([]byte, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, errors.New("numeric source unavailable")
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Size() < 1 || info.Size() > maxOutput {
		return nil, errors.New("numeric source file invalid")
	}
	raw, err := io.ReadAll(io.LimitReader(file, maxOutput+1))
	if err != nil || len(raw) > maxOutput {
		return nil, errors.New("numeric source read failed")
	}
	return raw, nil
}

type boundedBuffer struct {
	bytes.Buffer
	limit int
}

func (b *boundedBuffer) Write(raw []byte) (int, error) {
	remaining := b.limit - b.Len()
	if len(raw) > remaining {
		if remaining > 0 {
			_, _ = b.Buffer.Write(raw[:remaining])
		}
		return remaining, errors.New("numeric compiler output exceeded bound")
	}
	return b.Buffer.Write(raw)
}
func run(ctx context.Context, compiler string, args ...string) ([]byte, error) {
	command := exec.CommandContext(ctx, compiler, args...)
	for _, entry := range os.Environ() {
		if !strings.HasPrefix(entry, "GOOO_LAYA_URL=") && !strings.HasPrefix(entry, "GOOO_LAYA_API_KEY=") {
			command.Env = append(command.Env, entry)
		}
	}
	stdout := boundedBuffer{limit: maxOutput}
	stderr := boundedBuffer{limit: 16384}
	command.Stdout = &stdout
	command.Stderr = &stderr
	if command.Run() != nil {
		return nil, errors.New("numeric compiler operation failed")
	}
	return append([]byte{}, stdout.Bytes()...), nil
}
