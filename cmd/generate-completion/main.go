// generate-completion projects the pinned Gooo completion activities into Go.
package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"flag"
	"fmt"
	"go/ast"
	"go/format"
	"go/parser"
	"go/token"
	"os"
	"os/exec"
	"reflect"
	"sort"
	"strings"
	"time"

	"github.com/kimjooyoon/gooo-policy-studio/internal/jsoninput"
)

const example = "examples/completion-ledger/"
const destination = "internal/completion/"

type record struct {
	Name   string `json:"name"`
	GoName string `json:"go_name"`
}
type result struct {
	Source string `json:"source"`
	Report struct {
		Decision string   `json:"decision"`
		Records  []record `json:"record_types"`
	} `json:"report"`
}
type identity struct {
	Schema       string `json:"schema"`
	Source       string `json:"compiler_source_sha"`
	Version      string `json:"version"`
	GoVersion    string `json:"go_version"`
	SourceStatus string `json:"source_status"`
	VCSRevision  string `json:"vcs_revision"`
	VCSModified  string `json:"vcs_modified"`
	NativeGo     string `json:"native_go_required"`
}
type generation struct {
	Schema          string                     `json:"schema"`
	SourceDigest    string                     `json:"source_sha256"`
	GeneratedDigest string                     `json:"generated_sha256"`
	BridgeDigest    string                     `json:"bridge_sha256"`
	Compiler        json.RawMessage            `json:"compiler"`
	Activities      map[string]json.RawMessage `json:"activities"`
}

func main() {
	compiler := flag.String("compiler", "gooo", "Pinned Gooo executable")
	check := flag.Bool("check", false, "Compare projections without writing files")
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
	// Verify the actual compiler before asking it to project any source.
	pin, err := os.ReadFile(example + "compiler-version.txt")
	if err != nil {
		return err
	}
	version, err := run(ctx, compiler, "version", "--build", "--json")
	if err != nil {
		return err
	}
	var id identity
	if err := json.Unmarshal(version, &id); err != nil {
		return err
	}
	if id.Schema != "gooo/build-identity/v1" || id.Source != strings.TrimSpace(string(pin)) || id.Version != "0.6.32-dev" || id.GoVersion != "go1.27.2" || id.NativeGo != "go1.27.2" || id.SourceStatus != "CLEAN_VCS" || id.VCSRevision != id.Source || id.VCSModified != "false" {
		return fmt.Errorf("compiler identity does not match the clean pinned 0.6.32-dev / Go 1.27.2 source")
	}
	source, err := os.ReadFile(example + "completion.gooo")
	if err != nil {
		return err
	}
	var merged bytes.Buffer
	merged.WriteString("// Code generated from examples/completion-ledger/completion.gooo by Gooo; DO NOT EDIT.\npackage completion\n\n")
	seen := map[string]string{}
	records := map[string]string{}
	receipts := map[string]json.RawMessage{}
	for _, activity := range []string{"CompletionStep", "CompletionFinish", "CompletionReady"} {
		raw, err := run(ctx, compiler, "body-codegen", "--json", "--activity", activity, example+"completion.gooo")
		if err != nil {
			return fmt.Errorf("%s: %w", activity, err)
		}
		var out result
		if err := json.Unmarshal(raw, &out); err != nil {
			return err
		}
		if out.Report.Decision != "PASS" || out.Source == "" {
			return fmt.Errorf("generation rejected %s", activity)
		}
		receipts[activity] = raw
		for _, r := range out.Report.Records {
			if !token.IsIdentifier(r.GoName) {
				return fmt.Errorf("invalid generated record name")
			}
			if old, ok := records[r.Name]; ok && old != r.GoName {
				return fmt.Errorf("conflicting generated metadata for %s", r.Name)
			}
			records[r.Name] = r.GoName
		}
		fs := token.NewFileSet()
		file, err := parser.ParseFile(fs, activity+".go", out.Source, parser.ParseComments)
		if err != nil {
			return err
		}
		if len(file.Imports) != 0 {
			return fmt.Errorf("unexpected generated imports")
		}
		for _, decl := range file.Decls {
			var name string
			switch d := decl.(type) {
			case *ast.GenDecl:
				if d.Tok != token.TYPE || len(d.Specs) != 1 {
					return fmt.Errorf("unexpected generated declaration")
				}
				t, ok := d.Specs[0].(*ast.TypeSpec)
				if !ok {
					return fmt.Errorf("unexpected generated type")
				}
				name = t.Name.Name
			case *ast.FuncDecl:
				if d.Recv != nil {
					return fmt.Errorf("unexpected generated method")
				}
				name = d.Name.Name
			default:
				return fmt.Errorf("unexpected generated declaration")
			}
			start, end := fs.Position(decl.Pos()).Offset, fs.Position(decl.End()).Offset
			semantic := out.Source[start:end]
			if old, ok := seen[name]; ok {
				if old != semantic {
					return fmt.Errorf("conflicting generated declaration %s", name)
				}
				continue
			}
			seen[name] = semantic
			if marker := strings.LastIndex(out.Source[:start], "//gooo:generated:start"); marker >= 0 {
				start = marker
			}
			suffix := out.Source[end:]
			if marker := strings.Index(suffix, "//gooo:generated:end"); marker >= 0 {
				if line := strings.IndexByte(suffix[marker:], '\n'); line >= 0 {
					end += marker + line + 1
				}
			}
			merged.WriteString(out.Source[start:end])
			merged.WriteString("\n\n")
		}
	}
	for _, name := range []string{"CompletionCounts", "CompletionDecision", "CompletionCoverage", "CompletionReadiness"} {
		if records[name] == "" {
			return fmt.Errorf("missing generated record %s", name)
		}
	}
	generated, err := format.Source(merged.Bytes())
	if err != nil {
		return err
	}
	bridge := fmt.Sprintf(`// Code generated from Gooo record metadata; DO NOT EDIT.
package completion
import "encoding/json"
func stepNative(counts Counts, status string) (Decision,error) {
 var a %s
 if err:=transport(counts,&a);err!=nil{return Decision{},err}
 var out Decision; err:=transport(CompletionStep(a,status),&out);return out,err
}
func finishNative(counts Counts) (Decision,error) {
 var a %s
 if err:=transport(counts,&a);err!=nil{return Decision{},err}
 var out Decision;err:=transport(CompletionFinish(a),&out);return out,err
}
func readyNative(summary Decision,coverage Coverage) (Readiness,error) {
 var a %s;var b %s
 if err:=transport(summary,&a);err!=nil{return Readiness{},err}
 if err:=transport(coverage,&b);err!=nil{return Readiness{},err}
 var out Readiness;err:=transport(CompletionReady(a,b),&out);return out,err
}
func transport(in,out any) error {b,err:=json.Marshal(in);if err!=nil{return err};return json.Unmarshal(b,out)}
`, records["CompletionCounts"], records["CompletionCounts"], records["CompletionDecision"], records["CompletionCoverage"])
	adapter, err := format.Source([]byte(bridge))
	if err != nil {
		return err
	}
	evidence := generation{"policy-studio/completion-generation/v1", digest(source), digest(generated), digest(adapter), version, receipts}
	evidenceJSON, err := json.MarshalIndent(evidence, "", "  ")
	if err != nil {
		return err
	}
	evidenceJSON = append(evidenceJSON, '\n')
	files := map[string][]byte{"rules_generated.go": generated, "generated.txt": generated, "bridge_generated.go": adapter, "bridge.txt": adapter, "source.gooo": source, "compiler-version.txt": pin}
	if check {
		for name, content := range files {
			existing, err := os.ReadFile(destination + name)
			if err != nil {
				return err
			}
			if !bytes.Equal(existing, content) {
				return fmt.Errorf("stale projection: %s", destination+name)
			}
		}
		// Raw receipts may contain timing observations. Verify their stable source
		// and compiler bindings rather than comparing volatile receipt bytes.
		raw, err := os.ReadFile(destination + "generation.json")
		if err != nil {
			return err
		}
		var saved generation
		if _, err := rawValue(raw); err != nil {
			return err
		}
		if err := json.Unmarshal(raw, &saved); err != nil {
			return err
		}
		var savedID identity
		if err := json.Unmarshal(saved.Compiler, &savedID); err != nil {
			return err
		}
		if saved.Schema != evidence.Schema || saved.SourceDigest != evidence.SourceDigest || saved.GeneratedDigest != evidence.GeneratedDigest || saved.BridgeDigest != evidence.BridgeDigest || savedID != id || len(saved.Activities) != 3 {
			return fmt.Errorf("stale generation bindings")
		}
		oldIdentity, err := compilerIdentity(saved.Compiler)
		if err != nil {
			return err
		}
		freshIdentity, err := compilerIdentity(version)
		if err != nil {
			return err
		}
		if !reflect.DeepEqual(oldIdentity, freshIdentity) {
			return fmt.Errorf("stale complete compiler identity: %s", strings.Join(differencePaths(oldIdentity, freshIdentity, "$"), ","))
		}
		for activity, freshRaw := range receipts {
			old, err := stableReceipt(saved.Activities[activity])
			if err != nil {
				return err
			}
			fresh, err := stableReceipt(freshRaw)
			if err != nil {
				return err
			}
			if !reflect.DeepEqual(old, fresh) {
				return fmt.Errorf("stale %s receipt: %s", activity, strings.Join(differencePaths(old, fresh, "$"), ","))
			}
		}
	} else {
		files["generation.json"] = evidenceJSON
		for name, content := range files {
			if err := os.WriteFile(destination+name, content, 0644); err != nil {
				return err
			}
		}
	}
	fmt.Println("CompletionStep + CompletionFinish + CompletionReady projections and bindings accepted.")
	return nil
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
