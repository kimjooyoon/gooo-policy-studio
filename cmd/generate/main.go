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
	"strings"
	"time"
)

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

func main() {
	compiler := flag.String("compiler", "gooo", "Gooo executable")
	check := flag.Bool("check", false, "Compare projections without writing files")
	flag.Parse()
	if err := generate(*compiler, *check); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
func generate(compiler string, check bool) error {
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	source, err := os.ReadFile("policy/approval.gooo")
	if err != nil {
		return err
	}
	var merged bytes.Buffer
	merged.WriteString("// Code generated from policy/approval.gooo by Gooo; DO NOT EDIT.\npackage policy\n\n")
	seen := map[string]bool{}
	records := map[string]string{}
	receipts := map[string]json.RawMessage{}
	for _, activity := range []string{"Evaluate", "Compare"} {
		cmd := exec.CommandContext(ctx, compiler, "body-codegen", "--json", "--activity", activity, "policy/approval.gooo")
		for _, e := range os.Environ() {
			if !strings.HasPrefix(e, "GOOO_LAYA_URL=") {
				cmd.Env = append(cmd.Env, e)
			}
		}
		raw, err := cmd.Output()
		if err != nil {
			return fmt.Errorf("%s: %w", activity, err)
		}
		var out result
		if err := json.Unmarshal(raw, &out); err != nil {
			return err
		}
		if out.Report.Decision != "PASS" || out.Source == "" {
			return fmt.Errorf("generation rejected %s: %s", activity, raw)
		}
		receipts[activity] = raw
		for _, r := range out.Report.Records {
			records[r.Name] = r.GoName
		}
		fs := token.NewFileSet()
		file, err := parser.ParseFile(fs, "generated.go", out.Source, parser.ParseComments)
		if err != nil {
			return err
		}
		// Copy compiler byte ranges including generated markers; deduplicate shared types.
		for _, decl := range file.Decls {
			var name string
			switch d := decl.(type) {
			case *ast.GenDecl:
				name = d.Specs[0].(*ast.TypeSpec).Name.Name
			case *ast.FuncDecl:
				name = d.Name.Name
			}
			if seen[name] {
				continue
			}
			seen[name] = true
			start, end := fs.Position(decl.Pos()).Offset, fs.Position(decl.End()).Offset
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
	generated, err := format.Source(merged.Bytes())
	if err != nil {
		return err
	}
	bridge := fmt.Sprintf(`// Code generated from Gooo record metadata; DO NOT EDIT.
package policy
import "encoding/json"
func evaluateNative(request Request, reviewer Reviewer, policy Rules) (Decision,error) {
 var a %s;var b %s;var c %s
 if err:=transport(request,&a);err!=nil{return Decision{},err}
 if err:=transport(reviewer,&b);err!=nil{return Decision{},err}
 if err:=transport(policy,&c);err!=nil{return Decision{},err}
 var out Decision;err:=transport(Evaluate(a,b,c),&out);return out,err
}
func compareNative(before,after Decision) (Change,error) {
 var a %s;var b %s
 if err:=transport(before,&a);err!=nil{return Change{},err}
 if err:=transport(after,&b);err!=nil{return Change{},err}
 var out Change;err:=transport(Compare(a,b),&out);return out,err
}
func transport(in,out any) error {b,err:=json.Marshal(in);if err!=nil{return err};return json.Unmarshal(b,out)}
`, records["Request"], records["Reviewer"], records["Policy"], records["Decision"], records["Decision"])
	adapter, err := format.Source([]byte(bridge))
	if err != nil {
		return err
	}
	version, err := exec.CommandContext(ctx, compiler, "version", "--build", "--json").Output()
	if err != nil {
		return err
	}
	var identity struct {
		Source string `json:"compiler_source_sha"`
	}
	if err := json.Unmarshal(version, &identity); err != nil {
		return err
	}
	pin, err := os.ReadFile("tools/compiler-version.txt")
	if err != nil {
		return err
	}
	if identity.Source != strings.TrimSpace(string(pin)) {
		return fmt.Errorf("compiler must be built from the clean pinned Git checkout %s; observed %s", strings.TrimSpace(string(pin)), identity.Source)
	}
	evidence := struct {
		Schema          string                     `json:"schema"`
		SourceDigest    string                     `json:"source_sha256"`
		GeneratedDigest string                     `json:"generated_sha256"`
		AdapterDigest   string                     `json:"adapter_sha256"`
		Compiler        json.RawMessage            `json:"compiler"`
		Activities      map[string]json.RawMessage `json:"activities"`
	}{"policy-studio/generation/v1", digest(source), digest(generated), digest(adapter), version, receipts}
	evidenceJSON, err := json.MarshalIndent(evidence, "", "  ")
	if err != nil {
		return err
	}
	for p, b := range map[string][]byte{"internal/policy/rules_generated.go": generated, "internal/policy/bridge_generated.go": adapter, "evidence/generation.json": evidenceJSON, "internal/policy/generation.json": evidenceJSON, "internal/policy/approval.gooo": source, "internal/policy/generated.txt": generated} {
		if check {
			if strings.HasSuffix(p, "generation.json") {
				continue
			}
			existing, err := os.ReadFile(p)
			if err != nil {
				return err
			}
			if !bytes.Equal(existing, b) {
				return fmt.Errorf("stale projection: %s", p)
			}
			continue
		}
		if err := os.WriteFile(p, b, 0644); err != nil {
			return err
		}
	}
	fmt.Println("Generated Evaluate + Compare and source-bound evidence.")
	return nil
}
func digest(b []byte) string { return fmt.Sprintf("sha256:%x", sha256.Sum256(b)) }
