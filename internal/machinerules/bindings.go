package machinerules

import (
	"crypto/sha256"
	"embed"
	"encoding/json"
	"fmt"
	"strings"
	"sync"
)

//go:embed assets/* evidence/source.gooo evidence/generated.txt evidence/bridge.txt effects/source.gooo effects/generated.txt effects/bridge.txt final/source.gooo final/generated.txt final/bridge.txt generation.json
var inputs embed.FS

type SourceBinding struct {
	Path   string `json:"path"`
	SHA256 string `json:"sha256"`
}
type ProjectionBinding struct {
	Name                   string `json:"name"`
	SourceSHA256           string `json:"source_sha256"`
	GeneratedSHA256        string `json:"generated_sha256"`
	BridgeSHA256           string `json:"bridge_sha256"`
	WorkspaceReceiptSHA256 string `json:"workspace_receipt_sha256"`
}
type Provenance struct {
	Schema            string              `json:"schema"`
	CompilerSourceSHA string              `json:"compiler_source_sha"`
	GenerationSHA256  string              `json:"generation_sha256"`
	Sources           []SourceBinding     `json:"sources"`
	Projections       []ProjectionBinding `json:"projections"`
}

var provenanceOnce sync.Once
var provenance Provenance
var provenanceError error

// Bindings returns fresh slices over checked immutable embedded build inputs.
// It proves their byte consistency; the operator still trusts the executable.
func Bindings() (Provenance, error) {
	provenanceOnce.Do(func() { provenance, provenanceError = checkBindings() })
	result := provenance
	result.Sources = append([]SourceBinding{}, provenance.Sources...)
	result.Projections = append([]ProjectionBinding{}, provenance.Projections...)
	return result, provenanceError
}
func checkBindings() (Provenance, error) {
	raw, err := inputs.ReadFile("generation.json")
	if err != nil {
		return Provenance{}, err
	}
	var record struct {
		Schema   string `json:"schema"`
		Compiler struct {
			Source    string `json:"compiler_source_sha"`
			Status    string `json:"source_status"`
			Modified  string `json:"vcs_modified"`
			Version   string `json:"version"`
			GoVersion string `json:"go_version"`
		} `json:"compiler"`
		Sources     map[string]string `json:"sources"`
		Projections map[string]struct {
			Source           string `json:"source_sha256"`
			Generated        string `json:"generated_sha256"`
			Bridge           string `json:"bridge_sha256"`
			WorkspaceReceipt string `json:"workspace_receipt_sha256"`
		} `json:"projections"`
	}
	if err := json.Unmarshal(raw, &record); err != nil {
		return Provenance{}, err
	}
	if record.Schema != "policy-studio/machine-generation/v1" || record.Compiler.Source != "83928fa4538245abe33b08549da47f8cbdc50ed2" || record.Compiler.Status != "CLEAN_VCS" || record.Compiler.Modified != "false" || record.Compiler.Version != "0.6.32-dev" || record.Compiler.GoVersion != "go1.27.2" || len(record.Projections) != 3 {
		return Provenance{}, fmt.Errorf("machine generation compiler binding differs")
	}
	result := Provenance{Schema: "policy-studio/machine-provenance/v1", CompilerSourceSHA: record.Compiler.Source, GenerationSHA256: hash(raw), Sources: []SourceBinding{}, Projections: []ProjectionBinding{}}
	paths := []struct{ Path, Asset string }{
		{"examples/evidence-admission/admission.gooo", "original-admission.gooo"},
		{"examples/evidence-admission/proof_authority.gooo", "original-proof_authority.gooo"},
		{"examples/tool-effects/tool_effects.gooo", "original-tool_effects.gooo"},
		{"examples/tool-effects/effect_budget.gooo", "original-effect_budget.gooo"},
		{"cmd/generate-machine/main.go", "generator.go.txt"},
		{"internal/machinerules/rules.go", "host-transport.go.txt"},
		{"internal/machinerules/bindings.go", "host-bindings.go.txt"},
	}
	for _, name := range []string{"admission.gooo", "proof_authority.gooo", "tool_effects.gooo", "effect_budget.gooo", "machine.gooo", "LICENSE-REA", "compiler-version.txt", "evidence.workspace.json", "effects.workspace.json", "admission.workspace.json", "evidence.inputs.json", "effects.inputs.json", "receipts/evidence-workspace.json", "receipts/effects-workspace.json"} {
		paths = append(paths, struct{ Path, Asset string }{"examples/artifact-gate/" + name, strings.ReplaceAll(name, "/", "-")})
	}
	if len(record.Sources) != len(paths) {
		return Provenance{}, fmt.Errorf("machine source roster differs")
	}
	for _, item := range paths {
		b, err := inputs.ReadFile("assets/" + item.Asset)
		if err != nil {
			return Provenance{}, err
		}
		if record.Sources[item.Path] != hash(b) {
			return Provenance{}, fmt.Errorf("machine source bytes differ: %s", item.Path)
		}
		result.Sources = append(result.Sources, SourceBinding{item.Path, hash(b)})
	}
	for _, kind := range []string{"evidence", "effects", "final"} {
		p, ok := record.Projections[kind]
		if !ok {
			return Provenance{}, fmt.Errorf("missing projection: %s", kind)
		}
		for file, want := range map[string]string{"source.gooo": p.Source, "generated.txt": p.Generated, "bridge.txt": p.Bridge} {
			b, err := inputs.ReadFile(kind + "/" + file)
			if err != nil {
				return Provenance{}, err
			}
			if want != hash(b) {
				return Provenance{}, fmt.Errorf("projection bytes differ: %s/%s", kind, file)
			}
		}
		if kind != "final" {
			b, err := inputs.ReadFile("assets/receipts-" + kind + "-workspace.json")
			if err != nil {
				return Provenance{}, err
			}
			if p.WorkspaceReceipt != hash(b) {
				return Provenance{}, fmt.Errorf("workspace receipt bytes differ")
			}
		} else if p.WorkspaceReceipt != "" {
			return Provenance{}, fmt.Errorf("unexpected final workspace receipt")
		}
		result.Projections = append(result.Projections, ProjectionBinding{kind, p.Source, p.Generated, p.Bridge, p.WorkspaceReceipt})
	}
	return result, nil
}
func hash(raw []byte) string { return fmt.Sprintf("sha256:%x", sha256.Sum256(raw)) }
