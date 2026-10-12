package completion

import (
	_ "embed"
	"encoding/json"
	"fmt"
	"strings"
)

// These exact build inputs accompany the compiled Gooo projection.
//
//go:embed source.gooo
var sourceBytes []byte

//go:embed generated.txt
var generatedBytes []byte

//go:embed bridge.txt
var bridgeBytes []byte

//go:embed generation.json
var generationBytes []byte

//go:embed compiler-version.txt
var compilerPin string

func sourceBindings() (Bindings, error) {
	var record struct {
		Schema    string `json:"schema"`
		Source    string `json:"source_sha256"`
		Generated string `json:"generated_sha256"`
		Bridge    string `json:"bridge_sha256"`
		Compiler  struct {
			Source       string `json:"compiler_source_sha"`
			SourceStatus string `json:"source_status"`
			Modified     string `json:"vcs_modified"`
		} `json:"compiler"`
	}
	if err := json.Unmarshal(generationBytes, &record); err != nil {
		return Bindings{}, err
	}
	pin := strings.TrimSpace(compilerPin)
	if record.Schema != "policy-studio/completion-generation/v1" || record.Source != digest(sourceBytes) || record.Generated != digest(generatedBytes) || record.Bridge != digest(bridgeBytes) || record.Compiler.Source != pin || record.Compiler.SourceStatus != "CLEAN_VCS" || record.Compiler.Modified != "false" {
		return Bindings{}, fmt.Errorf("embedded Gooo generation inputs differ from their bindings")
	}
	return Bindings{SourceSHA256: digest(sourceBytes), GeneratedSHA256: digest(generatedBytes), BridgeSHA256: digest(bridgeBytes), GenerationSHA256: digest(generationBytes), CompilerSourceSHA: pin}, nil
}
