package artifactimpact

import (
	"embed"
	"encoding/json"
	"errors"
)

const ExplainIdentitySchema = "policy-studio/artifact-impact-explain-source/v1"

//go:embed explain.go explain_files.go explain_identity.go explain.html
var explanationSource embed.FS

var errExplanationSource = errors.New("explanation source is invalid")

// ExplainIdentity binds the renderer independently of the unchanged comparison
// and replay identities. CLI argument handling is explicitly outside this
// four-file roster. None of these hashes authenticates unsigned history.
type ExplainIdentity struct {
	Schema                   string         `json:"schema"`
	Sources                  []HostBinding  `json:"sources"`
	Replay                   ReplayIdentity `json:"replay"`
	CLIArgumentHandlingBound bool           `json:"cli_argument_handling_bound"`
	RendererSHA256           string         `json:"renderer_sha256"`
}

// ExplainSourceIdentity includes the current source/runtime-bound replay
// identity. Its consistency probes may execute compiled rules and read the host
// clock; it does not refresh any historical evidence time.
func ExplainSourceIdentity() (ExplainIdentity, error) {
	replay, err := ReplaySourceIdentity()
	if err != nil {
		return ExplainIdentity{}, errExplanationSource
	}
	identity := ExplainIdentity{Schema: ExplainIdentitySchema, Sources: make([]HostBinding, 0, 4), Replay: replay}
	for _, name := range []string{"explain.go", "explain_files.go", "explain_identity.go", "explain.html"} {
		raw, err := explanationSource.ReadFile(name)
		if err != nil {
			return ExplainIdentity{}, errExplanationSource
		}
		identity.Sources = append(identity.Sources, HostBinding{Path: name, SHA256: digest(raw)})
	}
	raw, err := json.Marshal(identity)
	if err != nil {
		return ExplainIdentity{}, errExplanationSource
	}
	identity.RendererSHA256 = digest(raw)
	return identity, nil
}
