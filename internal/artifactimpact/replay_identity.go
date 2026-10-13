package artifactimpact

import "embed"

//go:embed replay.go replay_identity.go replay_files.go
var replaySource embed.FS

type ReplayIdentity struct {
	Schema         string        `json:"schema"`
	Sources        []HostBinding `json:"sources"`
	Comparison     Identity      `json:"comparison"`
	VerifierSHA256 string        `json:"verifier_sha256"`
}

// ReplaySourceIdentity identifies this verifier separately from the unchanged
// comparison producer. Neither identity authenticates unsigned history.
func ReplaySourceIdentity() (ReplayIdentity, error) {
	comparison, err := SourceIdentity()
	if err != nil {
		return ReplayIdentity{}, errReplaySource
	}
	identity := ReplayIdentity{Schema: "policy-studio/artifact-impact-replay-source/v1", Sources: make([]HostBinding, 0, 3), Comparison: comparison}
	for _, name := range []string{"replay.go", "replay_identity.go", "replay_files.go"} {
		raw, err := replaySource.ReadFile(name)
		if err != nil {
			return ReplayIdentity{}, errReplaySource
		}
		identity.Sources = append(identity.Sources, HostBinding{Path: name, SHA256: digest(raw)})
	}
	identity.VerifierSHA256 = canonicalDigest(identity)
	return identity, nil
}
