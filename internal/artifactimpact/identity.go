package artifactimpact

import (
	"crypto/sha256"
	"embed"
	"encoding/hex"
	"encoding/json"
	"runtime"

	"github.com/kimjooyoon/gooo-policy-studio/internal/artifactpreflight"
	"github.com/kimjooyoon/gooo-policy-studio/internal/completion"
	"github.com/kimjooyoon/gooo-policy-studio/internal/jsoninput"
	"github.com/kimjooyoon/gooo-policy-studio/internal/machinerules"
	"github.com/kimjooyoon/gooo-policy-studio/internal/policy"
)

//go:embed model.go compare.go validate.go delta.go identity.go files.go files_unix.go files_other.go
var hostSource embed.FS

type HostBinding struct {
	Path   string `json:"path"`
	SHA256 string `json:"sha256"`
}
type Identity struct {
	Schema          string                     `json:"schema"`
	HostSources     []HostBinding              `json:"host_sources"`
	HostSHA256      string                     `json:"host_sha256"`
	JSONInputSHA256 string                     `json:"json_input_sha256"`
	Producer        artifactpreflight.Identity `json:"producer"`
	Base            policy.BatchProvenance     `json:"base"`
	Completion      completion.Bindings        `json:"completion"`
	MachineRules    machinerules.Provenance    `json:"machine_rules"`
	GoVersion       string                     `json:"go_version"`
	GOOS            string                     `json:"goos"`
	GOARCH          string                     `json:"goarch"`
}

func digest(raw []byte) string {
	sum := sha256.Sum256(raw)
	return "sha256:" + hex.EncodeToString(sum[:])
}
func canonicalDigest(value any) string { raw, _ := json.Marshal(value); return digest(raw) }

// SourceIdentity binds actual embedded host and compiled rule sources. This
// consistency record does not authenticate the operator or an artifact issuer.
func SourceIdentity() (Identity, error) {
	producer, err := artifactpreflight.CheckedSourceIdentity()
	if err != nil {
		return Identity{}, err
	}
	identity := Identity{Schema: "policy-studio/artifact-impact-source/v1", HostSources: make([]HostBinding, 0, 8), JSONInputSHA256: jsoninput.SourceIdentity(), Producer: producer, GoVersion: runtime.Version(), GOOS: runtime.GOOS, GOARCH: runtime.GOARCH}
	for _, name := range []string{"model.go", "compare.go", "validate.go", "delta.go", "identity.go", "files.go", "files_unix.go", "files_other.go"} {
		raw, err := hostSource.ReadFile(name)
		if err != nil {
			return Identity{}, err
		}
		identity.HostSources = append(identity.HostSources, HostBinding{name, digest(raw)})
	}
	identity.HostSHA256 = canonicalDigest(identity.HostSources)
	rules := policy.Rules{Limit: 0, SameTeam: true, ActiveReviewer: true, PreventSelf: true}
	request := policy.Request{Key: "impact-source-probe", Requester: "requester", Team: "team", Submitted: true}
	reviewer := policy.Reviewer{Key: "reviewer", Team: "team", Active: true}
	receipt, err := policy.Simulate(policy.Input{Request: request, Reviewer: reviewer, Before: rules, After: rules})
	if err != nil {
		return Identity{}, err
	}
	batch, err := policy.SimulateBatch(policy.BatchInput{Schema: policy.BatchInputSchema, Label: "artifact impact source consistency", Before: rules, After: rules, Cases: []policy.Case{{ID: "source", Request: request, Reviewer: reviewer, ExpectedAfter: receipt.Result.After}}})
	if err != nil {
		return Identity{}, err
	}
	identity.Base = batch.Provenance
	probe := completion.Policy{Schema: completion.PolicySchema, PolicyID: "impact-source-probe", Revision: 1, RequiredClaims: []string{"source"}}
	completed, err := completion.Evaluate(probe, completion.Input{Schema: completion.InputSchema, RequestID: "impact-source-probe", Records: []completion.Record{}}, canonicalDigest(probe))
	if err != nil {
		return Identity{}, err
	}
	identity.Completion = completed.Bindings
	identity.MachineRules, err = machinerules.Bindings()
	if err != nil {
		return Identity{}, err
	}
	return identity, nil
}
