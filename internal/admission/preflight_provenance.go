package admission

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
)

//go:embed model.go store.go validate.go preflight.go preflight_provenance.go lock_unix.go lock_other.go
var admissionSources embed.FS

type PreflightProvenance struct {
	Schema        string                     `json:"schema"`
	Machine       machinerules.Provenance    `json:"machine"`
	Completion    completion.Bindings        `json:"completion"`
	Producer      artifactpreflight.Identity `json:"producer"`
	HostSHA256    string                     `json:"host_sha256"`
	DecoderSHA256 string                     `json:"decoder_sha256"`
	AuditSHA256   string                     `json:"audit_sha256"`
	GoVersion     string                     `json:"go_version"`
	GOOS          string                     `json:"goos"`
	GOARCH        string                     `json:"goarch"`
}

func hostSourceIdentity() string {
	names := []string{"model.go", "store.go", "validate.go", "preflight.go", "preflight_provenance.go", "lock_unix.go", "lock_other.go"}
	files := map[string]string{}
	for _, name := range names {
		raw, err := admissionSources.ReadFile(name)
		if err != nil {
			return ""
		}
		sum := sha256.Sum256(raw)
		files[name] = hex.EncodeToString(sum[:])
	}
	raw, _ := json.Marshal(struct {
		Domain string            `json:"domain"`
		Files  map[string]string `json:"files"`
	}{"policy-studio/admission-host-source/v2", files})
	return digest(raw)
}

func currentOperationAudit() OperationAudit {
	approval := machinerules.ToolEffects{MutatesTarget: true, MutatesSession: true, WritesFilesystem: true, Idempotent: true}
	control := machinerules.ToolEffects{MutatesSession: true, WritesFilesystem: true, Idempotent: true}
	audit := OperationAudit{Schema: "policy-studio/local-admission-effect-audit/v1", ReadsArtifact: true, Approval: approval, ControlPlane: control}
	raw, _ := json.Marshal(struct {
		Audit      OperationAudit `json:"audit"`
		HostSHA256 string         `json:"host_sha256"`
	}{audit, hostSourceIdentity()})
	audit.Identity = digest(raw)
	return audit
}

func currentPreflightProvenance() (PreflightProvenance, error) {
	machine, err := machinerules.Bindings()
	if err != nil {
		return PreflightProvenance{}, failure(Unavailable, "compiled machine-rule bindings unavailable")
	}
	probePolicy := completion.Policy{Schema: completion.PolicySchema, PolicyID: "artifact-gate-source-probe", Revision: 1, RequiredClaims: []string{"source"}}
	raw, _ := json.Marshal(probePolicy)
	probe, err := completion.Evaluate(probePolicy, completion.Input{Schema: completion.InputSchema, RequestID: "source-probe", Records: []completion.Record{}}, digest(raw))
	if err != nil {
		return PreflightProvenance{}, failure(Unavailable, "compiled completion bindings unavailable")
	}
	return PreflightProvenance{Schema: "policy-studio/artifact-admission-code/v1", Machine: machine, Completion: probe.Bindings, Producer: artifactpreflight.SourceIdentity(), HostSHA256: hostSourceIdentity(), DecoderSHA256: jsoninput.SourceIdentity(), AuditSHA256: currentOperationAudit().Identity, GoVersion: runtime.Version(), GOOS: runtime.GOOS, GOARCH: runtime.GOARCH}, nil
}
