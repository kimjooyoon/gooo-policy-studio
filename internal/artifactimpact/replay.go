package artifactimpact

import (
	"encoding/json"
	"errors"
	"reflect"
	"strings"
	"time"

	"github.com/kimjooyoon/gooo-policy-studio/internal/admission"
	"github.com/kimjooyoon/gooo-policy-studio/internal/artifactpreflight"
	"github.com/kimjooyoon/gooo-policy-studio/internal/completion"
	"github.com/kimjooyoon/gooo-policy-studio/internal/jsoninput"
	"github.com/kimjooyoon/gooo-policy-studio/internal/machinerules"
	"github.com/kimjooyoon/gooo-policy-studio/internal/policy"
)

var (
	errReplayInvalid = errors.New("historical comparison is inconsistent")
	errReplaySource  = errors.New("replay source is unavailable")
)

// Replay checks the complete retained historical comparison against current
// compiled rules, using its original evidence time. It performs no artifact or
// input path IO. A coherently rewritten unsigned report can remain consistent:
// success is neither authenticity nor permission to perform a current action.
func Replay(saved Report) (Report, error) {
	// A strict round trip also rejects malformed typed strings and nil required
	// arrays, and yields an independent copy of every nested caller-owned slice.
	raw, err := json.Marshal(saved)
	if err != nil || len(raw) > MaxReportBytes {
		return Report{}, errReplayInvalid
	}
	var owned Report
	if jsoninput.Decode(raw, &owned, MaxReportBytes) != nil || !reflect.DeepEqual(saved, owned) {
		return Report{}, errReplayInvalid
	}
	if owned.Schema != ReportSchema || owned.Scope != Scope || !owned.Simulation || owned.AuthenticatedServerState || owned.Committed || owned.TargetEffectsExecuted || owned.ObservationUnix <= 0 {
		return Report{}, errReplayInvalid
	}
	id := owned.ID
	owned.ID = ""
	expectedID := canonicalDigest(owned)
	owned.ID = id
	if !replayDigest(id) || id != expectedID {
		return Report{}, errReplayInvalid
	}
	current, err := SourceIdentity()
	if err != nil {
		return Report{}, errReplaySource
	}
	if !reflect.DeepEqual(owned.Implementation, current) {
		return Report{}, errReplayInvalid
	}
	p, err := replayConfiguration(owned, current)
	if err != nil {
		return Report{}, err
	}
	createdAt, err := time.Parse(time.RFC3339Nano, owned.BaseReceipt.CreatedAt)
	if err != nil || !strings.HasSuffix(owned.BaseReceipt.CreatedAt, "Z") || createdAt.Format(time.RFC3339Nano) != owned.BaseReceipt.CreatedAt {
		return Report{}, errReplayInvalid
	}
	if owned.BaseReceipt.Input != baseInput(p.caseInput) || owned.BaseReceipt.SourceDigest != current.Base.SourceDigest || owned.BaseReceipt.GeneratedDigest != current.Base.GeneratedDigest || owned.BaseReceipt.CompilerSource != current.Base.CompilerSource {
		return Report{}, errReplayInvalid
	}
	base, err := policy.Replay(owned.BaseReceipt)
	if err != nil || base.Result != owned.BaseReceipt.Result || owned.BaseReceipt.Result.Before != owned.BaseReceipt.Result.After || owned.BaseReceipt.Result.Change != (policy.Change{Direction: "UNCHANGED"}) {
		return Report{}, errReplayInvalid
	}
	p.base = owned.BaseReceipt
	p.permission = Permission{Eligible: true, Reason: "PROPOSED_PERMISSION_ELIGIBLE", ModeledHTTPStatus: 200}
	if !p.caseInput.Principal.Enabled {
		p.permission = Permission{Reason: "PROPOSED_PRINCIPAL_DISABLED", ModeledHTTPStatus: 401}
	} else if !p.caseInput.Principal.CanExecute {
		p.permission = Permission{Reason: "PROPOSED_EXECUTION_FORBIDDEN", ModeledHTTPStatus: 403}
	}
	if owned.Permission != p.permission || !sameRetainedCapture(owned.Before.Producer, owned.After.Producer, owned.ObservationUnix, p.caseInput.Artifact.ExpectedSHA256) {
		return Report{}, errReplayInvalid
	}
	readAttempts := 0
	if p.permission.Eligible && p.base.Result.After.Approved {
		readAttempts = 1
	}
	if (readAttempts == 0) != (owned.Before.Producer.AcquisitionStatus == artifactpreflight.Skipped) {
		return Report{}, errReplayInvalid
	}
	audit := ComparisonAudit{Schema: "policy-studio/artifact-impact-audit/v1", ArtifactReadAttempts: readAttempts, AcquisitionStatus: owned.Before.Producer.AcquisitionStatus, InputFilesRead: 3, PrivateReportReserved: true, PrivateReportWritePlanned: true, Effects: machinerules.ToolEffects{WritesFilesystem: true}}
	if owned.Audit != audit {
		return Report{}, errReplayInvalid
	}
	before, err := replaySide(p, p.before, "before", owned.Before.Producer, owned.ObservationUnix)
	if err != nil {
		return Report{}, errReplayInvalid
	}
	after, err := replaySide(p, p.after, "after", owned.After.Producer, owned.ObservationUnix)
	if err != nil {
		return Report{}, errReplayInvalid
	}
	if !reflect.DeepEqual(before, owned.Before) || !reflect.DeepEqual(after, owned.After) || !reflect.DeepEqual(delta(before, after), owned.Delta) {
		return Report{}, errReplayInvalid
	}
	return owned, nil
}

func replayDigest(s string) bool {
	if len(s) != 71 || !strings.HasPrefix(s, "sha256:") {
		return false
	}
	for _, c := range s[7:] {
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
			return false
		}
	}
	return true
}

func replayConfiguration(saved Report, current Identity) (prepared, error) {
	b, a := saved.Before.Context, saved.After.Context
	p := prepared{caseInput: b.Case, before: b.Policy, after: a.Policy, inputs: saved.Inputs, source: current}
	if b.Domain != "policy-studio/artifact-impact-simulation-context/v1" || a.Domain != b.Domain || b.Side != "before" || a.Side != "after" || b.Case != a.Case || b.Inputs != saved.Inputs || a.Inputs != saved.Inputs || !reflect.DeepEqual(b.Implementation, current) || !reflect.DeepEqual(a.Implementation, current) {
		return prepared{}, errReplayInvalid
	}
	if !validateCase(p.caseInput) || !validatePolicy(p.before) || !validatePolicy(p.after) || p.before.Recipe.MaxBytes != p.after.Recipe.MaxBytes || p.before.RequiredAuthority != p.after.RequiredAuthority || p.before.MaxAgeSeconds != p.after.MaxAgeSeconds || p.before.ControlPlaneBudget != p.after.ControlPlaneBudget {
		return prepared{}, errReplayInvalid
	}
	control, err := machinerules.EvaluateEffects(controlFacts(), p.before.ControlPlaneBudget)
	if err != nil || !control.Admissible {
		return prepared{}, errReplayInvalid
	}
	for _, binding := range []InputBinding{saved.Inputs.Case, saved.Inputs.Before, saved.Inputs.After} {
		if !replayDigest(binding.RawSHA256) || !replayDigest(binding.SemanticSHA256) {
			return prepared{}, errReplayInvalid
		}
	}
	// Raw input JSON is absent from this historical format. Its raw hashes can
	// only be shape/cross-context checked; typed semantic hashes are recomputed.
	if saved.Inputs.Case.SemanticSHA256 != canonicalDigest(p.caseInput) || saved.Inputs.Before.SemanticSHA256 != canonicalDigest(p.before) || saved.Inputs.After.SemanticSHA256 != canonicalDigest(p.after) {
		return prepared{}, errReplayInvalid
	}
	return p, nil
}

func sameRetainedCapture(b, a artifactpreflight.Report, at int64, expectedSHA string) bool {
	return b.ArtifactBase64 == a.ArtifactBase64 && b.AcquisitionStatus == a.AcquisitionStatus && b.ObservedSize == a.ObservedSize && b.ActualSHA256 == a.ActualSHA256 && b.ByteCount == a.ByteCount && b.ObservationUnix == at && a.ObservationUnix == at && b.ExpectedSHA256 == expectedSHA && a.ExpectedSHA256 == expectedSHA
}

// The retained-byte boundary differs from first acquisition. This native-stage
// reconstruction deliberately leaves the eight legacy comparison sources
// unchanged; full comparison/replay parity tests guard this small host glue.
func replaySide(p prepared, selected admission.ArtifactPolicy, name string, saved artifactpreflight.Report, at int64) (Side, error) {
	context := Context{Domain: "policy-studio/artifact-impact-simulation-context/v1", Side: name, Case: p.caseInput, Inputs: p.inputs, Policy: selected, Implementation: p.source}
	binding := canonicalDigest(context)
	version := canonicalDigest(struct {
		Domain         string                   `json:"domain"`
		Policy         admission.ArtifactPolicy `json:"policy"`
		Case           Case                     `json:"case"`
		Implementation Identity                 `json:"implementation"`
	}{"policy-studio/artifact-impact-simulation-policy/v1", selected, p.caseInput, p.source})
	observed, err := artifactpreflight.Replay(selected.Recipe, p.caseInput.Artifact.ExpectedSHA256, binding, saved)
	if err != nil {
		return Side{}, errReplayInvalid
	}
	side := Side{Context: context, ContextSHA256: binding, SimulationPolicyVersion: version, Producer: observed, Evidence: make([]admission.EvidenceObservation, 0, len(observed.Observations))}
	records := make([]completion.Record, 0, len(observed.Observations))
	var admissible int64
	for _, o := range observed.Observations {
		facts := machinerules.EvidenceFacts{ActualAuthority: "live-observation", RequiredAuthority: selected.RequiredAuthority, Status: o.Status, Confidence: "observed", ProviderVerified: true, ObservedBinding: observed.ContextDigest, RequiredBinding: binding, ObservedArtifact: observed.ActualSHA256, RequiredArtifact: p.caseInput.Artifact.ExpectedSHA256, ObservedPolicy: version, RequiredPolicy: version, ObservedAtUnix: at, NowUnix: at, MaxAgeSeconds: selected.MaxAgeSeconds, ExpiresAtUnix: p.caseInput.Artifact.DeadlineUnix}
		decision, err := machinerules.EvaluateEvidence(facts)
		if err != nil {
			return Side{}, errReplayInvalid
		}
		side.Evidence = append(side.Evidence, admission.EvidenceObservation{ClaimID: o.ClaimID, Facts: facts, Decision: decision})
		if decision.Admissible {
			admissible++
		}
		records = append(records, completion.Record{ClaimID: o.ClaimID, Status: o.Status, EvidenceIDs: []string{o.EvidenceID}})
	}
	cp := completionPolicy(selected)
	side.Completion, err = completion.Evaluate(cp, completion.Input{Schema: completion.InputSchema, RequestID: "req_" + strings.TrimPrefix(binding, "sha256:"), Records: records}, canonicalDigest(cp))
	if err != nil {
		return Side{}, errReplayInvalid
	}
	side.ProposedApproval = EffectEvaluation{Facts: approvalFacts(), Budget: selected.ApprovalBudget}
	side.ProposedApproval.Decision, err = machinerules.EvaluateEffects(side.ProposedApproval.Facts, selected.ApprovalBudget)
	if err != nil {
		return Side{}, errReplayInvalid
	}
	side.ProposedControlPlane = EffectEvaluation{Facts: controlFacts(), Budget: selected.ControlPlaneBudget}
	side.ProposedControlPlane.Decision, err = machinerules.EvaluateEffects(side.ProposedControlPlane.Facts, selected.ControlPlaneBudget)
	if err != nil {
		return Side{}, errReplayInvalid
	}
	side.AdmissionFacts = machinerules.AdmissionFacts{ProvenanceOK: true, BasePolicyApproved: p.base.Result.After.Approved, RequiredCount: int64(len(selected.Recipe.Claims)), ObservedCount: int64(len(observed.Observations)), AdmissibleEvidenceCount: admissible, CompletionReady: side.Completion.Readiness.Ready, ApprovalEffectAdmissible: side.ProposedApproval.Decision.Admissible, ControlPlaneEffectAdmissible: side.ProposedControlPlane.Decision.Admissible}
	side.Decision, err = machinerules.EvaluateAdmission(side.AdmissionFacts)
	if err != nil {
		return Side{}, errReplayInvalid
	}
	side.WouldAdmit = p.permission.Eligible && side.Decision.Admitted
	side.Reason = side.Decision.Reason
	if !p.permission.Eligible {
		side.Reason = p.permission.Reason
	}
	return side, nil
}
