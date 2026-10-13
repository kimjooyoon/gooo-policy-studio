package artifactimpact

import (
	"encoding/json"
	"strings"
	"time"

	"github.com/kimjooyoon/gooo-policy-studio/internal/admission"
	"github.com/kimjooyoon/gooo-policy-studio/internal/artifactpreflight"
	"github.com/kimjooyoon/gooo-policy-studio/internal/completion"
	"github.com/kimjooyoon/gooo-policy-studio/internal/machinerules"
)

type dependencies struct {
	readArtifact func(artifactpreflight.Requirement, int64) (artifactpreflight.Acquisition, error)
	now          func() time.Time
}

// CompareFiles has no caller clock, acquisition status, pass flag, token or
// report inputs. The only acquisition is the existing guarded file reader.
func CompareFiles(paths Paths) (Summary, int) {
	return compareFiles(paths, dependencies{artifactpreflight.ReadArtifact, time.Now})
}

func compareFiles(paths Paths, deps dependencies) (Summary, int) {
	p, code := prepare(paths)
	if code != "" {
		return Failure(code), 2
	}
	output, err := createPrivateAgainst(paths.Report, paths.Case, paths.Before, paths.After, p.caseInput.Artifact.Path)
	if err != nil {
		return Failure("REPORT_FILE_UNAVAILABLE"), 2
	}
	defer output.Close()
	var acquired artifactpreflight.Acquisition
	readAttempts := 0
	if p.permission.Eligible && p.base.Result.After.Approved {
		readAttempts = 1
		acquired, err = deps.readArtifact(requirement(p.caseInput), p.before.Recipe.MaxBytes)
	} else {
		acquired, err = artifactpreflight.SkipArtifact(requirement(p.caseInput), p.before.Recipe.MaxBytes)
	}
	if err != nil {
		return Failure("ACQUISITION_SOURCE_INVALID"), 2
	}
	observationUnix := deps.now().Unix()
	if observationUnix <= 0 {
		return Failure("HOST_CLOCK_INVALID"), 2
	}
	before, err := evaluateSide(p, p.before, "before", acquired, observationUnix)
	if err != nil {
		return Failure("HOST_UNAVAILABLE"), 2
	}
	after, err := evaluateSide(p, p.after, "after", acquired, observationUnix)
	if err != nil {
		return Failure("HOST_UNAVAILABLE"), 2
	}
	report := Report{Schema: ReportSchema, Simulation: true, ObservationUnix: observationUnix, Inputs: p.inputs, Implementation: p.source, Permission: p.permission, BaseReceipt: p.base, Before: before, After: after, Delta: delta(before, after), Scope: Scope,
		Audit: ComparisonAudit{Schema: "policy-studio/artifact-impact-audit/v1", ArtifactReadAttempts: readAttempts, AcquisitionStatus: acquired.Status(), InputFilesRead: 3, PrivateReportReserved: true, PrivateReportWritePlanned: true, Effects: machinerules.ToolEffects{WritesFilesystem: true}}}
	report.ID = canonicalDigest(report)
	raw, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		return Failure("HOST_UNAVAILABLE"), 2
	}
	raw = append(raw, '\n')
	if len(raw) > MaxReportBytes {
		return Failure("REPORT_TOO_LARGE"), 2
	}
	if err = output.WriteAndSync(raw); err != nil {
		return Failure("REPORT_WRITE_FAILED"), 2
	}
	if err = output.Close(); err != nil {
		return Failure("REPORT_WRITE_FAILED"), 2
	}
	return Summary{Schema: SummarySchema, Status: "compared", Code: "COMPARISON_SAVED", Simulation: true, ReportSaved: true, Direction: report.Delta.Direction,
		Before: SideSummary{before.WouldAdmit, before.Reason, before.Completion.Summary.Counts()}, After: SideSummary{after.WouldAdmit, after.Reason, after.Completion.Summary.Counts()}, AddedClaims: len(report.Delta.Added), RemovedClaims: len(report.Delta.Removed), ChangedClaims: len(report.Delta.Changed), ClaimOrderChanged: report.Delta.ClaimOrderChanged, RecipeConfigurationChanged: report.Delta.RecipeConfigurationChanged, ApprovalBudgetChanged: report.Delta.ApprovalBudgetChanged, ApprovalChecksChanged: report.Delta.ApprovalChecksChanged}, 0
}

func evaluateSide(p prepared, selected admission.ArtifactPolicy, name string, a artifactpreflight.Acquisition, observationUnix int64) (Side, error) {
	context := Context{Domain: "policy-studio/artifact-impact-simulation-context/v1", Side: name, Case: p.caseInput, Inputs: p.inputs, Policy: selected, Implementation: p.source}
	binding := canonicalDigest(context)
	version := canonicalDigest(struct {
		Domain         string                   `json:"domain"`
		Policy         admission.ArtifactPolicy `json:"policy"`
		Case           Case                     `json:"case"`
		Implementation Identity                 `json:"implementation"`
	}{"policy-studio/artifact-impact-simulation-policy/v1", selected, p.caseInput, p.source})
	producer, err := artifactpreflight.New(selected.Recipe)
	if err != nil {
		return Side{}, err
	}
	observed, err := producer.Observe(a, p.caseInput.Artifact.ExpectedSHA256, binding, observationUnix)
	if err != nil {
		return Side{}, err
	}
	side := Side{Context: context, ContextSHA256: binding, SimulationPolicyVersion: version, Producer: observed, Evidence: make([]admission.EvidenceObservation, 0, len(observed.Observations))}
	records := make([]completion.Record, 0, len(observed.Observations))
	var admissible int64
	for _, o := range observed.Observations {
		facts := machinerules.EvidenceFacts{ActualAuthority: "live-observation", RequiredAuthority: selected.RequiredAuthority, Status: o.Status, Confidence: "observed", ProviderVerified: true,
			ObservedBinding: observed.ContextDigest, RequiredBinding: binding, ObservedArtifact: observed.ActualSHA256, RequiredArtifact: p.caseInput.Artifact.ExpectedSHA256, ObservedPolicy: version, RequiredPolicy: version,
			ObservedAtUnix: observationUnix, NowUnix: observationUnix, MaxAgeSeconds: selected.MaxAgeSeconds, ExpiresAtUnix: p.caseInput.Artifact.DeadlineUnix}
		decision, err := machinerules.EvaluateEvidence(facts)
		if err != nil {
			return Side{}, err
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
		return Side{}, err
	}
	side.ProposedApproval = EffectEvaluation{Facts: approvalFacts(), Budget: selected.ApprovalBudget}
	side.ProposedApproval.Decision, err = machinerules.EvaluateEffects(side.ProposedApproval.Facts, selected.ApprovalBudget)
	if err != nil {
		return Side{}, err
	}
	side.ProposedControlPlane = EffectEvaluation{Facts: controlFacts(), Budget: selected.ControlPlaneBudget}
	side.ProposedControlPlane.Decision, err = machinerules.EvaluateEffects(side.ProposedControlPlane.Facts, selected.ControlPlaneBudget)
	if err != nil {
		return Side{}, err
	}
	// SourceIdentity checked actual embedded rule and adapter consistency before
	// reservation. No input can choose this provenance observation.
	side.AdmissionFacts = machinerules.AdmissionFacts{ProvenanceOK: true, BasePolicyApproved: p.base.Result.After.Approved, RequiredCount: int64(len(selected.Recipe.Claims)), ObservedCount: int64(len(observed.Observations)), AdmissibleEvidenceCount: admissible, CompletionReady: side.Completion.Readiness.Ready, ApprovalEffectAdmissible: side.ProposedApproval.Decision.Admissible, ControlPlaneEffectAdmissible: side.ProposedControlPlane.Decision.Admissible}
	side.Decision, err = machinerules.EvaluateAdmission(side.AdmissionFacts)
	if err != nil {
		return Side{}, err
	}
	side.WouldAdmit = p.permission.Eligible && side.Decision.Admitted
	side.Reason = side.Decision.Reason
	if !p.permission.Eligible {
		side.Reason = p.permission.Reason
	}
	return side, nil
}
