package admission

import (
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"time"

	"github.com/kimjooyoon/gooo-policy-studio/internal/artifactpreflight"
	"github.com/kimjooyoon/gooo-policy-studio/internal/completion"
	"github.com/kimjooyoon/gooo-policy-studio/internal/machinerules"
	"github.com/kimjooyoon/gooo-policy-studio/internal/policy"
)

const (
	BootstrapSchemaV2     = "policy-studio/admission-bootstrap/v2"
	snapshotSchemaV2      = "policy-studio/admission-snapshot/v2"
	OutcomeSchemaV2       = "policy-studio/admission-outcome/v2"
	ViewSchemaV2          = "policy-studio/admission-view/v2"
	ArtifactPolicySchema  = "policy-studio/artifact-admission-policy/v1"
	PreflightReportSchema = "policy-studio/artifact-admission-report/v1"
	maxSnapshotBytesV2    = 64 << 20
	OutcomeScopeV2        = "Authenticated artifact-bound local request admission. The trusted built-in producer checks retained bytes and operator claims; compiled Gooo decides evidence, completion, effects and admission without per-call human approval. Committed means one local pending-to-approved transition, never an external target action. Unsigned history does not authenticate administrator rewrites."
)

// ArtifactPolicy is administrative input only. Every recipe claim is required.
type ArtifactPolicy struct {
	Schema             string                    `json:"schema"`
	ID                 string                    `json:"id"`
	Revision           int64                     `json:"revision"`
	Recipe             artifactpreflight.Recipe  `json:"recipe"`
	RequiredAuthority  string                    `json:"required_authority"`
	MaxAgeSeconds      int64                     `json:"max_age_seconds"`
	ApprovalBudget     machinerules.EffectBudget `json:"approval_budget"`
	ControlPlaneBudget machinerules.EffectBudget `json:"control_plane_budget"`
}

type ArtifactRequirement struct {
	RequestID      string `json:"request_id"`
	Path           string `json:"path"`
	ExpectedSHA256 string `json:"expected_sha256"`
	DeadlineUnix   int64  `json:"deadline_unix"`
}

type ExecutionContext struct {
	Domain         string              `json:"domain"`
	Command        Command             `json:"command"`
	Request        RequestState        `json:"request"`
	Principal      PrincipalView       `json:"principal"`
	PolicyVersion  string              `json:"policy_version"`
	Artifact       ArtifactRequirement `json:"artifact"`
	Implementation PreflightProvenance `json:"implementation"`
}

type EvidenceObservation struct {
	ClaimID  string                        `json:"claim_id"`
	Facts    machinerules.EvidenceFacts    `json:"facts"`
	Decision machinerules.EvidenceDecision `json:"decision"`
}

type OperationAudit struct {
	Schema        string                   `json:"schema"`
	ReadsArtifact bool                     `json:"reads_artifact"`
	Approval      machinerules.ToolEffects `json:"approval"`
	ControlPlane  machinerules.ToolEffects `json:"control_plane"`
	Identity      string                   `json:"identity"`
}

type PreflightReport struct {
	Schema              string                         `json:"schema"`
	Context             ExecutionContext               `json:"context"`
	ContextSHA256       string                         `json:"context_sha256"`
	DecisionUnix        int64                          `json:"decision_unix"`
	Producer            artifactpreflight.Report       `json:"producer"`
	Evidence            []EvidenceObservation          `json:"evidence"`
	Completion          completion.Report              `json:"completion"`
	Audit               OperationAudit                 `json:"audit"`
	ApprovalEffects     machinerules.EffectDecision    `json:"approval_effects"`
	ControlPlaneEffects machinerules.EffectDecision    `json:"control_plane_effects"`
	AdmissionFacts      machinerules.AdmissionFacts    `json:"admission_facts"`
	Decision            machinerules.AdmissionDecision `json:"decision"`
}

var errPrecommitExpired = errors.New("precommit artifact evidence expired")
var errClockRollback = errors.New("trusted clock moved backwards")

func operatorCompletionPolicy(p ArtifactPolicy) completion.Policy {
	claims := make([]string, len(p.Recipe.Claims))
	for i, c := range p.Recipe.Claims {
		claims[i] = c.ID
	}
	return completion.Policy{Schema: completion.PolicySchema, PolicyID: p.ID, Revision: p.Revision, RequiredClaims: claims}
}

func validateArtifactBootstrap(b Bootstrap) error {
	if b.Preflight == nil || len(b.Artifacts) != len(b.Requests) {
		return failure(InvalidInput, "v2 requires an operator preflight policy and one artifact requirement per request")
	}
	legacy := b
	legacy.Schema, legacy.Preflight, legacy.Artifacts = BootstrapSchema, nil, nil
	if err := ValidateBootstrap(legacy); err != nil {
		return err
	}
	p := b.Preflight
	if p.Schema != ArtifactPolicySchema || p.MaxAgeSeconds < 0 || p.MaxAgeSeconds > 86400 {
		return failure(InvalidInput, "invalid operator artifact policy or evidence age")
	}
	if _, err := artifactpreflight.New(p.Recipe); err != nil {
		return failure(InvalidInput, "unsupported or invalid built-in artifact recipe")
	}
	if err := completion.ValidatePolicy(operatorCompletionPolicy(*p)); err != nil {
		return failure(InvalidInput, "invalid required claim policy")
	}
	switch p.RequiredAuthority {
	case "unit", "integration", "protocol", "renderer", "packaged-process", "live-observation":
	default:
		return failure(InvalidInput, "built-in live observations cannot meet requested proof authority")
	}
	audit := currentOperationAudit()
	control, err := machinerules.EvaluateEffects(audit.ControlPlane, p.ControlPlaneBudget)
	if err != nil || !control.Admissible {
		return failure(InvalidInput, "control-plane budget must permit audited durable state and denial writes")
	}
	if _, err := currentPreflightProvenance(); err != nil {
		return err
	}
	requests := map[string]bool{}
	for _, r := range b.Requests {
		requests[r.Key] = true
	}
	seen := map[string]bool{}
	for _, a := range b.Artifacts {
		if !requests[a.RequestID] || seen[a.RequestID] || a.DeadlineUnix <= 0 || artifactpreflight.ValidateRequirement(artifactpreflight.Requirement{Path: a.Path, ExpectedSHA256: a.ExpectedSHA256}) != nil {
			return failure(InvalidInput, "invalid, duplicate or missing authoritative artifact requirement")
		}
		seen[a.RequestID] = true
	}
	return nil
}

func versionV2(saved snapshot) string {
	raw, _ := json.Marshal(struct {
		Domain         string                 `json:"domain"`
		Policy         policy.Rules           `json:"policy"`
		BaseCode       policy.BatchProvenance `json:"base_code"`
		Preflight      *ArtifactPolicy        `json:"preflight"`
		Artifacts      []ArtifactRequirement  `json:"artifacts"`
		Implementation *PreflightProvenance   `json:"implementation"`
	}{"policy-studio/artifact-policy-version/v2", saved.Policy, saved.Provenance, saved.Preflight, saved.Artifacts, saved.Implementation})
	return digest(raw)
}

func artifactFor(saved snapshot, requestID string) ArtifactRequirement {
	for _, a := range saved.Artifacts {
		if a.RequestID == requestID {
			return a
		}
	}
	return ArtifactRequirement{}
}

func executionContext(saved snapshot, r RequestState, p Principal, c Command) ExecutionContext {
	return ExecutionContext{"policy-studio/artifact-context/v1", c, r, PrincipalView{p.Key, p.Team, p.Active, p.Enabled, p.CanExecute}, saved.PolicyVersion, artifactFor(saved, r.Request.Key), *saved.Implementation}
}

func contextDigest(context ExecutionContext) string {
	raw, _ := json.Marshal(context)
	return digest(raw)
}

func evaluatePreflight(saved snapshot, context ExecutionContext, producer artifactpreflight.Report, decisionUnix int64, baseApproved bool) (PreflightReport, error) {
	p := *saved.Preflight
	binding := contextDigest(context)
	observed, err := artifactpreflight.Replay(p.Recipe, context.Artifact.ExpectedSHA256, binding, producer)
	if err != nil || !reflect.DeepEqual(observed, producer) {
		return PreflightReport{}, failure(Unavailable, "built-in producer report differs from retained bytes or current recipe")
	}
	report := PreflightReport{Schema: PreflightReportSchema, Context: context, ContextSHA256: binding, DecisionUnix: decisionUnix, Producer: observed, Evidence: make([]EvidenceObservation, 0, len(observed.Observations)), Audit: currentOperationAudit()}
	records := make([]completion.Record, 0, len(observed.Observations))
	var admittedEvidence int64
	for _, o := range observed.Observations {
		facts := machinerules.EvidenceFacts{ActualAuthority: "live-observation", RequiredAuthority: p.RequiredAuthority, Status: o.Status, Confidence: "observed", ProviderVerified: true, ObservedBinding: observed.ContextDigest, RequiredBinding: binding, ObservedArtifact: observed.ActualSHA256, RequiredArtifact: context.Artifact.ExpectedSHA256, ObservedPolicy: saved.PolicyVersion, RequiredPolicy: saved.PolicyVersion, ObservedAtUnix: observed.ObservationUnix, NowUnix: decisionUnix, MaxAgeSeconds: p.MaxAgeSeconds, ExpiresAtUnix: context.Artifact.DeadlineUnix}
		result, err := machinerules.EvaluateEvidence(facts)
		if err != nil {
			return PreflightReport{}, failure(Unavailable, "compiled evidence execution unavailable")
		}
		report.Evidence = append(report.Evidence, EvidenceObservation{o.ClaimID, facts, result})
		if result.Admissible {
			admittedEvidence++
		}
		records = append(records, completion.Record{ClaimID: o.ClaimID, Status: o.Status, EvidenceIDs: []string{o.EvidenceID}})
	}
	completionPolicy := operatorCompletionPolicy(p)
	rawPolicy, _ := json.Marshal(completionPolicy)
	report.Completion, err = completion.Evaluate(completionPolicy, completion.Input{Schema: completion.InputSchema, RequestID: "req_" + strings.TrimPrefix(binding, "sha256:"), Records: records}, digest(rawPolicy))
	if err != nil {
		return PreflightReport{}, failure(Unavailable, "compiled claim completion unavailable")
	}
	report.ApprovalEffects, err = machinerules.EvaluateEffects(report.Audit.Approval, p.ApprovalBudget)
	if err != nil {
		return PreflightReport{}, failure(Unavailable, "compiled approval effect decision unavailable")
	}
	report.ControlPlaneEffects, err = machinerules.EvaluateEffects(report.Audit.ControlPlane, p.ControlPlaneBudget)
	if err != nil || !report.ControlPlaneEffects.Admissible {
		return PreflightReport{}, failure(Unavailable, "control-plane operation is outside the bound budget")
	}
	current, err := currentPreflightProvenance()
	if err != nil {
		return PreflightReport{}, err
	}
	report.AdmissionFacts = machinerules.AdmissionFacts{ProvenanceOK: reflect.DeepEqual(current, *saved.Implementation), BasePolicyApproved: baseApproved, RequiredCount: int64(len(p.Recipe.Claims)), ObservedCount: int64(len(observed.Observations)), AdmissibleEvidenceCount: admittedEvidence, CompletionReady: report.Completion.Readiness.Ready, ApprovalEffectAdmissible: report.ApprovalEffects.Admissible, ControlPlaneEffectAdmissible: report.ControlPlaneEffects.Admissible}
	report.Decision, err = machinerules.EvaluateAdmission(report.AdmissionFacts)
	if err != nil {
		return PreflightReport{}, failure(Unavailable, "compiled final admission unavailable")
	}
	return report, nil
}

func (s *Store) clockNow() time.Time {
	if s.now != nil {
		return s.now()
	}
	return time.Now()
}

func (s *Store) artifactByteLimit() int {
	if s.byteLimit > 0 && s.byteLimit < maxSnapshotBytesV2 {
		return s.byteLimit
	}
	return maxSnapshotBytesV2
}

// Only an approved operation uses this pre-rename check. The saved decision
// time remains the earlier sample. The unsigned history cannot prove the wall
// clock instant of rename; this process enforces that boundary while running.
func (s *Store) guardArtifactFreshness(report PreflightReport) error {
	now := s.clockNow().Unix()
	if now < report.DecisionUnix || now < report.Producer.ObservationUnix {
		return errClockRollback
	}
	for _, o := range report.Evidence {
		facts := o.Facts
		facts.NowUnix = now
		d, err := machinerules.EvaluateEvidence(facts)
		if err != nil {
			return err
		}
		if !d.Admissible {
			return errPrecommitExpired
		}
	}
	return nil
}

func (s *Store) admitArtifact(token string, c Command) (Result, error) {
	p, err := s.authenticate(token)
	if err != nil {
		return Result{}, err
	}
	if !p.CanExecute {
		return Result{}, failure(Forbidden, "machine principal has no execution permission")
	}
	if !validKey(c.IdempotencyKey) {
		return Result{}, failure(InvalidInput, "invalid idempotency key")
	}
	for _, out := range s.state.Outcomes {
		if out.PrincipalKey == p.Key && out.Command.IdempotencyKey == c.IdempotencyKey {
			if out.Command != c {
				return Result{}, failure(Conflict, "idempotency key is already bound to a different command")
			}
			result := Result{Replayed: true, Outcome: cloneValue(out)}
			if !out.Committed {
				return result, failure(PolicyDenied, "compiled Gooo artifact policy denied the server-owned request")
			}
			return result, nil
		}
	}
	if err := validateCommand(c); err != nil {
		return Result{}, err
	}
	if c.PolicyVersion != s.state.PolicyVersion {
		return Result{}, failure(Conflict, "policy version is stale")
	}
	index := -1
	for i, r := range s.state.Requests {
		if r.Request.Key == c.RequestID {
			index = i
			break
		}
	}
	if index < 0 {
		return Result{}, failure(Conflict, "server-owned request does not exist")
	}
	r := s.state.Requests[index]
	if r.Status != Pending || r.Revision != c.ExpectedRevision {
		return Result{}, failure(Conflict, "request revision or pending state is stale")
	}
	if len(s.state.Outcomes) >= MaxOutcomes {
		return Result{}, failure(Unavailable, "durable outcome capacity is exhausted; no outcome is evicted")
	}
	receipt, err := policy.Simulate(policy.Input{Request: r.Request, Reviewer: policy.Reviewer{Key: p.Key, Team: p.Team, Active: p.Active}, Before: s.state.Policy, After: s.state.Policy})
	if err != nil || receipt.SourceDigest != s.state.Provenance.SourceDigest || receipt.GeneratedDigest != s.state.Provenance.GeneratedDigest || receipt.CompilerSource != s.state.Provenance.CompilerSource {
		s.failed = true
		return Result{}, failure(Unavailable, "base policy execution differs from store binding")
	}
	context := executionContext(s.state, r, p, c)
	producer, err := artifactpreflight.New(s.state.Preflight.Recipe)
	if err != nil {
		s.failed = true
		return Result{}, failure(Unavailable, "configured producer is unavailable")
	}
	requirement := artifactpreflight.Requirement{Path: context.Artifact.Path, ExpectedSHA256: context.Artifact.ExpectedSHA256}
	var acquisition artifactpreflight.Acquisition
	if receipt.Result.After.Approved {
		acquisition, err = artifactpreflight.ReadArtifact(requirement, s.state.Preflight.Recipe.MaxBytes)
	} else {
		// Execution permission alone does not grant the contents of a request's
		// artifact. Keep every required result, but do not acquire those bytes
		// when the authoritative base policy already denies this principal.
		acquisition, err = artifactpreflight.SkipArtifact(requirement, s.state.Preflight.Recipe.MaxBytes)
	}
	if err != nil {
		return Result{}, failure(Unavailable, "authoritative artifact source configuration is invalid")
	}
	observed, err := producer.Observe(acquisition, context.Artifact.ExpectedSHA256, contextDigest(context), s.clockNow().Unix())
	if err != nil {
		s.failed = true
		return Result{}, failure(Unavailable, "built-in artifact observation unavailable")
	}
	decision, err := evaluatePreflight(s.state, context, observed, s.clockNow().Unix(), receipt.Result.After.Approved)
	if err != nil {
		s.failed = true
		return Result{}, err
	}
	if decision.DecisionUnix < 0 || decision.DecisionUnix < observed.ObservationUnix {
		return Result{}, failure(Unavailable, "trusted clock moved backwards during observation")
	}
	out := Outcome{Schema: OutcomeSchemaV2, Command: c, PrincipalKey: p.Key, PriorRevision: r.Revision, NewRevision: r.Revision, PolicyVersion: s.state.PolicyVersion, Receipt: receipt, Committed: decision.Decision.Admitted, CreatedAt: receipt.CreatedAt, Scope: OutcomeScopeV2, Preflight: &decision}
	prepare := func() (snapshot, error) {
		next := cloneSnapshot(s.state)
		out.NewRevision = r.Revision
		if out.Committed {
			out.NewRevision++
			next.Requests[index].Status = Approved
			next.Requests[index].Revision = out.NewRevision
		}
		out.ID = outcomeID(out)
		next.Outcomes = append(next.Outcomes, cloneValue(out))
		next.ID = snapshotID(next)
		raw, err := json.Marshal(next)
		if err != nil || len(raw) > s.artifactByteLimit() {
			return snapshot{}, failure(Unavailable, "v2 snapshot byte capacity is exhausted; prior history remains available")
		}
		return next, nil
	}
	next, err := prepare()
	if err != nil {
		return Result{}, err
	}
	operations := s.operations
	if out.Committed {
		operations.beforeRename = func() error { return s.guardArtifactFreshness(decision) }
	}
	err = persist(s.dir, next, operations)
	if errors.Is(err, errPrecommitExpired) {
		now := s.clockNow().Unix()
		if now < decision.DecisionUnix || now < observed.ObservationUnix {
			return Result{}, failure(Unavailable, "trusted clock moved backwards before denial")
		}
		decision, err = evaluatePreflight(s.state, context, observed, now, receipt.Result.After.Approved)
		if err != nil {
			s.failed = true
			return Result{}, err
		}
		if decision.Decision.Admitted {
			return Result{}, failure(Unavailable, "trusted clock no longer proves the expired interval")
		}
		out.Committed, out.Preflight = false, &decision
		next, err = prepare()
		if err != nil {
			return Result{}, err
		}
		operations.beforeRename = nil
		err = persist(s.dir, next, operations)
	}
	if errors.Is(err, errClockRollback) {
		return Result{}, failure(Unavailable, "trusted clock moved backwards before commit")
	}
	if err != nil {
		s.failed = true
		return Result{}, failure(Unavailable, "durable commit failed; restart, recover, and retry the same idempotency key")
	}
	s.state = next
	result := Result{Outcome: cloneValue(out)}
	if !out.Committed {
		return result, failure(PolicyDenied, "compiled Gooo artifact policy denied the server-owned request")
	}
	return result, nil
}

func validateArtifactSnapshot(saved snapshot, current policy.BatchProvenance) error {
	implementation, err := currentPreflightProvenance()
	if err != nil {
		return err
	}
	if saved.Preflight == nil || saved.Implementation == nil || saved.ID != snapshotID(saved) || saved.Provenance != current || !reflect.DeepEqual(implementation, *saved.Implementation) || saved.PolicyVersion != versionV2(saved) || len(saved.Outcomes) > MaxOutcomes {
		return failure(Unavailable, "v2 snapshot code, configuration or content binding differs")
	}
	if _, err := time.Parse(time.RFC3339Nano, saved.CreatedAt); err != nil {
		return failure(Unavailable, "v2 creation time invalid")
	}
	bootstrap := Bootstrap{Schema: BootstrapSchemaV2, Policy: saved.Policy, Principals: saved.Principals, Requests: make([]policy.Request, len(saved.Requests)), Preflight: saved.Preflight, Artifacts: saved.Artifacts}
	for i, r := range saved.Requests {
		bootstrap.Requests[i] = r.Request
	}
	if err := ValidateBootstrap(bootstrap); err != nil {
		return failure(Unavailable, "v2 saved configuration invalid")
	}
	principals := map[string]Principal{}
	for _, p := range saved.Principals {
		principals[p.Key] = p
	}
	requests := map[string]RequestState{}
	for _, r := range saved.Requests {
		requests[r.Request.Key] = RequestState{r.Request, Pending, 1}
	}
	seen := map[operationKey]bool{}
	for i, out := range saved.Outcomes {
		bad := func() error {
			return failure(Unavailable, fmt.Sprintf("outcomes[%d]: v2 observation, replay or state binding invalid", i))
		}
		p, exists := principals[out.PrincipalKey]
		r, requestExists := requests[out.Command.RequestID]
		key := operationKey{out.PrincipalKey, out.Command.IdempotencyKey}
		if !exists || !p.Enabled || !p.CanExecute || !requestExists || seen[key] || validateCommand(out.Command) != nil || out.Schema != OutcomeSchemaV2 || out.Scope != OutcomeScopeV2 || out.Preflight == nil || out.ID != outcomeID(out) || out.PolicyVersion != saved.PolicyVersion || out.Command.PolicyVersion != saved.PolicyVersion || out.PriorRevision != r.Revision || out.Command.ExpectedRevision != r.Revision || r.Status != Pending || out.CreatedAt != out.Receipt.CreatedAt {
			return bad()
		}
		if _, err := time.Parse(time.RFC3339Nano, out.CreatedAt); err != nil {
			return bad()
		}
		input := policy.Input{Request: r.Request, Reviewer: policy.Reviewer{Key: p.Key, Team: p.Team, Active: p.Active}, Before: saved.Policy, After: saved.Policy}
		if out.Receipt.Input != input || out.Receipt.SourceDigest != current.SourceDigest || out.Receipt.GeneratedDigest != current.GeneratedDigest || out.Receipt.CompilerSource != current.CompilerSource {
			return bad()
		}
		if !out.Receipt.Result.After.Approved && out.Preflight.Producer.AcquisitionStatus != artifactpreflight.Skipped {
			return bad()
		}
		if _, err := policy.Replay(out.Receipt); err != nil {
			return bad()
		}
		context := executionContext(saved, r, p, out.Command)
		if out.Preflight.DecisionUnix < 0 || out.Preflight.DecisionUnix < out.Preflight.Producer.ObservationUnix {
			return bad()
		}
		expected, err := evaluatePreflight(saved, context, out.Preflight.Producer, out.Preflight.DecisionUnix, out.Receipt.Result.After.Approved)
		if err != nil || !reflect.DeepEqual(expected, *out.Preflight) || out.Committed != expected.Decision.Admitted || out.Receipt.Result.Before != out.Receipt.Result.After || out.Receipt.Result.Change != (policy.Change{Direction: "UNCHANGED"}) {
			return bad()
		}
		if out.Committed {
			if out.NewRevision != r.Revision+1 {
				return bad()
			}
			r.Status, r.Revision = Approved, out.NewRevision
			requests[r.Request.Key] = r
		} else if out.NewRevision != r.Revision {
			return bad()
		}
		seen[key] = true
	}
	for _, r := range saved.Requests {
		if r != requests[r.Request.Key] {
			return failure(Unavailable, "v2 state differs from complete outcome history")
		}
	}
	return nil
}
