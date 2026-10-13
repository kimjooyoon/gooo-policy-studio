package artifactimpact

import (
	"encoding/json"
	"errors"
	"html/template"
)

var errExplanationRender = errors.New("explanation rendering failed")

// The view is an explicit presentation allowlist. No Report, Context, Policy,
// Producer report, raw bytes, filesystem path or input identity is passed to
// the template. JSON strings below contain only the declared typed stages.
type explanationView struct {
	ObservationUnix                                          int64
	Direction                                                string
	Permission                                               Permission
	BaseBeforeJSON, BaseAfterJSON, BaseChangeJSON, DeltaJSON string
	Before, After                                            explanationSide
	BeforeSummary, AfterSummary                              SideSummary
	ChangedClaims                                            []explanationChangedClaim
	RendererSchema, RendererSHA256                           string
	ReplaySHA256, ComparisonSHA256                           string
	Sources                                                  []HostBinding
}

type explanationSide struct {
	WouldAdmit                                         bool
	Reason                                             string
	AdmissionDecisionJSON, AdmissionFactsJSON          string
	AcquisitionStatus                                  string
	ProducerJSON                                       string
	CompletionSummaryJSON, CoverageJSON, ReadinessJSON string
	OrderedResults                                     []explanationResult
	Claims                                             []explanationClaim
	ApprovalJSON, ControlPlaneJSON                     string
}

type explanationResult struct {
	Claim, Status string
	StepJSON      string
}

type explanationClaim struct {
	Claim, Verifier, Field, Expected, Status, Actual, Reason string
	Required, EvidenceAdmissible                             bool
	EvidenceReason, EvidenceFactsJSON, EvidenceDecisionJSON  string
	NativeExecuted                                           bool
	NativeProofJSON                                          string
}

// Changed claims are joined by the IDs already selected by the verified delta.
// Copying their two observations does not infer a cause or a new predicate.
type explanationChangedClaim struct {
	Claim                                     string
	BeforeExpected, BeforeStatus              string
	AfterExpected, AfterStatus                string
	BeforeActual, AfterActual                 string
	BeforeReason, AfterReason                 string
	BeforeEvidenceReason, AfterEvidenceReason string
}

// explanationProducer deliberately omits all bytes and content/context hashes.
type explanationProducer struct {
	Schema            string `json:"schema"`
	ProducerID        string `json:"producer_id"`
	ArtifactSchema    string `json:"artifact_schema"`
	AcquisitionStatus string `json:"acquisition_status"`
	ByteCount         int64  `json:"byte_count"`
	ObservedSize      int64  `json:"observed_size"`
	DigestOK          bool   `json:"digest_ok"`
	SchemaOK          bool   `json:"schema_ok"`
	TypesOK           bool   `json:"types_ok"`
	ArtifactReason    string `json:"artifact_reason"`
}

type explanationBuffer struct {
	raw   []byte
	limit int64
}

func (b *explanationBuffer) Len() int      { return len(b.raw) }
func (b *explanationBuffer) Bytes() []byte { return b.raw }

func (b *explanationBuffer) Write(raw []byte) (int, error) {
	if int64(len(raw)) > b.limit-int64(b.Len()) {
		return 0, errExplanationRender
	}
	needed := len(b.raw) + len(raw)
	if needed > cap(b.raw) {
		capacity := cap(b.raw) * 2
		if capacity < 4096 {
			capacity = 4096
		}
		if capacity < needed {
			capacity = needed
		}
		if int64(capacity) > b.limit {
			capacity = int(b.limit)
		}
		grown := make([]byte, len(b.raw), capacity)
		copy(grown, b.raw)
		b.raw = grown
	}
	b.raw = append(b.raw, raw...)
	return len(raw), nil
}

// renderExplanation is given only the owned, fully replay-verified historical
// report. It performs presentation projection, never policy or numeric truth.
// The cap applies while template escaping writes, before output reservation.
func renderExplanation(verified Report, identity ExplainIdentity, limit int64) ([]byte, error) {
	if limit < 1 || limit > int64(MaxReportBytes) {
		return nil, errExplanationRender
	}
	view, err := explanationViewOf(verified, identity)
	if err != nil {
		return nil, errExplanationRender
	}
	raw, err := explanationSource.ReadFile("explain.html")
	if err != nil {
		return nil, errExplanationRender
	}
	page, err := template.New("explain.html").Parse(string(raw))
	if err != nil {
		return nil, errExplanationRender
	}
	buffer := &explanationBuffer{limit: limit}
	if page.Execute(buffer, view) != nil {
		return nil, errExplanationRender
	}
	return buffer.Bytes(), nil
}

func explanationJSON(value any) (string, error) {
	raw, err := json.MarshalIndent(value, "", "  ")
	if err != nil || len(raw) > MaxReportBytes {
		return "", errExplanationRender
	}
	return string(raw), nil
}

func explanationViewOf(verified Report, identity ExplainIdentity) (explanationView, error) {
	view := explanationView{ObservationUnix: verified.ObservationUnix, Direction: verified.Delta.Direction, Permission: verified.Permission,
		RendererSchema: identity.Schema, RendererSHA256: identity.RendererSHA256, ReplaySHA256: identity.Replay.VerifierSHA256,
		ComparisonSHA256: canonicalDigest(verified.Implementation), Sources: append([]HostBinding{}, identity.Sources...)}
	var err error
	for _, stage := range []struct {
		value  any
		target *string
	}{
		{verified.BaseReceipt.Result.Before, &view.BaseBeforeJSON}, {verified.BaseReceipt.Result.After, &view.BaseAfterJSON},
		{verified.BaseReceipt.Result.Change, &view.BaseChangeJSON}, {verified.Delta, &view.DeltaJSON},
	} {
		*stage.target, err = explanationJSON(stage.value)
		if err != nil {
			return explanationView{}, errExplanationRender
		}
	}
	view.Before, err = explanationSideOf(verified.Before)
	if err != nil {
		return explanationView{}, errExplanationRender
	}
	view.After, err = explanationSideOf(verified.After)
	if err != nil {
		return explanationView{}, errExplanationRender
	}
	view.BeforeSummary = SideSummary{WouldAdmit: verified.Before.WouldAdmit, Reason: verified.Before.Reason, Counts: verified.Before.Completion.Summary.Counts()}
	view.AfterSummary = SideSummary{WouldAdmit: verified.After.WouldAdmit, Reason: verified.After.Reason, Counts: verified.After.Completion.Summary.Counts()}
	beforeClaims, afterClaims := make(map[string]explanationClaim, len(view.Before.Claims)), make(map[string]explanationClaim, len(view.After.Claims))
	for _, claim := range view.Before.Claims {
		beforeClaims[claim.Claim] = claim
	}
	for _, claim := range view.After.Claims {
		afterClaims[claim.Claim] = claim
	}
	view.ChangedClaims = make([]explanationChangedClaim, 0, len(verified.Delta.Changed))
	for _, change := range verified.Delta.Changed {
		before, beforeExists := beforeClaims[change.ClaimID]
		after, afterExists := afterClaims[change.ClaimID]
		if !beforeExists || !afterExists {
			return explanationView{}, errExplanationRender
		}
		view.ChangedClaims = append(view.ChangedClaims, explanationChangedClaim{Claim: change.ClaimID,
			BeforeExpected: before.Expected, BeforeStatus: before.Status, AfterExpected: after.Expected, AfterStatus: after.Status,
			BeforeActual: before.Actual, AfterActual: after.Actual, BeforeReason: before.Reason, AfterReason: after.Reason,
			BeforeEvidenceReason: before.EvidenceReason, AfterEvidenceReason: after.EvidenceReason})
	}
	return view, nil
}

func explanationSideOf(side Side) (explanationSide, error) {
	view := explanationSide{WouldAdmit: side.WouldAdmit, Reason: side.Reason, AcquisitionStatus: string(side.Producer.AcquisitionStatus),
		OrderedResults: make([]explanationResult, 0, len(side.Completion.Input.Records)), Claims: make([]explanationClaim, 0, len(side.Context.Policy.Recipe.Claims))}
	producer := explanationProducer{Schema: side.Producer.Schema, ProducerID: side.Producer.ProducerID, ArtifactSchema: side.Context.Policy.Recipe.ArtifactSchema,
		AcquisitionStatus: string(side.Producer.AcquisitionStatus), ByteCount: side.Producer.ByteCount, ObservedSize: side.Producer.ObservedSize,
		DigestOK: side.Producer.DigestOK, SchemaOK: side.Producer.SchemaOK, TypesOK: side.Producer.TypesOK, ArtifactReason: side.Producer.ArtifactReason}
	var err error
	for _, stage := range []struct {
		value  any
		target *string
	}{
		{side.Decision, &view.AdmissionDecisionJSON}, {side.AdmissionFacts, &view.AdmissionFactsJSON}, {producer, &view.ProducerJSON},
		{side.Completion.Summary, &view.CompletionSummaryJSON}, {side.Completion.Coverage, &view.CoverageJSON}, {side.Completion.Readiness, &view.ReadinessJSON},
		{side.ProposedApproval, &view.ApprovalJSON}, {side.ProposedControlPlane, &view.ControlPlaneJSON},
	} {
		*stage.target, err = explanationJSON(stage.value)
		if err != nil {
			return explanationSide{}, errExplanationRender
		}
	}
	if len(side.Completion.Input.Records) != len(side.Completion.Steps) {
		return explanationSide{}, errExplanationRender
	}
	for i, result := range side.Completion.Input.Records {
		step, err := explanationJSON(side.Completion.Steps[i])
		if err != nil {
			return explanationSide{}, errExplanationRender
		}
		view.OrderedResults = append(view.OrderedResults, explanationResult{Claim: result.ClaimID, Status: result.Status, StepJSON: step})
	}
	if len(side.Context.Policy.Recipe.Claims) != len(side.Producer.Observations) || len(side.Producer.Observations) != len(side.Evidence) {
		return explanationSide{}, errExplanationRender
	}
	required := make(map[string]bool, len(side.Completion.Policy.RequiredClaims))
	for _, claim := range side.Completion.Policy.RequiredClaims {
		required[claim] = true
	}
	for i, claim := range side.Context.Policy.Recipe.Claims {
		observed, evidence := side.Producer.Observations[i], side.Evidence[i]
		if claim.ID != observed.ClaimID || claim.ID != evidence.ClaimID {
			return explanationSide{}, errExplanationRender
		}
		row := explanationClaim{Claim: claim.ID, Required: required[claim.ID], Verifier: observed.Verifier, Field: observed.Field, Expected: observed.Expected,
			Status: observed.Status, Actual: observed.Actual, Reason: observed.Reason, EvidenceAdmissible: evidence.Decision.Admissible, EvidenceReason: evidence.Decision.Reason,
			NativeExecuted: observed.NativeProof != nil}
		row.EvidenceFactsJSON, err = explanationJSON(evidence.Facts)
		if err != nil {
			return explanationSide{}, errExplanationRender
		}
		row.EvidenceDecisionJSON, err = explanationJSON(evidence.Decision)
		if err != nil {
			return explanationSide{}, errExplanationRender
		}
		if observed.NativeProof != nil {
			row.NativeProofJSON, err = explanationJSON(*observed.NativeProof)
			if err != nil {
				return explanationSide{}, errExplanationRender
			}
		}
		view.Claims = append(view.Claims, row)
	}
	return view, nil
}
