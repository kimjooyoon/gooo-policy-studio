// Package machinerules runs source-bound compiled Gooo projections. These APIs
// consume trusted host facts; they never authenticate facts supplied by a caller.
package machinerules

import (
	"encoding/json"
	"github.com/kimjooyoon/gooo-policy-studio/internal/machinerules/effects"
	"github.com/kimjooyoon/gooo-policy-studio/internal/machinerules/evidence"
	"github.com/kimjooyoon/gooo-policy-studio/internal/machinerules/final"
)

type EvidenceFacts struct {
	ActualAuthority   string `json:"actual_authority"`
	RequiredAuthority string `json:"required_authority"`
	Status            string `json:"status"`
	Confidence        string `json:"confidence"`
	ProviderVerified  bool   `json:"provider_verified"`
	ObservedBinding   string `json:"observed_binding"`
	RequiredBinding   string `json:"required_binding"`
	ObservedArtifact  string `json:"observed_artifact"`
	RequiredArtifact  string `json:"required_artifact"`
	ObservedPolicy    string `json:"observed_policy"`
	RequiredPolicy    string `json:"required_policy"`
	ObservedAtUnix    int64  `json:"observed_at_unix"`
	NowUnix           int64  `json:"now_unix"`
	MaxAgeSeconds     int64  `json:"max_age_seconds"`
	ExpiresAtUnix     int64  `json:"expires_at_unix"`
}
type EvidenceDecision struct {
	Admissible  bool   `json:"admissible"`
	Reason      string `json:"reason"`
	ProviderOK  bool   `json:"provider_ok"`
	EvidenceOK  bool   `json:"evidence_ok"`
	AuthorityOK bool   `json:"authority_ok"`
	BindingOK   bool   `json:"binding_ok"`
	ArtifactOK  bool   `json:"artifact_ok"`
	PolicyOK    bool   `json:"policy_ok"`
	FreshnessOK bool   `json:"freshness_ok"`
	DeadlineOK  bool   `json:"deadline_ok"`
}
type ToolEffects struct {
	MutatesTarget       bool `json:"mutatesTarget"`
	MutatesSession      bool `json:"mutatesSession"`
	WritesFilesystem    bool `json:"writesFilesystem"`
	LaunchesProcess     bool `json:"launchesProcess"`
	AccessesNetwork     bool `json:"accessesNetwork"`
	ChangesUIState      bool `json:"changesUiState"`
	MayDiscardData      bool `json:"mayDiscardData"`
	ExecutesForeignCode bool `json:"executesForeignCode"`
	MutatesDevice       bool `json:"mutatesDevice"`
	Idempotent          bool `json:"idempotent"`
}
type EffectBudget struct {
	AllowTarget       bool `json:"allow_target"`
	AllowSession      bool `json:"allow_session"`
	AllowFilesystem   bool `json:"allow_filesystem"`
	AllowProcess      bool `json:"allow_process"`
	AllowNetwork      bool `json:"allow_network"`
	AllowUI           bool `json:"allow_ui"`
	AllowDiscard      bool `json:"allow_discard"`
	AllowForeignCode  bool `json:"allow_foreign_code"`
	AllowDevice       bool `json:"allow_device"`
	RequireIdempotent bool `json:"require_idempotent"`
}
type EffectDecision struct {
	Admissible    bool   `json:"admissible"`
	Reason        string `json:"reason"`
	TargetOK      bool   `json:"target_ok"`
	SessionOK     bool   `json:"session_ok"`
	FilesystemOK  bool   `json:"filesystem_ok"`
	ProcessOK     bool   `json:"process_ok"`
	NetworkOK     bool   `json:"network_ok"`
	UIOK          bool   `json:"ui_ok"`
	DiscardOK     bool   `json:"discard_ok"`
	ForeignCodeOK bool   `json:"foreign_code_ok"`
	DeviceOK      bool   `json:"device_ok"`
	IdempotencyOK bool   `json:"idempotency_ok"`
}
type AdmissionFacts struct {
	ProvenanceOK                 bool  `json:"provenance_ok"`
	BasePolicyApproved           bool  `json:"base_policy_approved"`
	RequiredCount                int64 `json:"required_count"`
	ObservedCount                int64 `json:"observed_count"`
	AdmissibleEvidenceCount      int64 `json:"admissible_evidence_count"`
	CompletionReady              bool  `json:"completion_ready"`
	ApprovalEffectAdmissible     bool  `json:"approval_effect_admissible"`
	ControlPlaneEffectAdmissible bool  `json:"control_plane_effect_admissible"`
}
type AdmissionDecision struct {
	Admitted             bool   `json:"admitted"`
	Reason               string `json:"reason"`
	CountsOK             bool   `json:"counts_ok"`
	ProvenanceOK         bool   `json:"provenance_ok"`
	BasePolicyOK         bool   `json:"base_policy_ok"`
	EvidenceOK           bool   `json:"evidence_ok"`
	CompletionOK         bool   `json:"completion_ok"`
	ApprovalEffectOK     bool   `json:"approval_effect_ok"`
	ControlPlaneEffectOK bool   `json:"control_plane_effect_ok"`
}

func EvaluateEvidence(facts EvidenceFacts) (EvidenceDecision, error) {
	if _, err := Bindings(); err != nil {
		return EvidenceDecision{}, err
	}
	raw, err := json.Marshal(facts)
	if err != nil {
		return EvidenceDecision{}, err
	}
	out, err := evidence.Evaluate(raw)
	if err != nil {
		return EvidenceDecision{}, err
	}
	var decision EvidenceDecision
	err = json.Unmarshal(out, &decision)
	return decision, err
}
func EvaluateEffects(facts ToolEffects, budget EffectBudget) (EffectDecision, error) {
	if _, err := Bindings(); err != nil {
		return EffectDecision{}, err
	}
	a, err := json.Marshal(facts)
	if err != nil {
		return EffectDecision{}, err
	}
	b, err := json.Marshal(budget)
	if err != nil {
		return EffectDecision{}, err
	}
	out, err := effects.Evaluate(a, b)
	if err != nil {
		return EffectDecision{}, err
	}
	var decision EffectDecision
	err = json.Unmarshal(out, &decision)
	return decision, err
}
func EvaluateAdmission(facts AdmissionFacts) (AdmissionDecision, error) {
	if _, err := Bindings(); err != nil {
		return AdmissionDecision{}, err
	}
	raw, err := json.Marshal(facts)
	if err != nil {
		return AdmissionDecision{}, err
	}
	out, err := final.Evaluate(raw)
	if err != nil {
		return AdmissionDecision{}, err
	}
	var decision AdmissionDecision
	err = json.Unmarshal(out, &decision)
	return decision, err
}
