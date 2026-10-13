// Package artifactimpact compares two proposed policies over one locally
// acquired artifact. Its reports simulate decisions and never authorize effects.
package artifactimpact

import (
	"github.com/kimjooyoon/gooo-policy-studio/internal/admission"
	"github.com/kimjooyoon/gooo-policy-studio/internal/artifactpreflight"
	"github.com/kimjooyoon/gooo-policy-studio/internal/completion"
	"github.com/kimjooyoon/gooo-policy-studio/internal/machinerules"
	"github.com/kimjooyoon/gooo-policy-studio/internal/policy"
)

const (
	CaseSchema           = "policy-studio/artifact-impact-case/v1"
	ReportSchema         = "policy-studio/artifact-policy-comparison/v1"
	SummarySchema        = "policy-studio/artifact-impact-summary/v1"
	MaxInputBytes  int64 = 1 << 20
	MaxReportBytes       = 64 << 20
	Scope                = "Finite comparison of two proposed v2 policies over one local artifact acquisition. Proposed principal facts are not authenticated server state; no admission is committed and no target effect is executed. Source hashes check implementation consistency, not issuer authenticity or production safety."
)

type Artifact struct {
	Path           string `json:"path"`
	ExpectedSHA256 string `json:"expected_sha256"`
	DeadlineUnix   int64  `json:"deadline_unix"`
}
type Case struct {
	Schema    string                  `json:"schema"`
	Request   policy.Request          `json:"request"`
	Principal admission.PrincipalView `json:"principal"`
	BaseRules policy.Rules            `json:"base_rules"`
	Artifact  Artifact                `json:"artifact"`
}
type Paths struct{ Case, Before, After, Report string }
type InputBinding struct {
	RawSHA256      string `json:"raw_sha256"`
	SemanticSHA256 string `json:"semantic_sha256"`
}
type InputBindings struct {
	Case   InputBinding `json:"case"`
	Before InputBinding `json:"before"`
	After  InputBinding `json:"after"`
}
type Permission struct {
	Eligible          bool   `json:"eligible"`
	Reason            string `json:"reason"`
	ModeledHTTPStatus int    `json:"modeled_http_status"`
}
type Context struct {
	Domain         string                   `json:"domain"`
	Side           string                   `json:"side"`
	Case           Case                     `json:"case"`
	Inputs         InputBindings            `json:"inputs"`
	Policy         admission.ArtifactPolicy `json:"policy"`
	Implementation Identity                 `json:"implementation"`
}
type EffectEvaluation struct {
	Facts    machinerules.ToolEffects    `json:"facts"`
	Budget   machinerules.EffectBudget   `json:"budget"`
	Decision machinerules.EffectDecision `json:"decision"`
}
type Side struct {
	Context                 Context                         `json:"context"`
	ContextSHA256           string                          `json:"context_sha256"`
	SimulationPolicyVersion string                          `json:"simulation_policy_version"`
	Producer                artifactpreflight.Report        `json:"producer"`
	Evidence                []admission.EvidenceObservation `json:"evidence"`
	Completion              completion.Report               `json:"completion"`
	ProposedApproval        EffectEvaluation                `json:"proposed_approval"`
	ProposedControlPlane    EffectEvaluation                `json:"proposed_control_plane"`
	AdmissionFacts          machinerules.AdmissionFacts     `json:"admission_facts"`
	Decision                machinerules.AdmissionDecision  `json:"decision"`
	WouldAdmit              bool                            `json:"would_admit"`
	Reason                  string                          `json:"reason"`
}
type ClaimChange struct {
	ClaimID                 string `json:"claim_id"`
	PredicateChanged        bool   `json:"predicate_changed"`
	ArtifactSchemaChanged   bool   `json:"artifact_schema_changed"`
	FieldTypeChanged        bool   `json:"field_type_changed"`
	StatusChanged           bool   `json:"status_changed"`
	ReasonChanged           bool   `json:"reason_changed"`
	ActualChanged           bool   `json:"actual_changed"`
	EvidenceDecisionChanged bool   `json:"evidence_decision_changed"`
}
type Delta struct {
	Direction                  string        `json:"direction"`
	Added                      []string      `json:"added"`
	Removed                    []string      `json:"removed"`
	Changed                    []ClaimChange `json:"changed"`
	PolicyIdentityChanged      bool          `json:"policy_identity_changed"`
	RecipeConfigurationChanged bool          `json:"recipe_configuration_changed"`
	ClaimOrderChanged          bool          `json:"claim_order_changed"`
	ApprovalBudgetChanged      bool          `json:"approval_budget_changed"`
	ApprovalChecksChanged      bool          `json:"approval_checks_changed"`
	ControlPlaneChecksChanged  bool          `json:"control_plane_checks_changed"`
}
type ComparisonAudit struct {
	Schema                    string                              `json:"schema"`
	ArtifactReadAttempts      int                                 `json:"artifact_read_attempts"`
	AcquisitionStatus         artifactpreflight.AcquisitionStatus `json:"acquisition_status"`
	InputFilesRead            int                                 `json:"input_files_read"`
	PrivateReportReserved     bool                                `json:"private_report_reserved"`
	PrivateReportWritePlanned bool                                `json:"private_report_write_planned"`
	Effects                   machinerules.ToolEffects            `json:"effects"`
}
type Report struct {
	Schema                   string          `json:"schema"`
	ID                       string          `json:"id"`
	Simulation               bool            `json:"simulation"`
	AuthenticatedServerState bool            `json:"authenticated_server_state"`
	Committed                bool            `json:"committed"`
	TargetEffectsExecuted    bool            `json:"target_effects_executed"`
	ObservationUnix          int64           `json:"observation_unix"`
	Inputs                   InputBindings   `json:"inputs"`
	Implementation           Identity        `json:"implementation"`
	Permission               Permission      `json:"permission"`
	BaseReceipt              policy.Receipt  `json:"base_receipt"`
	Before                   Side            `json:"before"`
	After                    Side            `json:"after"`
	Delta                    Delta           `json:"delta"`
	Audit                    ComparisonAudit `json:"audit"`
	Scope                    string          `json:"scope"`
}

// Summary contains only fixed labels, counts, and booleans. No private input
// values, identifiers, filesystem paths or producer bytes reach stdout.
type SideSummary struct {
	WouldAdmit bool              `json:"would_admit"`
	Reason     string            `json:"reason"`
	Counts     completion.Counts `json:"counts"`
}
type Summary struct {
	Schema                     string      `json:"schema"`
	Status                     string      `json:"status"`
	Code                       string      `json:"code"`
	Simulation                 bool        `json:"simulation"`
	ReportSaved                bool        `json:"report_saved"`
	Direction                  string      `json:"direction"`
	Before                     SideSummary `json:"before"`
	After                      SideSummary `json:"after"`
	AddedClaims                int         `json:"added_claims"`
	RemovedClaims              int         `json:"removed_claims"`
	ChangedClaims              int         `json:"changed_claims"`
	ClaimOrderChanged          bool        `json:"claim_order_changed"`
	RecipeConfigurationChanged bool        `json:"recipe_configuration_changed"`
	ApprovalBudgetChanged      bool        `json:"approval_budget_changed"`
	ApprovalChecksChanged      bool        `json:"approval_checks_changed"`
}

func Failure(code string) Summary {
	return Summary{Schema: SummarySchema, Status: "error", Code: code, Simulation: true}
}
