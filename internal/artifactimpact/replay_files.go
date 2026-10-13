package artifactimpact

import "github.com/kimjooyoon/gooo-policy-studio/internal/jsoninput"

const ReplaySummarySchema = "policy-studio/artifact-impact-replay-summary/v1"

// ReplaySummary discloses fixed historical labels, bounded counts and a public
// verifier source identity. It contains no report or private input identity.
type ReplaySummary struct {
	Schema                     string      `json:"schema"`
	Status                     string      `json:"status"`
	Code                       string      `json:"code"`
	Historical                 bool        `json:"historical"`
	Simulation                 bool        `json:"simulation"`
	ReadOnly                   bool        `json:"read_only"`
	AuthenticatedServerState   bool        `json:"authenticated_server_state"`
	Committed                  bool        `json:"committed"`
	TargetEffectsExecuted      bool        `json:"target_effects_executed"`
	CurrentArtifactReads       int         `json:"current_artifact_reads"`
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
	VerifierSHA256             string      `json:"verifier_sha256"`
}

// ReplayFailure accepts only public failure labels. Arbitrary caller text can
// never become a replay CLI error message through this helper.
func ReplayFailure(code string) ReplaySummary {
	switch code {
	case "USAGE_INVALID", "REPORT_FILE_INVALID", "REPORT_JSON_INVALID", "REPORT_REPLAY_INVALID", "REPLAY_SOURCE_INVALID":
	default:
		code = "USAGE_INVALID"
	}
	return ReplaySummary{Schema: ReplaySummarySchema, Status: "error", Code: code, Historical: true, Simulation: true, ReadOnly: true}
}

// ReplayFile reads only the private historical report. The paths and clock
// retained inside that report are data, never current acquisition inputs.
func ReplayFile(path string) (ReplaySummary, int) {
	raw, err := readPrivate(path, int64(MaxReportBytes))
	if err != nil {
		return ReplayFailure("REPORT_FILE_INVALID"), 2
	}
	var saved Report
	if jsoninput.Decode(raw, &saved, MaxReportBytes) != nil {
		return ReplayFailure("REPORT_JSON_INVALID"), 2
	}
	identity, err := ReplaySourceIdentity()
	if err != nil {
		return ReplayFailure("REPLAY_SOURCE_INVALID"), 2
	}
	replayed, err := Replay(saved)
	if err != nil {
		return ReplayFailure("REPORT_REPLAY_INVALID"), 2
	}
	return ReplaySummary{Schema: ReplaySummarySchema, Status: "verified", Code: "HISTORICAL_COMPARISON_MATCH", Historical: true, Simulation: true, ReadOnly: true,
		Direction: replayed.Delta.Direction, Before: SideSummary{replayed.Before.WouldAdmit, replayed.Before.Reason, replayed.Before.Completion.Summary.Counts()}, After: SideSummary{replayed.After.WouldAdmit, replayed.After.Reason, replayed.After.Completion.Summary.Counts()},
		AddedClaims: len(replayed.Delta.Added), RemovedClaims: len(replayed.Delta.Removed), ChangedClaims: len(replayed.Delta.Changed), ClaimOrderChanged: replayed.Delta.ClaimOrderChanged, RecipeConfigurationChanged: replayed.Delta.RecipeConfigurationChanged, ApprovalBudgetChanged: replayed.Delta.ApprovalBudgetChanged, ApprovalChecksChanged: replayed.Delta.ApprovalChecksChanged, VerifierSHA256: identity.VerifierSHA256}, 0
}
