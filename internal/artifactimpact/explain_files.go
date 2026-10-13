package artifactimpact

import "github.com/kimjooyoon/gooo-policy-studio/internal/jsoninput"

const ExplainSummarySchema = "policy-studio/artifact-impact-explain-summary/v1"

// ExplainSummary discloses fixed labels, bounded counts, and public source
// identities. The local file capability is declared even when no write occurs.
// OutputSaved describes only a successful write, sync and dependency close.
type ExplainSummary struct {
	Schema                   string      `json:"schema"`
	Status                   string      `json:"status"`
	Code                     string      `json:"code"`
	Historical               bool        `json:"historical"`
	Simulation               bool        `json:"simulation"`
	ReadOnly                 bool        `json:"read_only"`
	AuthenticatedServerState bool        `json:"authenticated_server_state"`
	Committed                bool        `json:"committed"`
	TargetEffectsExecuted    bool        `json:"target_effects_executed"`
	CurrentArtifactReads     int         `json:"current_artifact_reads"`
	LocalFileWriteDeclared   bool        `json:"local_file_write_declared"`
	OutputSaved              bool        `json:"output_saved"`
	Direction                string      `json:"direction"`
	Before                   SideSummary `json:"before"`
	After                    SideSummary `json:"after"`
	VerifierSHA256           string      `json:"verifier_sha256"`
	RendererSHA256           string      `json:"renderer_sha256"`
}

// ExplainFailure accepts a closed set of public labels, never caller values.
func ExplainFailure(code string) ExplainSummary {
	switch code {
	case "USAGE_INVALID", "REPORT_FILE_INVALID", "REPORT_JSON_INVALID", "REPORT_REPLAY_INVALID", "EXPLANATION_SOURCE_INVALID", "EXPLANATION_RENDER_INVALID", "OUTPUT_FILE_INVALID", "OUTPUT_WRITE_FAILED":
	default:
		code = "USAGE_INVALID"
	}
	return ExplainSummary{Schema: ExplainSummarySchema, Status: "error", Code: code, Historical: true, Simulation: true, LocalFileWriteDeclared: true}
}

type explainOutput interface {
	WriteAndSync([]byte) error
	Close() error
}

// These unexported dependencies allow deterministic new renderer/IO tests;
// ExplainFile always uses the existing guarded IO and full typed replay.
type explainDependencies struct {
	read         func(string, int64) ([]byte, error)
	replay       func(Report) (Report, error)
	identity     func() (ExplainIdentity, error)
	render       func(Report, ExplainIdentity, int64) ([]byte, error)
	reserve      func(string, ...string) (explainOutput, error)
	maxHTMLBytes int64
}

func explanationDependencies() explainDependencies {
	return explainDependencies{
		read: readPrivate, replay: Replay, identity: ExplainSourceIdentity,
		render: renderExplanation, maxHTMLBytes: int64(MaxReportBytes),
		reserve: func(path string, inputs ...string) (explainOutput, error) {
			return createPrivateAgainst(path, inputs...)
		},
	}
}

// ExplainFile reads a private report once, verifies its whole historical
// comparison, and writes a new private explanation. Retained input paths remain
// data. Only the actual report path participates in output alias protection.
func ExplainFile(reportPath, outputPath string) (ExplainSummary, int) {
	return explainFile(reportPath, outputPath, explanationDependencies())
}

func explainFile(reportPath, outputPath string, deps explainDependencies) (ExplainSummary, int) {
	if deps.read == nil || deps.replay == nil || deps.identity == nil || deps.render == nil || deps.reserve == nil {
		return ExplainFailure("EXPLANATION_SOURCE_INVALID"), 2
	}
	if deps.maxHTMLBytes < 1 || deps.maxHTMLBytes > int64(MaxReportBytes) {
		return ExplainFailure("EXPLANATION_RENDER_INVALID"), 2
	}
	raw, err := deps.read(reportPath, int64(MaxReportBytes))
	if err != nil {
		return ExplainFailure("REPORT_FILE_INVALID"), 2
	}
	var saved Report
	if jsoninput.Decode(raw, &saved, MaxReportBytes) != nil {
		return ExplainFailure("REPORT_JSON_INVALID"), 2
	}
	verified, err := deps.replay(saved)
	if err != nil {
		return ExplainFailure("REPORT_REPLAY_INVALID"), 2
	}
	identity, err := deps.identity()
	if err != nil {
		return ExplainFailure("EXPLANATION_SOURCE_INVALID"), 2
	}
	html, err := deps.render(verified, identity, deps.maxHTMLBytes)
	if err != nil || len(html) == 0 || int64(len(html)) > deps.maxHTMLBytes {
		return ExplainFailure("EXPLANATION_RENDER_INVALID"), 2
	}
	output, err := deps.reserve(outputPath, reportPath)
	if err != nil || output == nil {
		return ExplainFailure("OUTPUT_FILE_INVALID"), 2
	}
	closeAttempted := false
	defer func() {
		if !closeAttempted {
			_ = output.Close()
		}
	}()
	if output.WriteAndSync(html) != nil {
		return ExplainFailure("OUTPUT_WRITE_FAILED"), 2
	}
	closeErr := output.Close()
	closeAttempted = true
	if closeErr != nil {
		return ExplainFailure("OUTPUT_WRITE_FAILED"), 2
	}
	summary := ExplainFailure("USAGE_INVALID")
	summary.Status, summary.Code, summary.OutputSaved = "saved", "HISTORICAL_EXPLANATION_SAVED", true
	summary.Direction = verified.Delta.Direction
	summary.Before = SideSummary{WouldAdmit: verified.Before.WouldAdmit, Reason: verified.Before.Reason, Counts: verified.Before.Completion.Summary.Counts()}
	summary.After = SideSummary{WouldAdmit: verified.After.WouldAdmit, Reason: verified.After.Reason, Counts: verified.After.Completion.Summary.Counts()}
	summary.VerifierSHA256, summary.RendererSHA256 = identity.Replay.VerifierSHA256, identity.RendererSHA256
	return summary, 0
}
