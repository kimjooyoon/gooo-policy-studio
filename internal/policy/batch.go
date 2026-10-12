package policy

import (
	_ "embed"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"
	"unicode/utf8"
)

const (
	MaxBatchCases     = 256
	BatchInputSchema  = "policy-studio/impact-input/v1"
	BatchReportSchema = "policy-studio/impact-report/v1"
	BatchScope        = "Finite regression comparison of supplied ordered cases and expected observations against compiled Gooo activities under two policy parameter sets; not a general safety or authentication proof, a signed audit record, or authorization for an external effect."
)

//go:embed bridge_generated.go
var batchAdapterSource string

type Case struct {
	ID            string   `json:"id"`
	Request       Request  `json:"request"`
	Reviewer      Reviewer `json:"reviewer"`
	ExpectedAfter Decision `json:"expected_after"`
}

type BatchInput struct {
	Schema string `json:"schema"`
	Label  string `json:"label"`
	Before Rules  `json:"before"`
	After  Rules  `json:"after"`
	Cases  []Case `json:"cases"`
}

type BatchProvenance struct {
	SourceDigest     string `json:"source_sha256"`
	GeneratedDigest  string `json:"generated_sha256"`
	CompilerSource   string `json:"compiler_source_sha"`
	GenerationDigest string `json:"generation_sha256"`
	AdapterDigest    string `json:"adapter_sha256"`
}

type BatchRow struct {
	ID                 string  `json:"id"`
	Receipt            Receipt `json:"receipt"`
	ExpectationMatched bool    `json:"expectation_matched"`
}

type BatchChecks struct {
	Passed     bool `json:"passed"`
	Matched    int  `json:"matched"`
	Mismatched int  `json:"mismatched"`
}

type BatchRuleChanges struct {
	AmountOK    int `json:"amount_ok"`
	TeamOK      int `json:"team_ok"`
	ReviewerOK  int `json:"reviewer_ok"`
	SelfOK      int `json:"self_ok"`
	SubmittedOK int `json:"submitted_ok"`
}

type BatchSummary struct {
	Cases                int              `json:"cases"`
	BeforeApproved       int              `json:"before_approved"`
	AfterApproved        int              `json:"after_approved"`
	NewlyApproved        int              `json:"newly_approved"`
	NewlyDenied          int              `json:"newly_denied"`
	ReasonOnlyChanged    int              `json:"reason_only_changed"`
	BeforeApprovedAmount int64            `json:"before_approved_amount"`
	AfterApprovedAmount  int64            `json:"after_approved_amount"`
	RuleChanges          BatchRuleChanges `json:"rule_changes"`
}

type BatchReport struct {
	Schema       string          `json:"schema"`
	ID           string          `json:"id"`
	CreatedAt    string          `json:"created_at"`
	CorpusDigest string          `json:"corpus_sha256"`
	Input        BatchInput      `json:"input"`
	Provenance   BatchProvenance `json:"provenance"`
	Rows         []BatchRow      `json:"rows"`
	Summary      BatchSummary    `json:"summary"`
	Checks       BatchChecks     `json:"checks"`
	Scope        string          `json:"scope"`
}

// ValidateBatch validates the complete workload before any row is executed.
// IDs retain their exact spelling and cases retain their supplied order.
func ValidateBatch(in BatchInput) error {
	if in.Schema != BatchInputSchema {
		return errors.New("unsupported impact input schema")
	}
	if strings.TrimSpace(in.Label) == "" || len(in.Label) > 200 || !utf8.ValidString(in.Label) {
		return errors.New("label must be nonempty text of at most 200 UTF-8 bytes")
	}
	if len(in.Cases) == 0 || len(in.Cases) > MaxBatchCases {
		return fmt.Errorf("cases must contain 1..%d rows", MaxBatchCases)
	}
	seen := make(map[string]bool, len(in.Cases))
	for i, c := range in.Cases {
		if !validBatchCaseID(c.ID) {
			return fmt.Errorf("cases[%d]: id must match [A-Za-z0-9][A-Za-z0-9._:-]{0,79}", i)
		}
		if seen[c.ID] {
			return fmt.Errorf("cases[%d] (%q): duplicate case id", i, c.ID)
		}
		seen[c.ID] = true
		if err := Validate(batchCaseInput(in, c)); err != nil {
			return fmt.Errorf("cases[%d] (%q): %w", i, c.ID, err)
		}
		if err := validateExpectedAfter(c.ExpectedAfter); err != nil {
			return fmt.Errorf("cases[%d] (%q): expected_after: %w", i, c.ID, err)
		}
	}
	return nil
}

// These are consistency checks on independently supplied expectation data, not
// evaluations of a request. Wrong but well-formed expectations remain visible
// as mismatched observations after the actual compiled Gooo decision executes.
func validateExpectedAfter(expected Decision) error {
	switch expected.Reason {
	case "APPROVED", "NOT_SUBMITTED", "REVIEWER_INACTIVE", "SELF_APPROVAL", "TEAM_MISMATCH", "OVER_LIMIT":
	default:
		return errors.New("reason must be a known decision reason")
	}
	allExpectedConditions := expected.AmountOK && expected.TeamOK && expected.ReviewerOK && expected.SelfOK && expected.SubmittedOK
	if expected.Approved != (expected.Reason == "APPROVED") || expected.Approved != allExpectedConditions {
		return errors.New("approved, reason, and expected condition observations are inconsistent")
	}
	return nil
}

func validBatchCaseID(id string) bool {
	if len(id) == 0 || len(id) > 80 {
		return false
	}
	for i := 0; i < len(id); i++ {
		b := id[i]
		letterOrDigit := b >= 'A' && b <= 'Z' || b >= 'a' && b <= 'z' || b >= '0' && b <= '9'
		if !letterOrDigit && (i == 0 || b != '.' && b != '_' && b != ':' && b != '-') {
			return false
		}
	}
	return true
}

func batchCaseInput(in BatchInput, c Case) Input {
	return Input{Request: c.Request, Reviewer: c.Reviewer, Before: in.Before, After: in.After}
}

func cloneBatchInput(in BatchInput) BatchInput {
	in.Cases = append([]Case(nil), in.Cases...)
	return in
}

func currentBatchProvenance() (BatchProvenance, error) {
	var generation struct {
		Schema          string `json:"schema"`
		SourceDigest    string `json:"source_sha256"`
		GeneratedDigest string `json:"generated_sha256"`
		AdapterDigest   string `json:"adapter_sha256"`
		Compiler        struct {
			Source string `json:"compiler_source_sha"`
		} `json:"compiler"`
	}
	if err := json.Unmarshal(Generation, &generation); err != nil {
		return BatchProvenance{}, fmt.Errorf("invalid embedded generation evidence: %w", err)
	}
	provenance := BatchProvenance{
		SourceDigest: hash([]byte(Source)), GeneratedDigest: hash([]byte(Generated)),
		CompilerSource: generation.Compiler.Source, GenerationDigest: hash(Generation),
		AdapterDigest: hash([]byte(batchAdapterSource)),
	}
	compilerBytes, compilerErr := hex.DecodeString(provenance.CompilerSource)
	if generation.Schema != "policy-studio/generation/v1" || compilerErr != nil || len(compilerBytes) != 20 ||
		generation.SourceDigest != provenance.SourceDigest || generation.GeneratedDigest != provenance.GeneratedDigest ||
		generation.AdapterDigest != provenance.AdapterDigest {
		return BatchProvenance{}, errors.New("embedded source, generated code, adapter, or compiler evidence does not match")
	}
	return provenance, nil
}

// SimulateBatch executes existing compiled Gooo activities for every validated
// row. No partially completed report is returned if any row fails.
func SimulateBatch(in BatchInput) (BatchReport, error) {
	in = cloneBatchInput(in)
	if err := ValidateBatch(in); err != nil {
		return BatchReport{}, err
	}
	provenance, err := currentBatchProvenance()
	if err != nil {
		return BatchReport{}, err
	}
	rows := make([]BatchRow, 0, len(in.Cases))
	for i, c := range in.Cases {
		receipt, err := Simulate(batchCaseInput(in, c))
		if err != nil {
			return BatchReport{}, fmt.Errorf("cases[%d] (%q): %w", i, c.ID, err)
		}
		row := BatchRow{ID: c.ID, Receipt: receipt, ExpectationMatched: receipt.Result.After == c.ExpectedAfter}
		if err := validateBatchRow(row, c, in, provenance); err != nil {
			return BatchReport{}, fmt.Errorf("cases[%d] (%q): %w", i, c.ID, err)
		}
		rows = append(rows, row)
	}
	return makeBatchReport(in, provenance, rows), nil
}

func batchCorpusDigest(cases []Case) string {
	raw, _ := json.Marshal(cases)
	return hash(raw)
}

func batchReportID(report BatchReport) string {
	report.ID = ""
	raw, _ := json.Marshal(report)
	return hash(raw)
}

func makeBatchReport(in BatchInput, provenance BatchProvenance, rows []BatchRow) BatchReport {
	report := BatchReport{
		Schema: BatchReportSchema, CreatedAt: time.Now().UTC().Format(time.RFC3339Nano),
		CorpusDigest: batchCorpusDigest(in.Cases), Input: in, Provenance: provenance,
		Rows: rows, Summary: summarizeBatch(rows), Checks: checkBatch(rows), Scope: BatchScope,
	}
	report.ID = batchReportID(report)
	return report
}

func checkBatch(rows []BatchRow) BatchChecks {
	checks := BatchChecks{Passed: true}
	for _, row := range rows {
		if row.ExpectationMatched {
			checks.Matched++
		} else {
			checks.Mismatched++
			checks.Passed = false
		}
	}
	return checks
}

// summarizeBatch counts Gooo-returned decisions, classifications and observed
// rule changes; it does not independently implement an approval condition.
// MaxBatchCases * MaxAmount is 2,304,000,000,000,000, within JS safe integers.
func summarizeBatch(rows []BatchRow) BatchSummary {
	summary := BatchSummary{Cases: len(rows)}
	for _, row := range rows {
		result := row.Receipt.Result
		if result.Before.Approved {
			summary.BeforeApproved++
			summary.BeforeApprovedAmount += row.Receipt.Input.Request.Amount
		}
		if result.After.Approved {
			summary.AfterApproved++
			summary.AfterApprovedAmount += row.Receipt.Input.Request.Amount
		}
		switch result.Change.Direction {
		case "NEWLY_APPROVED":
			summary.NewlyApproved++
		case "NEWLY_DENIED":
			summary.NewlyDenied++
		}
		if !result.Change.Changed && result.Change.ReasonChanged {
			summary.ReasonOnlyChanged++
		}
		if result.Before.AmountOK != result.After.AmountOK {
			summary.RuleChanges.AmountOK++
		}
		if result.Before.TeamOK != result.After.TeamOK {
			summary.RuleChanges.TeamOK++
		}
		if result.Before.ReviewerOK != result.After.ReviewerOK {
			summary.RuleChanges.ReviewerOK++
		}
		if result.Before.SelfOK != result.After.SelfOK {
			summary.RuleChanges.SelfOK++
		}
		if result.Before.SubmittedOK != result.After.SubmittedOK {
			summary.RuleChanges.SubmittedOK++
		}
	}
	return summary
}

func validateBatchRow(row BatchRow, c Case, in BatchInput, provenance BatchProvenance) error {
	if row.ID != c.ID || row.Receipt.Input != batchCaseInput(in, c) {
		return errors.New("row identity, ordering, or input does not match the workload")
	}
	if row.ExpectationMatched != (row.Receipt.Result.After == c.ExpectedAfter) {
		return errors.New("row expectation comparison does not match the supplied expected observation")
	}
	receipt := row.Receipt
	if receipt.Schema != "policy-studio/execution/v1" || receipt.Scope != Scope || receipt.ID != receiptID(receipt) {
		return errors.New("row receipt schema, scope, or content hash does not match")
	}
	if receipt.SourceDigest != provenance.SourceDigest || receipt.GeneratedDigest != provenance.GeneratedDigest || receipt.CompilerSource != provenance.CompilerSource {
		return errors.New("row receipt provenance does not match the report")
	}
	if _, err := time.Parse(time.RFC3339Nano, receipt.CreatedAt); err != nil {
		return errors.New("row receipt execution time is invalid")
	}
	return nil
}

// ReplayBatch verifies a complete ordered report against the current embedded
// implementation, then calls Replay for every row and returns a fresh report.
// Its hashes establish content consistency, not issuer identity: a consistently
// rewritten bundle can pass, and a saved approval grants no execution permission.
func ReplayBatch(report BatchReport) (BatchReport, error) {
	report.Input = cloneBatchInput(report.Input)
	report.Rows = append([]BatchRow(nil), report.Rows...)
	if report.Schema != BatchReportSchema || report.Scope != BatchScope || report.ID != batchReportID(report) {
		return BatchReport{}, errors.New("impact report schema, scope, or content hash does not match")
	}
	if _, err := time.Parse(time.RFC3339Nano, report.CreatedAt); err != nil {
		return BatchReport{}, errors.New("impact report execution time is invalid")
	}
	if err := ValidateBatch(report.Input); err != nil {
		return BatchReport{}, err
	}
	provenance, err := currentBatchProvenance()
	if err != nil {
		return BatchReport{}, err
	}
	if report.Provenance != provenance {
		return BatchReport{}, errors.New("impact report provenance differs from the current implementation")
	}
	if report.CorpusDigest != batchCorpusDigest(report.Input.Cases) || len(report.Rows) != len(report.Input.Cases) {
		return BatchReport{}, errors.New("impact report corpus hash or row inventory does not match")
	}
	for i, c := range report.Input.Cases {
		if err := validateBatchRow(report.Rows[i], c, report.Input, provenance); err != nil {
			return BatchReport{}, fmt.Errorf("rows[%d] (%q): %w", i, c.ID, err)
		}
	}
	if report.Summary != summarizeBatch(report.Rows) {
		return BatchReport{}, errors.New("impact report summary does not match its rows")
	}
	if report.Checks != checkBatch(report.Rows) {
		return BatchReport{}, errors.New("impact report regression checks do not match its rows")
	}
	rows := make([]BatchRow, 0, len(report.Rows))
	for i, row := range report.Rows {
		receipt, err := Replay(row.Receipt)
		if err != nil {
			return BatchReport{}, fmt.Errorf("rows[%d] (%q): %w", i, row.ID, err)
		}
		rows = append(rows, BatchRow{ID: row.ID, Receipt: receipt, ExpectationMatched: receipt.Result.After == report.Input.Cases[i].ExpectedAfter})
	}
	fresh := makeBatchReport(report.Input, provenance, rows)
	if fresh.Summary != report.Summary || fresh.Checks != report.Checks || !equalBatchResults(rows, report.Rows) {
		return BatchReport{}, errors.New("replayed impact results, summary, or regression checks do not match")
	}
	return fresh, nil
}

func equalBatchResults(left, right []BatchRow) bool {
	for i := range left {
		if left[i].ID != right[i].ID || left[i].Receipt.Result != right[i].Receipt.Result || left[i].ExpectationMatched != right[i].ExpectationMatched {
			return false
		}
	}
	return true
}
