package policy

import (
	"encoding/json"
	"fmt"
	"reflect"
	"strings"
	"testing"
)

func batchFixture() BatchInput {
	base := fixture()
	in := BatchInput{
		Schema: BatchInputSchema, Label: "API automation approval budget review",
		Before: Rules{500000, false, true, true}, After: Rules{1000000, true, false, false},
	}
	add := func(id string, amount int64, team string, active, submitted, self bool) {
		request, reviewer := base.Request, base.Reviewer
		request.Key, request.Amount, request.Submitted = id, amount, submitted
		reviewer.Team, reviewer.Active = team, active
		if self {
			reviewer.Key = request.Requester
		}
		in.Cases = append(in.Cases, Case{ID: id, Request: request, Reviewer: reviewer})
	}
	add("unchanged", 100000, "product", true, true, false)
	add("new-budget", 750000, "product", true, true, false)
	add("new-team-restriction", 100000, "other", true, true, false)
	add("reason-only", 100000, "other", false, true, false)
	add("draft-observations", 750000, "other", false, false, false)
	add("self-rule-relaxed", 100000, "product", true, true, true)
	// Independently authored expectations: they are never used to evaluate a
	// request or to generate the actual Gooo result.
	expected := []Decision{
		{true, "APPROVED", true, true, true, true, true},
		{true, "APPROVED", true, true, true, true, true},
		{false, "TEAM_MISMATCH", true, false, true, true, true},
		{false, "TEAM_MISMATCH", true, false, true, true, true},
		{false, "NOT_SUBMITTED", true, false, true, true, false},
		{true, "APPROVED", true, true, true, true, true},
	}
	for i := range in.Cases {
		in.Cases[i].ExpectedAfter = expected[i]
	}
	return in
}

func TestBatchExecutionSummaryAndReplay(t *testing.T) {
	in := batchFixture()
	report, err := SimulateBatch(in)
	if err != nil {
		t.Fatal(err)
	}
	want := BatchSummary{
		Cases: 6, BeforeApproved: 2, AfterApproved: 3, NewlyApproved: 2, NewlyDenied: 1,
		ReasonOnlyChanged: 1, BeforeApprovedAmount: 200000, AfterApprovedAmount: 950000,
		RuleChanges: BatchRuleChanges{AmountOK: 2, TeamOK: 3, ReviewerOK: 2, SelfOK: 1},
	}
	if report.Summary != want {
		t.Fatalf("summary: got %+v, want %+v", report.Summary, want)
	}
	if report.Checks != (BatchChecks{Passed: true, Matched: 6}) {
		t.Fatalf("independent expectations were not all matched: %+v", report.Checks)
	}
	if report.Schema != BatchReportSchema || report.Scope != BatchScope || report.ID != batchReportID(report) || report.CorpusDigest != batchCorpusDigest(in.Cases) {
		t.Fatal("report envelope is not bound")
	}
	for i, row := range report.Rows {
		if row.ID != in.Cases[i].ID || row.Receipt.Input != batchCaseInput(in, in.Cases[i]) {
			t.Fatalf("row %d lost its ordered input", i)
		}
		if row.Receipt.Result.Change.Direction == "" {
			t.Fatalf("row %d has no Gooo change classification", i)
		}
	}
	fresh, err := ReplayBatch(report)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(fresh.Input, report.Input) || fresh.Provenance != report.Provenance || fresh.Summary != want || fresh.Checks != report.Checks || !equalBatchResults(fresh.Rows, report.Rows) {
		t.Fatal("replay changed the workload, provenance, or observed results")
	}
	if fresh.ID == report.ID || fresh.CreatedAt == report.CreatedAt {
		t.Fatal("replay did not issue a fresh complete report")
	}
	in.Cases[0].Request.Amount++
	if report.Input.Cases[0].Request.Amount != 100000 {
		t.Fatal("caller mutation changed the saved workload")
	}
}

func TestBatchValidationBoundaries(t *testing.T) {
	valid := batchFixture()
	valid.Label = strings.Repeat("가", 66) + "ab"
	valid.Cases[0].ID = "A" + strings.Repeat("x", 79)
	if err := ValidateBatch(valid); err != nil {
		t.Fatal("exact UTF-8 label and case id boundaries rejected", err)
	}
	tests := []struct {
		name string
		edit func(*BatchInput)
	}{
		{"schema", func(in *BatchInput) { in.Schema = "unknown" }},
		{"blank label", func(in *BatchInput) { in.Label = " \n\t" }},
		{"label too large", func(in *BatchInput) { in.Label = strings.Repeat("가", 67) }},
		{"invalid label UTF-8", func(in *BatchInput) { in.Label = string([]byte{0xff}) }},
		{"no cases", func(in *BatchInput) { in.Cases = nil }},
		{"too many cases", func(in *BatchInput) { in.Cases = make([]Case, MaxBatchCases+1) }},
		{"empty id", func(in *BatchInput) { in.Cases[0].ID = "" }},
		{"id too large", func(in *BatchInput) { in.Cases[0].ID = strings.Repeat("a", 81) }},
		{"id initial punctuation", func(in *BatchInput) { in.Cases[0].ID = "_case" }},
		{"id non-ASCII", func(in *BatchInput) { in.Cases[0].ID = "case-가" }},
		{"id spaces", func(in *BatchInput) { in.Cases[0].ID = "case 1" }},
		{"duplicate id", func(in *BatchInput) { in.Cases[1].ID = in.Cases[0].ID }},
		{"negative amount", func(in *BatchInput) { in.Cases[5].Request.Amount = -1 }},
		{"large amount", func(in *BatchInput) { in.Cases[5].Request.Amount = MaxAmount + 1 }},
		{"empty reviewer", func(in *BatchInput) { in.Cases[5].Reviewer.Key = " " }},
		{"invalid shared policy", func(in *BatchInput) { in.After.Limit = MaxAmount + 1 }},
		{"missing expectation", func(in *BatchInput) { in.Cases[5].ExpectedAfter = Decision{} }},
		{"unknown expected reason", func(in *BatchInput) { in.Cases[5].ExpectedAfter.Reason = "UNKNOWN" }},
		{"expected approval reason inconsistent", func(in *BatchInput) { in.Cases[5].ExpectedAfter.Reason = "OVER_LIMIT" }},
		{"expected approved conditions inconsistent", func(in *BatchInput) { in.Cases[5].ExpectedAfter.TeamOK = false }},
		{"expected denial conditions inconsistent", func(in *BatchInput) { in.Cases[2].ExpectedAfter.TeamOK = true }},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			in := batchFixture()
			tt.edit(&in)
			if err := ValidateBatch(in); err == nil {
				t.Fatal("invalid workload accepted")
			}
			out, err := SimulateBatch(in)
			if err == nil || !reflect.DeepEqual(out, BatchReport{}) {
				t.Fatal("invalid workload returned a partial report", err)
			}
		})
	}
	valid = batchFixture()
	valid.Cases[0].ID, valid.Cases[1].ID = "Case._:-1", "case._:-1"
	if err := ValidateBatch(valid); err != nil {
		t.Fatal("exact distinct ASCII identities rejected", err)
	}
}

func TestBatchMaximumAmountTotals(t *testing.T) {
	in := batchFixture()
	c := in.Cases[0]
	c.Request.Amount = MaxAmount
	in.Before, in.After = Rules{MaxAmount, true, true, true}, Rules{MaxAmount, true, true, true}
	in.Cases = make([]Case, MaxBatchCases)
	for i := range in.Cases {
		in.Cases[i] = c
		in.Cases[i].ID = fmt.Sprintf("case-%03d", i)
	}
	report, err := SimulateBatch(in)
	if err != nil {
		t.Fatal(err)
	}
	wantAmount := int64(MaxBatchCases) * MaxAmount
	if report.Summary.Cases != MaxBatchCases || report.Summary.BeforeApproved != MaxBatchCases || report.Summary.AfterApproved != MaxBatchCases || report.Summary.BeforeApprovedAmount != wantAmount || report.Summary.AfterApprovedAmount != wantAmount || wantAmount > 9_007_199_254_740_991 {
		t.Fatalf("maximum totals lost their integer bounds: %+v", report.Summary)
	}
}

func TestBatchValidatesLastRowBeforeExecution(t *testing.T) {
	original := Generation
	defer func() { Generation = original }()
	Generation = json.RawMessage(`{"broken":`)
	in := batchFixture()
	in.Cases[5].Request.Amount = -1
	_, err := SimulateBatch(in)
	if err == nil || !strings.Contains(err.Error(), "cases[5]") {
		t.Fatal("execution evidence was consulted before the last invalid row was checked", err)
	}
}

func TestBatchReplayRejectsRehashedMutations(t *testing.T) {
	original, err := SimulateBatch(batchFixture())
	if err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name string
		edit func(*BatchReport)
	}{
		{"schema", func(r *BatchReport) { r.Schema = "unknown" }},
		{"scope", func(r *BatchReport) { r.Scope = "signed authorization" }},
		{"time", func(r *BatchReport) { r.CreatedAt = "invalid" }},
		{"corpus hash", func(r *BatchReport) { r.CorpusDigest = "sha256:changed" }},
		{"input order", func(r *BatchReport) {
			r.Input.Cases[0], r.Input.Cases[1] = r.Input.Cases[1], r.Input.Cases[0]
			r.CorpusDigest = batchCorpusDigest(r.Input.Cases)
		}},
		{"input removed", func(r *BatchReport) {
			r.Input.Cases = r.Input.Cases[:5]
			r.CorpusDigest = batchCorpusDigest(r.Input.Cases)
		}},
		{"input duplicated", func(r *BatchReport) {
			r.Input.Cases[1].ID = r.Input.Cases[0].ID
			r.CorpusDigest = batchCorpusDigest(r.Input.Cases)
		}},
		{"input out of bounds", func(r *BatchReport) {
			r.Input.Cases[5].Request.Amount = MaxAmount + 1
			r.CorpusDigest = batchCorpusDigest(r.Input.Cases)
		}},
		{"expected observation", func(r *BatchReport) {
			r.Input.Cases[3].ExpectedAfter.Reason = "SELF_APPROVAL"
			r.CorpusDigest = batchCorpusDigest(r.Input.Cases)
		}},
		{"rows reordered", func(r *BatchReport) { r.Rows[0], r.Rows[1] = r.Rows[1], r.Rows[0] }},
		{"row removed", func(r *BatchReport) { r.Rows = r.Rows[:5] }},
		{"row duplicated", func(r *BatchReport) { r.Rows[1] = r.Rows[0] }},
		{"row id", func(r *BatchReport) { r.Rows[0].ID = "replacement" }},
		{"row receipt hash", func(r *BatchReport) { r.Rows[0].Receipt.ID = "sha256:changed" }},
		{"row receipt schema", func(r *BatchReport) {
			r.Rows[0].Receipt.Schema = "unknown"
			r.Rows[0].Receipt.ID = receiptID(r.Rows[0].Receipt)
		}},
		{"row receipt scope", func(r *BatchReport) {
			r.Rows[0].Receipt.Scope = "authorization"
			r.Rows[0].Receipt.ID = receiptID(r.Rows[0].Receipt)
		}},
		{"row receipt time", func(r *BatchReport) {
			r.Rows[0].Receipt.CreatedAt = "invalid"
			r.Rows[0].Receipt.ID = receiptID(r.Rows[0].Receipt)
		}},
		{"row input", func(r *BatchReport) {
			r.Rows[0].Receipt.Input.Request.Amount++
			r.Rows[0].Receipt.ID = receiptID(r.Rows[0].Receipt)
		}},
		{"row policy", func(r *BatchReport) {
			r.Rows[0].Receipt.Input.After.Limit++
			r.Rows[0].Receipt.ID = receiptID(r.Rows[0].Receipt)
		}},
		{"row result", func(r *BatchReport) {
			r.Rows[5].Receipt.Result.After.Reason = "FORGED"
			r.Rows[5].Receipt.ID = receiptID(r.Rows[5].Receipt)
			r.Rows[5].ExpectationMatched = false
			r.Summary = summarizeBatch(r.Rows)
			r.Checks = checkBatch(r.Rows)
		}},
		{"row source", func(r *BatchReport) {
			r.Rows[0].Receipt.SourceDigest = "sha256:changed"
			r.Rows[0].Receipt.ID = receiptID(r.Rows[0].Receipt)
		}},
		{"row compiler", func(r *BatchReport) {
			r.Rows[0].Receipt.CompilerSource = strings.Repeat("a", 40)
			r.Rows[0].Receipt.ID = receiptID(r.Rows[0].Receipt)
		}},
		{"summary", func(r *BatchReport) { r.Summary.NewlyApproved++ }},
		{"amount summary", func(r *BatchReport) { r.Summary.AfterApprovedAmount++ }},
		{"rule summary", func(r *BatchReport) { r.Summary.RuleChanges.TeamOK++ }},
		{"row expectation match", func(r *BatchReport) { r.Rows[0].ExpectationMatched = false }},
		{"checks passed", func(r *BatchReport) { r.Checks.Passed = false }},
		{"checks matched", func(r *BatchReport) { r.Checks.Matched++ }},
		{"checks mismatched", func(r *BatchReport) { r.Checks.Mismatched++ }},
		{"source provenance", func(r *BatchReport) { r.Provenance.SourceDigest = "sha256:changed" }},
		{"generated provenance", func(r *BatchReport) { r.Provenance.GeneratedDigest = "sha256:changed" }},
		{"compiler provenance", func(r *BatchReport) { r.Provenance.CompilerSource = strings.Repeat("a", 40) }},
		{"generation provenance", func(r *BatchReport) { r.Provenance.GenerationDigest = "sha256:changed" }},
		{"adapter provenance", func(r *BatchReport) { r.Provenance.AdapterDigest = "sha256:changed" }},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			report := copyBatchReport(t, original)
			tt.edit(&report)
			report.ID = batchReportID(report)
			fresh, err := ReplayBatch(report)
			if err == nil || !reflect.DeepEqual(fresh, BatchReport{}) {
				t.Fatal("mutated report returned a successful or partial replay", err)
			}
		})
	}
	original.ID = "sha256:changed"
	if _, err := ReplayBatch(original); err == nil {
		t.Fatal("invalid outer report hash accepted")
	}
}

func TestBatchMismatchesProduceCompleteFailedChecks(t *testing.T) {
	in := batchFixture()
	in.Cases[1].ExpectedAfter = Decision{false, "OVER_LIMIT", false, true, true, true, true}
	in.Cases[3].ExpectedAfter.Reason = "SELF_APPROVAL"
	report, err := SimulateBatch(in)
	if err != nil {
		t.Fatal("well-formed expectation mismatches must still return a complete report", err)
	}
	want := BatchChecks{Passed: false, Matched: 4, Mismatched: 2}
	if len(report.Rows) != len(in.Cases) || report.Checks != want || report.Rows[1].ExpectationMatched || report.Rows[3].ExpectationMatched {
		t.Fatalf("mismatches were lost or promoted to a pass: %+v", report.Checks)
	}
	if report.Rows[5].Receipt.Result.After != batchFixture().Cases[5].ExpectedAfter {
		t.Fatal("the last case did not execute after an earlier mismatch")
	}
	fresh, err := ReplayBatch(report)
	if err != nil || fresh.Checks != want {
		t.Fatal("replay failed to preserve complete failed regression checks", err)
	}
}

func copyBatchReport(t *testing.T, report BatchReport) BatchReport {
	t.Helper()
	raw, err := json.Marshal(report)
	if err != nil {
		t.Fatal(err)
	}
	var copied BatchReport
	if err := json.Unmarshal(raw, &copied); err != nil {
		t.Fatal(err)
	}
	return copied
}

func TestBatchProvenanceBindsActualEmbeddedFiles(t *testing.T) {
	originalGeneration, originalAdapter := Generation, batchAdapterSource
	defer func() { Generation, batchAdapterSource = originalGeneration, originalAdapter }()
	for _, field := range []string{"schema", "source_sha256", "generated_sha256", "adapter_sha256"} {
		t.Run(field, func(t *testing.T) {
			var generation map[string]any
			if err := json.Unmarshal(originalGeneration, &generation); err != nil {
				t.Fatal(err)
			}
			generation[field] = "changed"
			raw, err := json.Marshal(generation)
			if err != nil {
				t.Fatal(err)
			}
			Generation = raw
			if out, err := SimulateBatch(batchFixture()); err == nil || !reflect.DeepEqual(out, BatchReport{}) {
				t.Fatal("unbound generation evidence accepted", err)
			}
		})
	}
	Generation = originalGeneration
	batchAdapterSource += "\nchanged\n"
	if _, err := SimulateBatch(batchFixture()); err == nil {
		t.Fatal("actual embedded adapter was not checked against the evidence")
	}
}

func TestBatchReportDoesNotAuthenticateIssuer(t *testing.T) {
	report, err := SimulateBatch(batchFixture())
	if err != nil {
		t.Fatal(err)
	}
	// A file author can consistently replace the workload, regenerate its actual
	// decision, and recompute every hash. Replay proves reproducibility, not who
	// issued the original report or whether this modification was authorized.
	report.Input.Label = "Consistently rewritten by another file author"
	report.Input.Cases[0].Request.Amount = 50000
	receipt, err := Simulate(batchCaseInput(report.Input, report.Input.Cases[0]))
	if err != nil {
		t.Fatal(err)
	}
	report.Rows[0].Receipt = receipt
	report.CorpusDigest = batchCorpusDigest(report.Input.Cases)
	report.Summary = summarizeBatch(report.Rows)
	report.ID = batchReportID(report)
	if _, err := ReplayBatch(report); err != nil {
		t.Fatal("a consistent unsigned bundle should remain reproducible", err)
	}
}
