package completion

import (
	"bytes"
	"encoding/json"
	"fmt"
	"reflect"
	"strings"
	"testing"
)

func testPolicy(claims ...string) Policy {
	return Policy{PolicySchema, "release-policy", 3, claims}
}

func testRecord(claim, status string) Record {
	return Record{claim, status, []string{"ev_" + strings.Repeat("a", 64)}}
}

func testInput(records ...Record) Input {
	return Input{InputSchema, "candidate-a", append([]Record{}, records...)}
}

func marshalForTest(t *testing.T, value any) []byte {
	t.Helper()
	raw, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func checkedForTest(t *testing.T, policy Policy, input Input) Report {
	t.Helper()
	report, err := Check(marshalForTest(t, policy), marshalForTest(t, input))
	if err != nil {
		t.Fatal(err)
	}
	return report
}

func TestAllObservedPassDoesNotSubstituteForRequiredCoverage(t *testing.T) {
	policy := testPolicy("scenario.z", "scenario.a", "scenario.m")
	tests := []struct {
		name       string
		records    []Record
		coverage   Coverage
		missing    []string
		unexpected []string
		ready      bool
	}{
		{"complete", []Record{testRecord("scenario.a", "pass"), testRecord("scenario.m", "pass"), testRecord("scenario.z", "pass")}, Coverage{3, 3, 0, 3}, []string{}, []string{}, true},
		{"missing", []Record{testRecord("scenario.m", "pass")}, Coverage{3, 1, 0, 1}, []string{"scenario.a", "scenario.z"}, []string{}, false},
		{"replacement", []Record{testRecord("scenario.a", "pass"), testRecord("scenario.x", "pass"), testRecord("scenario.b", "pass")}, Coverage{3, 1, 2, 3}, []string{"scenario.m", "scenario.z"}, []string{"scenario.b", "scenario.x"}, false},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			input := testInput(test.records...)
			report := checkedForTest(t, policy, input)
			if !report.Summary.Complete || report.Coverage != test.coverage || report.Readiness.Ready != test.ready ||
				!reflect.DeepEqual(report.MissingClaims, test.missing) || !reflect.DeepEqual(report.UnexpectedClaims, test.unexpected) {
				t.Fatalf("wrong complete report: %+v", report)
			}
			if !test.ready && report.Readiness.Reason != "INCOMPLETE_CLAIM_COVERAGE" {
				t.Fatalf("all-pass incomplete coverage reason = %q", report.Readiness.Reason)
			}
			if !reflect.DeepEqual(report.Policy, policy) || !reflect.DeepEqual(report.Input, input) {
				t.Fatal("supplied policy or record order was altered")
			}
		})
	}
}

func TestLaterPassCannotEraseEarlierNonPassOutcomes(t *testing.T) {
	statuses := []string{"unsupported", "pass", "unknown", "truncated", "fail", "pass"}
	expected := []Counts{
		{1, 0, 0, 1, 0, 0}, {2, 1, 0, 1, 0, 0}, {3, 1, 0, 1, 0, 1},
		{4, 1, 0, 1, 1, 1}, {5, 1, 1, 1, 1, 1}, {6, 2, 1, 1, 1, 1},
	}
	var claims []string
	var records []Record
	for i, status := range statuses {
		claim := fmt.Sprintf("scenario.%d", i)
		claims = append(claims, claim)
		records = append(records, testRecord(claim, status))
	}
	report := checkedForTest(t, testPolicy(claims...), testInput(records...))
	if len(report.Steps) != 6 || report.Summary.Counts() != expected[5] || report.Summary.Complete ||
		!report.Summary.Valid || report.Summary.Reason != "NON_PASS_RESULTS" || report.Readiness.Ready ||
		report.Readiness.Reason != "NON_PASS_RESULTS" || !report.Readiness.CoverageOK || !report.Readiness.SummaryOK {
		t.Fatalf("wrong non-pass summary/readiness: %+v", report)
	}
	for i, step := range report.Steps {
		before := Counts{}
		if i > 0 {
			before = expected[i-1]
		}
		if step.Index != int64(i) || step.Status != statuses[i] || step.CountsBefore != before ||
			step.Decision.Counts() != expected[i] || !step.Decision.Valid || step.Decision.Complete || step.Decision.Reason != "ACCUMULATED" {
			t.Fatalf("step %d lost a supplied outcome: %+v", i, step)
		}
	}
}

func TestEmptyRecordsProduceCompleteNotReadyReportWithArrays(t *testing.T) {
	report := checkedForTest(t, testPolicy("scenario.z", "scenario.a"), testInput())
	if report.Summary != (Decision{Reason: "NO_RECORDS"}) || report.Readiness.Ready ||
		report.Coverage != (Coverage{RequiredCount: 2}) || !reflect.DeepEqual(report.MissingClaims, []string{"scenario.a", "scenario.z"}) {
		t.Fatalf("wrong empty report: %+v", report)
	}
	raw := marshalForTest(t, report)
	if bytes.Contains(raw, []byte("null")) || len(report.Steps) != 0 {
		t.Fatal("empty report must encode arrays as [] and retain no fabricated step")
	}
}

func TestFullHostCapacityAndMultipleEvidenceItemsAreSupported(t *testing.T) {
	claims := make([]string, MaxRecords)
	records := make([]Record, MaxRecords)
	for i := range records {
		claims[i] = fmt.Sprintf("scenario.%03d", i)
		records[i] = testRecord(claims[i], "pass")
	}
	// More than four rows and more than one hundred evidence items are real
	// supported inputs; the finite source test domains do not constrain this API.
	records[0].EvidenceIDs = make([]string, 101)
	for i := range records[0].EvidenceIDs {
		records[0].EvidenceIDs[i] = fmt.Sprintf("ev_%064x", 100-i)
	}
	report := checkedForTest(t, testPolicy(claims...), testInput(records...))
	if !report.Readiness.Ready || report.Summary.Total != 256 || report.Summary.Pass != 256 || len(report.Steps) != 256 ||
		!reflect.DeepEqual(report.Input.Records[0].EvidenceIDs, records[0].EvidenceIDs) {
		t.Fatalf("host capacity or evidence order was narrowed: %+v", report.Summary)
	}
	tooMany := append(append([]Record{}, records...), testRecord("scenario.extra", "pass"))
	if _, err := Check(marshalForTest(t, testPolicy(claims...)), marshalForTest(t, testInput(tooMany...))); err == nil {
		t.Fatal("257 observed records must be rejected")
	}
	if _, _, err := DecodePolicy(marshalForTest(t, testPolicy(append(claims, "scenario.extra")...))); err == nil {
		t.Fatal("257 required claims must be rejected")
	}
}

func TestDecodeRejectsAmbiguousOrClientSelectedPolicyBeforeExecution(t *testing.T) {
	policy := marshalForTest(t, testPolicy("scenario.a"))
	valid := string(marshalForTest(t, testInput(testRecord("scenario.a", "pass"))))
	tests := []string{
		strings.Replace(valid, `"request_id":"candidate-a"`, `"request_id":"candidate-a","request_id":"candidate-b"`, 1),
		strings.Replace(valid, `"status":"pass"`, `"status":"pass","status":"fail"`, 1),
		strings.Replace(valid, `"status":"pass"`, `"Status":"pass"`, 1),
		strings.Replace(valid, `"status":"pass"`, `"status":null`, 1),
		strings.Replace(valid, `"records":[`, `"records":null,"discarded":[`, 1),
		strings.Replace(valid, `"schema":`, `"required_claims":["scenario.a"],"schema":`, 1),
		strings.Replace(valid, `"schema":`, `"policy":{},"schema":`, 1),
		strings.Replace(valid, `"status":"pass"`, `"status":true`, 1),
		strings.Replace(valid, `"request_id":"candidate-a"`, `"request_id":"candidate\ud800"`, 1),
		valid + ` {}`,
		strings.Replace(valid, "candidate-a", "candidate-\xff", 1),
	}
	for i, input := range tests {
		if _, err := Check(policy, []byte(input)); err == nil {
			t.Fatalf("ambiguous structural input %d was accepted", i)
		}
	}
	for _, field := range []string{`"revision":0`, `"revision":-1`, `"revision":3.0`, `"revision":true`, `"revision":9223372036854775808`, `"revision":null`} {
		bad := strings.Replace(string(policy), `"revision":3`, field, 1)
		if _, _, err := DecodePolicy([]byte(bad)); err == nil {
			t.Fatalf("bad policy numeric field was accepted: %s", field)
		}
	}
}

func TestDomainChecksRejectDuplicatesAndInvalidExactLabels(t *testing.T) {
	valid := testInput(testRecord("scenario.a", "pass"))
	tests := []Input{}
	add := func(change func(*Input)) {
		input := cloneInput(valid)
		change(&input)
		tests = append(tests, input)
	}
	add(func(in *Input) { in.Records = append(in.Records, in.Records[0]) })
	add(func(in *Input) {
		in.Records[0].EvidenceIDs = append(in.Records[0].EvidenceIDs, in.Records[0].EvidenceIDs[0])
	})
	add(func(in *Input) { in.Records[0].EvidenceIDs = []string{} })
	add(func(in *Input) { in.Records[0].EvidenceIDs = []string{"ev_" + strings.Repeat("A", 64)} })
	add(func(in *Input) { in.Records[0].EvidenceIDs = []string{"ev_not-a-digest"} })
	add(func(in *Input) { in.Records[0].Status = "Pass" })
	add(func(in *Input) { in.Records[0].Status = "pass " })
	add(func(in *Input) { in.Records[0].Status = "skipped" })
	add(func(in *Input) { in.Records[0].ClaimID = "scenario/a" })
	add(func(in *Input) { in.Records[0].ClaimID = "1scenario" })
	add(func(in *Input) { in.RequestID = strings.Repeat("a", 81) })
	for i, input := range tests {
		if err := ValidateInput(input); err == nil {
			t.Fatalf("invalid domain input %d was accepted", i)
		}
	}
	if err := ValidatePolicy(testPolicy("scenario.a", "scenario.a")); err == nil {
		t.Fatal("duplicate configured claims were accepted")
	}
	// Sharing one supplied evidence label between different claims is allowed.
	if _, err := Check(marshalForTest(t, testPolicy("scenario.a", "scenario.b")), marshalForTest(t, testInput(testRecord("scenario.a", "pass"), testRecord("scenario.b", "pass")))); err != nil {
		t.Fatalf("cross-claim evidence label reuse was incorrectly rejected: %v", err)
	}
}

func TestReplayRejectsDerivedTamperingAndCurrentPolicyChanges(t *testing.T) {
	policy := testPolicy("scenario.a", "scenario.b")
	policyRaw := marshalForTest(t, policy)
	_, policyDigest, err := DecodePolicy(policyRaw)
	if err != nil {
		t.Fatal(err)
	}
	report := checkedForTest(t, policy, testInput(testRecord("scenario.a", "pass"), testRecord("scenario.b", "unknown")))
	if replay, err := Replay(policy, policyDigest, report); err != nil || !reflect.DeepEqual(replay, report) {
		t.Fatalf("unchanged complete report did not replay: %v", err)
	}
	mutations := []func(*Report){
		func(r *Report) { r.Schema = "other/v1" },
		func(r *Report) { r.Policy.Revision++ },
		func(r *Report) { r.Policy.RequiredClaims[0] = "scenario.c" },
		func(r *Report) { r.Input.Records[1].Status = "pass" },
		func(r *Report) { r.Steps[1].CountsBefore.Pass++ },
		func(r *Report) { r.Steps[1].Index = 0 },
		func(r *Report) { r.Steps[0].Status = "fail" },
		func(r *Report) { r.Steps[1].Decision.Unknown = 0 },
		func(r *Report) { r.Steps = r.Steps[:1] },
		func(r *Report) { r.Summary.Complete = true },
		func(r *Report) { r.Coverage.MatchedCount = 1 },
		func(r *Report) { r.MissingClaims = []string{"scenario.b"} },
		func(r *Report) { r.UnexpectedClaims = []string{"scenario.c"} },
		func(r *Report) { r.Readiness.Ready = true },
		func(r *Report) { r.Readiness.SummaryOK = false },
		func(r *Report) { r.Bindings.PolicySHA256 = digest([]byte("other policy")) },
		func(r *Report) { r.Bindings.SourceSHA256 = digest([]byte("other source")) },
		func(r *Report) { r.Bindings.GeneratedSHA256 = digest([]byte("other generated")) },
		func(r *Report) { r.Bindings.BridgeSHA256 = digest([]byte("other bridge")) },
		func(r *Report) { r.Bindings.GenerationSHA256 = digest([]byte("other generation")) },
		func(r *Report) { r.Bindings.CompilerSourceSHA = strings.Repeat("0", 40) },
	}
	for i, mutate := range mutations {
		var altered Report
		if err := json.Unmarshal(marshalForTest(t, report), &altered); err != nil {
			t.Fatal(err)
		}
		mutate(&altered)
		if _, err := Replay(policy, policyDigest, altered); err == nil {
			t.Fatalf("derived/binding mutation %d was accepted", i)
		}
	}
	changed := clonePolicy(policy)
	changed.Revision++
	if _, err := Replay(changed, digest(marshalForTest(t, changed)), report); err == nil {
		t.Fatal("replay trusted the embedded retired policy")
	}
	if _, err := Replay(policy, digest(append(policyRaw, '\n')), report); err == nil {
		t.Fatal("a change to the actual policy file bytes was not detected")
	}
}

func TestUnsignedReplayDoesNotClaimAuthenticationOfSuppliedEvidence(t *testing.T) {
	policy := testPolicy("scenario.a")
	report := checkedForTest(t, policy, testInput(testRecord("scenario.a", "pass")))
	// This label is an input fact, not authenticated evidence. A consistently
	// changed valid label still produces the same Gooo counters/readiness.
	report.Input.Records[0].EvidenceIDs[0] = "ev_" + strings.Repeat("b", 64)
	if _, err := Replay(policy, report.Bindings.PolicySHA256, report); err != nil {
		t.Fatalf("unsigned replay was misrepresented as issuer authentication: %v", err)
	}
}
