package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"testing"

	"github.com/kimjooyoon/gooo-policy-studio/internal/policy"
)

const samplePath = "../../examples/automation-policy/impact-input.json"

func TestHeadlessCheckAndReplayExitCodes(t *testing.T) {
	raw, err := os.ReadFile(samplePath)
	if err != nil {
		t.Fatal(err)
	}
	var output, diagnostics bytes.Buffer
	if status := run([]string{"--input", samplePath}, strings.NewReader(""), &output, &diagnostics); status != 0 {
		t.Fatalf("sample exit %d: %s", status, diagnostics.String())
	}
	var report policy.BatchReport
	if err := json.Unmarshal(output.Bytes(), &report); err != nil {
		t.Fatal(err)
	}
	if !report.Checks.Passed || report.Checks.Matched != 5 || len(report.Rows) != 5 || report.Summary.NewlyApproved != 1 {
		t.Fatalf("sample not completely observed: %+v", report.Checks)
	}
	saved := append([]byte(nil), output.Bytes()...)
	output.Reset()
	if status := run([]string{"--replay"}, bytes.NewReader(saved), &output, &diagnostics); status != 0 {
		t.Fatalf("replay exit %d: %s", status, diagnostics.String())
	}
	// Preserve the independently authored expectation while lowering the new
	// limit. A complete report must remain available, with a failing exit code.
	raw = bytes.Replace(raw, []byte(`"limit": 1000000`), []byte(`"limit": 500000`), 1)
	output.Reset()
	if status := run(nil, bytes.NewReader(raw), &output, &diagnostics); status != 1 {
		t.Fatalf("mismatch exit %d", status)
	}
	if err := json.Unmarshal(output.Bytes(), &report); err != nil {
		t.Fatal(err)
	}
	if report.Checks.Passed || report.Checks.Mismatched != 1 || len(report.Rows) != 5 {
		t.Fatal("mismatch was hidden or report truncated")
	}
	saved = append([]byte(nil), output.Bytes()...)
	output.Reset()
	if status := run([]string{"--replay"}, bytes.NewReader(saved), &output, &diagnostics); status != 1 {
		t.Fatalf("failed report replay became pass: %d", status)
	}
}

func TestHeadlessRejectsAmbiguousInputAndOutputFailure(t *testing.T) {
	raw, err := os.ReadFile(samplePath)
	if err != nil {
		t.Fatal(err)
	}
	for _, input := range [][]byte{
		bytes.Replace(raw, []byte(`"amount": 750000`), []byte(`"amount": 750000,"Amount":0`), 1),
		bytes.Replace(raw, []byte(`"amount": 750000`), []byte(`"amount": 750000,"amount":0`), 1),
		[]byte(strings.Repeat(" ", maxInputBytes+1)),
	} {
		var output, diagnostics bytes.Buffer
		if code := run(nil, bytes.NewReader(input), &output, &diagnostics); code != 2 || output.Len() != 0 {
			t.Fatalf("invalid input produced report/exit%d", code)
		}
	}
	var diagnostics bytes.Buffer
	if code := run(nil, bytes.NewReader(raw), failingWriter{}, &diagnostics); code != 2 {
		t.Fatalf("write failure exit%d", code)
	}
}

type failingWriter struct{}

func (failingWriter) Write([]byte) (int, error) { return 0, os.ErrPermission }

func TestMaximumEscapedWorkloadRemainsReplayable(t *testing.T) {
	// All domain strings are at their byte limit, and each byte requires JSON
	// escaping. This exercises the worst size expansion of a valid workload.
	text := strings.Repeat("<", 120)
	rules := policy.Rules{Limit: 1, SameTeam: true, ActiveReviewer: true, PreventSelf: false}
	in := policy.BatchInput{Schema: policy.BatchInputSchema, Label: "max escaped workload", Before: rules, After: rules}
	for i := 0; i < policy.MaxBatchCases; i++ {
		in.Cases = append(in.Cases, policy.Case{
			ID:            fmt.Sprintf("%03d", i) + strings.Repeat("x", 77),
			Request:       policy.Request{Key: text, Requester: text, Team: text, Amount: 1, Submitted: true},
			Reviewer:      policy.Reviewer{Key: text, Team: text, Active: true},
			ExpectedAfter: policy.Decision{Approved: true, Reason: "APPROVED", AmountOK: true, TeamOK: true, ReviewerOK: true, SelfOK: true, SubmittedOK: true},
		})
	}
	raw, _ := json.Marshal(in)
	if len(raw) > maxInputBytes {
		t.Fatal("maximum valid input exceeds admitted cap")
	}
	var out, diagnostics bytes.Buffer
	if code := run(nil, bytes.NewReader(raw), &out, &diagnostics); code != 0 {
		t.Fatal(code, diagnostics.String())
	}
	if out.Len() <= 2<<20 || out.Len() > 4<<20 {
		t.Fatalf("expected expanded report between2 and4MiB, got%d", out.Len())
	}
	saved := append([]byte(nil), out.Bytes()...)
	out.Reset()
	if code := run([]string{"--replay"}, bytes.NewReader(saved), &out, &diagnostics); code != 0 {
		t.Fatal("valid exported report cannot round-trip", code, diagnostics.String())
	}
}
