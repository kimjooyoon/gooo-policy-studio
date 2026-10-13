//go:build darwin || linux || freebsd || openbsd || netbsd || dragonfly

package admission

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/kimjooyoon/gooo-policy-studio/internal/artifactnumeric"
	"github.com/kimjooyoon/gooo-policy-studio/internal/artifactpreflight"
	"github.com/kimjooyoon/gooo-policy-studio/internal/completion"
	"github.com/kimjooyoon/gooo-policy-studio/internal/machinerules"
)

func int64GateBootstrap(t *testing.T, token string) (Bootstrap, []byte, time.Time) {
	t.Helper()
	b, _, moment := artifactFixture(t, 1)
	b.Preflight.ID = "artifact-impact-row-limit-bounds"
	b.Preflight.Recipe = artifactpreflight.Recipe{Schema: artifactpreflight.NewRecipeSchema, ProducerID: artifactpreflight.NewProducerID, ArtifactSchema: "gooo/export-plan/v1", MaxBytes: 65536,
		Fields: []artifactpreflight.Field{{Name: "action", Type: "text"}, {Name: "destination", Type: "text"}, {Name: "row_limit", Type: "int64"}, {Name: "dry_run", Type: "bool"}, {Name: "format", Type: "text"}},
		Claims: []artifactpreflight.Claim{
			{ID: "action_equal", Verifier: artifactpreflight.VerifierID, Field: "action", Expected: "prepare_export"},
			{ID: "destination_equal", Verifier: artifactpreflight.VerifierID, Field: "destination", Expected: "internal"},
			{ID: "row_limit_at_least", Verifier: artifactpreflight.Int64GTEVerifierID, Field: "row_limit", Expected: "0"},
			{ID: "row_limit_at_most", Verifier: artifactpreflight.Int64LTEVerifierID, Field: "row_limit", Expected: "500"},
			{ID: "dry_run_equal", Verifier: artifactpreflight.VerifierID, Field: "dry_run", Expected: "true"},
			{ID: "format_equal", Verifier: artifactpreflight.VerifierID, Field: "format", Expected: "jsonl"},
		}}
	raw := []byte(fmt.Sprintf("{\n  \"schema\": \"gooo/export-plan/v1\",\n  \"action\": \"prepare_export\",\n  \"destination\": \"internal\",\n  \"row_limit\": %s,\n  \"dry_run\": true,\n  \"format\": \"jsonl\"\n}\n", token))
	replaceArtifactBytes(t, &b, raw, true)
	return b, raw, moment
}

func assertInt64GatePreflight(t *testing.T, report *PreflightReport, row int64, lower, upper artifactnumeric.Decision, pass, fail int64, failed int, admitted bool) {
	t.Helper()
	if report == nil || len(report.Producer.Observations) != 6 || len(report.Evidence) != 6 || len(report.Completion.Steps) != 6 || len(report.Completion.Input.Records) != 6 {
		t.Fatal("gate did not preserve all six claim outcomes")
	}
	counts := completion.Counts{Total: 6, Pass: pass, Fail: fail}
	if report.Completion.Summary.Counts() != counts || report.Completion.Steps[5].Decision.Counts() != counts || report.Completion.Coverage != (completion.Coverage{RequiredCount: 6, MatchedCount: 6, ObservedCount: 6}) || report.Completion.Readiness.Ready != admitted {
		t.Fatal("gate completion disagrees with the literal bounded decisions")
	}
	reason := "EVIDENCE_REJECTED"
	if admitted {
		reason = "ADMITTED"
	}
	wantFacts := machinerules.AdmissionFacts{ProvenanceOK: true, BasePolicyApproved: true, RequiredCount: 6, ObservedCount: 6, AdmissibleEvidenceCount: pass, CompletionReady: admitted, ApprovalEffectAdmissible: true, ControlPlaneEffectAdmissible: true}
	wantDecision := machinerules.AdmissionDecision{Admitted: admitted, Reason: reason, CountsOK: true, ProvenanceOK: true, BasePolicyOK: true, EvidenceOK: admitted, CompletionOK: admitted, ApprovalEffectOK: true, ControlPlaneEffectOK: true}
	if report.AdmissionFacts != wantFacts || report.Decision != wantDecision {
		t.Fatal("gate final native decision lost numeric evidence")
	}
	ids := []string{"action_equal", "destination_equal", "row_limit_at_least", "row_limit_at_most", "dry_run_equal", "format_equal"}
	for i, observation := range report.Producer.Observations {
		status := "pass"
		if i == failed {
			status = "fail"
		}
		if observation.ClaimID != ids[i] || observation.Status != status || report.Evidence[i].ClaimID != ids[i] || report.Evidence[i].Decision.Admissible != (status == "pass") || report.Completion.Input.Records[i].Status != status || report.Completion.Steps[i].Status != status {
			t.Fatalf("gate claim %d does not retain its required outcome", i)
		}
		if i == 2 || i == 3 {
			facts, decision := artifactnumeric.Facts{Value: row, Bound: 0, Operator: "gte"}, lower
			if i == 3 {
				facts, decision = artifactnumeric.Facts{Value: row, Bound: 500, Operator: "lte"}, upper
			}
			p := observation.NativeProof
			if p == nil || p.Facts != facts || p.Decision != decision || p.Bindings != report.Producer.Identity.NumericBindings || p.Bindings.CompilerSourceSHA != artifactnumeric.CompilerSourcePin {
				t.Fatalf("gate numeric proof %d differs from the fixed whole contract", i)
			}
		} else if observation.NativeProof != nil {
			t.Fatal("equality acquired a numeric proof")
		}
	}
}

func TestInt64BoundsTrustedGateTransitionsAndDurableRetry(t *testing.T) {
	cases := []struct {
		row          int64
		sha          string
		lower, upper artifactnumeric.Decision
		pass, fail   int64
		failed       int
		admitted     bool
	}{
		{-1, "sha256:d60f6fc796ff7caede85febd0adda153ef18417b892d8fe97386db1f7356739e", artifactnumeric.Decision{AtMost: true, AtLeast: false, OperatorOK: true, Matched: false, Reason: "BOUND_MISMATCH"}, artifactnumeric.Decision{AtMost: true, AtLeast: false, OperatorOK: true, Matched: true, Reason: "BOUND_MATCH"}, 5, 1, 2, false},
		{500, "sha256:462147ef4a0025b680de1337e78fd91e04a0fa3bd8aae3d438024000839db533", artifactnumeric.Decision{AtMost: false, AtLeast: true, OperatorOK: true, Matched: true, Reason: "BOUND_MATCH"}, artifactnumeric.Decision{AtMost: true, AtLeast: true, OperatorOK: true, Matched: true, Reason: "BOUND_MATCH"}, 6, 0, -1, true},
		{501, "sha256:e6766b36e840581b461fb698048e71622c1f22dc2184460f1431fe42f0171653", artifactnumeric.Decision{AtMost: false, AtLeast: true, OperatorOK: true, Matched: true, Reason: "BOUND_MATCH"}, artifactnumeric.Decision{AtMost: false, AtLeast: true, OperatorOK: true, Matched: false, Reason: "BOUND_MISMATCH"}, 5, 1, 3, false},
	}
	for _, tc := range cases {
		t.Run(fmt.Sprint(tc.row), func(t *testing.T) {
			b, raw, moment := int64GateBootstrap(t, fmt.Sprint(tc.row))
			if b.Artifacts[0].ExpectedSHA256 != tc.sha {
				t.Fatal("trusted fixture bytes differ from their frozen source hash")
			}
			s, dir := artifactStore(t, b, moment)
			command := commandFor(t, s, b.Requests[0].Key, "int64-bound-decision")
			result, err := s.Admit(fixtureToken, command)
			if tc.admitted {
				if err != nil || !result.Outcome.Committed || result.Outcome.NewRevision != 2 || s.state.Requests[0].Status != Approved {
					t.Fatalf("valid bound was not committed once: %v", err)
				}
			} else {
				assertArtifactDenial(t, s, result, err)
			}
			assertInt64GatePreflight(t, result.Outcome.Preflight, tc.row, tc.lower, tc.upper, tc.pass, tc.fail, tc.failed, tc.admitted)
			if result.Outcome.Preflight.Producer.ActualSHA256 != tc.sha || !result.Outcome.Preflight.Producer.TypesOK {
				t.Fatal("gate lost authoritative artifact bytes/types")
			}
			original := cloneValue(result.Outcome)
			if err := os.WriteFile(b.Artifacts[0].Path, append([]byte("changed after decision:"), raw...), 0600); err != nil {
				t.Fatal(err)
			}
			s = reopenStore(t, s, dir)
			again, err := s.Admit(fixtureToken, command)
			if tc.admitted {
				if err != nil {
					t.Fatal(err)
				}
			} else {
				requireCode(t, err, PolicyDenied)
			}
			if !again.Replayed || !reflect.DeepEqual(again.Outcome, original) || len(s.state.Outcomes) != 1 {
				t.Fatal("historical retry reran current artifacts or changed the saved numeric proof")
			}
		})
	}
}

func TestInt64BoundsGateWrongTypeHasNoNativeProof(t *testing.T) {
	b, _, moment := int64GateBootstrap(t, `"500"`)
	s, _ := artifactStore(t, b, moment)
	result, err := s.Admit(fixtureToken, commandFor(t, s, b.Requests[0].Key, "wrong-int64-type"))
	assertArtifactDenial(t, s, result, err)
	report := result.Outcome.Preflight
	if report.Producer.TypesOK || !report.Producer.DigestOK || report.Completion.Summary.Counts() != (completion.Counts{Total: 6, Fail: 6}) {
		t.Fatal("mandatory type failure became an inferred numeric decision")
	}
	for _, observation := range report.Producer.Observations {
		if observation.Status != "fail" || observation.NativeProof != nil {
			t.Fatal("wrong type emitted a native numeric proof")
		}
	}
}

func TestInt64BoundsSnapshotRejectsCoherentlyRehashedProofTampering(t *testing.T) {
	b, _, moment := int64GateBootstrap(t, "500")
	s, dir := artifactStore(t, b, moment)
	if _, err := s.Admit(fixtureToken, commandFor(t, s, b.Requests[0].Key, "saved-numeric-proof")); err != nil {
		t.Fatal(err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	original := savedSnapshot(t, dir)
	cases := []struct {
		name   string
		change func(*artifactpreflight.ClaimObservation)
	}{
		{"facts", func(o *artifactpreflight.ClaimObservation) { o.NativeProof.Facts.Bound = 501 }},
		{"decision", func(o *artifactpreflight.ClaimObservation) { o.NativeProof.Decision.AtLeast = false }},
		{"binding", func(o *artifactpreflight.ClaimObservation) {
			o.NativeProof.Bindings.SourceSHA256 = "sha256:" + strings.Repeat("0", 64)
		}},
		{"absent", func(o *artifactpreflight.ClaimObservation) { o.NativeProof = nil }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			altered := cloneSnapshot(original)
			tc.change(&altered.Outcomes[0].Preflight.Producer.Observations[3])
			altered.Outcomes[0].ID = outcomeID(altered.Outcomes[0])
			replaceSnapshot(t, dir, altered)
			before, err := os.ReadFile(filepath.Join(dir, snapshotName))
			if err != nil {
				t.Fatal(err)
			}
			next, err := Open(dir)
			if next != nil {
				_ = next.Close()
			}
			requireCode(t, err, Unavailable)
			after, readErr := os.ReadFile(filepath.Join(dir, snapshotName))
			if readErr != nil || !bytes.Equal(before, after) {
				t.Fatal("rejection rewrote the inconsistent snapshot")
			}
		})
	}
}

func TestInt64BoundsSnapshotRejectsSyntheticLegacySourceIdentity(t *testing.T) {
	b, _, moment := int64GateBootstrap(t, "500")
	s, dir := artifactStore(t, b, moment)
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	saved := savedSnapshot(t, dir)
	// This is an explicit source-identity fixture, not an imported historical
	// binary/report. Recompute its policy and outer IDs to isolate source refusal.
	saved.Implementation.Producer.Schema = "policy-studio/artifact-producer-source/v1"
	saved.Implementation.Producer.NumericBindings = artifactnumeric.Bindings{}
	saved.PolicyVersion = versionV2(saved)
	replaceSnapshot(t, dir, saved)
	next, err := Open(dir)
	if next != nil {
		_ = next.Close()
	}
	requireCode(t, err, Unavailable)
}
