package artifactimpact

import (
	"encoding/base64"
	"fmt"
	"os"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/kimjooyoon/gooo-policy-studio/internal/artifactnumeric"
	"github.com/kimjooyoon/gooo-policy-studio/internal/artifactpreflight"
	"github.com/kimjooyoon/gooo-policy-studio/internal/completion"
	"github.com/kimjooyoon/gooo-policy-studio/internal/machinerules"
)

// These six rows and their complete native decisions come from the source-only
// fixture contract frozen before the new native activity was executed.
type int64ImpactExpectation struct {
	row                         int64
	sha                         string
	lower, upper                artifactnumeric.Decision
	before, after               bool
	beforeCounts, afterCounts   completion.Counts
	beforeFailure, afterFailure int
	direction                   string
}

var int64ImpactRows = []int64ImpactExpectation{
	{-1, "sha256:d60f6fc796ff7caede85febd0adda153ef18417b892d8fe97386db1f7356739e", artifactnumeric.Decision{AtMost: true, AtLeast: false, OperatorOK: true, Matched: false, Reason: "BOUND_MISMATCH"}, artifactnumeric.Decision{AtMost: true, AtLeast: false, OperatorOK: true, Matched: true, Reason: "BOUND_MATCH"}, false, false, completion.Counts{Total: 6, Pass: 5, Fail: 1}, completion.Counts{Total: 6, Pass: 5, Fail: 1}, 2, 2, "unchanged"},
	{0, "sha256:40b8270ab3e1a7c8d2a20cce209c8051b1666a8fe983ef10391802d2cf7d6ac6", artifactnumeric.Decision{AtMost: true, AtLeast: true, OperatorOK: true, Matched: true, Reason: "BOUND_MATCH"}, artifactnumeric.Decision{AtMost: true, AtLeast: false, OperatorOK: true, Matched: true, Reason: "BOUND_MATCH"}, true, true, completion.Counts{Total: 6, Pass: 6}, completion.Counts{Total: 6, Pass: 6}, -1, -1, "unchanged"},
	{100, "sha256:429b281f3f90562129e2365366b31afccf104610d67463a0aa02938e0c8a6fc3", artifactnumeric.Decision{AtMost: false, AtLeast: true, OperatorOK: true, Matched: true, Reason: "BOUND_MATCH"}, artifactnumeric.Decision{AtMost: true, AtLeast: false, OperatorOK: true, Matched: true, Reason: "BOUND_MATCH"}, true, true, completion.Counts{Total: 6, Pass: 6}, completion.Counts{Total: 6, Pass: 6}, -1, -1, "unchanged"},
	{499, "sha256:ecddf9e6ec96e10d815c0a7d9a9cea1040f124c22dfe8e43b393a9dc4568d981", artifactnumeric.Decision{AtMost: false, AtLeast: true, OperatorOK: true, Matched: true, Reason: "BOUND_MATCH"}, artifactnumeric.Decision{AtMost: true, AtLeast: false, OperatorOK: true, Matched: true, Reason: "BOUND_MATCH"}, true, true, completion.Counts{Total: 6, Pass: 6}, completion.Counts{Total: 6, Pass: 6}, -1, -1, "unchanged"},
	{500, "sha256:462147ef4a0025b680de1337e78fd91e04a0fa3bd8aae3d438024000839db533", artifactnumeric.Decision{AtMost: false, AtLeast: true, OperatorOK: true, Matched: true, Reason: "BOUND_MATCH"}, artifactnumeric.Decision{AtMost: true, AtLeast: true, OperatorOK: true, Matched: true, Reason: "BOUND_MATCH"}, true, true, completion.Counts{Total: 6, Pass: 6}, completion.Counts{Total: 6, Pass: 6}, -1, -1, "unchanged"},
	{501, "sha256:e6766b36e840581b461fb698048e71622c1f22dc2184460f1431fe42f0171653", artifactnumeric.Decision{AtMost: false, AtLeast: true, OperatorOK: true, Matched: true, Reason: "BOUND_MATCH"}, artifactnumeric.Decision{AtMost: false, AtLeast: true, OperatorOK: true, Matched: false, Reason: "BOUND_MISMATCH"}, true, false, completion.Counts{Total: 6, Pass: 6}, completion.Counts{Total: 6, Pass: 5, Fail: 1}, -1, 3, "newly_denied"},
}

func int64ImpactRecipe(upper string) artifactpreflight.Recipe {
	return artifactpreflight.Recipe{Schema: artifactpreflight.NewRecipeSchema, ProducerID: artifactpreflight.NewProducerID, ArtifactSchema: "gooo/export-plan/v1", MaxBytes: 65536,
		Fields: []artifactpreflight.Field{{Name: "action", Type: "text"}, {Name: "destination", Type: "text"}, {Name: "row_limit", Type: "int64"}, {Name: "dry_run", Type: "bool"}, {Name: "format", Type: "text"}},
		Claims: []artifactpreflight.Claim{
			{ID: "action_equal", Verifier: artifactpreflight.VerifierID, Field: "action", Expected: "prepare_export"},
			{ID: "destination_equal", Verifier: artifactpreflight.VerifierID, Field: "destination", Expected: "internal"},
			{ID: "row_limit_at_least", Verifier: artifactpreflight.Int64GTEVerifierID, Field: "row_limit", Expected: "0"},
			{ID: "row_limit_at_most", Verifier: artifactpreflight.Int64LTEVerifierID, Field: "row_limit", Expected: upper},
			{ID: "dry_run_equal", Verifier: artifactpreflight.VerifierID, Field: "dry_run", Expected: "true"},
			{ID: "format_equal", Verifier: artifactpreflight.VerifierID, Field: "format", Expected: "jsonl"},
		}}
}

func int64ImpactFixture(t *testing.T, token, sha string) (Paths, Case) {
	t.Helper()
	paths, c, before := fixture(t, 1)
	raw := []byte(fmt.Sprintf("{\n  \"schema\": \"gooo/export-plan/v1\",\n  \"action\": \"prepare_export\",\n  \"destination\": \"internal\",\n  \"row_limit\": %s,\n  \"dry_run\": true,\n  \"format\": \"jsonl\"\n}\n", token))
	if digest(raw) != sha {
		t.Fatal("authored fixture bytes differ from the frozen trusted digest")
	}
	if err := os.WriteFile(c.Artifact.Path, raw, 0600); err != nil {
		t.Fatal(err)
	}
	c.Artifact.ExpectedSHA256 = sha
	before.ID, before.Recipe = "artifact-impact-row-limit-bounds", int64ImpactRecipe("1000")
	after := before
	after.Revision, after.Recipe = 2, int64ImpactRecipe("500")
	privateJSON(t, paths.Case, c)
	privateJSON(t, paths.Before, before)
	privateJSON(t, paths.After, after)
	return paths, c
}

func assertInt64ImpactSide(t *testing.T, side Side, row, upperBound int64, lower, upper artifactnumeric.Decision, counts completion.Counts, failed int, admitted bool, rawSHA string) {
	t.Helper()
	if len(side.Producer.Observations) != 6 || len(side.Evidence) != 6 || len(side.Completion.Steps) != 6 || len(side.Completion.Input.Records) != 6 || len(side.Completion.Policy.RequiredClaims) != 6 {
		t.Fatal("six required claims were not retained")
	}
	if side.Producer.Schema != artifactpreflight.ReportSchema || side.Producer.ProducerID != artifactpreflight.NewProducerID || !side.Producer.DigestOK || !side.Producer.SchemaOK || !side.Producer.TypesOK || side.Producer.ActualSHA256 != rawSHA {
		t.Fatal("mandatory artifact or producer binding changed")
	}
	if side.Completion.Summary.Counts() != counts || side.Completion.Steps[5].Decision.Counts() != counts || side.Completion.Coverage != (completion.Coverage{RequiredCount: 6, MatchedCount: 6, ObservedCount: 6}) {
		t.Fatal("whole ordered completion counts disagree")
	}
	readyReason, summaryReason, admissionReason := "NON_PASS_RESULTS", "NON_PASS_RESULTS", "EVIDENCE_REJECTED"
	if admitted {
		readyReason, summaryReason, admissionReason = "READY", "ALL_PASS", "ADMITTED"
	}
	wantReady := completion.Readiness{Ready: admitted, Reason: readyReason, CountsOK: true, CoverageOK: true, SummaryOK: true, AllPassOK: admitted}
	if side.Completion.Readiness != wantReady || !side.Completion.Summary.Valid || side.Completion.Summary.Complete != admitted || side.Completion.Summary.Reason != summaryReason || len(side.Completion.MissingClaims) != 0 || len(side.Completion.UnexpectedClaims) != 0 {
		t.Fatal("completion readiness lost a failed bound")
	}
	wantFacts := machinerules.AdmissionFacts{ProvenanceOK: true, BasePolicyApproved: true, RequiredCount: 6, ObservedCount: 6, AdmissibleEvidenceCount: counts.Pass, CompletionReady: admitted, ApprovalEffectAdmissible: true, ControlPlaneEffectAdmissible: true}
	wantDecision := machinerules.AdmissionDecision{Admitted: admitted, Reason: admissionReason, CountsOK: true, ProvenanceOK: true, BasePolicyOK: true, EvidenceOK: admitted, CompletionOK: admitted, ApprovalEffectOK: true, ControlPlaneEffectOK: true}
	if side.AdmissionFacts != wantFacts || side.Decision != wantDecision || side.WouldAdmit != admitted || side.Reason != admissionReason {
		t.Fatal("numeric evidence did not reach the complete final native decision")
	}
	for i, observation := range side.Producer.Observations {
		claim := side.Context.Policy.Recipe.Claims[i]
		status, evidenceReason := "pass", "ADMISSIBLE"
		if i == failed {
			status, evidenceReason = "fail", "EVIDENCE_INCOMPLETE"
		}
		pass := status == "pass"
		wantEvidence := machinerules.EvidenceDecision{Admissible: pass, Reason: evidenceReason, ProviderOK: true, EvidenceOK: pass, AuthorityOK: true, BindingOK: true, ArtifactOK: true, PolicyOK: true, FreshnessOK: true, DeadlineOK: true}
		if observation.ClaimID != claim.ID || observation.Status != status || side.Evidence[i].ClaimID != claim.ID || side.Evidence[i].Decision != wantEvidence || side.Completion.Policy.RequiredClaims[i] != claim.ID || side.Completion.Input.Records[i].ClaimID != claim.ID || side.Completion.Input.Records[i].Status != status || side.Completion.Steps[i].Index != int64(i) || side.Completion.Steps[i].Status != status {
			t.Fatalf("claim %d lost its ordered evidence/decision", i)
		}
		if i == 2 || i == 3 {
			facts, decision := artifactnumeric.Facts{Value: row, Bound: 0, Operator: "gte"}, lower
			if i == 3 {
				facts, decision = artifactnumeric.Facts{Value: row, Bound: upperBound, Operator: "lte"}, upper
			}
			proof := observation.NativeProof
			if proof == nil || proof.Facts != facts || proof.Decision != decision || proof.Bindings != side.Producer.Identity.NumericBindings || proof.Bindings.Schema != artifactnumeric.BindingsSchema || proof.Bindings.CompilerSourceSHA != artifactnumeric.CompilerSourcePin {
				t.Fatalf("claim %d native whole proof differs from frozen literals", i)
			}
		} else if observation.NativeProof != nil {
			t.Fatal("equality claim acquired a numeric proof")
		}
	}
}

func TestInt64BoundsComparisonSixClaimsAndReverse(t *testing.T) {
	for _, tc := range int64ImpactRows {
		t.Run(fmt.Sprint(tc.row), func(t *testing.T) {
			paths, c := int64ImpactFixture(t, fmt.Sprint(tc.row), tc.sha)
			r := assertComparison(t, paths, tc.before, tc.after, tc.direction)
			assertInt64ImpactSide(t, r.Before, tc.row, 1000, tc.lower, artifactnumeric.Decision{AtMost: true, AtLeast: false, OperatorOK: true, Matched: true, Reason: "BOUND_MATCH"}, tc.beforeCounts, tc.beforeFailure, tc.before, tc.sha)
			assertInt64ImpactSide(t, r.After, tc.row, 500, tc.lower, tc.upper, tc.afterCounts, tc.afterFailure, tc.after, tc.sha)
			if len(r.Delta.Changed) != 1 || r.Delta.Changed[0].ClaimID != "row_limit_at_most" || !r.Delta.Changed[0].PredicateChanged || len(r.Delta.Added) != 0 || len(r.Delta.Removed) != 0 || r.Delta.ClaimOrderChanged || r.Audit.ArtifactReadAttempts != 1 {
				t.Fatal("rollout delta or one-capture boundary changed")
			}
			raw, _ := os.ReadFile(c.Artifact.Path)
			if r.Before.Producer.ArtifactBase64 != base64.StdEncoding.EncodeToString(raw) || r.After.Producer.ArtifactBase64 != r.Before.Producer.ArtifactBase64 {
				t.Fatal("comparison did not retain the same exact source bytes")
			}
		})
	}
	t.Run("501-reverse", func(t *testing.T) {
		tc := int64ImpactRows[5]
		paths, _ := int64ImpactFixture(t, "501", tc.sha)
		paths.Before, paths.After = paths.After, paths.Before
		r := assertComparison(t, paths, false, true, "newly_allowed")
		assertInt64ImpactSide(t, r.Before, 501, 500, tc.lower, tc.upper, tc.afterCounts, 3, false, tc.sha)
		assertInt64ImpactSide(t, r.After, 501, 1000, tc.lower, artifactnumeric.Decision{AtMost: true, AtLeast: false, OperatorOK: true, Matched: true, Reason: "BOUND_MATCH"}, tc.beforeCounts, -1, true, tc.sha)
	})
}

func TestInt64BoundsMandatoryTypeFailureHasNoNumericProof(t *testing.T) {
	paths, _ := int64ImpactFixture(t, `"500"`, "sha256:a01dd2631ea252f8730bcf1f5aa2439ee78ccfae9d68c1e9ce165bd56c994465")
	r := assertComparison(t, paths, false, false, "unchanged")
	for _, side := range []Side{r.Before, r.After} {
		if !side.Producer.DigestOK || !side.Producer.SchemaOK || side.Producer.TypesOK || side.Completion.Summary.Counts() != (completion.Counts{Total: 6, Fail: 6}) || side.Decision.Admitted {
			t.Fatal("wrong type was guessed into a numeric value")
		}
		for _, observation := range side.Producer.Observations {
			if observation.Status != "fail" || observation.NativeProof != nil {
				t.Fatal("mandatory failure executed or retained a native numeric proof")
			}
		}
	}
}

func TestInt64BoundsInvalidRecipesFailBeforeAcquisitionAndReservation(t *testing.T) {
	cases := []struct {
		name   string
		change func(*artifactpreflight.Recipe)
	}{
		{"legacy-v1", func(r *artifactpreflight.Recipe) {
			r.Schema, r.ProducerID = artifactpreflight.RecipeSchema, artifactpreflight.ProducerID
		}},
		{"text", func(r *artifactpreflight.Recipe) { r.Claims[3].Field = "destination" }},
		{"bool", func(r *artifactpreflight.Recipe) { r.Claims[3].Field = "dry_run" }},
		{"unknown-verifier", func(r *artifactpreflight.Recipe) { r.Claims[3].Verifier = "field_int64_lt/v1" }},
		{"noncanonical", func(r *artifactpreflight.Recipe) { r.Claims[3].Expected = "500.0" }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			paths, c := int64ImpactFixture(t, "500", int64ImpactRows[4].sha)
			if err := os.Remove(c.Artifact.Path); err != nil {
				t.Fatal(err)
			}
			p := testPolicy(1)
			p.Recipe = int64ImpactRecipe("500")
			tc.change(&p.Recipe)
			privateJSON(t, paths.After, p)
			reads := 0
			s, exit := compareFiles(paths, dependencies{readArtifact: func(artifactpreflight.Requirement, int64) (artifactpreflight.Acquisition, error) {
				reads++
				return artifactpreflight.Acquisition{}, fmt.Errorf("unexpected read")
			}, now: func() time.Time { return time.Unix(testUnix, 0) }})
			if exit != 2 || s.Code != "AFTER_POLICY_INVALID" || s.ReportSaved || reads != 0 {
				t.Fatalf("invalid recipe reached acquisition/reservation: %+v reads=%d", s, reads)
			}
			if _, err := os.Lstat(paths.Report); !os.IsNotExist(err) {
				t.Fatal("invalid recipe reserved an output")
			}
		})
	}
}

func TestInt64BoundsSavedReplayRejectsWholeProofAndLegacyIdentityTampering(t *testing.T) {
	paths, c := int64ImpactFixture(t, "501", int64ImpactRows[5].sha)
	saved := assertComparison(t, paths, true, false, "newly_denied")
	if err := os.Remove(c.Artifact.Path); err != nil {
		t.Fatal(err)
	}
	if got, err := Replay(saved); err != nil || !reflect.DeepEqual(got, saved) {
		t.Fatalf("retained numeric replay changed: %v", err)
	}
	cases := []struct {
		name   string
		change func(*Report)
	}{
		{"input", func(r *Report) { r.After.Producer.Observations[3].NativeProof.Facts.Value = 500 }},
		{"at-most", func(r *Report) { r.After.Producer.Observations[3].NativeProof.Decision.AtMost = true }},
		{"at-least", func(r *Report) { r.After.Producer.Observations[3].NativeProof.Decision.AtLeast = false }},
		{"operator-ok", func(r *Report) { r.After.Producer.Observations[3].NativeProof.Decision.OperatorOK = false }},
		{"matched", func(r *Report) { r.After.Producer.Observations[3].NativeProof.Decision.Matched = true }},
		{"reason", func(r *Report) { r.After.Producer.Observations[3].NativeProof.Decision.Reason = "BOUND_MATCH" }},
		{"binding", func(r *Report) {
			r.After.Producer.Observations[3].NativeProof.Bindings.SourceSHA256 = "sha256:" + strings.Repeat("0", 64)
		}},
		{"missing-proof", func(r *Report) { r.After.Producer.Observations[3].NativeProof = nil }},
		{"equality-proof", func(r *Report) {
			p := *r.After.Producer.Observations[3].NativeProof
			r.After.Producer.Observations[0].NativeProof = &p
		}},
		{"synthetic-legacy-source", func(r *Report) {
			r.Implementation.Producer.Schema = "policy-studio/artifact-producer-source/v1"
			r.Implementation.Producer.NumericBindings = artifactnumeric.Bindings{}
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			altered := ownedReplayTestReport(t, saved)
			tc.change(&altered)
			rehashReplayTestReport(&altered)
			if _, err := Replay(altered); err == nil {
				t.Fatal("coherently rehashed but altered native proof/source identity was accepted")
			}
		})
	}
}
