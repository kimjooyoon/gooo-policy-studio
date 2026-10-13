package artifactimpact

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/kimjooyoon/gooo-policy-studio/internal/admission"
	"github.com/kimjooyoon/gooo-policy-studio/internal/artifactpreflight"
	"github.com/kimjooyoon/gooo-policy-studio/internal/machinerules"
	"github.com/kimjooyoon/gooo-policy-studio/internal/policy"
)

const testUnix int64 = 1900000000

var testArtifact = []byte(`{"schema":"impact.test/v1","destination":"internal"}`)

func testPolicy(claims int) admission.ArtifactPolicy {
	r := artifactpreflight.Recipe{Schema: artifactpreflight.RecipeSchema, ProducerID: artifactpreflight.ProducerID, ArtifactSchema: "impact.test/v1", MaxBytes: 65536, Fields: []artifactpreflight.Field{{Name: "destination", Type: "text"}}, Claims: []artifactpreflight.Claim{}}
	for i := 0; i < claims; i++ {
		r.Claims = append(r.Claims, artifactpreflight.Claim{ID: fmt.Sprintf("claim_%03d", i), Verifier: artifactpreflight.VerifierID, Field: "destination", Expected: "internal"})
	}
	return admission.ArtifactPolicy{Schema: admission.ArtifactPolicySchema, ID: "policy", Revision: 1, Recipe: r, RequiredAuthority: "live-observation", MaxAgeSeconds: 60,
		ApprovalBudget: machinerules.EffectBudget{AllowTarget: true, AllowSession: true, AllowFilesystem: true, RequireIdempotent: true}, ControlPlaneBudget: machinerules.EffectBudget{AllowSession: true, AllowFilesystem: true, RequireIdempotent: true}}
}
func privateJSON(t *testing.T, path string, value any) {
	t.Helper()
	raw, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(path, raw, 0600); err != nil {
		t.Fatal(err)
	}
}
func fixture(t *testing.T, claims int) (Paths, Case, admission.ArtifactPolicy) {
	t.Helper()
	dir, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	paths := Paths{filepath.Join(dir, "case.json"), filepath.Join(dir, "before.json"), filepath.Join(dir, "after.json"), filepath.Join(dir, "report.json")}
	artifact := filepath.Join(dir, "artifact.json")
	if err = os.WriteFile(artifact, testArtifact, 0600); err != nil {
		t.Fatal(err)
	}
	c := Case{Schema: CaseSchema, Request: policy.Request{Key: "private-request", Requester: "requester", Team: "team", Amount: 1, Submitted: true}, Principal: admission.PrincipalView{Key: "private-reviewer", Team: "team", Active: true, Enabled: true, CanExecute: true}, BaseRules: policy.Rules{Limit: 10, SameTeam: true, ActiveReviewer: true, PreventSelf: true}, Artifact: Artifact{Path: artifact, ExpectedSHA256: digest(testArtifact), DeadlineUnix: testUnix + 100}}
	p := testPolicy(claims)
	privateJSON(t, paths.Case, c)
	privateJSON(t, paths.Before, p)
	privateJSON(t, paths.After, p)
	return paths, c, p
}
func compareAtTestTime(paths Paths) (Summary, int) {
	return compareFiles(paths, dependencies{artifactpreflight.ReadArtifact, func() time.Time { return time.Unix(testUnix, 0) }})
}
func readReport(t *testing.T, path string) Report {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var r Report
	if err = json.Unmarshal(raw, &r); err != nil {
		t.Fatal(err)
	}
	return r
}
func assertComparison(t *testing.T, paths Paths, before, after bool, direction string) Report {
	t.Helper()
	s, exit := compareAtTestTime(paths)
	if exit != 0 || s.Status != "compared" || s.Code != "COMPARISON_SAVED" || !s.ReportSaved || s.Direction != direction || s.Before.WouldAdmit != before || s.After.WouldAdmit != after {
		t.Fatalf("safe summary mismatch: %+v exit %d", s, exit)
	}
	r := readReport(t, paths.Report)
	if r.Before.WouldAdmit != before || r.After.WouldAdmit != after || r.Delta.Direction != direction || !r.Simulation || r.Committed || r.AuthenticatedServerState || r.TargetEffectsExecuted {
		t.Fatal("report simulation boundary mismatch")
	}
	if r.ObservationUnix != testUnix || r.Before.Producer.ObservationUnix != testUnix || r.After.Producer.ObservationUnix != testUnix {
		t.Fatal("not one observation clock")
	}
	for _, side := range []Side{r.Before, r.After} {
		for _, e := range side.Evidence {
			if e.Facts.NowUnix != testUnix || e.Facts.ObservedAtUnix != testUnix {
				t.Fatal("evidence clock differs")
			}
		}
	}
	if r.Before.Producer.ArtifactBase64 != r.After.Producer.ArtifactBase64 || r.Before.Producer.ActualSHA256 != r.After.Producer.ActualSHA256 || r.Before.ContextSHA256 == r.After.ContextSHA256 {
		t.Fatal("artifact capture or explicit side binding mismatch")
	}
	stat, err := os.Stat(paths.Report)
	if err != nil || stat.Mode().Perm() != 0600 {
		t.Fatal("not a private output")
	}
	rID := r.ID
	r.ID = ""
	if canonicalDigest(r) != rID {
		t.Fatal("report content identity mismatch")
	}
	r.ID = rID
	return r
}

func TestNativeComparisonAndCaptureOwnership(t *testing.T) {
	paths, c, p := fixture(t, 5)
	p.Recipe.Claims[2].Expected = "external"
	privateJSON(t, paths.After, p)
	reads, clocks := 0, 0
	s, exit := compareFiles(paths, dependencies{readArtifact: func(req artifactpreflight.Requirement, max int64) (artifactpreflight.Acquisition, error) {
		reads++
		a, err := artifactpreflight.ReadArtifact(req, max)
		if err == nil {
			if e := os.WriteFile(c.Artifact.Path, []byte("changed after capture"), 0600); e != nil {
				t.Fatal(e)
			}
		}
		return a, err
	}, now: func() time.Time { clocks++; return time.Unix(testUnix, 0) }})
	if exit != 0 || reads != 1 || clocks != 1 || s.Direction != "newly_denied" || s.Before.Counts.Pass != 5 || s.After.Counts.Fail != 1 || s.After.Counts.Pass != 4 {
		t.Fatalf("capture/native facts mismatch: %+v reads%d clocks%d", s, reads, clocks)
	}
	r := readReport(t, paths.Report)
	want := base64.StdEncoding.EncodeToString(testArtifact)
	if r.Before.Producer.ArtifactBase64 != want || r.After.Producer.ArtifactBase64 != want || r.After.Decision.Reason != "EVIDENCE_REJECTED" || !r.BaseReceipt.Result.After.Approved || len(r.Delta.Changed) != 1 || r.Delta.Changed[0].ClaimID != "claim_002" || !r.Delta.Changed[0].PredicateChanged || !r.Delta.Changed[0].EvidenceDecisionChanged {
		t.Fatal("private report lost actual captured/native observations")
	}
	if r.Audit.ArtifactReadAttempts != 1 || !r.Audit.Effects.WritesFilesystem || r.Audit.Effects.MutatesTarget || r.Audit.Effects.MutatesSession || r.Audit.Effects.AccessesNetwork || r.Audit.Effects.Idempotent || !r.Before.ProposedApproval.Facts.MutatesTarget {
		t.Fatal("actual versus proposed effects conflated")
	}
	raw, _ := json.Marshal(s)
	for _, private := range []string{"private-request", "private-reviewer", "destination", "internal", "external", c.Artifact.Path, want} {
		if bytes.Contains(raw, []byte(private)) {
			t.Fatal("private data in safe summary")
		}
	}
}

func TestNativeClaimBoundsAndEarlyMiddleLastFailures(t *testing.T) {
	for _, n := range []int{1, 5, 256} {
		t.Run(fmt.Sprint(n), func(t *testing.T) {
			paths, _, _ := fixture(t, n)
			r := assertComparison(t, paths, true, true, "unchanged")
			if r.Before.Completion.Summary.Pass != int64(n) || len(r.Before.Completion.Steps) != n || len(r.Before.Evidence) != n {
				t.Fatal("native ordered fold incomplete")
			}
		})
	}
	for _, index := range []int{0, 2, 4} {
		t.Run("failure"+fmt.Sprint(index), func(t *testing.T) {
			paths, _, p := fixture(t, 5)
			p.Recipe.Claims[index].Expected = "external"
			privateJSON(t, paths.After, p)
			r := assertComparison(t, paths, true, false, "newly_denied")
			if r.After.Completion.Summary.Fail != 1 || len(r.After.Producer.Observations) != 5 || len(r.After.Completion.Steps) != 5 || r.Delta.Changed[0].ClaimID != fmt.Sprintf("claim_%03d", index) {
				t.Fatal("early/middle/last failure omitted outcomes")
			}
		})
	}
}

func TestDeniedComparisonsAreCompleteAndPermissionIsSeparate(t *testing.T) {
	cases := []struct {
		name                           string
		change                         func(*Case, *admission.ArtifactPolicy, Paths)
		status                         artifactpreflight.AcquisitionStatus
		pass, fail, unknown, truncated int64
		reason                         string
		read                           int
		nativeBase                     bool
	}{
		{"digest", func(c *Case, p *admission.ArtifactPolicy, paths Paths) {
			c.Artifact.ExpectedSHA256 = "sha256:" + strings.Repeat("0", 64)
		}, artifactpreflight.ReadSuccess, 0, 5, 0, 0, "EVIDENCE_REJECTED", 1, true},
		{"expired", func(c *Case, p *admission.ArtifactPolicy, paths Paths) { c.Artifact.DeadlineUnix = testUnix - 1 }, artifactpreflight.ReadSuccess, 5, 0, 0, 0, "EVIDENCE_REJECTED", 1, true},
		{"disabled", func(c *Case, p *admission.ArtifactPolicy, paths Paths) { c.Principal.Enabled = false }, artifactpreflight.Skipped, 0, 0, 5, 0, "PROPOSED_PRINCIPAL_DISABLED", 0, true},
		{"noexecute", func(c *Case, p *admission.ArtifactPolicy, paths Paths) { c.Principal.CanExecute = false }, artifactpreflight.Skipped, 0, 0, 5, 0, "PROPOSED_EXECUTION_FORBIDDEN", 0, true},
		{"base", func(c *Case, p *admission.ArtifactPolicy, paths Paths) { c.Request.Submitted = false }, artifactpreflight.Skipped, 0, 0, 5, 0, "BASE_POLICY_DENIED", 0, false},
		{"effects", func(c *Case, p *admission.ArtifactPolicy, paths Paths) { p.ApprovalBudget.AllowTarget = false }, artifactpreflight.ReadSuccess, 5, 0, 0, 0, "OPERATION_EFFECT_DISALLOWED", 1, true},
		{"missing", func(c *Case, p *admission.ArtifactPolicy, paths Paths) {
			if err := os.Remove(c.Artifact.Path); err != nil {
				t.Fatal(err)
			}
		}, artifactpreflight.ReadError, 0, 0, 5, 0, "EVIDENCE_REJECTED", 1, true},
		{"oversized", func(c *Case, p *admission.ArtifactPolicy, paths Paths) {
			if err := os.WriteFile(c.Artifact.Path, bytes.Repeat([]byte{'x'}, 65537), 0600); err != nil {
				t.Fatal(err)
			}
		}, artifactpreflight.Oversized, 0, 0, 0, 5, "EVIDENCE_REJECTED", 1, true},
		{"schema", func(c *Case, p *admission.ArtifactPolicy, paths Paths) {
			raw := []byte(`{"schema":"other","destination":"internal"}`)
			c.Artifact.ExpectedSHA256 = digest(raw)
			if err := os.WriteFile(c.Artifact.Path, raw, 0600); err != nil {
				t.Fatal(err)
			}
		}, artifactpreflight.ReadSuccess, 0, 5, 0, 0, "EVIDENCE_REJECTED", 1, true},
		{"type", func(c *Case, p *admission.ArtifactPolicy, paths Paths) {
			raw := []byte(`{"schema":"impact.test/v1","destination":false}`)
			c.Artifact.ExpectedSHA256 = digest(raw)
			if err := os.WriteFile(c.Artifact.Path, raw, 0600); err != nil {
				t.Fatal(err)
			}
		}, artifactpreflight.ReadSuccess, 0, 5, 0, 0, "EVIDENCE_REJECTED", 1, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			paths, c, p := fixture(t, 5)
			tc.change(&c, &p, paths)
			privateJSON(t, paths.Case, c)
			privateJSON(t, paths.Before, p)
			privateJSON(t, paths.After, p)
			r := assertComparison(t, paths, false, false, "unchanged")
			counts := r.Before.Completion.Summary
			if r.Before.Reason != tc.reason || r.Before.Producer.AcquisitionStatus != tc.status || counts.Pass != tc.pass || counts.Fail != tc.fail || counts.Unknown != tc.unknown || counts.Truncated != tc.truncated || r.Audit.ArtifactReadAttempts != tc.read || r.BaseReceipt.Result.After.Approved != tc.nativeBase || r.Before.AdmissionFacts.BasePolicyApproved != tc.nativeBase {
				t.Fatal("denial counts/permission/base/capture conflated")
			}
			if tc.name == "disabled" && r.Permission.ModeledHTTPStatus != 401 || tc.name == "noexecute" && r.Permission.ModeledHTTPStatus != 403 {
				t.Fatal("modeled permission mismatch")
			}
		})
	}
}

func TestDeltaIgnoresBindingsIdentityWhitespaceAndSeparatesOrderBudget(t *testing.T) {
	paths, _, p := fixture(t, 5)
	p.ID = "another-policy"
	p.Revision = 2
	p.Recipe.Claims[0], p.Recipe.Claims[4] = p.Recipe.Claims[4], p.Recipe.Claims[0]
	raw, _ := json.MarshalIndent(p, "", " \t")
	if err := os.WriteFile(paths.After, raw, 0600); err != nil {
		t.Fatal(err)
	}
	r := assertComparison(t, paths, true, true, "unchanged")
	if len(r.Delta.Changed) != 0 || len(r.Delta.Added) != 0 || len(r.Delta.Removed) != 0 || !r.Delta.ClaimOrderChanged || r.Delta.RecipeConfigurationChanged || !r.Delta.PolicyIdentityChanged || r.Inputs.Before.SemanticSHA256 == r.Inputs.After.SemanticSHA256 {
		t.Fatal("identity/order confused with behavior")
	}
	paths, _, p = fixture(t, 1)
	p.ApprovalBudget.AllowNetwork = true
	privateJSON(t, paths.After, p)
	r = assertComparison(t, paths, true, true, "unchanged")
	if !r.Delta.ApprovalBudgetChanged || r.Delta.ApprovalChecksChanged || len(r.Delta.Changed) != 0 {
		t.Fatal("budget values conflated with native checks")
	}
}

func TestDisjoint256ClaimDeltaArraysRemainBounded(t *testing.T) {
	paths, _, p := fixture(t, 256)
	for i := range p.Recipe.Claims {
		p.Recipe.Claims[i].ID = fmt.Sprintf("after_%03d", i)
	}
	privateJSON(t, paths.After, p)
	r := assertComparison(t, paths, true, true, "unchanged")
	if len(r.Delta.Added) != 256 || len(r.Delta.Removed) != 256 || len(r.Delta.Changed) != 0 || r.Delta.ClaimOrderChanged || r.Delta.Added[0] != "after_000" || r.Delta.Removed[255] != "claim_255" {
		t.Fatal("bounded ordered disjoint delta mismatch")
	}
}

func TestRawWhitespaceBindingAndOrderedClaimSetChanges(t *testing.T) {
	paths, _, p := fixture(t, 5)
	raw, _ := json.MarshalIndent(p, "", "  ")
	if err := os.WriteFile(paths.After, append(raw, '\n'), 0600); err != nil {
		t.Fatal(err)
	}
	r := assertComparison(t, paths, true, true, "unchanged")
	if r.Inputs.Before.RawSHA256 == r.Inputs.After.RawSHA256 || r.Inputs.Before.SemanticSHA256 != r.Inputs.After.SemanticSHA256 || len(r.Delta.Changed) != 0 || r.Delta.RecipeConfigurationChanged || r.Delta.ClaimOrderChanged {
		t.Fatal("raw whitespace classified as behavior")
	}
	paths, _, p = fixture(t, 5)
	p.Recipe.Claims = []artifactpreflight.Claim{{ID: "added_b", Verifier: artifactpreflight.VerifierID, Field: "destination", Expected: "internal"}, p.Recipe.Claims[4], p.Recipe.Claims[2], {ID: "added_a", Verifier: artifactpreflight.VerifierID, Field: "destination", Expected: "internal"}}
	privateJSON(t, paths.After, p)
	r = assertComparison(t, paths, true, true, "unchanged")
	if !reflect.DeepEqual(r.Delta.Added, []string{"added_b", "added_a"}) || !reflect.DeepEqual(r.Delta.Removed, []string{"claim_000", "claim_001", "claim_003"}) || !r.Delta.ClaimOrderChanged || len(r.Delta.Changed) != 0 {
		t.Fatal("ordered added/removed/common-order delta mismatch")
	}
}

func TestSourceIdentityOwnedAndActualBindings(t *testing.T) {
	identity, err := SourceIdentity()
	if err != nil {
		t.Fatal(err)
	}
	if len(identity.HostSources) != 8 || identity.HostSHA256 != canonicalDigest(identity.HostSources) || len(identity.MachineRules.Projections) != 3 || identity.Base.SourceDigest == "" || identity.Completion.BridgeSHA256 == "" || identity.JSONInputSHA256 == "" {
		t.Fatal("missing actual source bindings")
	}
	for _, binding := range identity.HostSources {
		raw, err := os.ReadFile(binding.Path)
		if err != nil || digest(raw) != binding.SHA256 {
			t.Fatal("identity not actual compiled source bytes")
		}
	}
	identity.HostSources[0].SHA256 = "changed"
	identity.MachineRules.Sources[0].SHA256 = "changed"
	fresh, err := SourceIdentity()
	if err != nil || reflect.DeepEqual(identity, fresh) || fresh.HostSources[0].SHA256 == "changed" || fresh.MachineRules.Sources[0].SHA256 == "changed" {
		t.Fatal("source slices not owned")
	}
}
