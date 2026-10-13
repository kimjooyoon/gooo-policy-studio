package artifactimpact

import (
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
)

func replayFixture(t *testing.T, claims int, alter func(*Case, *admission.ArtifactPolicy)) (Paths, Report) {
	t.Helper()
	paths, c, p := fixture(t, claims)
	if alter != nil {
		alter(&c, &p)
	}
	privateJSON(t, paths.Case, c)
	privateJSON(t, paths.Before, p)
	privateJSON(t, paths.After, p)
	s, exit := compareAtTestTime(paths)
	if exit != 0 || !s.ReportSaved {
		t.Fatalf("comparison fixture failed %+v", s)
	}
	return paths, readReport(t, paths.Report)
}
func ownedReplayTestReport(t *testing.T, r Report) Report {
	t.Helper()
	raw, err := json.Marshal(r)
	if err != nil {
		t.Fatal(err)
	}
	var clone Report
	if err = json.Unmarshal(raw, &clone); err != nil {
		t.Fatal(err)
	}
	return clone
}
func rehashReplayTestReport(r *Report) { r.ID = ""; r.ID = canonicalDigest(*r) }
func rehashReplayTestReceipt(r *Report) {
	r.BaseReceipt.ID = ""
	r.BaseReceipt.ID = canonicalDigest(r.BaseReceipt)
}

func TestReplayHistoricalComparisonAfterAllOriginalPathsRemoved(t *testing.T) {
	paths, c, p := fixture(t, 5)
	p.Recipe.Claims[2].Expected = "external"
	privateJSON(t, paths.After, p)
	if s, exit := compareAtTestTime(paths); exit != 0 || s.Direction != "newly_denied" {
		t.Fatal("fixture native outcome")
	}
	saved := readReport(t, paths.Report)
	dir := filepath.Dir(c.Artifact.Path)
	if err := os.RemoveAll(dir); err != nil {
		t.Fatal(err)
	}
	got, err := Replay(saved)
	if err != nil || !reflect.DeepEqual(got, saved) {
		t.Fatalf("deleted paths historical mismatch: %v", err)
	}
	if _, err = os.Lstat(dir); !os.IsNotExist(err) {
		t.Fatal("replay recreated original directory")
	}
	if got.Before.Completion.Summary.Pass != 5 || got.After.Completion.Summary.Pass != 4 || got.After.Completion.Summary.Fail != 1 || got.Delta.Direction != "newly_denied" || got.After.Decision.Reason != "EVIDENCE_REJECTED" {
		t.Fatal("historical native observations changed")
	}
}

func TestReplayReplacementArtifactDoesNotChangeRetainedJudgment(t *testing.T) {
	paths, saved := replayFixture(t, 5, nil)
	artifact := saved.Before.Context.Case.Artifact.Path
	for _, kind := range []string{"bytes", "directory", "symlink"} {
		t.Run(kind, func(t *testing.T) {
			if err := os.RemoveAll(artifact); err != nil {
				t.Fatal(err)
			}
			switch kind {
			case "bytes":
				if err := os.WriteFile(artifact, []byte("unrelated private current content"), 0600); err != nil {
					t.Fatal(err)
				}
			case "directory":
				if err := os.Mkdir(artifact, 0700); err != nil {
					t.Fatal(err)
				}
			case "symlink":
				if err := os.Symlink(paths.Report, artifact); err != nil {
					t.Fatal(err)
				}
			}
			before, err := os.Lstat(artifact)
			if err != nil {
				t.Fatal(err)
			}
			got, err := Replay(saved)
			if err != nil || !reflect.DeepEqual(got, saved) {
				t.Fatalf("current artifact replacement affected historical result: %v", err)
			}
			after, err := os.Lstat(artifact)
			if err != nil || !os.SameFile(before, after) || before.Mode() != after.Mode() || before.Size() != after.Size() {
				t.Fatal("current artifact touched")
			}
		})
	}
}

func TestReplayAllNativeDenialClassesAndClaimBounds(t *testing.T) {
	cases := []struct {
		name                string
		alter               func(*Case, *admission.ArtifactPolicy)
		reason              string
		pass, fail, unknown int64
	}{
		{"pass", nil, "ADMITTED", 5, 0, 0},
		{"predicate", func(c *Case, p *admission.ArtifactPolicy) { p.Recipe.Claims[2].Expected = "external" }, "EVIDENCE_REJECTED", 4, 1, 0},
		{"digest", func(c *Case, p *admission.ArtifactPolicy) {
			c.Artifact.ExpectedSHA256 = "sha256:" + strings.Repeat("0", 64)
		}, "EVIDENCE_REJECTED", 0, 5, 0},
		{"deadline", func(c *Case, p *admission.ArtifactPolicy) { c.Artifact.DeadlineUnix = testUnix - 1 }, "EVIDENCE_REJECTED", 5, 0, 0},
		{"disabled", func(c *Case, p *admission.ArtifactPolicy) { c.Principal.Enabled = false }, "PROPOSED_PRINCIPAL_DISABLED", 0, 0, 5},
		{"noexecute", func(c *Case, p *admission.ArtifactPolicy) { c.Principal.CanExecute = false }, "PROPOSED_EXECUTION_FORBIDDEN", 0, 0, 5},
		{"base", func(c *Case, p *admission.ArtifactPolicy) { c.Request.Submitted = false }, "BASE_POLICY_DENIED", 0, 0, 5},
		{"effect", func(c *Case, p *admission.ArtifactPolicy) { p.ApprovalBudget.AllowTarget = false }, "OPERATION_EFFECT_DISALLOWED", 5, 0, 0},
		{"readerror", func(c *Case, p *admission.ArtifactPolicy) {
			if err := os.Remove(c.Artifact.Path); err != nil {
				t.Fatal(err)
			}
		}, "EVIDENCE_REJECTED", 0, 0, 5},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, saved := replayFixture(t, 5, tc.alter)
			got, err := Replay(saved)
			if err != nil || !reflect.DeepEqual(got, saved) || got.Before.Reason != tc.reason || got.Before.Completion.Summary.Pass != tc.pass || got.Before.Completion.Summary.Fail != tc.fail || got.Before.Completion.Summary.Unknown != tc.unknown {
				t.Fatalf("historical denial mismatch %v", err)
			}
		})
	}
	for _, n := range []int{1, 256} {
		t.Run("bound"+fmt.Sprint(n), func(t *testing.T) {
			_, saved := replayFixture(t, n, nil)
			got, err := Replay(saved)
			if err != nil || !reflect.DeepEqual(got, saved) || len(got.Before.Completion.Steps) != n {
				t.Fatal("historical complete claim fold mismatch")
			}
		})
	}
}

func TestReplaySchemaTypeOversizeAndConfigurationDeltas(t *testing.T) {
	for _, tc := range []struct {
		name            string
		raw             []byte
		status          artifactpreflight.AcquisitionStatus
		fail, truncated int64
	}{{"schema", []byte(`{"schema":"different","destination":"internal"}`), artifactpreflight.ReadSuccess, 5, 0}, {"type", []byte(`{"schema":"impact.test/v1","destination":false}`), artifactpreflight.ReadSuccess, 5, 0}, {"oversize", []byte(strings.Repeat("x", 65537)), artifactpreflight.Oversized, 0, 5}} {
		t.Run(tc.name, func(t *testing.T) {
			_, saved := replayFixture(t, 5, func(c *Case, p *admission.ArtifactPolicy) {
				c.Artifact.ExpectedSHA256 = digest(tc.raw)
				if err := os.WriteFile(c.Artifact.Path, tc.raw, 0600); err != nil {
					t.Fatal(err)
				}
			})
			got, err := Replay(saved)
			if err != nil || !reflect.DeepEqual(got, saved) || got.Before.Producer.AcquisitionStatus != tc.status || got.Before.Completion.Summary.Fail != tc.fail || got.Before.Completion.Summary.Truncated != tc.truncated || got.Before.WouldAdmit {
				t.Fatal("retained structural denial mismatch")
			}
		})
	}
	paths, _, p := fixture(t, 5)
	p.Recipe.Fields[0].Type = "bool"
	for i := range p.Recipe.Claims {
		p.Recipe.Claims[i].Expected = "true"
	}
	privateJSON(t, paths.After, p)
	if _, exit := compareAtTestTime(paths); exit != 0 {
		t.Fatal("field type comparison")
	}
	saved := readReport(t, paths.Report)
	got, err := Replay(saved)
	if err != nil || !reflect.DeepEqual(got, saved) || len(got.Delta.Changed) != 5 || !got.Delta.Changed[0].FieldTypeChanged {
		t.Fatal("retained field-type/predicate delta mismatch")
	}
	paths, _, p = fixture(t, 5)
	p.Recipe.Claims = []artifactpreflight.Claim{p.Recipe.Claims[4], p.Recipe.Claims[2], {ID: "added", Verifier: artifactpreflight.VerifierID, Field: "destination", Expected: "internal"}}
	p.ApprovalBudget.AllowTarget = false
	privateJSON(t, paths.After, p)
	if _, exit := compareAtTestTime(paths); exit != 0 {
		t.Fatal("set/budget comparison")
	}
	saved = readReport(t, paths.Report)
	got, err = Replay(saved)
	if err != nil || !reflect.DeepEqual(got, saved) || !got.Delta.ClaimOrderChanged || !got.Delta.ApprovalBudgetChanged || !got.Delta.ApprovalChecksChanged || len(got.Delta.Added) != 1 || len(got.Delta.Removed) != 3 || got.Delta.Direction != "newly_denied" {
		t.Fatal("retained ordered set/budget delta mismatch")
	}
}

func TestReplayUsesOriginalClockAndPreservesOriginalReceiptMetadata(t *testing.T) {
	paths, c, _ := fixture(t, 1)
	c.Artifact.DeadlineUnix = 110
	privateJSON(t, paths.Case, c)
	if s, exit := compareFiles(paths, dependencies{artifactpreflight.ReadArtifact, func() time.Time { return time.Unix(100, 0) }}); exit != 0 || !s.Before.WouldAdmit {
		t.Fatal("historical original clock fixture")
	}
	saved := readReport(t, paths.Report)
	if saved.BaseReceipt.CreatedAt == "" || saved.ObservationUnix != 100 {
		t.Fatal("metadata fixture")
	}
	got, err := Replay(saved)
	if err != nil || !reflect.DeepEqual(got, saved) || !got.Before.WouldAdmit || got.Before.Evidence[0].Facts.NowUnix != 100 || got.BaseReceipt.CreatedAt != saved.BaseReceipt.CreatedAt || got.BaseReceipt.ID != saved.BaseReceipt.ID {
		t.Fatal("replay refreshed historical clock/receipt")
	}
}

func TestReplayRejectsNestedIncoherentTamperingEvenAfterOuterRehash(t *testing.T) {
	_, original := replayFixture(t, 5, nil)
	cases := []struct {
		name  string
		alter func(*Report)
	}{
		{"flags", func(r *Report) { r.Committed = true }},
		{"scope", func(r *Report) { r.Scope = "private tampered scope" }},
		{"time", func(r *Report) { r.ObservationUnix++ }},
		{"source", func(r *Report) { r.Implementation.HostSources[0].SHA256 = "sha256:" + strings.Repeat("0", 64) }},
		{"platform", func(r *Report) { r.Implementation.GOOS = "other" }},
		{"rawhashshape", func(r *Report) { r.Inputs.Case.RawSHA256 = "bad" }},
		{"semantichash", func(r *Report) { r.Inputs.Before.SemanticSHA256 = "sha256:" + strings.Repeat("0", 64) }},
		{"contextrole", func(r *Report) { r.After.Context.Side = "before" }},
		{"contextcase", func(r *Report) { r.After.Context.Case.Principal.Enabled = false }},
		{"contextbinding", func(r *Report) { r.After.ContextSHA256 = r.Before.ContextSHA256 }},
		{"version", func(r *Report) { r.Before.SimulationPolicyVersion = "sha256:" + strings.Repeat("0", 64) }},
		{"producerbytes", func(r *Report) { r.Before.Producer.ArtifactBase64 = "e30=" }},
		{"producerdigest", func(r *Report) { r.Before.Producer.ActualSHA256 = "sha256:" + strings.Repeat("0", 64) }},
		{"producerstate", func(r *Report) { r.Before.Producer.AcquisitionStatus = artifactpreflight.Skipped }},
		{"producersize", func(r *Report) { r.Before.Producer.ObservedSize++ }},
		{"producerclaimactual", func(r *Report) { r.Before.Producer.Observations[2].Actual = "external" }},
		{"producerclaimstatus", func(r *Report) { r.Before.Producer.Observations[2].Status = "unknown" }},
		{"producerclaimreason", func(r *Report) { r.Before.Producer.Observations[2].Reason = "caller pass" }},
		{"producerclaimid", func(r *Report) { r.Before.Producer.Observations[2].EvidenceID = "ev_" + strings.Repeat("0", 64) }},
		{"evidencefact", func(r *Report) { r.Before.Evidence[2].Facts.ProviderVerified = false }},
		{"evidencedecision", func(r *Report) { r.Before.Evidence[2].Decision.Admissible = false }},
		{"completionearly", func(r *Report) { r.Before.Completion.Steps[0].Decision.Pass = 0 }},
		{"completionmiddle", func(r *Report) { r.Before.Completion.Steps[2].CountsBefore.Pass = 0 }},
		{"completionlast", func(r *Report) { r.Before.Completion.Steps[4].Status = "fail" }},
		{"completionrecord", func(r *Report) { r.Before.Completion.Input.Records[2].Status = "fail" }},
		{"completionreadiness", func(r *Report) { r.Before.Completion.Readiness.Ready = false }},
		{"effectfacts", func(r *Report) { r.Before.ProposedApproval.Facts.MutatesTarget = false }},
		{"effectbudget", func(r *Report) { r.Before.ProposedApproval.Budget.AllowTarget = false }},
		{"effectcheck", func(r *Report) { r.Before.ProposedApproval.Decision.TargetOK = false }},
		{"controlcheck", func(r *Report) { r.Before.ProposedControlPlane.Decision.Admissible = false }},
		{"finalfacts", func(r *Report) { r.Before.AdmissionFacts.AdmissibleEvidenceCount = 0 }},
		{"finaldecision", func(r *Report) { r.Before.Decision.Admitted = false }},
		{"finalreason", func(r *Report) { r.Before.Reason = "private forged reason" }},
		{"permission", func(r *Report) { r.Permission.Eligible = false }},
		{"baseinput", func(r *Report) { r.BaseReceipt.Input.Request.Amount++; rehashReplayTestReceipt(r) }},
		{"baseresult", func(r *Report) { r.BaseReceipt.Result.After.Approved = false; rehashReplayTestReceipt(r) }},
		{"basetimeformat", func(r *Report) { r.BaseReceipt.CreatedAt = "not-time"; rehashReplayTestReceipt(r) }},
		{"basetimeoffset", func(r *Report) { r.BaseReceipt.CreatedAt = "2000-01-01T01:00:00+01:00"; rehashReplayTestReceipt(r) }},
		{"basetimefraction", func(r *Report) { r.BaseReceipt.CreatedAt = "2000-01-01T00:00:00.000Z"; rehashReplayTestReceipt(r) }},
		{"basecompiler", func(r *Report) { r.BaseReceipt.CompilerSource = strings.Repeat("0", 40); rehashReplayTestReceipt(r) }},
		{"delta", func(r *Report) { r.Delta.Direction = "newly_denied" }},
		{"deltaclaim", func(r *Report) { r.Delta.Added = []string{"extra"} }},
		{"auditread", func(r *Report) { r.Audit.ArtifactReadAttempts = 0 }},
		{"auditstate", func(r *Report) { r.Audit.AcquisitionStatus = artifactpreflight.ReadError }},
		{"auditeffect", func(r *Report) { r.Audit.Effects.MutatesTarget = true }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := ownedReplayTestReport(t, original)
			tc.alter(&r)
			rehashReplayTestReport(&r)
			if _, err := Replay(r); err == nil {
				t.Fatal("rehashed incoherent historical rewrite accepted")
			}
		})
	}
}

func TestReplayDeepOwnershipAndUnsignedCoherentMetadataLimit(t *testing.T) {
	_, saved := replayFixture(t, 5, nil)
	original := ownedReplayTestReport(t, saved)
	got, err := Replay(saved)
	if err != nil {
		t.Fatal(err)
	}
	got.Before.Context.Policy.Recipe.Claims[0].Expected = "changed"
	got.After.Producer.Observations[0].Actual = "changed"
	got.Before.Completion.Input.Records[0].EvidenceIDs[0] = "changed"
	got.Implementation.HostSources[0].SHA256 = "changed"
	if !reflect.DeepEqual(saved, original) {
		t.Fatal("returned historical report aliases caller")
	}
	again, err := Replay(saved)
	if err != nil || !reflect.DeepEqual(again, original) {
		t.Fatal("second replay affected by returned mutation")
	}
	// No signature authenticates original metadata: a self-consistent timestamp
	// rewrite with recomputed receipt/outer hashes remains internally consistent.
	coherent := ownedReplayTestReport(t, saved)
	coherent.BaseReceipt.CreatedAt = "2000-01-01T00:00:00Z"
	rehashReplayTestReceipt(&coherent)
	rehashReplayTestReport(&coherent)
	if verified, err := Replay(coherent); err != nil || !reflect.DeepEqual(verified, coherent) {
		t.Fatal("consistency API implied unsigned metadata authentication")
	}
}

func TestReplayVerifierIdentityIsSeparateAndOwned(t *testing.T) {
	identity, err := ReplaySourceIdentity()
	if err != nil {
		t.Fatal(err)
	}
	if identity.Schema != "policy-studio/artifact-impact-replay-source/v1" || len(identity.Sources) != 3 || len(identity.Comparison.HostSources) != 8 {
		t.Fatal("new/legacy identity rosters mixed")
	}
	sha := identity.VerifierSHA256
	identity.VerifierSHA256 = ""
	if sha != canonicalDigest(identity) {
		t.Fatal("verifier hash not source-bound")
	}
	for _, s := range identity.Sources {
		raw, err := os.ReadFile(s.Path)
		if err != nil || digest(raw) != s.SHA256 {
			t.Fatal("verifier source is not actual embedded bytes")
		}
	}
	identity.Sources[0].SHA256 = "changed"
	identity.Comparison.HostSources[0].SHA256 = "changed"
	fresh, err := ReplaySourceIdentity()
	if err != nil || fresh.Sources[0].SHA256 == "changed" || fresh.Comparison.HostSources[0].SHA256 == "changed" {
		t.Fatal("verifier identity shares mutable storage")
	}
}
