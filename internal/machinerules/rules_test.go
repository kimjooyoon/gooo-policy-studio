package machinerules

import (
	"encoding/json"
	"os"
	"reflect"
	"strings"
	"testing"
)

func TestFinalRelationWholeDeclaredCorpus(t *testing.T) {
	raw, err := os.ReadFile("../../examples/artifact-gate/admission-cases.json")
	if err != nil {
		t.Fatal(err)
	}
	var corpus struct {
		Cases []struct {
			Inputs   map[string]AdmissionFacts    `json:"inputs"`
			Expected map[string]AdmissionDecision `json:"expected"`
		} `json:"cases"`
	}
	if err := json.Unmarshal(raw, &corpus); err != nil {
		t.Fatal(err)
	}
	if len(corpus.Cases) != 31 {
		t.Fatalf("changed declared case corpus: %d", len(corpus.Cases))
	}
	const entry = "gooo/artifact-gate:ArtifactGateAdmits"
	for i, c := range corpus.Cases {
		actual, err := EvaluateAdmission(c.Inputs[entry])
		if err != nil || actual != c.Expected[entry] {
			t.Fatalf("case %d: got %#v err %v, want %#v", i, actual, err, c.Expected[entry])
		}
	}
}

func baselineEvidence() EvidenceFacts {
	a := "sha256:" + strings.Repeat("a", 64)
	b := "sha256:" + strings.Repeat("b", 64)
	c := "sha256:" + strings.Repeat("c", 64)
	return EvidenceFacts{"live-observation", "live-observation", "pass", "observed", true, a, a, b, b, c, c, 100, 100, 0, 101}
}
func TestEvidenceTransportRetainsEveryDerivedCondition(t *testing.T) {
	wanted := EvidenceDecision{true, "ADMISSIBLE", true, true, true, true, true, true, true, true}
	actual, err := EvaluateEvidence(baselineEvidence())
	if err != nil || actual != wanted {
		t.Fatalf("baseline %#v %v", actual, err)
	}
	tests := []struct {
		Name, Reason string
		Mutate       func(*EvidenceFacts)
		Clear        func(*EvidenceDecision)
	}{
		{"provider", "PROVIDER_UNVERIFIED", func(f *EvidenceFacts) { f.ProviderVerified = false }, func(d *EvidenceDecision) { d.ProviderOK = false }},
		{"status", "EVIDENCE_INCOMPLETE", func(f *EvidenceFacts) { f.Status = "fail" }, func(d *EvidenceDecision) { d.EvidenceOK = false }},
		{"confidence", "EVIDENCE_INCOMPLETE", func(f *EvidenceFacts) { f.Confidence = "claimed" }, func(d *EvidenceDecision) { d.EvidenceOK = false }},
		{"authority", "AUTHORITY_INSUFFICIENT", func(f *EvidenceFacts) { f.ActualAuthority = "unit" }, func(d *EvidenceDecision) { d.AuthorityOK = false }},
		{"binding", "BINDING_MISMATCH", func(f *EvidenceFacts) { f.ObservedBinding = "sha256:" + strings.Repeat("d", 64) }, func(d *EvidenceDecision) { d.BindingOK = false }},
		{"artifact", "ARTIFACT_MISMATCH", func(f *EvidenceFacts) { f.ObservedArtifact = "sha256:" + strings.Repeat("d", 64) }, func(d *EvidenceDecision) { d.ArtifactOK = false }},
		{"policy", "POLICY_MISMATCH", func(f *EvidenceFacts) { f.ObservedPolicy = "sha256:" + strings.Repeat("d", 64) }, func(d *EvidenceDecision) { d.PolicyOK = false }},
		{"freshness", "EVIDENCE_STALE", func(f *EvidenceFacts) { f.ObservedAtUnix = 99 }, func(d *EvidenceDecision) { d.FreshnessOK = false }},
		{"deadline", "DEADLINE_EXPIRED", func(f *EvidenceFacts) { f.ExpiresAtUnix = 100 }, func(d *EvidenceDecision) { d.DeadlineOK = false }},
	}
	for _, tc := range tests {
		t.Run(tc.Name, func(t *testing.T) {
			facts := baselineEvidence()
			tc.Mutate(&facts)
			want := wanted
			want.Admissible = false
			want.Reason = tc.Reason
			tc.Clear(&want)
			got, err := EvaluateEvidence(facts)
			if err != nil || got != want {
				t.Fatalf("got %#v err %v want %#v", got, err, want)
			}
		})
	}
}
func TestEffectTransportRetainsAllTenBudgetChecks(t *testing.T) {
	facts := ToolEffects{true, true, true, true, true, true, true, true, true, false}
	all := EffectBudget{true, true, true, true, true, true, true, true, true, false}
	wanted := EffectDecision{true, "WITHIN_EFFECT_BUDGET", true, true, true, true, true, true, true, true, true, true}
	actual, err := EvaluateEffects(facts, all)
	if err != nil || actual != wanted {
		t.Fatalf("baseline %#v %v", actual, err)
	}
	tests := []struct {
		Name, Reason string
		Mutate       func(*EffectBudget)
		Clear        func(*EffectDecision)
	}{
		{"target", "TARGET_MUTATION_DISALLOWED", func(b *EffectBudget) { b.AllowTarget = false }, func(d *EffectDecision) { d.TargetOK = false }},
		{"session", "SESSION_MUTATION_DISALLOWED", func(b *EffectBudget) { b.AllowSession = false }, func(d *EffectDecision) { d.SessionOK = false }},
		{"filesystem", "FILESYSTEM_WRITE_DISALLOWED", func(b *EffectBudget) { b.AllowFilesystem = false }, func(d *EffectDecision) { d.FilesystemOK = false }},
		{"process", "PROCESS_LAUNCH_DISALLOWED", func(b *EffectBudget) { b.AllowProcess = false }, func(d *EffectDecision) { d.ProcessOK = false }},
		{"network", "NETWORK_ACCESS_DISALLOWED", func(b *EffectBudget) { b.AllowNetwork = false }, func(d *EffectDecision) { d.NetworkOK = false }},
		{"ui", "UI_CHANGE_DISALLOWED", func(b *EffectBudget) { b.AllowUI = false }, func(d *EffectDecision) { d.UIOK = false }},
		{"discard", "DATA_DISCARD_DISALLOWED", func(b *EffectBudget) { b.AllowDiscard = false }, func(d *EffectDecision) { d.DiscardOK = false }},
		{"foreign_code", "FOREIGN_CODE_DISALLOWED", func(b *EffectBudget) { b.AllowForeignCode = false }, func(d *EffectDecision) { d.ForeignCodeOK = false }},
		{"device", "DEVICE_MUTATION_DISALLOWED", func(b *EffectBudget) { b.AllowDevice = false }, func(d *EffectDecision) { d.DeviceOK = false }},
		{"idempotency", "IDEMPOTENCY_REQUIRED", func(b *EffectBudget) { b.RequireIdempotent = true }, func(d *EffectDecision) { d.IdempotencyOK = false }},
	}
	for _, tc := range tests {
		t.Run(tc.Name, func(t *testing.T) {
			budget := all
			tc.Mutate(&budget)
			want := wanted
			want.Admissible = false
			want.Reason = tc.Reason
			tc.Clear(&want)
			got, err := EvaluateEffects(facts, budget)
			if err != nil || got != want {
				t.Fatalf("got %#v err %v want %#v", got, err, want)
			}
		})
	}
}
func TestBindingsAreCheckedAndOwned(t *testing.T) {
	first, err := Bindings()
	if err != nil {
		t.Fatal(err)
	}
	if len(first.Sources) != 21 || len(first.Projections) != 3 || first.CompilerSourceSHA != "83928fa4538245abe33b08549da47f8cbdc50ed2" {
		t.Fatalf("unexpected provenance %#v", first)
	}
	original, _ := Bindings()
	first.Sources[0].SHA256 = "changed"
	first.Projections[0].GeneratedSHA256 = "changed"
	again, err := Bindings()
	if err != nil || !reflect.DeepEqual(original, again) {
		t.Fatalf("returned provenance aliases embedded state: %v", err)
	}
	independentlyChecked, err := checkBindings()
	if err != nil || !reflect.DeepEqual(original, independentlyChecked) {
		t.Fatalf("independent embedded byte check differs: %v", err)
	}
}
