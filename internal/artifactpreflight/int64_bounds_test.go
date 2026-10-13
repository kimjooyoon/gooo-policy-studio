package artifactpreflight

import (
	"encoding/json"
	"fmt"
	"os"
	"reflect"
	"strings"
	"testing"

	"github.com/kimjooyoon/gooo-policy-studio/internal/artifactnumeric"
	"github.com/kimjooyoon/gooo-policy-studio/internal/jsoninput"
)

func boundsRecipe() Recipe {
	return Recipe{Schema: NewRecipeSchema, ProducerID: NewProducerID, ArtifactSchema: "export-bounds/v1", MaxBytes: MaxBytes,
		Fields: []Field{{"row_limit", "int64"}, {"destination", "text"}, {"dry_run", "bool"}},
		Claims: []Claim{{"rows_nonnegative", Int64GTEVerifierID, "row_limit", "0"}, {"rows_at_most", Int64LTEVerifierID, "row_limit", "500"}, {"destination_internal", VerifierID, "destination", "internal"}, {"dry_run_required", VerifierID, "dry_run", "true"}}}
}

func boundsArtifact(value string) []byte {
	return []byte(`{"schema":"export-bounds/v1","row_limit":` + value + `,"destination":"internal","dry_run":true}`)
}

func TestInt64BoundsActualAcquisitionMixedClaims(t *testing.T) {
	rows := []struct {
		Value        string
		Statuses     []string
		Lower, Upper artifactnumeric.Decision
	}{
		{"499", []string{"pass", "pass", "pass", "pass"}, artifactnumeric.Decision{false, true, true, true, "BOUND_MATCH"}, artifactnumeric.Decision{true, false, true, true, "BOUND_MATCH"}},
		{"500", []string{"pass", "pass", "pass", "pass"}, artifactnumeric.Decision{false, true, true, true, "BOUND_MATCH"}, artifactnumeric.Decision{true, true, true, true, "BOUND_MATCH"}},
		{"501", []string{"pass", "fail", "pass", "pass"}, artifactnumeric.Decision{false, true, true, true, "BOUND_MATCH"}, artifactnumeric.Decision{false, true, true, false, "BOUND_MISMATCH"}},
		{"-1", []string{"fail", "pass", "pass", "pass"}, artifactnumeric.Decision{true, false, true, false, "BOUND_MISMATCH"}, artifactnumeric.Decision{true, false, true, true, "BOUND_MATCH"}},
		{"0", []string{"pass", "pass", "pass", "pass"}, artifactnumeric.Decision{true, true, true, true, "BOUND_MATCH"}, artifactnumeric.Decision{true, false, true, true, "BOUND_MATCH"}},
	}
	for _, row := range rows {
		t.Run(row.Value, func(t *testing.T) {
			r := observeFile(t, boundsRecipe(), artifactFile(t, boundsArtifact(row.Value)))
			if r.Schema != ReportSchema || r.ProducerID != NewProducerID || r.Identity.Schema != "policy-studio/artifact-producer-source/v2" || r.Identity.ProducerID != NewProducerID || r.Identity.VerifierID != RegistryVerifierID {
				t.Fatal("incorrect current report and registry scope")
			}
			for i, o := range r.Observations {
				if o.Status != row.Statuses[i] {
					t.Fatalf("ordered status %d: %#v", i, o)
				}
			}
			if r.Observations[0].NativeProof == nil || r.Observations[1].NativeProof == nil || r.Observations[0].NativeProof.Decision != row.Lower || r.Observations[1].NativeProof.Decision != row.Upper {
				t.Fatal("native full independent lower/upper decisions missing")
			}
			if r.Observations[0].NativeProof.Facts.Operator != "gte" || r.Observations[0].NativeProof.Facts.Bound != 0 || r.Observations[1].NativeProof.Facts.Operator != "lte" || r.Observations[1].NativeProof.Facts.Bound != 500 {
				t.Fatal("native facts differ from operator recipe")
			}
			if r.Observations[2].NativeProof != nil || r.Observations[3].NativeProof != nil {
				t.Fatal("equality received fabricated numeric proof")
			}
			for _, o := range r.Observations[:2] {
				if o.NativeProof.Bindings != r.Identity.NumericBindings || fmt.Sprint(o.NativeProof.Facts.Value) != row.Value {
					t.Fatal("proof lost canonical acquired facts/source binding")
				}
			}
		})
	}
}

func TestInt64BoundsRecipeVersionAndCanonicalConfiguration(t *testing.T) {
	for _, change := range []func(*Recipe){
		func(r *Recipe) { r.Schema = RecipeSchema; r.ProducerID = ProducerID },
		func(r *Recipe) { r.Schema = RecipeSchema }, func(r *Recipe) { r.ProducerID = ProducerID },
		func(r *Recipe) { r.Claims[0].Verifier = "field_int64_lte/v2" },
		func(r *Recipe) { r.Claims[0].Field = "destination" }, func(r *Recipe) { r.Claims[0].Field = "dry_run" },
	} {
		r := boundsRecipe()
		change(&r)
		if ValidateRecipe(r) == nil {
			t.Fatal("invalid numeric recipe accepted")
		}
	}
	for _, value := range []string{"01", "+1", "-0", "1e3", "1.0", "9223372036854775808", "-9223372036854775809", "", `"1"`} {
		r := boundsRecipe()
		r.Claims[0].Expected = value
		if _, err := New(r); err == nil {
			t.Fatalf("noncanonical bound accepted: %s", value)
		}
	}
	for _, value := range []string{"-9223372036854775808", "9223372036854775807", "-1", "0"} {
		r := boundsRecipe()
		r.Claims[0].Expected = value
		if ValidateRecipe(r) != nil {
			t.Fatalf("canonical signed bound rejected: %s", value)
		}
	}
	legacy := testRecipe(1)
	r := observeFile(t, legacy, artifactFile(t, goodArtifact))
	if r.Schema != ReportSchema || r.ProducerID != ProducerID || r.Observations[0].NativeProof != nil {
		t.Fatal("legacy equality recipe identity/proof was silently broadened")
	}
	current := testRecipe(1)
	current.Schema, current.ProducerID = NewRecipeSchema, NewProducerID
	if ValidateRecipe(current) != nil {
		t.Fatal("v2 equality-only recipe rejected")
	}
}

func TestInt64BoundsMandatoryChecksSuppressEveryNativeProof(t *testing.T) {
	rawRows := []string{`"500"`, `true`, `null`, `[]`, `{}`, `1.0`, `1e0`, `-0`, `9223372036854775808`, `-9223372036854775809`}
	for _, value := range rawRows {
		t.Run(value, func(t *testing.T) {
			r := observeFile(t, boundsRecipe(), artifactFile(t, boundsArtifact(value)))
			for _, o := range r.Observations {
				if o.NativeProof != nil || o.Status != "fail" {
					t.Fatal("invalid acquired type executed numeric predicate")
				}
			}
		})
	}
	t.Run("digest mismatch despite favorable bound", func(t *testing.T) {
		req := artifactFile(t, boundsArtifact("500"))
		if err := os.WriteFile(req.Path, boundsArtifact("499"), 0600); err != nil {
			t.Fatal(err)
		}
		r := observeFile(t, boundsRecipe(), req)
		for _, o := range r.Observations {
			if o.Status != "fail" || o.NativeProof != nil {
				t.Fatal("digest failure bypassed or proof fabricated")
			}
		}
	})
	t.Run("schema mismatch despite favorable bound", func(t *testing.T) {
		raw := []byte(strings.Replace(string(boundsArtifact("499")), "export-bounds/v1", "wrong/v1", 1))
		r := observeFile(t, boundsRecipe(), artifactFile(t, raw))
		for _, o := range r.Observations {
			if o.Status != "fail" || o.NativeProof != nil {
				t.Fatal("schema failure executed native predicate")
			}
		}
	})
	for _, status := range []AcquisitionStatus{ReadError, Skipped, Oversized} {
		t.Run(string(status), func(t *testing.T) {
			recipe := boundsRecipe()
			p, err := New(recipe)
			if err != nil {
				t.Fatal(err)
			}
			a := Acquisition{status: status, expectedSHA: digest(boundsArtifact("499")), maxBytes: recipe.MaxBytes, observedSize: -1}
			if status == Oversized {
				a.observedSize = recipe.MaxBytes + 1
			}
			r, err := p.Observe(a, a.expectedSHA, digest([]byte("trusted")), 123456789)
			if err != nil {
				t.Fatal(err)
			}
			for _, o := range r.Observations {
				if o.Status == "pass" || o.NativeProof != nil {
					t.Fatal("non-success acquisition fabricated native pass")
				}
			}
		})
	}
}

func TestInt64BoundsOneFiveAnd256ClaimsOwnedAndOrdered(t *testing.T) {
	for _, count := range []int{1, 5, 256} {
		t.Run(fmt.Sprint(count), func(t *testing.T) {
			recipe := boundsRecipe()
			recipe.Claims = nil
			for i := 0; i < count; i++ {
				claim := Claim{ID: fmt.Sprintf("claim_%03d", i), Verifier: VerifierID, Field: "destination", Expected: "internal"}
				switch i % 3 {
				case 0:
					claim.Verifier, claim.Field, claim.Expected = Int64GTEVerifierID, "row_limit", "0"
				case 1:
					claim.Verifier, claim.Field, claim.Expected = Int64LTEVerifierID, "row_limit", "500"
				}
				recipe.Claims = append(recipe.Claims, claim)
			}
			report := observeFile(t, recipe, artifactFile(t, boundsArtifact("500")))
			assertStatuses(t, report, count, "pass")
			for i, o := range report.Observations {
				if (o.NativeProof == nil) != (i%3 == 2) {
					t.Fatal("ordered proof presence differs from selected native predicates")
				}
			}
			if report.Observations[0].NativeProof != nil {
				report.Observations[0].NativeProof.Bindings.SourceSHA256 = "changed"
				fresh := observeFile(t, recipe, artifactFile(t, boundsArtifact("500")))
				if fresh.Observations[0].NativeProof.Bindings.SourceSHA256 == "changed" {
					t.Fatal("proof alias escaped producer")
				}
			}
		})
	}
}

func cloneBoundsReport(t *testing.T, report Report) Report {
	t.Helper()
	raw, err := json.Marshal(report)
	if err != nil {
		t.Fatal(err)
	}
	var owned Report
	if err := jsoninput.Decode(raw, &owned, 1024*1024); err != nil {
		t.Fatal(err)
	}
	return owned
}

func rehashBoundsObservations(report *Report) {
	base := *report
	base.Observations = make([]ClaimObservation, 0)
	baseHash := encodedDigest(struct {
		Domain string `json:"domain"`
		Report Report `json:"report"`
	}{"policy-studio/artifact-observation-base/v1", base})
	for i := range report.Observations {
		o := report.Observations[i]
		o.EvidenceID = ""
		value := encodedDigest(struct {
			Domain      string           `json:"domain"`
			BaseSHA256  string           `json:"base_sha256"`
			Observation ClaimObservation `json:"observation"`
		}{"policy-studio/artifact-claim/v1", baseHash, o})
		report.Observations[i].EvidenceID = "ev_" + value[7:]
	}
}

func TestInt64BoundsReplayRetainedBytesAndCoherentProofTampering(t *testing.T) {
	recipe := boundsRecipe()
	req := artifactFile(t, boundsArtifact("500"))
	original := observeFile(t, recipe, req)
	if err := os.Remove(req.Path); err != nil {
		t.Fatal(err)
	}
	current, err := Replay(recipe, req.ExpectedSHA256, original.ContextDigest, original)
	if err != nil || !reflect.DeepEqual(original, current) {
		t.Fatal("historical native replay needed current artifact")
	}
	for _, change := range []func(*Report){
		func(r *Report) { r.Observations[0].NativeProof.Facts.Value = -1 },
		func(r *Report) { r.Observations[0].NativeProof.Facts.Bound = 1 },
		func(r *Report) { r.Observations[0].NativeProof.Facts.Operator = "lte" },
		func(r *Report) { r.Observations[0].NativeProof.Decision.AtMost = true },
		func(r *Report) { r.Observations[0].NativeProof.Decision.AtLeast = false },
		func(r *Report) { r.Observations[0].NativeProof.Decision.OperatorOK = false },
		func(r *Report) {
			r.Observations[0].NativeProof.Decision.Matched = false
			r.Observations[0].Status = "fail"
			r.Observations[0].Reason = "BOUND_MISMATCH"
		},
		func(r *Report) { r.Observations[0].NativeProof.Decision.Reason = "UNSUPPORTED_OPERATOR" },
		func(r *Report) { r.Observations[0].NativeProof.Bindings.GeneratedSHA256 = digest([]byte("changed")) },
		func(r *Report) { r.Observations[0].NativeProof = nil },
		func(r *Report) { r.Observations[2].NativeProof = r.Observations[0].NativeProof },
		func(r *Report) { r.Identity.NumericBindings.SourceSHA256 = digest([]byte("old")) },
	} {
		candidate := cloneBoundsReport(t, original)
		change(&candidate)
		rehashBoundsObservations(&candidate)
		if _, err := Replay(recipe, req.ExpectedSHA256, original.ContextDigest, candidate); err == nil {
			t.Fatal("coherently rehashed forged native proof accepted")
		}
	}
	old := cloneBoundsReport(t, original)
	old.Schema = "policy-studio/artifact-preflight/v1"
	if _, err := Replay(recipe, req.ExpectedSHA256, original.ContextDigest, old); err == nil {
		t.Fatal("old report schema silently migrated")
	}
}

func TestInt64BoundsStrictProofNullAndMissingFields(t *testing.T) {
	r := observeFile(t, boundsRecipe(), artifactFile(t, boundsArtifact("500")))
	for _, mutate := range []func(map[string]any){
		func(o map[string]any) { o["native_proof"] = nil },
		func(o map[string]any) { delete(o["native_proof"].(map[string]any)["facts"].(map[string]any), "value") },
		func(o map[string]any) {
			o["native_proof"].(map[string]any)["decision"].(map[string]any)["matched"] = nil
		},
	} {
		raw, _ := json.Marshal(r)
		var object map[string]any
		if json.Unmarshal(raw, &object) != nil {
			t.Fatal("fixture clone")
		}
		mutate(object["observations"].([]any)[0].(map[string]any))
		raw, _ = json.Marshal(object)
		var decoded Report
		if jsoninput.Decode(raw, &decoded, 1<<20) == nil {
			t.Fatal("null or incomplete typed numeric proof accepted")
		}
	}
}
