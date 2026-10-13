package artifactpreflight

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func testRecipe(n int) Recipe {
	r := Recipe{Schema: RecipeSchema, ProducerID: ProducerID, ArtifactSchema: "deployment-artifact/v1", MaxBytes: MaxBytes,
		Fields: []Field{{"service", "text"}, {"enabled", "bool"}, {"revision", "int64"}}, Claims: make([]Claim, 0, n)}
	for i := 0; i < n; i++ {
		field, expected := "service", "payments"
		switch i % 3 {
		case 1:
			field, expected = "enabled", "true"
		case 2:
			field, expected = "revision", "9223372036854775807"
		}
		r.Claims = append(r.Claims, Claim{fmt.Sprintf("claim_%03d", i), VerifierID, field, expected})
	}
	return r
}

var goodArtifact = []byte(`{"schema":"deployment-artifact/v1","service":"payments","enabled":true,"revision":9223372036854775807}`)

func realDir(t *testing.T) string {
	t.Helper()
	path, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	return path
}

func artifactFile(t *testing.T, raw []byte) Requirement {
	t.Helper()
	path := filepath.Join(realDir(t), "artifact.json")
	if err := os.WriteFile(path, raw, 0600); err != nil {
		t.Fatal(err)
	}
	return Requirement{path, digest(raw)}
}

func observeFile(t *testing.T, recipe Recipe, requirement Requirement) Report {
	t.Helper()
	p, err := New(recipe)
	if err != nil {
		t.Fatal(err)
	}
	a, err := ReadArtifact(requirement, recipe.MaxBytes)
	if err != nil {
		t.Fatal(err)
	}
	r, err := p.Observe(a, requirement.ExpectedSHA256, digest([]byte("trusted command context")), 123456789)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Replay(recipe, requirement.ExpectedSHA256, r.ContextDigest, r); err != nil {
		t.Fatal(err)
	}
	return r
}

func assertStatuses(t *testing.T, r Report, n int, status string) {
	t.Helper()
	if len(r.Observations) != n {
		t.Fatalf("got %d observations, expected every one of %d", len(r.Observations), n)
	}
	seen := make(map[string]bool)
	for i, o := range r.Observations {
		if o.ClaimID != fmt.Sprintf("claim_%03d", i) || o.Status != status || len(o.EvidenceID) != 67 || !validDigest("sha256:"+o.EvidenceID[3:]) || seen[o.EvidenceID] {
			t.Fatalf("observation %d: %#v", i, o)
		}
		seen[o.EvidenceID] = true
	}
}

func TestActualArtifactClaimsAndCanonicalValues(t *testing.T) {
	for _, n := range []int{1, 5, 256} {
		t.Run(fmt.Sprint(n), func(t *testing.T) {
			r := observeFile(t, testRecipe(n), artifactFile(t, goodArtifact))
			assertStatuses(t, r, n, "pass")
			if !r.DigestOK || !r.SchemaOK || !r.TypesOK || r.AcquisitionStatus != ReadSuccess || r.ActualSHA256 != digest(goodArtifact) || r.ByteCount != int64(len(goodArtifact)) || r.ObservedSize != int64(len(goodArtifact)) {
				t.Fatalf("missing actual integrity/type/schema observations: %#v", r)
			}
			raw, err := base64.StdEncoding.Strict().DecodeString(r.ArtifactBase64)
			if err != nil || string(raw) != string(goodArtifact) {
				t.Fatalf("retained actual bytes mismatch: %v", err)
			}
		})
	}
	for _, integer := range []string{"-9223372036854775808", "0", "9223372036854775807"} {
		r := testRecipe(1)
		r.Claims[0].Field, r.Claims[0].Expected = "revision", integer
		raw := []byte(strings.Replace(string(goodArtifact), "9223372036854775807", integer, 1))
		assertStatuses(t, observeFile(t, r, artifactFile(t, raw)), 1, "pass")
	}
}

func TestMandatoryArtifactChecksCannotBeOmittedByOneClaim(t *testing.T) {
	bad := []struct {
		name, raw, reason string
		schemaOK, typesOK bool
	}{
		{"schema", `{"schema":"different/v1","service":"payments","enabled":true,"revision":1}`, "ARTIFACT_SCHEMA_MISMATCH", false, true},
		{"missing unrelated field", `{"schema":"deployment-artifact/v1","service":"payments","enabled":true}`, "ARTIFACT_SCHEMA_MISMATCH", false, false},
		{"extra", `{"schema":"deployment-artifact/v1","service":"payments","enabled":true,"revision":1,"canApprove":true}`, "ARTIFACT_SCHEMA_MISMATCH", false, true},
		{"case alias", `{"Schema":"deployment-artifact/v1","service":"payments","enabled":true,"revision":1}`, "ARTIFACT_SCHEMA_MISMATCH", false, true},
		{"unrelated wrong type", `{"schema":"deployment-artifact/v1","service":"payments","enabled":"true","revision":1}`, "ARTIFACT_TYPE_MISMATCH", true, false},
		{"duplicate", `{"schema":"deployment-artifact/v1","service":"payments","service":"evil","enabled":true,"revision":1}`, "INVALID_ARTIFACT_JSON", false, false},
		{"escaped duplicate", `{"schema":"deployment-artifact/v1","service":"payments","\u0073ervice":"evil","enabled":true,"revision":1}`, "INVALID_ARTIFACT_JSON", false, false},
		{"unpaired surrogate", `{"schema":"deployment-artifact/v1","service":"\ud800","enabled":true,"revision":1}`, "INVALID_ARTIFACT_JSON", false, false},
		{"fraction", `{"schema":"deployment-artifact/v1","service":"payments","enabled":true,"revision":1.0}`, "ARTIFACT_TYPE_MISMATCH", true, false},
		{"exponent", `{"schema":"deployment-artifact/v1","service":"payments","enabled":true,"revision":1e0}`, "ARTIFACT_TYPE_MISMATCH", true, false},
		{"overflow", `{"schema":"deployment-artifact/v1","service":"payments","enabled":true,"revision":9223372036854775808}`, "ARTIFACT_TYPE_MISMATCH", true, false},
		{"negative zero", `{"schema":"deployment-artifact/v1","service":"payments","enabled":true,"revision":-0}`, "ARTIFACT_TYPE_MISMATCH", true, false},
		{"null", `{"schema":"deployment-artifact/v1","service":"payments","enabled":null,"revision":1}`, "ARTIFACT_TYPE_MISMATCH", true, false},
		{"array scalar", `{"schema":"deployment-artifact/v1","service":"payments","enabled":[],"revision":1}`, "ARTIFACT_TYPE_MISMATCH", true, false},
		{"object scalar", `{"schema":"deployment-artifact/v1","service":"payments","enabled":{},"revision":1}`, "ARTIFACT_TYPE_MISMATCH", true, false},
		{"root array", `[]`, "INVALID_ARTIFACT_OBJECT", false, false},
		{"root null", `null`, "INVALID_ARTIFACT_JSON", false, false},
		{"trailing", string(goodArtifact) + ` {}`, "INVALID_ARTIFACT_JSON", false, false},
		{"empty", ``, "EMPTY_ARTIFACT", false, false},
	}
	for _, tc := range bad {
		t.Run(tc.name, func(t *testing.T) {
			r := observeFile(t, testRecipe(1), artifactFile(t, []byte(tc.raw)))
			assertStatuses(t, r, 1, "fail")
			if r.ArtifactReason != tc.reason || r.SchemaOK != tc.schemaOK || r.TypesOK != tc.typesOK {
				t.Fatalf("unexpected mandatory failure %#v", r)
			}
		})
	}
	t.Run("invalid UTF8", func(t *testing.T) {
		raw := append(append([]byte{}, goodArtifact...), 0xff)
		assertStatuses(t, observeFile(t, testRecipe(1), artifactFile(t, raw)), 1, "fail")
	})
	t.Run("changed bytes compared with independently pinned expected SHA", func(t *testing.T) {
		req := artifactFile(t, goodArtifact)
		changed := []byte(strings.Replace(string(goodArtifact), "payments", "paymentx", 1))
		if err := os.WriteFile(req.Path, changed, 0600); err != nil {
			t.Fatal(err)
		}
		r := observeFile(t, testRecipe(1), req)
		assertStatuses(t, r, 1, "fail")
		if r.DigestOK || !r.SchemaOK || !r.TypesOK || r.ActualSHA256 != digest(changed) || r.ArtifactReason != "ARTIFACT_DIGEST_MISMATCH" {
			t.Fatalf("changed artifact accepted: %#v", r)
		}
	})
}

func TestEveryClaimRemainsObservedThroughEarlyMiddleLateFailure(t *testing.T) {
	for _, index := range []int{0, 127, 255} {
		r := testRecipe(256)
		r.Claims[index].Expected = "not-equal"
		// Each selected position is a text predicate, independent of the repeating
		// field assignment used for other test claims.
		r.Claims[index].Field = "service"
		report := observeFile(t, r, artifactFile(t, goodArtifact))
		if len(report.Observations) != 256 {
			t.Fatal("a failed predicate erased subsequent required claims")
		}
		for i, o := range report.Observations {
			expected := "pass"
			if i == index {
				expected = "fail"
			}
			if o.Status != expected {
				t.Fatalf("failure at %d, claim %d unexpectedly %s", index, i, o.Status)
			}
		}
	}
}

func TestInitializationRejectsUnknownOrAmbiguousConfiguration(t *testing.T) {
	mutations := []func(*Recipe){
		func(r *Recipe) { r.Schema = "wrong" }, func(r *Recipe) { r.ProducerID = "remote-trusted/v1" },
		func(r *Recipe) { r.ArtifactSchema = "" }, func(r *Recipe) { r.ArtifactSchema = string([]byte{0xff}) },
		func(r *Recipe) { r.MaxBytes = 0 }, func(r *Recipe) { r.MaxBytes = 65537 }, func(r *Recipe) { r.Fields = nil },
		func(r *Recipe) { r.Fields = append(r.Fields, r.Fields[0]) }, func(r *Recipe) { r.Fields[0].Name = "schema" },
		func(r *Recipe) { r.Fields[0].Name = "☃" }, func(r *Recipe) { r.Fields[0].Type = "float64" },
		func(r *Recipe) { r.Claims = nil }, func(r *Recipe) { r.Claims = append(r.Claims, r.Claims[0]) },
		func(r *Recipe) { r.Claims[0].Verifier = "caller_says_pass/v1" }, func(r *Recipe) { r.Claims[0].ID = "7claim" },
		func(r *Recipe) { r.Claims[0].Field = "notConfigured" },
		func(r *Recipe) { r.Claims[0].Field = "enabled"; r.Claims[0].Expected = "True" },
		func(r *Recipe) { r.Claims[0].Field = "revision"; r.Claims[0].Expected = "01" },
		func(r *Recipe) { r.Claims[0].Field = "revision"; r.Claims[0].Expected = "+1" },
		func(r *Recipe) { r.Claims[0].Field = "revision"; r.Claims[0].Expected = "-0" },
		func(r *Recipe) { r.Claims[0].Field = "revision"; r.Claims[0].Expected = "9223372036854775808" },
	}
	for i, mutate := range mutations {
		r := testRecipe(1)
		mutate(&r)
		if _, err := New(r); err == nil {
			t.Fatalf("invalid config mutation %d accepted: %#v", i, r)
		}
	}
	r := testRecipe(257)
	if _, err := New(r); err == nil {
		t.Fatal("257 claims accepted")
	}
	r = testRecipe(1)
	r.Fields = make([]Field, 256)
	for i := range r.Fields {
		r.Fields[i] = Field{fmt.Sprintf("f%03d", i), "text"}
	}
	r.Claims[0].Field = "f000"
	if _, err := New(r); err == nil {
		t.Fatal("256 configured fields accepted in addition to schema")
	}
	for _, requirement := range []Requirement{{"relative", digest(goodArtifact)}, {"/tmp/../artifact", digest(goodArtifact)}, {"/tmp/artifact", "sha256:" + strings.Repeat("A", 64)}} {
		if err := ValidateRequirement(requirement); err == nil {
			t.Fatalf("invalid requirement accepted: %#v", requirement)
		}
	}
}

func TestMaximumExactFieldSet(t *testing.T) {
	r := testRecipe(1)
	r.Fields = make([]Field, 255)
	object := map[string]any{"schema": r.ArtifactSchema}
	for i := range r.Fields {
		name := fmt.Sprintf("field_%03d", i)
		r.Fields[i] = Field{name, "bool"}
		object[name] = true
	}
	r.Claims[0].Field, r.Claims[0].Expected = r.Fields[254].Name, "true"
	raw, err := json.Marshal(object)
	if err != nil {
		t.Fatal(err)
	}
	assertStatuses(t, observeFile(t, r, artifactFile(t, raw)), 1, "pass")
}

func TestExactByteLimitAndContentContextBinding(t *testing.T) {
	recipe := Recipe{RecipeSchema, ProducerID, "deployment-artifact/v1", MaxBytes, []Field{{"service", "text"}}, []Claim{{"claim_000", VerifierID, "service", ""}}}
	empty, err := json.Marshal(map[string]string{"schema": recipe.ArtifactSchema, "service": ""})
	if err != nil {
		t.Fatal(err)
	}
	recipe.Claims[0].Expected = strings.Repeat("p", int(MaxBytes)-len(empty))
	raw, err := json.Marshal(map[string]string{"schema": recipe.ArtifactSchema, "service": recipe.Claims[0].Expected})
	if err != nil || int64(len(raw)) != MaxBytes {
		t.Fatalf("wrong byte boundary: %d %v", len(raw), err)
	}
	report := observeFile(t, recipe, artifactFile(t, raw))
	assertStatuses(t, report, 1, "pass")
	tooLarge := append(append([]byte{}, raw...), ' ')
	assertStatuses(t, observeFile(t, recipe, artifactFile(t, tooLarge)), 1, "truncated")

	ordinary := testRecipe(1)
	requirement := artifactFile(t, goodArtifact)
	p, _ := New(ordinary)
	a, _ := ReadArtifact(requirement, ordinary.MaxBytes)
	first, err := p.Observe(a, requirement.ExpectedSHA256, digest([]byte("first principal/request")), 100)
	if err != nil {
		t.Fatal(err)
	}
	second, err := p.Observe(a, requirement.ExpectedSHA256, digest([]byte("second principal/request")), 100)
	if err != nil {
		t.Fatal(err)
	}
	if first.Observations[0].EvidenceID == second.Observations[0].EvidenceID {
		t.Fatal("observations lost principal/request context binding")
	}
	spaced := append(append([]byte{}, goodArtifact...), '\n')
	other := observeFile(t, ordinary, artifactFile(t, spaced))
	if first.ActualSHA256 == other.ActualSHA256 || first.Observations[0].EvidenceID == other.Observations[0].EvidenceID {
		t.Fatal("observations lost actual byte binding")
	}
}

func TestSourceIdentityBindsActualImplementationBytes(t *testing.T) {
	identity := SourceIdentity()
	if identity.ProducerID != ProducerID || identity.VerifierID != VerifierID || !validDigest(identity.JSONInputSHA256) {
		t.Fatal("source identity omitted registry or shared JSON binding")
	}
	for name, expected := range map[string]string{
		"model.go": identity.ModelSHA256, "validation.go": identity.ValidationSHA256,
		"verifier.go": identity.VerifierSHA256, "reader.go": identity.ReaderSHA256,
		"reader_unix.go": identity.ReaderUnixSHA256, "reader_other.go": identity.ReaderOtherSHA256,
		"identity.go": identity.IdentitySHA256,
	} {
		raw, err := os.ReadFile(name)
		if err != nil || digest(raw) != expected {
			t.Fatalf("compiled source identity differs from %s: %v", name, err)
		}
	}
}

func TestReplayBindingsTamperingAndNoPathReopen(t *testing.T) {
	recipe := testRecipe(5)
	requirement := artifactFile(t, goodArtifact)
	saved := observeFile(t, recipe, requirement)
	if err := os.Remove(requirement.Path); err != nil {
		t.Fatal(err)
	}
	if _, err := Replay(recipe, requirement.ExpectedSHA256, saved.ContextDigest, saved); err != nil {
		t.Fatalf("historical replay reopened operator file: %v", err)
	}
	mutations := []func(*Report){
		func(r *Report) { r.ArtifactBase64 = base64.StdEncoding.EncodeToString([]byte("changed")) },
		func(r *Report) { r.ArtifactBase64 += "\n" }, func(r *Report) { r.ActualSHA256 = digest([]byte("changed")) },
		func(r *Report) { r.DigestOK = false }, func(r *Report) { r.SchemaOK = false }, func(r *Report) { r.TypesOK = false },
		func(r *Report) { r.Identity.VerifierID = "forged" }, func(r *Report) { r.Identity.ReaderSHA256 = digest([]byte("changed source")) },
		func(r *Report) { r.ObservationUnix++ }, func(r *Report) { r.AcquisitionStatus = ReadError },
		func(r *Report) { r.ObservedSize++ }, func(r *Report) { r.Observations[4].Status = "fail" },
		func(r *Report) { r.Observations[0].EvidenceID = "ev_" + strings.Repeat("0", 64) },
		func(r *Report) { r.Observations = r.Observations[:4] },
	}
	for i, mutate := range mutations {
		raw, _ := json.Marshal(saved)
		var copy Report
		if err := json.Unmarshal(raw, &copy); err != nil {
			t.Fatal(err)
		}
		mutate(&copy)
		if _, err := Replay(recipe, requirement.ExpectedSHA256, saved.ContextDigest, copy); err == nil {
			t.Fatalf("tamper %d accepted", i)
		}
	}
	if _, err := Replay(recipe, digest([]byte("changed requirement")), saved.ContextDigest, saved); err == nil {
		t.Fatal("changed operator digest accepted")
	}
	if _, err := Replay(recipe, requirement.ExpectedSHA256, digest([]byte("changed context")), saved); err == nil {
		t.Fatal("changed original command context accepted")
	}
	changed := cloneRecipe(recipe)
	changed.Claims[0].Expected = "different"
	if _, err := Replay(changed, requirement.ExpectedSHA256, saved.ContextDigest, saved); err == nil {
		t.Fatal("changed operator predicate accepted")
	}
}

func TestOpaqueAcquisitionAndReturnedOwnership(t *testing.T) {
	recipe := testRecipe(5)
	requirement := artifactFile(t, goodArtifact)
	p, err := New(recipe)
	if err != nil {
		t.Fatal(err)
	}
	recipe.Claims[0].Expected = "evil"
	recipe.Fields[0].Type = "bool"
	copy := p.Recipe()
	copy.Claims[0].Expected = "evil"
	copy.Fields[0].Type = "bool"
	a, err := ReadArtifact(requirement, p.Recipe().MaxBytes)
	if err != nil {
		t.Fatal(err)
	}
	ctx := digest([]byte("context"))
	r, err := p.Observe(a, requirement.ExpectedSHA256, ctx, 100)
	if err != nil {
		t.Fatal(err)
	}
	assertStatuses(t, r, 5, "pass")
	r.Observations[0].Status = "fail"
	again, err := p.Observe(a, requirement.ExpectedSHA256, ctx, 100)
	if err != nil {
		t.Fatal(err)
	}
	assertStatuses(t, again, 5, "pass")
	if _, err := p.Observe(Acquisition{}, requirement.ExpectedSHA256, ctx, 100); err == nil {
		t.Fatal("zero acquisition forged a observation")
	}
	if _, err := p.Observe(a, digest([]byte("different requirement")), ctx, 100); err == nil {
		t.Fatal("acquisition relabeled under another operator digest")
	}
	if _, err := p.Observe(a, requirement.ExpectedSHA256, ctx, 0); err == nil {
		t.Fatal("zero trusted observation time accepted")
	}
	if reflect.DeepEqual(r, again) {
		t.Fatal("test mutation failed to modify owned output")
	}
}

func TestReadFailuresOverlimitAndSymlinksAreWholeNonPassReports(t *testing.T) {
	recipe := testRecipe(5)
	req := artifactFile(t, goodArtifact)
	t.Run("missing", func(t *testing.T) {
		missing := req
		missing.Path = filepath.Join(filepath.Dir(req.Path), "missing")
		r := observeFile(t, recipe, missing)
		assertStatuses(t, r, 5, "unknown")
		if r.DigestOK || r.AcquisitionStatus != ReadError {
			t.Fatal("missing artifact passed")
		}
	})
	t.Run("directory", func(t *testing.T) {
		dir := req
		dir.Path = filepath.Dir(req.Path)
		assertStatuses(t, observeFile(t, recipe, dir), 5, "unknown")
	})
	t.Run("symlink file", func(t *testing.T) {
		link := req
		link.Path = filepath.Join(filepath.Dir(req.Path), "link.json")
		if err := os.Symlink(req.Path, link.Path); err != nil {
			t.Fatal(err)
		}
		assertStatuses(t, observeFile(t, recipe, link), 5, "unknown")
	})
	t.Run("symlink ancestor", func(t *testing.T) {
		dir := realDir(t)
		link := filepath.Join(dir, "link")
		if err := os.Symlink(filepath.Dir(req.Path), link); err != nil {
			t.Fatal(err)
		}
		linked := req
		linked.Path = filepath.Join(link, filepath.Base(req.Path))
		assertStatuses(t, observeFile(t, recipe, linked), 5, "unknown")
	})
	t.Run("oversized", func(t *testing.T) {
		small := testRecipe(5)
		small.MaxBytes = int64(len(goodArtifact)) - 1
		r := observeFile(t, small, req)
		assertStatuses(t, r, 5, "truncated")
		if r.DigestOK || r.AcquisitionStatus != Oversized || r.ObservedSize != int64(len(goodArtifact)) {
			t.Fatal("overlimit artifact not retained as nonpass")
		}
	})
	t.Run("skipped", func(t *testing.T) {
		p, _ := New(recipe)
		a, err := SkipArtifact(req, recipe.MaxBytes)
		if err != nil {
			t.Fatal(err)
		}
		r, err := p.Observe(a, req.ExpectedSHA256, digest([]byte("context")), 100)
		if err != nil {
			t.Fatal(err)
		}
		assertStatuses(t, r, 5, "unknown")
		if _, err := Replay(recipe, req.ExpectedSHA256, r.ContextDigest, r); err != nil {
			t.Fatal(err)
		}
	})
}
