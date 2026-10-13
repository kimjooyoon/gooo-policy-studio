package artifactimpact

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"html"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/kimjooyoon/gooo-policy-studio/internal/admission"
	"github.com/kimjooyoon/gooo-policy-studio/internal/artifactpreflight"
)

// These ten fresh cases use independent, source-first literals. They do not
// import a historical execution corpus or calculate expected numeric truth.
type explainFixtureCatalog struct {
	ObservationUnix int64                    `json:"observation_unix"`
	SharedCase      Case                     `json:"shared_case"`
	Before          admission.ArtifactPolicy `json:"shared_policy_before"`
	After           admission.ArtifactPolicy `json:"shared_policy_after"`
	RejectedIDs     []string                 `json:"rejected_identifier_cases"`
	TaintedText     string                   `json:"valid_taint_text"`
	Fixtures        []explainFixtureSpec     `json:"fixtures"`
}

type explainFixtureSpec struct {
	ID        string `json:"id"`
	Raw       string `json:"raw_artifact_utf8"`
	SHA       string `json:"raw_artifact_sha256"`
	Mutations []struct {
		Scope string          `json:"scope"`
		Op    string          `json:"op"`
		Value json.RawMessage `json:"value"`
	} `json:"case_and_policy_mutations"`
}

func explainReadCatalog(t *testing.T) (explainFixtureCatalog, map[string]any) {
	t.Helper()
	var catalog explainFixtureCatalog
	raw, err := os.ReadFile("testdata/explain-fixtures.json")
	if err != nil || json.Unmarshal(raw, &catalog) != nil {
		t.Fatalf("fixture catalog: %v", err)
	}
	raw, err = os.ReadFile("testdata/explain-expectations.json")
	if err != nil {
		t.Fatal(err)
	}
	return catalog, explainObject(t, raw)
}

func explainObject(t *testing.T, raw []byte) map[string]any {
	t.Helper()
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	var value map[string]any
	if err := decoder.Decode(&value); err != nil {
		t.Fatalf("typed JSON: %v", err)
	}
	return value
}

func explainMap(value any) map[string]any { return value.(map[string]any) }
func explainList(value any) []any         { return value.([]any) }

func explainJSON(t *testing.T, value any) []byte {
	t.Helper()
	raw, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func explainWrite(t *testing.T, path string, raw []byte) {
	t.Helper()
	if err := os.WriteFile(path, raw, 0600); err != nil {
		t.Fatal(err)
	}
}

func explainFreshReport(t *testing.T, catalog explainFixtureCatalog, spec explainFixtureSpec) (Paths, Report, Case, []string) {
	t.Helper()
	// The artifact reader intentionally rejects symlink ancestors. macOS test
	// temporary paths commonly start under /var, so select the physical directory
	// for every fresh input/report/alias fixture rather than weaken that reader.
	dir, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal("fresh physical fixture directory unavailable")
	}
	var c Case
	var before, after admission.ArtifactPolicy
	if json.Unmarshal(explainJSON(t, catalog.SharedCase), &c) != nil || json.Unmarshal(explainJSON(t, catalog.Before), &before) != nil || json.Unmarshal(explainJSON(t, catalog.After), &after) != nil {
		t.Fatal("fresh fixture copy")
	}
	c.Artifact.Path = filepath.Join(dir, "artifact.json")
	c.Artifact.ExpectedSHA256 = spec.SHA
	if digest([]byte(spec.Raw)) != spec.SHA {
		t.Fatal("frozen artifact bytes/digest mismatch")
	}
	for _, mutation := range spec.Mutations {
		switch mutation.Scope {
		case "case.artifact.expected_sha256":
			if json.Unmarshal(mutation.Value, &c.Artifact.ExpectedSHA256) != nil {
				t.Fatal("digest mutation")
			}
		case "case.artifact.deadline_unix":
			if json.Unmarshal(mutation.Value, &c.Artifact.DeadlineUnix) != nil {
				t.Fatal("deadline mutation")
			}
		case "case.principal.can_execute":
			if json.Unmarshal(mutation.Value, &c.Principal.CanExecute) != nil {
				t.Fatal("permission mutation")
			}
		case "case.request.submitted":
			if json.Unmarshal(mutation.Value, &c.Request.Submitted) != nil {
				t.Fatal("base mutation")
			}
		case "after.approval_budget.allow_target":
			if json.Unmarshal(mutation.Value, &after.ApprovalBudget.AllowTarget) != nil {
				t.Fatal("budget mutation")
			}
		case "before.recipe.claims.destination_equal.expected", "after.recipe.claims.destination_equal.expected":
			selected := &before
			if strings.HasPrefix(mutation.Scope, "after.") {
				selected = &after
			}
			for i := range selected.Recipe.Claims {
				if selected.Recipe.Claims[i].ID == "destination_equal" && json.Unmarshal(mutation.Value, &selected.Recipe.Claims[i].Expected) != nil {
					t.Fatal("text mutation")
				}
			}
		case "":
			if mutation.Op != "swap_before_after_policies" {
				t.Fatal("unknown fixture mutation")
			}
			before, after = after, before
		default:
			t.Fatalf("unreviewed fixture mutation %q", mutation.Scope)
		}
	}
	paths := Paths{Case: filepath.Join(dir, "case.json"), Before: filepath.Join(dir, "before.json"), After: filepath.Join(dir, "after.json"), Report: filepath.Join(dir, "report.json")}
	explainWrite(t, c.Artifact.Path, []byte(spec.Raw))
	explainWrite(t, paths.Case, explainJSON(t, c))
	explainWrite(t, paths.Before, explainJSON(t, before))
	explainWrite(t, paths.After, explainJSON(t, after))
	summary, exit := compareFiles(paths, dependencies{readArtifact: artifactpreflight.ReadArtifact, now: func() time.Time { return time.Unix(catalog.ObservationUnix, 0) }})
	if exit != 0 || !summary.ReportSaved {
		t.Fatalf("fresh synthetic comparison failed: %d %+v", exit, summary)
	}
	raw, err := os.ReadFile(paths.Report)
	if err != nil {
		t.Fatal(err)
	}
	var report Report
	if json.Unmarshal(raw, &report) != nil {
		t.Fatal("fresh report decode")
	}
	wantAcquisition := artifactpreflight.ReadSuccess
	wantNative := 2
	switch spec.ID {
	case "permission_denied_before_acquisition", "base_denied_before_acquisition":
		wantAcquisition, wantNative = artifactpreflight.Skipped, 0
	case "mandatory_wrong_type", "mandatory_digest_mismatch":
		wantNative = 0
	}
	if report.Audit.AcquisitionStatus != wantAcquisition {
		t.Fatalf("fresh fixture acquisition wiring mismatch; actual_safe_summary=%s", explainJSON(t, summary))
	}
	for _, side := range []Side{report.Before, report.After} {
		nativeCount := 0
		for _, observation := range side.Producer.Observations {
			if observation.NativeProof != nil {
				nativeCount++
			}
		}
		if len(side.Producer.Observations) != 6 || nativeCount != wantNative {
			t.Fatalf("fresh fixture typed-proof wiring mismatch; actual_safe_summary=%s", explainJSON(t, summary))
		}
	}
	return paths, report, c, []string{paths.Case, paths.Before, paths.After, c.Artifact.Path}
}

func explainSection(t *testing.T, doc, id string) string {
	t.Helper()
	match := regexp.MustCompile(`(?s)<section id="` + regexp.QuoteMeta(id) + `"[^>]*>(.*?)</section>`).FindStringSubmatch(doc)
	if len(match) != 2 {
		t.Fatalf("missing unique section %s", id)
	}
	return match[1]
}

func explainPlain(raw string) string {
	return html.UnescapeString(regexp.MustCompile(`<[^>]*>`).ReplaceAllString(raw, ""))
}

func explainPreJSON(t *testing.T, body string) []map[string]any {
	t.Helper()
	var result []map[string]any
	for _, match := range regexp.MustCompile(`(?s)<pre><code>(.*?)</code></pre>`).FindAllStringSubmatch(body, -1) {
		result = append(result, explainObject(t, []byte(html.UnescapeString(match[1]))))
	}
	return result
}

func explainContainsJSON(t *testing.T, body string, wanted map[string]any) {
	t.Helper()
	for _, got := range explainPreJSON(t, body) {
		match := true
		for key, value := range wanted {
			if !reflect.DeepEqual(got[key], value) {
				match = false
				break
			}
		}
		if match {
			return
		}
	}
	t.Fatalf("missing full typed displayed JSON %v", wanted)
}

func explainTable(t *testing.T, body, caption string) [][]string {
	t.Helper()
	match := regexp.MustCompile(`(?s)<table><caption>` + regexp.QuoteMeta(caption) + `</caption>(.*?)</table>`).FindStringSubmatch(body)
	if len(match) != 2 {
		t.Fatalf("missing table %s", caption)
	}
	var rows [][]string
	for _, row := range regexp.MustCompile(`(?s)<tr>(.*?)</tr>`).FindAllStringSubmatch(match[1], -1) {
		var cells []string
		for _, cell := range regexp.MustCompile(`(?s)<(?:th|td)(?:\s[^>]*)?>(.*?)</(?:th|td)>`).FindAllStringSubmatch(row[1], -1) {
			cells = append(cells, explainPlain(cell[1]))
		}
		rows = append(rows, cells)
	}
	return rows
}

func explainAssertSide(t *testing.T, body string, expected map[string]any, actual Side, c Case, fixtureSHA string, columns []any) {
	t.Helper()
	final := explainMap(expected["final"])
	explainContainsJSON(t, body, explainMap(final["Decision"]))
	explainContainsJSON(t, body, explainMap(final["AdmissionFacts"]))
	for label, value := range map[string]any{"Would admit": final["WouldAdmit"], "Reason": final["Reason"]} {
		if !strings.Contains(body, "<dt>"+label+"</dt><dd>"+fmt.Sprint(value)+"</dd>") {
			t.Fatalf("missing final %s", label)
		}
	}
	producer := explainMap(expected["producer"])
	explainContainsJSON(t, body, producer)
	completion := explainMap(expected["completion"])
	countJSON := make(map[string]any)
	for k, v := range explainMap(completion["counts"]) {
		countJSON[k] = v
	}
	countJSON["valid"], countJSON["complete"], countJSON["reason"] = completion["summary_valid"], completion["summary_complete"], completion["summary_reason"]
	explainContainsJSON(t, body, countJSON)
	explainContainsJSON(t, body, explainMap(completion["readiness"]))
	for _, label := range []string{"proposed_approval", "proposed_control_plane"} {
		explainContainsJSON(t, body, explainMap(expected[label]))
	}
	rows := explainTable(t, body, "Claims in configured required order")
	claims := explainList(expected["claims"])
	if len(rows) != len(claims)+1 || len(rows[0]) != 10 {
		t.Fatalf("claim table dimensions %d", len(rows))
	}
	for i, column := range columns {
		if rows[0][i] != column.(string) {
			t.Fatalf("column%d: %q", i, rows[0][i])
		}
	}
	articles := regexp.MustCompile(`(?s)<article class="claim-detail">(.*?)</article>`).FindAllStringSubmatch(body, -1)
	if len(articles) != len(claims) {
		t.Fatalf("claim detail count%d", len(articles))
	}
	for i, value := range claims {
		claim := explainMap(value)
		if len(rows[i+1]) != 10 {
			t.Fatal("claim row width")
		}
		for j, column := range columns {
			if rows[i+1][j] != fmt.Sprint(claim[column.(string)]) {
				t.Fatalf("claim%d column%s got%q want%q", i, column, rows[i+1][j], fmt.Sprint(claim[column.(string)]))
			}
		}
		article := articles[i][1]
		if !strings.Contains(article, "<h4>Claim evidence: "+claim["Claim"].(string)+"</h4>") {
			t.Fatal("claim detail association/order")
		}
		explainContainsJSON(t, article, explainMap(claim["evidence_decision"]))
		facts := map[string]any{"actual_authority": "live-observation", "required_authority": "live-observation", "status": claim["Status"], "confidence": "observed", "provider_verified": true, "observed_binding": actual.ContextSHA256, "required_binding": actual.ContextSHA256, "observed_artifact": fixtureSHA, "required_artifact": c.Artifact.ExpectedSHA256, "observed_policy": actual.SimulationPolicyVersion, "required_policy": actual.SimulationPolicyVersion}
		if producer["acquisition_status"] == "skipped" {
			facts["observed_artifact"] = "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
		}
		for k, v := range explainMap(claim["evidence_time"]) {
			facts[k] = v
		}
		explainContainsJSON(t, article, facts)
		if claim["Native proof"] == "Not executed" {
			if !strings.Contains(article, "<p>Not executed</p>") {
				t.Fatal("absent native proof fabricated or omitted")
			}
			for _, block := range explainPreJSON(t, article) {
				if _, exists := block["bindings"]; exists {
					t.Fatal("native proof fabricated")
				}
			}
		} else {
			proof := explainMap(claim["Native proof"])
			explainContainsJSON(t, article, proof)
			found := false
			for _, block := range explainPreJSON(t, article) {
				if _, exists := block["bindings"]; exists {
					if !reflect.DeepEqual(block, proof) || len(block) != 3 || len(explainMap(block["facts"])) != 3 || len(explainMap(block["decision"])) != 5 || len(explainMap(block["bindings"])) != 12 {
						t.Fatal("native full3facts/5outputs/12bindings mismatch")
					}
					found = true
				}
			}
			if !found {
				t.Fatal("missing numeric proof")
			}
		}
	}
	ordered := explainTable(t, body, "Ordered completion results")
	if len(ordered) != len(claims)+1 {
		t.Fatal("ordered completion rows")
	}
	for i, value := range claims {
		claim := explainMap(value)
		if ordered[i+1][0] != claim["Claim"] || ordered[i+1][1] != claim["Status"] {
			t.Fatal("completion required claim/status order")
		}
		explainContainsJSON(t, body, explainObject(t, explainJSON(t, actual.Completion.Steps[i])))
	}
}

func explainAssertSummary(t *testing.T, summary ExplainSummary, expected, contract map[string]any) {
	t.Helper()
	got := explainObject(t, explainJSON(t, summary))
	if len(got) != len(explainList(contract["field_roster"])) {
		t.Fatal("stdout schema added private fields")
	}
	for _, field := range explainList(contract["field_roster"]) {
		if _, ok := got[field.(string)]; !ok {
			t.Fatal("stdout field omitted")
		}
	}
	for k, v := range explainMap(contract["fixed_flags"]) {
		if !reflect.DeepEqual(got[k], v) {
			t.Fatalf("stdout flag%s", k)
		}
	}
	if got["status"] != "saved" || got["code"] != "HISTORICAL_EXPLANATION_SAVED" || got["output_saved"] != true || got["schema"] != contract["schema"] || got["direction"] != explainMap(expected["delta"])["direction"] {
		t.Fatalf("safe saved summary mismatch; actual_safe_summary=%s", explainJSON(t, summary))
	}
	for _, side := range []string{"before", "after"} {
		want := explainMap(expected[side])
		final := explainMap(want["final"])
		if !reflect.DeepEqual(got[side], map[string]any{"would_admit": final["WouldAdmit"], "reason": final["Reason"], "counts": explainMap(want["completion"])["counts"]}) {
			t.Fatalf("stdout%s fixed counts/labels mismatch; actual_safe_summary=%s", side, explainJSON(t, summary))
		}
	}
	if !replayDigest(summary.RendererSHA256) || !replayDigest(summary.VerifierSHA256) {
		t.Fatal("actual source hashes omitted")
	}
}

func TestExplainFreshFrozenScenarios(t *testing.T) {
	catalog, oracle := explainReadCatalog(t)
	wants := explainList(oracle["scenarios"])
	if len(catalog.Fixtures) != 10 || len(wants) != 10 {
		t.Fatal("frozen finite10case roster")
	}
	var observations []map[string]any
	for i, spec := range catalog.Fixtures {
		want := explainMap(wants[i])
		if want["id"] != spec.ID {
			t.Fatal("fixture/oracle order changed")
		}
		t.Run(spec.ID, func(t *testing.T) {
			paths, report, c, originals := explainFreshReport(t, catalog, spec)
			before, err := os.ReadFile(paths.Report)
			if err != nil {
				t.Fatal(err)
			}
			for _, path := range originals {
				if err := os.Remove(path); err != nil {
					t.Fatal(err)
				}
			}
			output := filepath.Join(filepath.Dir(paths.Report), "explanation.html")
			summary, exit := ExplainFile(paths.Report, output)
			if exit != 0 {
				t.Fatalf("explain failed%d %+v", exit, summary)
			}
			explainAssertSummary(t, summary, want, explainMap(oracle["stdout_contract"]))
			raw, err := os.ReadFile(output)
			if err != nil {
				t.Fatal(err)
			}
			info, err := os.Stat(output)
			if err != nil || info.Mode().Perm() != 0600 {
				t.Fatal("private output permissions")
			}
			doc := string(raw)
			hc := explainMap(oracle["HTML_contract"])
			if !strings.Contains(doc, "<title>"+hc["title"].(string)+"</title>") || !strings.Contains(doc, hc["fixed_disclosure"].(string)) {
				t.Fatal("historical disclosure/title")
			}
			last := -1
			for _, id := range explainList(hc["section_ids"]) {
				pos := strings.Index(doc, `<section id="`+id.(string)+`"`)
				if pos <= last {
					t.Fatal("fixed section order")
				}
				last = pos
			}
			comparison := explainSection(t, doc, "comparison")
			if !strings.Contains(comparison, "<dt>Observation Unix</dt><dd>2000000000</dd>") || !strings.Contains(comparison, "<dt>Direction</dt><dd>"+explainMap(want["delta"])["direction"].(string)+"</dd>") {
				t.Fatal("historical time/direction")
			}
			permission := explainMap(want["permission"])
			for label, value := range map[string]any{"Permission eligible": permission["eligible"], "Permission reason": permission["reason"], "Modeled HTTP status": permission["modeled_http_status"]} {
				if !strings.Contains(comparison, "<dt>"+label+"</dt><dd>"+fmt.Sprint(value)+"</dd>") {
					t.Fatalf("permission%s", label)
				}
			}
			for _, key := range []string{"base_before_decision", "base_after_decision", "base_change", "delta"} {
				explainContainsJSON(t, comparison, explainMap(want[key]))
			}
			explainAssertSide(t, explainSection(t, doc, "side-before"), explainMap(want["before"]), report.Before, c, spec.SHA, explainList(hc["claim_columns"]))
			explainAssertSide(t, explainSection(t, doc, "side-after"), explainMap(want["after"]), report.After, c, spec.SHA, explainList(hc["claim_columns"]))
			for _, secret := range append(originals, paths.Report, report.ID, c.Request.Key, c.Principal.Key, report.Before.Producer.ArtifactBase64, report.Inputs.Case.RawSHA256, report.Inputs.Before.RawSHA256, report.Inputs.After.RawSHA256) {
				if secret != "" && strings.Contains(doc, secret) {
					t.Fatalf("private omitted field leaked%q", secret)
				}
			}
			stdout := string(explainJSON(t, summary))
			for _, secret := range append(originals, paths.Report, report.ID, c.Request.Key, c.Principal.Key, "row_limit_at_most", "prepare_export", catalog.TaintedText, spec.Raw) {
				if secret != "" && strings.Contains(stdout, secret) {
					t.Fatal("private summary leaked")
				}
			}
			for _, active := range []string{"<script", "<iframe", "<form", "<img", "<a ", "<button", "javascript:", "src=", "onerror="} {
				if strings.Contains(strings.ToLower(doc), active) {
					t.Fatalf("active or remote HTML%s", active)
				}
			}
			if spec.ID == "valid_tainted_text" && (!strings.Contains(doc, "&lt;script&gt;alert(&#34;fixture&#34;)&lt;/script&gt;") || !strings.Contains(doc, "<bdi>")) {
				t.Fatal("tainted actual/expected escaping")
			}
			after, err := os.ReadFile(paths.Report)
			if err != nil || !bytes.Equal(before, after) {
				t.Fatal("readreport altered")
			}
			for _, path := range originals {
				if _, err := os.Lstat(path); !os.IsNotExist(err) {
					t.Fatal("retained input path reacquired/recreated")
				}
			}
			identity, err := ExplainSourceIdentity()
			if err != nil {
				t.Fatal(err)
			}
			if identity.RendererSHA256 != summary.RendererSHA256 || identity.Replay.VerifierSHA256 != summary.VerifierSHA256 || identity.CLIArgumentHandlingBound || len(identity.Sources) != 4 {
				t.Fatal("separate renderer/replay provenance")
			}
			provenance := explainSection(t, doc, "provenance")
			for _, source := range identity.Sources {
				if !strings.Contains(provenance, source.Path) || !strings.Contains(provenance, source.SHA256) {
					t.Fatal("renderer roster")
				}
			}
			observations = append(observations, map[string]any{"case_id": spec.ID, "summary": summary, "actual_html_base64": base64.StdEncoding.EncodeToString(raw), "actual_html_sha256": digest(raw), "actual_html_bytes": len(raw), "actual_html_mode": "0600", "input_report_before_sha256": digest(before), "input_report_after_sha256": digest(after), "original_inputs_deleted": true, "retained_observation_unix": report.ObservationUnix, "renderer_source_identity": identity, "historical_comparison_identity_sha256": canonicalDigest(report.Implementation)})
		})
	}
	if target := os.Getenv("GOOO_EXPLAIN_OBSERVATIONS_PATH"); target != "" && !t.Failed() {
		if len(observations) != 10 || !filepath.IsAbs(target) || filepath.Clean(target) != target {
			t.Fatal("observation output contract")
		}
		raw := explainJSON(t, map[string]any{"schema": "policy-studio/artifact-impact-explain-observations/v1", "scope": "Ten fresh synthetic private explanation cases; total native calls not instrumented. No raw reports or local input paths retained.", "cases": observations})
		file, err := os.OpenFile(target, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
		if err != nil {
			t.Fatal(err)
		}
		if _, err = file.Write(append(raw, '\n')); err != nil {
			file.Close()
			t.Fatal(err)
		}
		if err = file.Sync(); err != nil {
			file.Close()
			t.Fatal(err)
		}
		if err = file.Close(); err != nil {
			t.Fatal(err)
		}
	}
}

func TestExplainRejectsTamperingBeforeRenderingOrReservation(t *testing.T) {
	catalog, _ := explainReadCatalog(t)
	paths, report, _, _ := explainFreshReport(t, catalog, catalog.Fixtures[0])
	if len(report.Before.Producer.Observations) < 4 || report.Before.Producer.Observations[2].NativeProof == nil || report.Before.Producer.Observations[3].NativeProof == nil {
		t.Fatal("fresh numeric tamper fixture lacks required executed proofs")
	}
	tests := []struct {
		name, code string
		change     func(*Report)
		raw        func([]byte) []byte
	}{
		{name: "native-output", code: "REPORT_REPLAY_INVALID", change: func(r *Report) { r.Before.Producer.Observations[2].NativeProof.Decision.AtMost = true }},
		{name: "native-binding", code: "REPORT_REPLAY_INVALID", change: func(r *Report) {
			r.Before.Producer.Observations[2].NativeProof.Bindings.SourceSHA256 = "sha256:" + strings.Repeat("0", 64)
		}},
		{name: "source", code: "REPORT_REPLAY_INVALID", change: func(r *Report) { r.Implementation.HostSHA256 = "sha256:" + strings.Repeat("0", 64) }},
		{name: "runtime", code: "REPORT_REPLAY_INVALID", change: func(r *Report) { r.Implementation.GOOS = "unexpected-os" }},
		{name: "null-native", code: "REPORT_JSON_INVALID", raw: func(b []byte) []byte {
			v := explainObject(t, b)
			obs := explainList(explainMap(explainMap(v["before"])["producer"])["observations"])
			explainMap(obs[2])["native_proof"] = nil
			return explainJSON(t, v)
		}},
		{name: "unknown-field", code: "REPORT_JSON_INVALID", raw: func(b []byte) []byte {
			v := explainObject(t, b)
			v["private_unexpected"] = "DO_NOT_DISCLOSE"
			return explainJSON(t, v)
		}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var changed Report
			if json.Unmarshal(explainJSON(t, report), &changed) != nil {
				t.Fatal("fresh clone")
			}
			if tc.change != nil {
				tc.change(&changed)
				changed.ID = ""
				changed.ID = canonicalDigest(changed)
			}
			raw := explainJSON(t, changed)
			if tc.raw != nil {
				raw = tc.raw(raw)
			}
			explainWrite(t, paths.Report, raw)
			deps := explanationDependencies()
			render, reserve := 0, 0
			deps.render = func(Report, ExplainIdentity, int64) ([]byte, error) {
				render++
				return nil, errors.New("should not render")
			}
			deps.reserve = func(string, ...string) (explainOutput, error) {
				reserve++
				return nil, errors.New("should not reserve")
			}
			summary, exit := explainFile(paths.Report, filepath.Join(filepath.Dir(paths.Report), tc.name+".html"), deps)
			if exit != 2 || summary.Code != tc.code || summary.OutputSaved || render != 0 || reserve != 0 {
				t.Fatalf("tampered unverified report reached renderer/reservation: %+v", summary)
			}
			if bytes.Contains(explainJSON(t, summary), []byte("DO_NOT_DISCLOSE")) {
				t.Fatal("failure exposed input")
			}
		})
	}
}

func TestExplainExclusivePrivateOutputAliases(t *testing.T) {
	catalog, _ := explainReadCatalog(t)
	paths, _, _, _ := explainFreshReport(t, catalog, catalog.Fixtures[0])
	original, err := os.ReadFile(paths.Report)
	if err != nil {
		t.Fatal(err)
	}
	dir := filepath.Dir(paths.Report)
	existing := filepath.Join(dir, "existing.html")
	explainWrite(t, existing, []byte("KEEP_EXISTING"))
	hard := filepath.Join(dir, "hard.json")
	sym := filepath.Join(dir, "symbolic.json")
	if err := os.Link(paths.Report, hard); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(paths.Report, sym); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{paths.Report, hard, sym, existing} {
		t.Run(filepath.Base(path), func(t *testing.T) {
			summary, exit := ExplainFile(paths.Report, path)
			if exit != 2 || summary.Code != "OUTPUT_FILE_INVALID" || summary.OutputSaved {
				t.Fatal("output overwrite or alias accepted")
			}
		})
	}
	after, err := os.ReadFile(paths.Report)
	if err != nil || !bytes.Equal(original, after) {
		t.Fatal("report alias overwritten")
	}
	got, err := os.ReadFile(existing)
	if err != nil || string(got) != "KEEP_EXISTING" {
		t.Fatal("existing output overwritten")
	}
	if err := os.Chmod(paths.Report, 0644); err != nil {
		t.Fatal(err)
	}
	summary, exit := ExplainFile(paths.Report, filepath.Join(dir, "public-report.html"))
	if exit != 2 || summary.Code != "REPORT_FILE_INVALID" {
		t.Fatal("nonprivate report accepted")
	}
}

type explainFailOutput struct {
	writeErr, closeErr error
	writes, closes     int
}

func (o *explainFailOutput) WriteAndSync([]byte) error { o.writes++; return o.writeErr }
func (o *explainFailOutput) Close() error              { o.closes++; return o.closeErr }

func TestExplainIOOrderAndBoundedFailure(t *testing.T) {
	catalog, _ := explainReadCatalog(t)
	paths, _, _, _ := explainFreshReport(t, catalog, catalog.Fixtures[0])
	for _, kind := range []string{"cap", "write", "close", "success"} {
		t.Run(kind, func(t *testing.T) {
			deps := explanationDependencies()
			original := deps
			var calls []string
			output := &explainFailOutput{}
			target := filepath.Join(filepath.Dir(paths.Report), kind+".html")
			deps.read = func(path string, cap int64) ([]byte, error) {
				calls = append(calls, "read")
				return original.read(path, cap)
			}
			deps.replay = func(r Report) (Report, error) { calls = append(calls, "replay"); return original.replay(r) }
			deps.identity = func() (ExplainIdentity, error) { calls = append(calls, "identity"); return original.identity() }
			deps.render = func(r Report, id ExplainIdentity, cap int64) ([]byte, error) {
				calls = append(calls, "render")
				return original.render(r, id, cap)
			}
			deps.reserve = func(path string, inputs ...string) (explainOutput, error) {
				calls = append(calls, "reserve")
				if path != target || len(inputs) != 1 || inputs[0] != paths.Report {
					t.Fatal("reservation inspected retained original paths")
				}
				if kind == "success" {
					return original.reserve(path, inputs...)
				}
				return output, nil
			}
			if kind == "cap" {
				deps.maxHTMLBytes = 32
			}
			if kind == "write" {
				output.writeErr = errors.New("PRIVATE_IO_ERROR")
			}
			if kind == "close" {
				output.closeErr = errors.New("PRIVATE_CLOSE_ERROR")
			}
			summary, exit := explainFile(paths.Report, target, deps)
			want := []string{"read", "replay", "identity", "render"}
			if kind != "cap" {
				want = append(want, "reserve")
			}
			if !reflect.DeepEqual(calls, want) {
				t.Fatalf("trustorder/readonce mismatch%v", calls)
			}
			if kind == "success" {
				if exit != 0 || !summary.OutputSaved {
					t.Fatal("normal IO failed")
				}
				return
			}
			code := "OUTPUT_WRITE_FAILED"
			if kind == "cap" {
				code = "EXPLANATION_RENDER_INVALID"
			}
			if exit != 2 || summary.Code != code || summary.OutputSaved {
				t.Fatal("failed output reported saved")
			}
			if kind != "cap" && (output.writes != 1 || output.closes != 1) {
				t.Fatalf("failure dependencies not closed exactlyonce%d/%d", output.writes, output.closes)
			}
			if strings.Contains(string(explainJSON(t, summary)), "PRIVATE_") {
				t.Fatal("IO error private detail leaked")
			}
			if _, err := os.Lstat(target); !os.IsNotExist(err) {
				t.Fatal("cap/fake-output failure unexpectedly created file")
			}
		})
	}
}

func TestExplainClosedFailuresAndRejectedIdentifiers(t *testing.T) {
	if ExplainFailure("PRIVATE_PATH_OR_TEXT").Code != "USAGE_INVALID" {
		t.Fatal("unknown error label exposed")
	}
	catalog, _ := explainReadCatalog(t)
	for _, id := range catalog.RejectedIDs {
		recipe := catalog.Before.Recipe
		recipe.Claims = append([]artifactpreflight.Claim{}, recipe.Claims...)
		recipe.Claims[0].ID = id
		if artifactpreflight.ValidateRecipe(recipe) == nil {
			t.Fatalf("invalid identifier accepted%q", id)
		}
	}
	for _, cap := range []int64{0, int64(MaxReportBytes) + 1} {
		deps := explanationDependencies()
		deps.maxHTMLBytes = cap
		deps.read = func(string, int64) ([]byte, error) { t.Fatal("bad cap read report"); return nil, nil }
		summary, exit := explainFile("unused", "unused", deps)
		if exit != 2 || summary.Code != "EXPLANATION_RENDER_INVALID" || summary.OutputSaved {
			t.Fatal("invalidcap")
		}
	}
}
