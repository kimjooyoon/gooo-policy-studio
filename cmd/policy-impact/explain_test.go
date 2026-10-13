package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/kimjooyoon/gooo-policy-studio/internal/admission"
	"github.com/kimjooyoon/gooo-policy-studio/internal/artifactimpact"
)

type explainCLIRejectWriter struct{}

func (explainCLIRejectWriter) Write([]byte) (int, error) {
	return 0, errors.New("private writer failure")
}

func TestExplainCLIRejectsUnboundedArguments(t *testing.T) {
	for _, args := range [][]string{
		{"explain"},
		{"explain", "--report", "PRIVATE_REPORT"},
		{"explain", "--output", "PRIVATE_OUTPUT"},
		{"explain", "--report", "", "--output", "PRIVATE_OUTPUT"},
		{"explain", "--report", "PRIVATE_REPORT", "--output", ""},
		{"explain", "--report", "PRIVATE_REPORT", "--report", "OTHER", "--output", "PRIVATE_OUTPUT"},
		{"explain", "--report", "PRIVATE_REPORT", "--output", "PRIVATE_OUTPUT", "--output", "OTHER"},
		{"explain", "--report", "PRIVATE_REPORT", "--output", "PRIVATE_OUTPUT", "extra"},
		{"explain", "--report", "PRIVATE_REPORT", "--output", "PRIVATE_OUTPUT", "--clock", "2000000000"},
	} {
		t.Run(strings.Join(args, " "), func(t *testing.T) {
			var out bytes.Buffer
			if exit := run(args, &out); exit != 2 {
				t.Fatalf("usage accepted%d", exit)
			}
			var summary artifactimpact.ExplainSummary
			if json.Unmarshal(out.Bytes(), &summary) != nil || summary.Code != "USAGE_INVALID" || summary.Schema != "policy-studio/artifact-impact-explain-summary/v1" || summary.OutputSaved {
				t.Fatal("fixed explain usage summary")
			}
			if strings.Contains(out.String(), "PRIVATE_") || strings.Contains(out.String(), "OTHER") {
				t.Fatal("usage leaked caller input")
			}
		})
	}
	var help bytes.Buffer
	if run([]string{"explain", "--help"}, &help) != 0 || !strings.Contains(help.String(), "policy-impact explain --report") {
		t.Fatal("explain help")
	}
	if run([]string{"explain"}, explainCLIRejectWriter{}) != 2 {
		t.Fatal("stdout failure exit")
	}
}

func TestExplainCLIFreshHistoricalReportAfterInputDeletion(t *testing.T) {
	// One fresh CLI-routing fixture, independent of the ten fixed-clock package
	// fixtures. Actual host time is allowed here; the deadline is explicitly2100.
	raw, err := os.ReadFile("../../internal/artifactimpact/testdata/explain-fixtures.json")
	if err != nil {
		t.Fatal(err)
	}
	var catalog struct {
		Case     artifactimpact.Case      `json:"shared_case"`
		Before   admission.ArtifactPolicy `json:"shared_policy_before"`
		After    admission.ArtifactPolicy `json:"shared_policy_after"`
		Fixtures []struct {
			Raw string `json:"raw_artifact_utf8"`
			SHA string `json:"raw_artifact_sha256"`
		} `json:"fixtures"`
	}
	if json.Unmarshal(raw, &catalog) != nil || len(catalog.Fixtures) != 10 {
		t.Fatal("sanitized fixture catalog")
	}
	// Use a physical directory because the unchanged artifact reader rejects
	// symlink ancestors, including the macOS /var temporary-path alias.
	dir, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal("fresh physical CLI fixture directory unavailable")
	}
	artifact := filepath.Join(dir, "artifact.json")
	catalog.Case.Artifact.Path = artifact
	catalog.Case.Artifact.ExpectedSHA256 = catalog.Fixtures[0].SHA
	catalog.Case.Artifact.DeadlineUnix = 4102444800
	paths := artifactimpact.Paths{Case: filepath.Join(dir, "case.json"), Before: filepath.Join(dir, "before.json"), After: filepath.Join(dir, "after.json"), Report: filepath.Join(dir, "report.json")}
	write := func(path string, value any) {
		t.Helper()
		b, e := json.Marshal(value)
		if e != nil {
			t.Fatal(e)
		}
		if e = os.WriteFile(path, b, 0600); e != nil {
			t.Fatal(e)
		}
	}
	if err = os.WriteFile(artifact, []byte(catalog.Fixtures[0].Raw), 0600); err != nil {
		t.Fatal(err)
	}
	write(paths.Case, catalog.Case)
	write(paths.Before, catalog.Before)
	write(paths.After, catalog.After)
	compared, exit := artifactimpact.CompareFiles(paths)
	if exit != 0 || !compared.ReportSaved || compared.Direction != "newly_denied" {
		actualSafe, marshalErr := json.Marshal(compared)
		if marshalErr != nil {
			t.Fatal("safe comparison diagnostic unavailable")
		}
		t.Fatalf("fresh row501 comparison mismatch; exit=%d actual_safe_summary=%s", exit, actualSafe)
	}
	before, err := os.ReadFile(paths.Report)
	if err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{paths.Case, paths.Before, paths.After, artifact} {
		if err = os.Remove(path); err != nil {
			t.Fatal(err)
		}
	}
	output := filepath.Join(dir, "explanation.html")
	var out bytes.Buffer
	if run([]string{"explain", "--report", paths.Report, "--output", output}, &out) != 0 {
		t.Fatalf("actual explain dispatch%s", out.String())
	}
	var summary artifactimpact.ExplainSummary
	if json.Unmarshal(out.Bytes(), &summary) != nil || summary.Code != "HISTORICAL_EXPLANATION_SAVED" || summary.Status != "saved" || !summary.Historical || !summary.Simulation || summary.ReadOnly || !summary.LocalFileWriteDeclared || !summary.OutputSaved || summary.CurrentArtifactReads != 0 || summary.AuthenticatedServerState || summary.Committed || summary.TargetEffectsExecuted {
		t.Fatal("CLI effect and historical summary")
	}
	if summary.Direction != "newly_denied" || !summary.Before.WouldAdmit || summary.After.WouldAdmit || summary.Before.Counts.Pass != 6 || summary.After.Counts.Pass != 5 || summary.After.Counts.Fail != 1 {
		t.Fatal("literal CLI decision/counts")
	}
	for _, secret := range []string{dir, paths.Report, output, "row_limit_at_most", "prepare_export", catalog.Case.Request.Key, catalog.Case.Principal.Key} {
		if strings.Contains(out.String(), secret) {
			t.Fatal("CLI private output leaked")
		}
	}
	page, err := os.ReadFile(output)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(page, []byte("Historical policy comparison")) || !bytes.Contains(page, []byte("BOUND_MISMATCH")) || !bytes.Contains(page, []byte("EVIDENCE_REJECTED")) || !bytes.Contains(page, []byte("Not executed")) {
		t.Fatal("actual HTML source-only feature missing")
	}
	info, err := os.Stat(output)
	if err != nil || info.Mode().Perm() != 0600 {
		t.Fatal("CLI output privacy")
	}
	after, err := os.ReadFile(paths.Report)
	if err != nil || !bytes.Equal(before, after) {
		t.Fatal("CLI input report changed")
	}
	out.Reset()
	if run([]string{"explain", "--report", paths.Report, "--output", output}, &out) != 2 {
		t.Fatal("CLI overwrote existing explanation")
	}
	if json.Unmarshal(out.Bytes(), &summary) != nil || summary.Code != "OUTPUT_FILE_INVALID" || summary.OutputSaved {
		t.Fatal("CLI exclusive output failure")
	}
}
