package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/kimjooyoon/gooo-policy-studio/internal/admission"
	"github.com/kimjooyoon/gooo-policy-studio/internal/artifactimpact"
	"github.com/kimjooyoon/gooo-policy-studio/internal/artifactpreflight"
	"github.com/kimjooyoon/gooo-policy-studio/internal/machinerules"
	"github.com/kimjooyoon/gooo-policy-studio/internal/policy"
)

func TestHelpShowsCompleteLocalPrivateComparisonFlow(t *testing.T) {
	for _, args := range [][]string{{"--help"}, {"compare", "--help"}} {
		var out bytes.Buffer
		if run(args, &out) != 0 {
			t.Fatal("help failed")
		}
		for _, text := range []string{"go build", "examples/artifact-impact/README.md", "--case", "--before", "--after", "--report", "Reverse", "0600", "Exit 0", "Exit 2", "No server, token"} {
			if !strings.Contains(out.String(), text) {
				t.Fatalf("help missing %s", text)
			}
		}
	}
}

func TestReplayHelpDiscoverabilityAndFixedFlagErrors(t *testing.T) {
	var out bytes.Buffer
	if run([]string{"replay", "--help"}, &out) != 0 {
		t.Fatal("replay help")
	}
	for _, text := range []string{"policy-impact replay --report SAVED_FILE", "Replay reads only", "original evidence time", "not current authorization", "unsigned history"} {
		if !strings.Contains(out.String(), text) {
			t.Fatalf("replay help missing %s", text)
		}
	}
	for _, args := range [][]string{{"replay"}, {"replay", "--report="}, {"replay", "--report=x", "--report=y"}, {"replay", "-report=x", "-report=y"}, {"replay", "--report=", "--report=private-secret"}, {"replay", "--report=x", "--case=private-secret"}, {"replay", "--report=x", "--clock=private-secret"}, {"replay", "--report=x", "--output=private-secret"}, {"replay", "--report=x", "private-secret"}} {
		out.Reset()
		if run(args, &out) != 2 {
			t.Fatal("invalid replay flags")
		}
		var s artifactimpact.ReplaySummary
		if json.Unmarshal(out.Bytes(), &s) != nil || s.Schema != artifactimpact.ReplaySummarySchema || s.Code != "USAGE_INVALID" || s.Status != "error" || !s.Historical || !s.ReadOnly || !s.Simulation || s.AuthenticatedServerState || s.Committed || s.TargetEffectsExecuted || s.CurrentArtifactReads != 0 || strings.Contains(out.String(), "private-secret") {
			t.Fatal("unsafe replay usage summary")
		}
	}
	out.Reset()
	if run([]string{"replay", "--report", "--report"}, &out) != 2 {
		t.Fatal("replay flag value")
	}
	var s artifactimpact.ReplaySummary
	_ = json.Unmarshal(out.Bytes(), &s)
	if s.Code != "REPORT_FILE_INVALID" {
		t.Fatal("replay value rescanned as flag")
	}
}

func TestReplayCLISafeReadOnlyHistoricalSuccess(t *testing.T) {
	dir, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	artifact := filepath.Join(dir, "private-artifact.json")
	raw := []byte(`{"schema":"cli.replay/v1","secret":"private-secret-value"}`)
	if err = os.WriteFile(artifact, raw, 0600); err != nil {
		t.Fatal(err)
	}
	c := artifactimpact.Case{Schema: artifactimpact.CaseSchema, Request: policy.Request{Key: "private-request", Requester: "requester", Team: "team", Submitted: true}, Principal: admission.PrincipalView{Key: "reviewer", Team: "team", Active: true, Enabled: true, CanExecute: true}, BaseRules: policy.Rules{Limit: 1, SameTeam: true, ActiveReviewer: true, PreventSelf: true}, Artifact: artifactimpact.Artifact{Path: artifact, ExpectedSHA256: fmt.Sprintf("sha256:%x", sha256.Sum256(raw)), DeadlineUnix: time.Now().Unix() + 60}}
	p := admission.ArtifactPolicy{Schema: admission.ArtifactPolicySchema, ID: "cli-policy", Revision: 1, Recipe: artifactpreflight.Recipe{Schema: artifactpreflight.RecipeSchema, ProducerID: artifactpreflight.ProducerID, ArtifactSchema: "cli.replay/v1", MaxBytes: 65536, Fields: []artifactpreflight.Field{{Name: "secret", Type: "text"}}, Claims: []artifactpreflight.Claim{{ID: "private_claim", Verifier: artifactpreflight.VerifierID, Field: "secret", Expected: "private-secret-value"}}}, RequiredAuthority: "live-observation", MaxAgeSeconds: 60, ApprovalBudget: machinerules.EffectBudget{AllowTarget: true, AllowSession: true, AllowFilesystem: true, RequireIdempotent: true}, ControlPlaneBudget: machinerules.EffectBudget{AllowSession: true, AllowFilesystem: true, RequireIdempotent: true}}
	paths := artifactimpact.Paths{Case: filepath.Join(dir, "case.json"), Before: filepath.Join(dir, "before.json"), After: filepath.Join(dir, "after.json"), Report: filepath.Join(dir, "saved.json")}
	for _, file := range []struct {
		path  string
		value any
	}{{paths.Case, c}, {paths.Before, p}, {paths.After, p}} {
		b, err := json.Marshal(file.value)
		if err != nil || os.WriteFile(file.path, b, 0600) != nil {
			t.Fatal("private fixture")
		}
	}
	if s, exit := artifactimpact.CompareFiles(paths); exit != 0 || !s.Before.WouldAdmit {
		t.Fatal("historical fixture")
	}
	original, err := os.ReadFile(paths.Report)
	if err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{artifact, paths.Case, paths.Before, paths.After} {
		if err = os.Remove(path); err != nil {
			t.Fatal(err)
		}
	}
	var out bytes.Buffer
	if run([]string{"replay", "--report", paths.Report}, &out) != 0 {
		t.Fatal("replay CLI")
	}
	var s artifactimpact.ReplaySummary
	if json.Unmarshal(out.Bytes(), &s) != nil || s.Status != "verified" || s.Code != "HISTORICAL_COMPARISON_MATCH" || !s.Historical || !s.ReadOnly || s.CurrentArtifactReads != 0 || !s.Before.WouldAdmit || s.Before.Counts.Pass != 1 || s.Direction != "unchanged" || len(s.VerifierSHA256) != 71 {
		t.Fatal("historical safe result")
	}
	for _, private := range []string{"private-secret-value", "private-request", "private_claim", "cli-policy", paths.Report, artifact} {
		if strings.Contains(out.String(), private) {
			t.Fatal("private historical value printed")
		}
	}
	after, err := os.ReadFile(paths.Report)
	entries, listErr := os.ReadDir(dir)
	if err != nil || listErr != nil || !bytes.Equal(original, after) || len(entries) != 1 || entries[0].Name() != "saved.json" {
		t.Fatal("replay wrote original report/directory")
	}
}
func TestUsageRejectsUnknownOverridesRepeatsAndDoesNotEchoValues(t *testing.T) {
	cases := [][]string{nil, {"submit"}, {"compare"}, {"compare", "--case", "private-secret", "--before", "x", "--after", "y", "--report", "z", "--clock", "123"}, {"compare", "--case=private-secret", "--case=x", "--before=x", "--after=y", "--report=z"}, {"compare", "--case=", "--case=x", "--before=x", "--after=y", "--report=z"}, {"compare", "-case=x", "-case=y", "--before=x", "--after=y", "--report=z"}, {"compare", "--case=x", "--before=x", "--after=y", "--report=z", "private-secret"}}
	for _, args := range cases {
		var out bytes.Buffer
		if run(args, &out) != 2 {
			t.Fatal("invalid flags accepted")
		}
		var s artifactimpact.Summary
		if json.Unmarshal(out.Bytes(), &s) != nil || s.Code != "USAGE_INVALID" || s.Status != "error" || s.ReportSaved || strings.Contains(out.String(), "private-secret") {
			t.Fatal("unsafe or noncanonical usage output")
		}
	}
}
func TestFlagValueIsNotRescannedAsSwitch(t *testing.T) {
	var out bytes.Buffer
	exit := run([]string{"compare", "--case", "--case", "--before=x", "--after=y", "--report=z"}, &out)
	var s artifactimpact.Summary
	_ = json.Unmarshal(out.Bytes(), &s)
	if exit != 2 || s.Code != "CASE_FILE_INVALID" {
		t.Fatalf("flag value rescanned: %s", out.String())
	}
}
