package main

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/kimjooyoon/gooo-policy-studio/internal/artifactimpact"
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
