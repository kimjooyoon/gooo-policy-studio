package main

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/kimjooyoon/gooo-policy-studio/internal/gateclient"
)

func TestHelpAndSafeUsageErrors(t *testing.T) {
	for _, args := range [][]string{{"--help"}, {"prepare", "--help"}, {"submit", "--help"}} {
		var out bytes.Buffer
		if run(args, &out) != 0 || !strings.Contains(out.String(), "--command-file") || !strings.Contains(out.String(), "--report-file") || !strings.Contains(out.String(), "Exit codes:") || !strings.Contains(out.String(), "policy-gate -init") || !strings.Contains(out.String(), "-addr 127.0.0.1:8092") || strings.Count(out.String(), "./bin/policy-client submit --server") != 2 {
			t.Fatal("help incomplete")
		}
	}
	secret := "private-argument-must-not-be-printed"
	for _, args := range [][]string{nil, {secret}, {"submit", "--provider", secret}, {"submit", "--token", secret}, {"prepare", "--request-id", secret}, {"submit", "--server", "http://127.0.0.1:80", "--token-file", "none", "--command-file", "none", secret}} {
		var out bytes.Buffer
		if run(args, &out) != 2 || strings.Contains(out.String(), secret) {
			t.Fatal("usage error disclosed supplied values")
		}
		var summary gateclient.Summary
		if json.Unmarshal(out.Bytes(), &summary) != nil || summary.Schema != gateclient.SummarySchema || summary.Code != "USAGE_INVALID" {
			t.Fatal("usage error is not a safe summary")
		}
	}
}
