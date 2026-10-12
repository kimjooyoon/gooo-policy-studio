package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/kimjooyoon/gooo-policy-studio/internal/completion"
)

func cliPolicyFile(t *testing.T, raw string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "operator-policy.json")
	if err := os.WriteFile(path, []byte(raw), 0600); err != nil {
		t.Fatal(err)
	}
	return path
}

func cliPolicy(t *testing.T) string {
	return cliPolicyFile(t, `{"schema":"policy-studio/completion-policy/v1","policy_id":"release","revision":1,"required_claims":["scenario.a","scenario.b"]}`)
}

func cliInput(status string, both bool) string {
	evidence := `"ev_` + strings.Repeat("a", 64) + `"`
	records := `{"claim_id":"scenario.a","status":"pass","evidence_ids":[` + evidence + `]}`
	if both {
		records += `,{"claim_id":"scenario.b","status":"` + status + `","evidence_ids":[` + evidence + `]}`
	}
	return `{"schema":"policy-studio/completion-input/v1","request_id":"candidate","records":[` + records + `]}`
}

func TestCLIExitCodesAndCompleteReport(t *testing.T) {
	policyPath := cliPolicy(t)
	tests := []struct {
		name, raw string
		exit      int
		reason    string
	}{
		{"ready", cliInput("pass", true), 0, "READY"},
		{"unknown", cliInput("unknown", true), 1, "NON_PASS_RESULTS"},
		{"missing", cliInput("pass", false), 1, "INCOMPLETE_CLAIM_COVERAGE"},
		{"empty", `{"schema":"policy-studio/completion-input/v1","request_id":"candidate","records":[]}`, 1, "INCOMPLETE_CLAIM_COVERAGE"},
		{"bad status", cliInput("PASS", true), 2, ""},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var output, diagnostics bytes.Buffer
			code := run([]string{"--policy", policyPath}, strings.NewReader(test.raw), &output, &diagnostics)
			if code != test.exit {
				t.Fatalf("exit = %d, expected %d: %s", code, test.exit, diagnostics.String())
			}
			if code == 2 {
				if output.Len() != 0 {
					t.Fatal("invalid input emitted an apparently completed report")
				}
				return
			}
			var report completion.Report
			if err := json.Unmarshal(output.Bytes(), &report); err != nil || report.Schema != completion.ReportSchema || report.Readiness.Reason != test.reason {
				t.Fatalf("complete report missing or wrong: %v; %s", err, output.String())
			}
			var replay, replayDiagnostics bytes.Buffer
			if code := run([]string{"--policy", policyPath, "--replay"}, bytes.NewReader(output.Bytes()), &replay, &replayDiagnostics); code != test.exit || !bytes.Equal(replay.Bytes(), output.Bytes()) {
				t.Fatalf("complete report did not replay with same exit/output: %d, %s", code, replayDiagnostics.String())
			}
		})
	}
}

func TestCLIRequiresSeparatePolicyAndRejectsPayloadConfiguration(t *testing.T) {
	path := cliPolicy(t)
	for _, args := range [][]string{{}, {"--policy", "-"}, {"--policy", path, "unexpected"}, {"--policy", path, "--unknown"}} {
		var output, diagnostics bytes.Buffer
		if code := run(args, strings.NewReader(cliInput("pass", true)), &output, &diagnostics); code != 2 || output.Len() != 0 {
			t.Fatalf("missing/invalid operator policy arguments were accepted: %+v", args)
		}
	}
	clientSelected := strings.Replace(cliInput("pass", false), `"schema":`, `"required_claims":["scenario.a"],"schema":`, 1)
	var output, diagnostics bytes.Buffer
	if code := run([]string{"--policy", path}, strings.NewReader(clientSelected), &output, &diagnostics); code != 2 || output.Len() != 0 {
		t.Fatal("regular input selected its own required claims")
	}
}

func TestCLIReplayReloadsCurrentPolicyAndRejectsUnknownReportFields(t *testing.T) {
	path := cliPolicy(t)
	var output, diagnostics bytes.Buffer
	if code := run([]string{"--policy", path}, strings.NewReader(cliInput("pass", true)), &output, &diagnostics); code != 0 {
		t.Fatalf("initial check failed: %s", diagnostics.String())
	}
	saved := append([]byte{}, output.Bytes()...)
	if err := os.WriteFile(path, []byte(`{"schema":"policy-studio/completion-policy/v1","policy_id":"release","revision":2,"required_claims":["scenario.a","scenario.b"]}`), 0600); err != nil {
		t.Fatal(err)
	}
	var replay, replayDiagnostics bytes.Buffer
	if code := run([]string{"--policy", path, "--replay"}, bytes.NewReader(saved), &replay, &replayDiagnostics); code != 2 || replay.Len() != 0 {
		t.Fatal("replay used the embedded policy instead of the current operator file")
	}
	path = cliPolicy(t)
	extra := strings.Replace(string(saved), `"schema":`, `"untrusted_claim":true,"schema":`, 1)
	if code := run([]string{"--policy", path, "--replay"}, strings.NewReader(extra), io.Discard, io.Discard); code != 2 {
		t.Fatal("unknown report property was accepted during replay")
	}
}

type failingReader struct{}

func (failingReader) Read([]byte) (int, error) { return 0, errors.New("synthetic read failure") }

type failingWriter struct{}

func (failingWriter) Write([]byte) (int, error) { return 0, errors.New("synthetic write failure") }

func TestCLIBoundedReadsAndOutputFailures(t *testing.T) {
	path := cliPolicy(t)
	if code := run([]string{"--policy", path}, failingReader{}, io.Discard, io.Discard); code != 2 {
		t.Fatal("read failure was not an error exit")
	}
	if code := run([]string{"--policy", path}, strings.NewReader(strings.Repeat(" ", completion.MaxInputBytes+1)), io.Discard, io.Discard); code != 2 {
		t.Fatal("oversized regular input was accepted")
	}
	if code := run([]string{"--policy", path, "--replay"}, strings.NewReader(strings.Repeat(" ", completion.MaxReplayBytes+1)), io.Discard, io.Discard); code != 2 {
		t.Fatal("oversized replay input was accepted")
	}
	tooLargePolicy := cliPolicyFile(t, strings.Repeat(" ", completion.MaxPolicyBytes+1))
	if code := run([]string{"--policy", tooLargePolicy}, strings.NewReader(cliInput("pass", true)), io.Discard, io.Discard); code != 2 {
		t.Fatal("oversized policy was accepted")
	}
	if code := run([]string{"--policy", path}, strings.NewReader(cliInput("pass", true)), failingWriter{}, io.Discard); code != 2 {
		t.Fatal("output failure was not an error exit")
	}
}
