//go:build darwin || linux

package artifactimpact

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"syscall"
	"testing"
)

func TestReplayFilePreservesSavedReportAndDoesNotReadOriginalPaths(t *testing.T) {
	paths, c, p := fixture(t, 5)
	p.Recipe.Claims[2].Expected = "external"
	privateJSON(t, paths.After, p)
	if _, exit := compareAtTestTime(paths); exit != 0 {
		t.Fatal("comparison fixture failed")
	}
	before, err := os.ReadFile(paths.Report)
	if err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{paths.Case, paths.Before, paths.After, c.Artifact.Path} {
		if err := os.Remove(path); err != nil {
			t.Fatal(err)
		}
	}
	for _, replacement := range []string{"missing", "symlink", "fifo"} {
		t.Run(replacement, func(t *testing.T) {
			if replacement == "symlink" {
				if err := os.Symlink("nonexistent-private-artifact", c.Artifact.Path); err != nil {
					t.Fatal(err)
				}
			} else if replacement == "fifo" {
				if err := syscall.Mkfifo(c.Artifact.Path, 0o600); err != nil {
					t.Fatal(err)
				}
			}
			identity, err := ReplaySourceIdentity()
			if err != nil {
				t.Fatal(err)
			}
			want := ReplaySummary{Schema: ReplaySummarySchema, Status: "verified", Code: "HISTORICAL_COMPARISON_MATCH", Historical: true, Simulation: true, ReadOnly: true,
				Direction: "newly_denied", Before: SideSummary{WouldAdmit: true, Reason: "ADMITTED"}, After: SideSummary{WouldAdmit: false, Reason: "EVIDENCE_REJECTED"}, ChangedClaims: 1, RecipeConfigurationChanged: true, VerifierSHA256: identity.VerifierSHA256}
			want.Before.Counts.Total, want.Before.Counts.Pass = 5, 5
			want.After.Counts.Total, want.After.Counts.Pass, want.After.Counts.Fail = 5, 4, 1
			got, exit := ReplayFile(paths.Report)
			if exit != 0 || !reflect.DeepEqual(got, want) {
				t.Fatalf("historical summary mismatch: %+v exit%d", got, exit)
			}
			after, err := os.ReadFile(paths.Report)
			if err != nil || !bytes.Equal(before, after) {
				t.Fatal("replay changed original report bytes")
			}
			for _, path := range []string{paths.Case, paths.Before, paths.After} {
				if _, err := os.Lstat(path); !os.IsNotExist(err) {
					t.Fatal("replay recreated an input")
				}
			}
			if replacement != "missing" {
				if err := os.Remove(c.Artifact.Path); err != nil {
					t.Fatal(err)
				}
			}
		})
	}
}

func TestReplayFileStrictJSONAndStaticFailureSummary(t *testing.T) {
	paths, _, _ := fixture(t, 1)
	if _, exit := compareAtTestTime(paths); exit != 0 {
		t.Fatal("comparison fixture failed")
	}
	raw, err := os.ReadFile(paths.Report)
	if err != nil {
		t.Fatal(err)
	}
	var object map[string]any
	if err := json.Unmarshal(raw, &object); err != nil {
		t.Fatal(err)
	}
	mutate := func(change func(map[string]any)) []byte {
		var copy map[string]any
		if err := json.Unmarshal(raw, &copy); err != nil {
			t.Fatal(err)
		}
		change(copy)
		out, err := json.Marshal(copy)
		if err != nil {
			t.Fatal(err)
		}
		return out
	}
	cases := map[string][]byte{
		"duplicate":    append([]byte(`{"schema":"private-secret",`), bytes.TrimSpace(raw)[1:]...),
		"trailing":     append(append([]byte{}, raw...), []byte(` {"private-secret":true}`)...),
		"missing":      mutate(func(v map[string]any) { delete(v, "scope") }),
		"unknown":      mutate(func(v map[string]any) { v["private-secret"] = true }),
		"null":         mutate(func(v map[string]any) { v["before"] = nil }),
		"wrong_type":   mutate(func(v map[string]any) { v["committed"] = "false" }),
		"unicode":      []byte(`{"schema":"\ud800-private-secret"}`),
		"invalid_utf8": []byte{'{', '"', 'x', '"', ':', '"', 0xff, '"', '}'},
	}
	for name, invalid := range cases {
		t.Run(name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "report.json")
			privateTestFile(t, path, invalid)
			got, exit := ReplayFile(path)
			if exit != 2 || !reflect.DeepEqual(got, ReplayFailure("REPORT_JSON_INVALID")) {
				t.Fatal("ambiguous report did not produce exact safe failure")
			}
			retained, err := os.ReadFile(path)
			if err != nil || !bytes.Equal(invalid, retained) {
				t.Fatal("failed replay changed report")
			}
		})
	}
	saved := readReport(t, paths.Report)
	saved.After.WouldAdmit = !saved.After.WouldAdmit
	saved.ID = ""
	saved.ID = canonicalDigest(saved)
	privateJSON(t, paths.Report, saved)
	got, exit := ReplayFile(paths.Report)
	if exit != 2 || !reflect.DeepEqual(got, ReplayFailure("REPORT_REPLAY_INVALID")) {
		t.Fatal("rehashing a forged decision bypassed historical replay")
	}
	if got := ReplayFailure("private-secret /private/path"); !reflect.DeepEqual(got, ReplayFailure("USAGE_INVALID")) {
		t.Fatal("caller text leaked through error helper")
	}
}

func TestReplayFilePrivateRegularBoundAndAliases(t *testing.T) {
	paths, _, _ := fixture(t, 1)
	if _, exit := compareAtTestTime(paths); exit != 0 {
		t.Fatal("comparison fixture failed")
	}
	for _, name := range []string{"missing", "mode", "symlink", "fifo", "oversize"} {
		t.Run(name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "private-secret.json")
			switch name {
			case "mode":
				privateTestFile(t, path, []byte("private-secret"))
				if err := os.Chmod(path, 0o644); err != nil {
					t.Fatal(err)
				}
			case "symlink":
				if err := os.Symlink(paths.Report, path); err != nil {
					t.Fatal(err)
				}
			case "fifo":
				if err := syscall.Mkfifo(path, 0o600); err != nil {
					t.Fatal(err)
				}
			case "oversize":
				f, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
				if err != nil {
					t.Fatal(err)
				}
				if err := f.Truncate(MaxReportBytes + 1); err != nil {
					t.Fatal(err)
				}
				if err := f.Close(); err != nil {
					t.Fatal(err)
				}
			}
			got, exit := ReplayFile(path)
			if exit != 2 || !reflect.DeepEqual(got, ReplayFailure("REPORT_FILE_INVALID")) {
				t.Fatal("non-private or oversized input did not fail closed")
			}
			raw, err := json.Marshal(got)
			if err != nil || strings.Contains(string(raw), "private-secret") || strings.Contains(string(raw), path) {
				t.Fatal("private file failure leaked caller values")
			}
		})
	}
	alias := filepath.Join(t.TempDir(), "parent")
	if err := os.Symlink(filepath.Dir(paths.Report), alias); err != nil {
		t.Fatal(err)
	}
	if got, exit := ReplayFile(filepath.Join(alias, filepath.Base(paths.Report))); exit != 0 || got.Status != "verified" {
		t.Fatal("stable administrative parent alias was rejected")
	}
}
