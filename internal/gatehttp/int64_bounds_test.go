//go:build darwin || linux || freebsd || openbsd || netbsd || dragonfly

package gatehttp

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/kimjooyoon/gooo-policy-studio/internal/admission"
	"github.com/kimjooyoon/gooo-policy-studio/internal/artifactnumeric"
	"github.com/kimjooyoon/gooo-policy-studio/internal/artifactpreflight"
	"github.com/kimjooyoon/gooo-policy-studio/internal/completion"
)

func int64HTTPBootstrap(t *testing.T, row int64) admission.Bootstrap {
	t.Helper()
	b, _ := artifactHTTPBootstrap(t)
	b.Preflight.ID = "artifact-impact-row-limit-bounds"
	b.Preflight.Recipe = artifactpreflight.Recipe{Schema: artifactpreflight.NewRecipeSchema, ProducerID: artifactpreflight.NewProducerID, ArtifactSchema: "gooo/export-plan/v1", MaxBytes: 65536,
		Fields: []artifactpreflight.Field{{Name: "action", Type: "text"}, {Name: "destination", Type: "text"}, {Name: "row_limit", Type: "int64"}, {Name: "dry_run", Type: "bool"}, {Name: "format", Type: "text"}},
		Claims: []artifactpreflight.Claim{
			{ID: "action_equal", Verifier: artifactpreflight.VerifierID, Field: "action", Expected: "prepare_export"},
			{ID: "destination_equal", Verifier: artifactpreflight.VerifierID, Field: "destination", Expected: "internal"},
			{ID: "row_limit_at_least", Verifier: artifactpreflight.Int64GTEVerifierID, Field: "row_limit", Expected: "0"},
			{ID: "row_limit_at_most", Verifier: artifactpreflight.Int64LTEVerifierID, Field: "row_limit", Expected: "500"},
			{ID: "dry_run_equal", Verifier: artifactpreflight.VerifierID, Field: "dry_run", Expected: "true"},
			{ID: "format_equal", Verifier: artifactpreflight.VerifierID, Field: "format", Expected: "jsonl"},
		}}
	raw := []byte(fmt.Sprintf("{\n  \"schema\": \"gooo/export-plan/v1\",\n  \"action\": \"prepare_export\",\n  \"destination\": \"internal\",\n  \"row_limit\": %d,\n  \"dry_run\": true,\n  \"format\": \"jsonl\"\n}\n", row))
	if err := os.WriteFile(b.Artifacts[0].Path, raw, 0600); err != nil {
		t.Fatal(err)
	}
	b.Artifacts[0].ExpectedSHA256 = fmt.Sprintf("sha256:%x", sha256.Sum256(raw))
	return b
}

func TestInt64BoundsAuthenticatedHTTPUsesTrustedRecipeAndLiteralNativeProof(t *testing.T) {
	cases := []struct {
		row          int64
		sha          string
		status       int
		counts       completion.Counts
		lower, upper artifactnumeric.Decision
		state        string
		revision     int64
	}{
		{-1, "sha256:d60f6fc796ff7caede85febd0adda153ef18417b892d8fe97386db1f7356739e", http.StatusForbidden, completion.Counts{Total: 6, Pass: 5, Fail: 1}, artifactnumeric.Decision{true, false, true, false, "BOUND_MISMATCH"}, artifactnumeric.Decision{true, false, true, true, "BOUND_MATCH"}, admission.Pending, 1},
		{500, "sha256:462147ef4a0025b680de1337e78fd91e04a0fa3bd8aae3d438024000839db533", http.StatusOK, completion.Counts{Total: 6, Pass: 6}, artifactnumeric.Decision{false, true, true, true, "BOUND_MATCH"}, artifactnumeric.Decision{true, true, true, true, "BOUND_MATCH"}, admission.Approved, 2},
		{501, "sha256:e6766b36e840581b461fb698048e71622c1f22dc2184460f1431fe42f0171653", http.StatusForbidden, completion.Counts{Total: 6, Pass: 5, Fail: 1}, artifactnumeric.Decision{false, true, true, true, "BOUND_MATCH"}, artifactnumeric.Decision{false, true, true, false, "BOUND_MISMATCH"}, admission.Pending, 1},
	}
	for _, tc := range cases {
		t.Run(fmt.Sprint(tc.row), func(t *testing.T) {
			b := int64HTTPBootstrap(t, tc.row)
			if b.Artifacts[0].ExpectedSHA256 != tc.sha {
				t.Fatal("HTTP trusted artifact differs from frozen fixture bytes")
			}
			dir := filepath.Join(t.TempDir(), "state")
			if err := admission.Init(dir, b); err != nil {
				t.Fatal(err)
			}
			store, err := admission.Open(dir)
			if err != nil {
				t.Fatal(err)
			}
			defer store.Close()
			h := Handler(store)
			viewResponse := artifactHTTPRequest(t, h, http.MethodGet, "/api/state", "")
			var view admission.View
			if viewResponse.Code != http.StatusOK || json.Unmarshal(viewResponse.Body.Bytes(), &view) != nil {
				t.Fatal("authenticated state unavailable")
			}
			command := admission.Command{RequestID: "req-1", ExpectedRevision: 1, PolicyVersion: view.PolicyVersion, IdempotencyKey: "int64-http-bound"}
			rawCommand, err := json.Marshal(command)
			if err != nil {
				t.Fatal(err)
			}
			if tc.row == 501 {
				// Neither a claimed native result nor human approval is accepted as a
				// fifth command field. The server owns the recipe and artifact source.
				for _, extra := range []string{`,"native_proof":{"decision":{"matched":true}}`, `,"human_approval":true`} {
					injected := strings.TrimSuffix(string(rawCommand), "}") + extra + "}"
					w := artifactHTTPRequest(t, h, http.MethodPost, "/api/admit", injected)
					if w.Code != http.StatusBadRequest || !strings.Contains(w.Body.String(), "INVALID_COMMAND_JSON") {
						t.Fatal("caller-provided proof or approval reached the trusted gate")
					}
				}
				r := httptest.NewRequest(http.MethodPost, "/api/admit", strings.NewReader(string(rawCommand)))
				r.Header.Set("Authorization", "Bearer "+strings.Repeat("z", 64))
				r.Header.Set("Content-Type", "application/json")
				w := httptest.NewRecorder()
				h.ServeHTTP(w, r)
				if w.Code != http.StatusUnauthorized {
					t.Fatal("numeric recipe bypassed authentication")
				}
			}
			w := artifactHTTPRequest(t, h, http.MethodPost, "/api/admit", string(rawCommand))
			first := int64HTTPResult(t, w, tc.status)
			if first.Replayed || first.Outcome.Preflight == nil || first.Outcome.Committed != (tc.status == http.StatusOK) || first.Outcome.NewRevision != tc.revision {
				t.Fatal("HTTP first decision or local revision changed")
			}
			p := first.Outcome.Preflight
			if p.Producer.ActualSHA256 != tc.sha || len(p.Producer.Observations) != 6 || len(p.Evidence) != 6 || len(p.Completion.Steps) != 6 || p.Completion.Summary.Counts() != tc.counts || p.Decision.Admitted != (tc.status == http.StatusOK) {
				t.Fatal("HTTP decision did not preserve six-claim native outcomes")
			}
			for _, index := range []int{2, 3} {
				facts, decision := artifactnumeric.Facts{Value: tc.row, Bound: 0, Operator: "gte"}, tc.lower
				if index == 3 {
					facts, decision = artifactnumeric.Facts{Value: tc.row, Bound: 500, Operator: "lte"}, tc.upper
				}
				proof := p.Producer.Observations[index].NativeProof
				if proof == nil || proof.Facts != facts || proof.Decision != decision || proof.Bindings != p.Producer.Identity.NumericBindings {
					t.Fatal("HTTP exposed an altered or host-only numeric proof")
				}
			}
			for _, index := range []int{0, 1, 4, 5} {
				if p.Producer.Observations[index].NativeProof != nil {
					t.Fatal("equality acquired a numeric proof")
				}
			}
			if err := os.WriteFile(b.Artifacts[0].Path, []byte("different current artifact"), 0600); err != nil {
				t.Fatal(err)
			}
			retry := artifactHTTPRequest(t, h, http.MethodPost, "/api/admit", string(rawCommand))
			again := int64HTTPResult(t, retry, tc.status)
			if !again.Replayed || !reflect.DeepEqual(first.Outcome, again.Outcome) {
				t.Fatal("HTTP retry changed the historical numeric judgment")
			}
			viewResponse = artifactHTTPRequest(t, h, http.MethodGet, "/api/state", "")
			if json.Unmarshal(viewResponse.Body.Bytes(), &view) != nil || view.Requests[0].Status != tc.state || view.Requests[0].Revision != tc.revision {
				t.Fatal("unsafe artifact was approved or a retry repeated the local transition")
			}
		})
	}
}

func int64HTTPResult(t *testing.T, response *httptest.ResponseRecorder, status int) admission.Result {
	t.Helper()
	if response.Code != status {
		t.Fatalf("HTTP status=%d, want=%d: %s", response.Code, status, response.Body.String())
	}
	var result admission.Result
	if status == http.StatusOK {
		if err := json.Unmarshal(response.Body.Bytes(), &result); err != nil {
			t.Fatal(err)
		}
	} else {
		var denied struct {
			Error  string           `json:"error"`
			Result admission.Result `json:"result"`
		}
		if err := json.Unmarshal(response.Body.Bytes(), &denied); err != nil || denied.Error != admission.PolicyDenied {
			t.Fatal("HTTP denial is not an artifact policy outcome")
		}
		result = denied.Result
	}
	return result
}
