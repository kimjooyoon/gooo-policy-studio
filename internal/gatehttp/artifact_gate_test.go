package gatehttp

// Contract-derived HTTP expectations were written before reading the new
// admission implementation. Actual artifact tests use the real Store and Gooo.

import (
	"bytes"
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
	"time"

	"github.com/kimjooyoon/gooo-policy-studio/internal/admission"
	"github.com/kimjooyoon/gooo-policy-studio/internal/artifactpreflight"
	"github.com/kimjooyoon/gooo-policy-studio/internal/machinerules"
	"github.com/kimjooyoon/gooo-policy-studio/internal/policy"
)

func TestArtifactGateHTTPCallerProofAndPolicyOverridesNeverReachAdmission(t *testing.T) {
	valid := commandJSON("sha256:" + strings.Repeat("a", 64))
	fields := map[string]string{
		"pass":              `true`,
		"provider_verified": `true`,
		"artifact_path":     `"/caller/selected.json"`,
		"artifact":          `{"path":"/caller/selected.json","expected_sha256":"self-asserted"}`,
		"required_claims":   `["OnlyClaim"]`,
		"records":           `[{"claim_id":"OnlyClaim","status":"pass","evidence_ids":[]}]`,
		"completion":        `{"ready":true}`,
		"effects":           `{"writesFilesystem":false,"idempotent":true}`,
		"approval_budget":   `{"allow_target":true}`,
		"now_unix":          `0`,
		"preflight":         `null`,
		"implementation":    `{"host_sha256":"caller"}`,
	}
	for field, value := range fields {
		t.Run(field, func(t *testing.T) {
			backend := &probe{}
			body := strings.TrimSuffix(valid, "}") + `,"` + field + `":` + value + `}`
			r := httptest.NewRequest(http.MethodPost, "/api/admit", strings.NewReader(body))
			r.Header.Set("Authorization", "Bearer "+testToken)
			r.Header.Set("Content-Type", "application/json")
			w := httptest.NewRecorder()
			Handler(backend).ServeHTTP(w, r)
			if w.Code != http.StatusBadRequest || backend.admits != 0 || backend.inspects != 1 {
				t.Fatalf("caller-controlled proof/config reached admission: status=%d calls=%d", w.Code, backend.admits)
			}
		})
	}
}

func artifactHTTPBootstrap(t *testing.T) (admission.Bootstrap, []byte) {
	t.Helper()
	recipe := artifactpreflight.Recipe{Schema: artifactpreflight.RecipeSchema, ProducerID: artifactpreflight.ProducerID,
		ArtifactSchema: "policy-studio/http-artifact/v1", MaxBytes: artifactpreflight.MaxBytes,
		Fields: []artifactpreflight.Field{{Name: "action", Type: "text"}, {Name: "enabled", Type: "bool"}, {Name: "amount", Type: "int64"}},
		Claims: []artifactpreflight.Claim{
			{ID: "Action", Verifier: artifactpreflight.VerifierID, Field: "action", Expected: "publish"},
			{ID: "Enabled", Verifier: artifactpreflight.VerifierID, Field: "enabled", Expected: "true"},
			{ID: "Amount", Verifier: artifactpreflight.VerifierID, Field: "amount", Expected: "9007199254740993"},
			{ID: "ActionAgain", Verifier: artifactpreflight.VerifierID, Field: "action", Expected: "publish"},
			{ID: "AmountAgain", Verifier: artifactpreflight.VerifierID, Field: "amount", Expected: "9007199254740993"},
		}}
	raw := []byte(`{"schema":"policy-studio/http-artifact/v1","action":"publish","enabled":true,"amount":9007199254740993}`)
	artifactDir, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(artifactDir, "operator-artifact.json")
	if err := os.WriteFile(path, raw, 0600); err != nil {
		t.Fatal(err)
	}
	b := admission.Bootstrap{Schema: admission.BootstrapSchemaV2,
		Policy:     policy.Rules{Limit: 100, SameTeam: true, ActiveReviewer: true, PreventSelf: true},
		Principals: []admission.Principal{{Key: "http-validator", Team: "platform", Active: true, Enabled: true, CanExecute: true, TokenSHA256: admission.TokenDigest(testToken)}},
		Requests:   []policy.Request{{Key: "req-1", Requester: "api-client", Team: "platform", Amount: 50, Submitted: true}},
		Preflight: &admission.ArtifactPolicy{Schema: admission.ArtifactPolicySchema, ID: "HTTPPolicy", Revision: 1, Recipe: recipe, RequiredAuthority: "live-observation", MaxAgeSeconds: 60,
			ApprovalBudget:     machinerules.EffectBudget{AllowTarget: true, AllowSession: true, AllowFilesystem: true, RequireIdempotent: true},
			ControlPlaneBudget: machinerules.EffectBudget{AllowSession: true, AllowFilesystem: true, RequireIdempotent: true}},
		Artifacts: []admission.ArtifactRequirement{{RequestID: "req-1", Path: path, ExpectedSHA256: fmt.Sprintf("sha256:%x", sha256.Sum256(raw)), DeadlineUnix: time.Now().Unix() + 3600}}}
	return b, raw
}

func artifactHTTPRequest(t *testing.T, h http.Handler, method, path, body string) *httptest.ResponseRecorder {
	t.Helper()
	r := httptest.NewRequest(method, path, strings.NewReader(body))
	r.Header.Set("Authorization", "Bearer "+testToken)
	if body != "" {
		r.Header.Set("Content-Type", "application/json")
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if strings.Contains(w.Body.String(), testToken) || strings.Contains(w.Body.String(), "token_sha256") {
		t.Fatal("HTTP artifact report disclosed machine credentials")
	}
	return w
}

func TestArtifactGateHTTPActualArtifactTransitionAndHistoricalRetry(t *testing.T) {
	b, _ := artifactHTTPBootstrap(t)
	dir := filepath.Join(t.TempDir(), "state")
	if err := admission.Init(dir, b); err != nil {
		t.Fatal(err)
	}
	store, err := admission.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	h := Handler(store)
	viewResponse := artifactHTTPRequest(t, h, http.MethodGet, "/api/state", "")
	var view admission.View
	if viewResponse.Code != http.StatusOK || json.Unmarshal(viewResponse.Body.Bytes(), &view) != nil || view.Schema != admission.ViewSchemaV2 {
		t.Fatal("v2 store was not identified through authenticated HTTP")
	}
	command := admission.Command{RequestID: "req-1", ExpectedRevision: 1, PolicyVersion: view.PolicyVersion, IdempotencyKey: "actual-http-artifact"}
	rawCommand, _ := json.Marshal(command)
	w := artifactHTTPRequest(t, h, http.MethodPost, "/api/admit", string(rawCommand))
	var first admission.Result
	if w.Code != http.StatusOK || json.Unmarshal(w.Body.Bytes(), &first) != nil || !first.Outcome.Committed || first.Outcome.Preflight == nil ||
		len(first.Outcome.Preflight.Completion.Steps) != 5 || !first.Outcome.Preflight.Decision.Admitted {
		t.Fatalf("real artifact did not reach one Gooo-gated transition: %d %s", w.Code, w.Body.String())
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(b.Artifacts[0].Path, []byte("changed after commit"), 0600); err != nil {
		t.Fatal(err)
	}
	store, err = admission.Open(dir)
	if err != nil {
		t.Fatal("startup reopened changed artifact instead of replaying retained bytes", err)
	}
	h = Handler(store)
	w = artifactHTTPRequest(t, h, http.MethodPost, "/api/admit", string(rawCommand))
	var retry admission.Result
	if w.Code != http.StatusOK || json.Unmarshal(w.Body.Bytes(), &retry) != nil || !retry.Replayed || !reflect.DeepEqual(first.Outcome, retry.Outcome) {
		t.Fatal("HTTP retry changed the original artifact-bound result")
	}
	viewResponse = artifactHTTPRequest(t, h, http.MethodGet, "/api/state", "")
	if json.Unmarshal(viewResponse.Body.Bytes(), &view) != nil || view.Requests[0].Revision != 2 || view.Requests[0].Status != admission.Approved {
		t.Fatal("HTTP retry lost or repeated the local transition")
	}
	command.IdempotencyKey = "second-effect"
	rawCommand, _ = json.Marshal(command)
	w = artifactHTTPRequest(t, h, http.MethodPost, "/api/admit", string(rawCommand))
	if w.Code != http.StatusConflict {
		t.Fatal("second key reused the already approved pending revision")
	}
}

func TestArtifactGateHTTPMalformedActualArtifactRetainsDenial(t *testing.T) {
	b, _ := artifactHTTPBootstrap(t)
	bad := []byte(`{"schema":"policy-studio/http-artifact/v1","action":"publish","enabled":true,"amount":9007199254740993,"caller_pass":true}`)
	if err := os.WriteFile(b.Artifacts[0].Path, bad, 0600); err != nil {
		t.Fatal(err)
	}
	b.Artifacts[0].ExpectedSHA256 = fmt.Sprintf("sha256:%x", sha256.Sum256(bad))
	dir := filepath.Join(t.TempDir(), "state")
	if err := admission.Init(dir, b); err != nil {
		t.Fatal(err)
	}
	store, err := admission.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	view, err := store.Inspect(testToken)
	if err != nil {
		t.Fatal(err)
	}
	command := admission.Command{RequestID: "req-1", ExpectedRevision: 1, PolicyVersion: view.PolicyVersion, IdempotencyKey: "actual-http-denial"}
	raw, _ := json.Marshal(command)
	w := artifactHTTPRequest(t, Handler(store), http.MethodPost, "/api/admit", string(raw))
	var response struct {
		Error  string           `json:"error"`
		Result admission.Result `json:"result"`
	}
	if w.Code != http.StatusForbidden || json.Unmarshal(w.Body.Bytes(), &response) != nil || response.Error != admission.PolicyDenied || response.Result.Outcome.Committed ||
		response.Result.Outcome.Preflight == nil || response.Result.Outcome.Preflight.Producer.SchemaOK || response.Result.Outcome.Preflight.Decision.Admitted {
		t.Fatalf("malformed actual artifact became permission: %d %s", w.Code, w.Body.String())
	}
	view, err = store.Inspect(testToken)
	if err != nil || view.Requests[0].Status != admission.Pending || view.Requests[0].Revision != 1 {
		t.Fatal("denial changed the pending request")
	}
	again := artifactHTTPRequest(t, Handler(store), http.MethodPost, "/api/admit", string(raw))
	if again.Code != http.StatusForbidden || bytes.Equal(again.Body.Bytes(), w.Body.Bytes()) {
		t.Fatal("denial retry was not identified as a historical result")
	}
	var replay struct {
		Error  string           `json:"error"`
		Result admission.Result `json:"result"`
	}
	if json.Unmarshal(again.Body.Bytes(), &replay) != nil || !replay.Result.Replayed || !reflect.DeepEqual(replay.Result.Outcome, response.Result.Outcome) {
		t.Fatal("HTTP denial retry changed the retained outcome")
	}
}
