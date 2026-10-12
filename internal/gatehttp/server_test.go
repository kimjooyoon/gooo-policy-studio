package gatehttp

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"github.com/kimjooyoon/gooo-policy-studio/internal/admission"
	"github.com/kimjooyoon/gooo-policy-studio/internal/policy"
)

const testToken = "local-test-credential-with-thirty-two-or-more-characters"

type probe struct {
	inspects, admits int
	inspectErr       error
	admitErr         error
	command          admission.Command
}

func (p *probe) Inspect(string) (admission.View, error) {
	p.inspects++
	return admission.View{}, p.inspectErr
}

func (p *probe) Admit(_ string, c admission.Command) (admission.Result, error) {
	p.admits++
	p.command = c
	return admission.Result{}, p.admitErr
}

func commandJSON(version string) string {
	b, _ := json.Marshal(admission.Command{RequestID: "req-1", ExpectedRevision: 1, PolicyVersion: version, IdempotencyKey: "job-1"})
	return string(b)
}

func TestAmbiguousOrUntrustedCommandsCannotReachTransition(t *testing.T) {
	valid := commandJSON("version")
	tests := []struct {
		name, body, auth, content, origin, query string
		status                                   int
		duplicateAuth, cancelled                 bool
	}{
		{name: "no credential", body: valid, content: "application/json", status: 401},
		{name: "short credential", body: valid, auth: "Bearer tiny", content: "application/json", status: 401},
		{name: "duplicate credential", body: valid, auth: "Bearer " + testToken, content: "application/json", duplicateAuth: true, status: 401},
		{name: "combined credentials", body: valid, auth: "Bearer " + testToken + ",other", content: "application/json", status: 401},
		{name: "browser origin", body: valid, auth: "Bearer " + testToken, content: "application/json", origin: "http://127.0.0.1", status: 403},
		{name: "query credential", body: valid, auth: "Bearer " + testToken, content: "application/json", query: "?token=not-a-permit", status: 403},
		{name: "non JSON", body: valid, auth: "Bearer " + testToken, content: "text/plain", status: 415},
		{name: "ambiguous media parameter", body: valid, auth: "Bearer " + testToken, content: "application/json; charset=latin1", status: 415},
		{name: "duplicate key", body: `{"request_id":"req-1","request_id":"req-2","expected_revision":1,"policy_version":"version","idempotency_key":"job-1"}`, auth: "Bearer " + testToken, content: "application/json", status: 400},
		{name: "case alias", body: `{"Request_ID":"req-1","expected_revision":1,"policy_version":"version","idempotency_key":"job-1"}`, auth: "Bearer " + testToken, content: "application/json", status: 400},
		{name: "caller policy", body: strings.TrimSuffix(valid, "}") + `,"policy":{"limit":9000000000000}}`, auth: "Bearer " + testToken, content: "application/json", status: 400},
		{name: "caller reviewer", body: strings.TrimSuffix(valid, "}") + `,"reviewer":{"active":true}}`, auth: "Bearer " + testToken, content: "application/json", status: 400},
		{name: "missing field", body: `{"request_id":"req-1","expected_revision":1,"policy_version":"version"}`, auth: "Bearer " + testToken, content: "application/json", status: 400},
		{name: "null revision", body: `{"request_id":"req-1","expected_revision":null,"policy_version":"version","idempotency_key":"job-1"}`, auth: "Bearer " + testToken, content: "application/json", status: 400},
		{name: "unpaired escape", body: `{"request_id":"\ud800","expected_revision":1,"policy_version":"version","idempotency_key":"job-1"}`, auth: "Bearer " + testToken, content: "application/json", status: 400},
		{name: "invalid UTF8", body: strings.Replace(valid, "req-1", "req-\xff", 1), auth: "Bearer " + testToken, content: "application/json", status: 400},
		{name: "too large", body: valid + strings.Repeat(" ", MaxCommandBytes), auth: "Bearer " + testToken, content: "application/json", status: 413},
		{name: "cancelled", body: valid, auth: "Bearer " + testToken, content: "application/json", cancelled: true, status: 408},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			backend := &probe{}
			r := httptest.NewRequest("POST", "/api/admit"+tc.query, strings.NewReader(tc.body))
			if tc.auth != "" {
				r.Header.Set("Authorization", tc.auth)
			}
			if tc.duplicateAuth {
				r.Header.Add("Authorization", tc.auth)
			}
			r.Header.Set("Content-Type", tc.content)
			if tc.origin != "" {
				r.Header.Set("Origin", tc.origin)
			}
			if tc.cancelled {
				ctx, cancel := context.WithCancel(r.Context())
				cancel()
				r = r.WithContext(ctx)
			}
			w := httptest.NewRecorder()
			Handler(backend).ServeHTTP(w, r)
			if w.Code != tc.status || backend.admits != 0 {
				t.Fatalf("status=%d transitions=%d", w.Code, backend.admits)
			}
			if strings.Contains(w.Body.String(), testToken) || w.Header().Get("Cache-Control") != "no-store" {
				t.Fatal("response must not reveal credentials or be cacheable")
			}
		})
	}
}

func TestAuthenticationAndAvailabilityErrorsNeverBecomeSuccess(t *testing.T) {
	for _, tc := range []struct {
		name string
		err  error
		want int
	}{
		{"unknown credential", &admission.Error{Code: admission.Unauthorized}, 401},
		{"permission", &admission.Error{Code: admission.Forbidden}, 403},
		{"poisoned store", &admission.Error{Code: admission.Unavailable}, 503},
		{"unknown internal failure", errors.New("private internal data"), 503},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p := &probe{inspectErr: tc.err}
			r := httptest.NewRequest("POST", "/api/admit", strings.NewReader("invalid"))
			r.Header.Set("Authorization", "Bearer "+testToken)
			w := httptest.NewRecorder()
			Handler(p).ServeHTTP(w, r)
			if w.Code != tc.want || p.admits != 0 || strings.Contains(w.Body.String(), "private internal data") {
				t.Fatalf("status=%d transitions=%d", w.Code, p.admits)
			}
		})
	}
}

func TestActualAuthenticatedStateTransitionSurvivesHTTPRetryAndRestart(t *testing.T) {
	digest := sha256.Sum256([]byte(testToken))
	dir := filepath.Join(t.TempDir(), "state")
	b := admission.Bootstrap{Schema: admission.BootstrapSchema,
		Policy:     policy.Rules{Limit: 100, SameTeam: true, ActiveReviewer: true, PreventSelf: true},
		Principals: []admission.Principal{{Key: "service-validator", Team: "platform", Active: true, Enabled: true, CanExecute: true, TokenSHA256: hex.EncodeToString(digest[:])}},
		Requests:   []policy.Request{{Key: "req-1", Requester: "service-client", Team: "platform", Amount: 50, Submitted: true}, {Key: "req-2", Requester: "service-client", Team: "platform", Amount: 101, Submitted: true}},
	}
	if err := admission.Init(dir, b); err != nil {
		t.Fatal(err)
	}
	store, err := admission.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	view, err := store.Inspect(testToken)
	if err != nil {
		t.Fatal(err)
	}
	request := func(h http.Handler, method, path, body string) *httptest.ResponseRecorder {
		r := httptest.NewRequest(method, path, strings.NewReader(body))
		r.Header.Set("Authorization", "Bearer "+testToken)
		r.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		return w
	}
	h := Handler(store)
	get := request(h, "GET", "/api/state", "")
	if get.Code != 200 || strings.Contains(get.Body.String(), b.Principals[0].TokenSHA256) || strings.Contains(get.Body.String(), "token_sha256") {
		t.Fatal("authenticated state response reveals a token hash or failed")
	}
	command := commandJSON(view.PolicyVersion)
	first := request(h, "POST", "/api/admit", command)
	if first.Code != 200 {
		t.Fatalf("first transition status=%d body=%s", first.Code, first.Body)
	}
	var out admission.Result
	if err := json.Unmarshal(first.Body.Bytes(), &out); err != nil || !out.Outcome.Committed || out.Replayed {
		t.Fatal("expected one committed Gooo-authorized transition")
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	store, err = admission.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	h = Handler(store)
	retry := request(h, "POST", "/api/admit", command)
	var retried admission.Result
	if retry.Code != 200 || json.Unmarshal(retry.Body.Bytes(), &retried) != nil || !retried.Replayed || retried.Outcome.ID != out.Outcome.ID {
		t.Fatal("restart must return the original durable outcome")
	}
	conflict := request(h, "POST", "/api/admit", strings.Replace(command, `"expected_revision":1`, `"expected_revision":2`, 1))
	if conflict.Code != 409 {
		t.Fatalf("same key with changed intent status=%d", conflict.Code)
	}
	deniedCmd := admission.Command{RequestID: "req-2", ExpectedRevision: 1, PolicyVersion: view.PolicyVersion, IdempotencyKey: "job-2"}
	deniedJSON, _ := json.Marshal(deniedCmd)
	denied := request(h, "POST", "/api/admit", string(deniedJSON))
	if denied.Code != 403 || !strings.Contains(denied.Body.String(), "OVER_LIMIT") || !strings.Contains(denied.Body.String(), `"committed":false`) {
		t.Fatalf("actual Gooo denial was not preserved: %d", denied.Code)
	}
}
