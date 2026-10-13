package gateclient

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/kimjooyoon/gooo-policy-studio/internal/admission"
	"github.com/kimjooyoon/gooo-policy-studio/internal/artifactpreflight"
	"github.com/kimjooyoon/gooo-policy-studio/internal/gatehttp"
	"github.com/kimjooyoon/gooo-policy-studio/internal/machinerules"
	"github.com/kimjooyoon/gooo-policy-studio/internal/policy"
)

type fixture struct {
	root, token, tokenFile, artifact, stateDir string
	store                                      *admission.Store
}

func newFixture(t *testing.T, baseDenied bool) fixture {
	return fixtureWithOptions(t, baseDenied, false, false)
}

func fixtureWithOptions(t *testing.T, baseDenied, effectDenied, expired bool) fixture {
	t.Helper()
	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal("cannot select test directory")
	}
	f := fixture{root: root, token: strings.Repeat("a", 64), tokenFile: filepath.Join(root, "private-token"), artifact: filepath.Join(root, "artifact.json"), stateDir: filepath.Join(root, "state")}
	artifact := []byte(`{"schema":"client-test/v1","private_a":"private-a-value","private_b":"private-b-value","private_c":"private-c-value","private_d":"private-d-value","private_e":"private-e-value"}`)
	if os.WriteFile(f.tokenFile, []byte(f.token+"\n"), 0600) != nil || os.WriteFile(f.artifact, artifact, 0600) != nil {
		t.Fatal("fixture files unavailable")
	}
	sum := sha256.Sum256(artifact)
	recipe := artifactpreflight.Recipe{Schema: artifactpreflight.RecipeSchema, ProducerID: artifactpreflight.ProducerID, ArtifactSchema: "client-test/v1", MaxBytes: 65536, Fields: []artifactpreflight.Field{}, Claims: []artifactpreflight.Claim{}}
	for _, name := range []string{"a", "b", "c", "d", "e"} {
		recipe.Fields = append(recipe.Fields, artifactpreflight.Field{Name: "private_" + name, Type: "text"})
		recipe.Claims = append(recipe.Claims, artifactpreflight.Claim{ID: "claim_" + name, Verifier: artifactpreflight.VerifierID, Field: "private_" + name, Expected: "private-" + name + "-value"})
	}
	b := admission.Bootstrap{Schema: admission.BootstrapSchemaV2, Policy: policy.Rules{Limit: 100, SameTeam: true, ActiveReviewer: true, PreventSelf: true}, Principals: []admission.Principal{{Key: "svc-client", Team: "team", Active: !baseDenied, Enabled: true, CanExecute: true, TokenSHA256: admission.TokenDigest(f.token)}}, Requests: []policy.Request{{Key: "request", Requester: "operator", Team: "team", Submitted: true}}, Preflight: &admission.ArtifactPolicy{Schema: admission.ArtifactPolicySchema, ID: "client-test", Revision: 1, Recipe: recipe, RequiredAuthority: "live-observation", MaxAgeSeconds: 60, ApprovalBudget: machinerules.EffectBudget{AllowTarget: true, AllowSession: true, AllowFilesystem: true, RequireIdempotent: true}, ControlPlaneBudget: machinerules.EffectBudget{AllowSession: true, AllowFilesystem: true, RequireIdempotent: true}}, Artifacts: []admission.ArtifactRequirement{{RequestID: "request", Path: f.artifact, ExpectedSHA256: "sha256:" + hex.EncodeToString(sum[:]), DeadlineUnix: 4102444800}}}
	if effectDenied {
		b.Preflight.ApprovalBudget.AllowTarget = false
	}
	if expired {
		b.Artifacts[0].DeadlineUnix = time.Now().Unix() - 1
	}
	if admission.Init(f.stateDir, b) != nil {
		t.Fatal("real v2 store initialization failed")
	}
	f.store, err = admission.Open(f.stateDir)
	if err != nil {
		t.Fatal("real v2 store unavailable")
	}
	t.Cleanup(func() { f.store.Close() })
	return f
}

func (f fixture) prepare(server, key, command string) Result {
	return Prepare(context.Background(), PrepareOptions{Server: server, TokenFile: f.tokenFile, RequestID: "request", IdempotencyKey: key, CommandFile: command})
}
func (f fixture) submit(server, command, report string) Result {
	return Submit(context.Background(), SubmitOptions{Server: server, TokenFile: f.tokenFile, CommandFile: command, ReportFile: report})
}

func TestPrepareSubmitActualV2AndRetainedReplay(t *testing.T) {
	f := newFixture(t, false)
	var gets, posts atomic.Int64
	var sent, reply []byte
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "GET" {
			gets.Add(1)
		} else {
			posts.Add(1)
			sent, _ = io.ReadAll(r.Body)
			r.Body = io.NopCloser(bytes.NewReader(sent))
		}
		recorder := httptest.NewRecorder()
		gatehttp.Handler(f.store).ServeHTTP(recorder, r)
		reply = append([]byte{}, recorder.Body.Bytes()...)
		for k, v := range recorder.Header() {
			w.Header()[k] = v
		}
		w.WriteHeader(recorder.Code)
		w.Write(reply)
	}))
	defer server.Close()
	command := filepath.Join(f.root, "command.json")
	p := f.prepare(server.URL, "one-operation", command)
	if p.ExitCode != 0 || p.Summary.Status != "prepared" || gets.Load() != 1 || posts.Load() != 0 {
		t.Fatal("prepare must inspect without admitting")
	}
	view, err := f.store.Inspect(f.token)
	if err != nil || view.Requests[0].Status != admission.Pending {
		t.Fatal("prepare mutated state")
	}
	raw, _ := os.ReadFile(command)
	// Whitespace is part of the submitted saved bytes, not re-marshaled input.
	raw = append([]byte(" \n"), raw...)
	if os.WriteFile(command, raw, 0600) != nil {
		t.Fatal("command whitespace fixture failed")
	}
	report := filepath.Join(f.root, "report.json")
	got := f.submit(server.URL, command, report)
	if got.ExitCode != 0 || got.Summary.Status != "approved" || got.Summary.Replayed || got.Summary.Reason != "ADMITTED" || got.Summary.ClaimCounts.Pass != 5 || posts.Load() != 1 || gets.Load() != 1 || !bytes.Equal(raw, sent) {
		t.Fatal("actual v2 approval or original-byte transport mismatch")
	}
	exported, _ := os.ReadFile(report)
	if !bytes.Equal(exported, reply) {
		t.Fatal("private report differs from bounded received bytes")
	}
	for _, path := range []string{command, report} {
		info, _ := os.Stat(path)
		if info.Mode().Perm() != 0600 {
			t.Fatal("private output mode mismatch")
		}
	}
	stdout, _ := json.Marshal(got.Summary)
	if bytes.Contains(stdout, []byte(f.token)) || bytes.Contains(stdout, []byte("private-")) || bytes.Contains(stdout, []byte(f.artifact)) {
		t.Fatal("default summary disclosed private facts")
	}
	if os.Remove(f.artifact) != nil {
		t.Fatal("cannot remove artifact for historical replay")
	}
	replay := f.submit(server.URL, command, "")
	if replay.ExitCode != 0 || !replay.Summary.Replayed || replay.Summary.OutcomeID != got.Summary.OutcomeID || posts.Load() != 2 || gets.Load() != 1 {
		t.Fatal("explicit retry did not recover unchanged original approval")
	}
	unchanged, _ := os.ReadFile(command)
	if !bytes.Equal(raw, unchanged) {
		t.Fatal("submit changed command")
	}
}

func TestActualDurableDenialUsesFinalReasonAndCounts(t *testing.T) {
	for _, baseDenied := range []bool{false, true} {
		t.Run(map[bool]string{false: "integrity-denial", true: "base-denial"}[baseDenied], func(t *testing.T) {
			f := newFixture(t, baseDenied)
			server := httptest.NewServer(gatehttp.Handler(f.store))
			defer server.Close()
			command := filepath.Join(f.root, "command.json")
			if f.prepare(server.URL, "denial-key", command).ExitCode != 0 {
				t.Fatal("prepare denied by client-side policy")
			}
			if baseDenied {
				if os.Remove(f.artifact) != nil {
					t.Fatal("cannot remove confidential artifact")
				}
			} else {
				if os.WriteFile(f.artifact, []byte(`{"schema":"changed"}`), 0600) != nil {
					t.Fatal("cannot change artifact")
				}
			}
			got := f.submit(server.URL, command, "")
			reason := "EVIDENCE_REJECTED"
			unknown, failed := int64(0), int64(5)
			if baseDenied {
				reason = "BASE_POLICY_DENIED"
				unknown, failed = 5, 0
			}
			if got.ExitCode != 1 || got.Summary.HTTPStatus != 403 || got.Summary.Status != "denied" || got.Summary.Reason != reason || got.Summary.ClaimCounts == nil || got.Summary.ClaimCounts.Unknown != unknown || got.Summary.ClaimCounts.Fail != failed {
				t.Fatal("durable denial used base approval or invented counts")
			}
			replay := f.submit(server.URL, command, "")
			if replay.ExitCode != 1 || !replay.Summary.Replayed || replay.Summary.OutcomeID != got.Summary.OutcomeID {
				t.Fatal("denial replay changed the original result")
			}
		})
	}
}

func TestAllClaimsPassingDoesNotReplaceFinalAdmission(t *testing.T) {
	for _, tc := range []struct {
		name, reason          string
		effectDenied, expired bool
	}{
		{"approval-budget", "OPERATION_EFFECT_DISALLOWED", true, false},
		{"authoritative-deadline", "EVIDENCE_REJECTED", false, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := fixtureWithOptions(t, false, tc.effectDenied, tc.expired)
			gate := httptest.NewServer(gatehttp.Handler(f.store))
			defer gate.Close()
			command := filepath.Join(f.root, "command.json")
			if f.prepare(gate.URL, "all-pass-denial", command).ExitCode != 0 {
				t.Fatal("prepare failed")
			}
			got := f.submit(gate.URL, command, "")
			if got.ExitCode != 1 || got.Summary.Status != "denied" || got.Summary.Reason != tc.reason || got.Summary.ClaimCounts == nil || got.Summary.ClaimCounts.Pass != 5 || got.Summary.ClaimCounts.Fail != 0 || got.Summary.ClaimCounts.Unknown != 0 {
				t.Fatal("all-pass completion replaced authoritative final denial")
			}
		})
	}
}

func TestLocalRejectsBeforeAnyNetworkAndPreservesFiles(t *testing.T) {
	f := newFixture(t, false)
	var calls atomic.Int64
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { calls.Add(1); gatehttp.Handler(f.store).ServeHTTP(w, r) }))
	defer server.Close()
	command := filepath.Join(f.root, "command.json")
	if f.prepare(server.URL, "key", command).ExitCode != 0 {
		t.Fatal("prepare failed")
	}
	valid, _ := os.ReadFile(command)
	calls.Store(0)
	report := filepath.Join(f.root, "existing-report")
	os.WriteFile(report, []byte("preserve"), 0600)
	got := f.submit(server.URL, command, report)
	if got.ExitCode != 2 || got.Summary.Code != "REPORT_FILE_UNAVAILABLE" || calls.Load() != 0 {
		t.Fatal("existing report did not prevent POST")
	}
	still, _ := os.ReadFile(report)
	if string(still) != "preserve" {
		t.Fatal("existing report overwritten")
	}
	for _, bad := range [][]byte{
		bytes.Replace(valid, []byte(`"request_id":`), []byte(`"Request_ID":`), 1),
		bytes.Replace(valid, []byte(`"request_id":`), []byte(`"extra":"private","request_id":`), 1),
		bytes.Replace(valid, []byte(`"expected_revision":1`), []byte(`"expected_revision":null`), 1),
		bytes.Replace(valid, []byte(`"expected_revision":1`), []byte(`"expected_revision":1,"expected_revision":1`), 1),
		bytes.Replace(valid, []byte(`"request_id":"request"`), []byte(`"request_id":"`+f.token+`"`), 1),
	} {
		os.WriteFile(command, bad, 0600)
		got = f.submit(server.URL, command, "")
		if got.ExitCode != 2 || calls.Load() != 0 {
			t.Fatal("invalid saved command reached network")
		}
		still, _ := os.ReadFile(command)
		if !bytes.Equal(still, bad) {
			t.Fatal("rejected command changed")
		}
	}
	for _, badServer := range []string{"https://127.0.0.1:80", "http://localhost:80", "http://192.0.2.1:80", "http://127.0.0.1", "http://127.0.0.1:0", "http://127.0.0.1:65536", "http://user@127.0.0.1:80", "http://127.0.0.1:80/", "http://127.0.0.1:80?", "http://127.0.0.1:80#"} {
		got = f.submit(badServer, command, "")
		if got.ExitCode != 2 || got.Summary.Code != "SERVER_INVALID" || calls.Load() != 0 {
			t.Fatal("nonliteral endpoint accepted")
		}
	}
}

func TestRedirectProxyAndLostResponseDoNotReplayImplicitly(t *testing.T) {
	f := newFixture(t, false)
	gate := httptest.NewServer(gatehttp.Handler(f.store))
	defer gate.Close()
	command := filepath.Join(f.root, "command.json")
	if f.prepare(gate.URL, "lost-response-key", command).ExitCode != 0 {
		t.Fatal("prepare failed")
	}
	raw, _ := os.ReadFile(command)
	var redirects atomic.Int64
	redirect := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		redirects.Add(1)
		http.Redirect(w, r, gate.URL+"/api/admit", 307)
	}))
	defer redirect.Close()
	if got := f.submit(redirect.URL, command, ""); got.ExitCode != 2 || got.Summary.Code != "REDIRECT_REJECTED" || redirects.Load() != 1 {
		t.Fatal("redirect was followed")
	}
	// This relay commits through the real handler, then closes the connection
	// before returning its response. It proves lost-response recovery, not crash durability.
	var posts atomic.Int64
	lost := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		posts.Add(1)
		recorder := httptest.NewRecorder()
		gatehttp.Handler(f.store).ServeHTTP(recorder, r)
		conn, _, err := w.(http.Hijacker).Hijack()
		if err == nil {
			conn.Close()
		}
	}))
	defer lost.Close()
	proxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { t.Error("environment proxy contacted") }))
	defer proxy.Close()
	t.Setenv("HTTP_PROXY", proxy.URL)
	t.Setenv("http_proxy", proxy.URL)
	got := f.submit(lost.URL, command, "")
	if got.ExitCode != 2 || got.Summary.Code != "TRANSPORT_UNCERTAIN" || posts.Load() != 1 {
		t.Fatal("response loss was treated as success or auto retried")
	}
	unchanged, _ := os.ReadFile(command)
	if !bytes.Equal(raw, unchanged) {
		t.Fatal("uncertainty changed command")
	}
	replay := f.submit(gate.URL, command, "")
	if replay.ExitCode != 0 || !replay.Summary.Replayed {
		t.Fatal("explicit retry did not recover committed original")
	}
}

func TestUntrustedResponseValuesNeverReachOutputOrReport(t *testing.T) {
	f := newFixture(t, false)
	gate := httptest.NewServer(gatehttp.Handler(f.store))
	defer gate.Close()
	command := filepath.Join(f.root, "command.json")
	if f.prepare(gate.URL, "safe-key", command).ExitCode != 0 {
		t.Fatal("prepare failed")
	}
	for i, body := range []string{
		`{"error":"` + f.token + `"}`,
		`{"error":"` + strings.ReplaceAll(f.token, "a", `\u0061`) + `"}`,
		`{"error":"\u0042earer private-secret"}`,
		`{"error":"arbitrary-private-message"}`,
		`{"error":"unavailable","authorization":"hidden"}`,
	} {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(503)
			io.WriteString(w, body)
		}))
		report := filepath.Join(f.root, "rejected-report-"+string(rune('a'+i)))
		got := f.submit(server.URL, command, report)
		server.Close()
		if got.ExitCode != 2 {
			t.Fatal("unsafe response accepted")
		}
		output, _ := json.Marshal(got.Summary)
		stored, _ := os.ReadFile(report)
		if bytes.Contains(output, []byte(f.token)) || bytes.Contains(output, []byte("private-secret")) || bytes.Contains(output, []byte("arbitrary-private-message")) || len(stored) != 0 {
			t.Fatal("response values escaped safe failure")
		}
	}
}

func TestActualDenialCannotExportEscapedCredentialInRetainedArtifact(t *testing.T) {
	f := newFixture(t, false)
	gate := httptest.NewServer(gatehttp.Handler(f.store))
	defer gate.Close()
	command := filepath.Join(f.root, "command.json")
	if f.prepare(gate.URL, "retained-credential-key", command).ExitCode != 0 {
		t.Fatal("prepare failed")
	}
	artifact, _ := os.ReadFile(f.artifact)
	artifact = bytes.Replace(artifact, []byte(`"schema":`), []byte(`"extra_credential":"`+strings.ReplaceAll(f.token, "a", `\u0061`)+`","schema":`), 1)
	if os.WriteFile(f.artifact, artifact, 0600) != nil {
		t.Fatal("escaped retained credential fixture unavailable")
	}
	report := filepath.Join(f.root, "rejected-private-report.json")
	got := f.submit(gate.URL, command, report)
	stored, _ := os.ReadFile(report)
	if got.ExitCode != 2 || got.Summary.Code != "CREDENTIAL_ECHO_REJECTED" || len(stored) != 0 {
		t.Fatal("escaped credential survived retained-artifact export check")
	}
	// The server has a durable denial even though the client refuses to expose
	// its credential-bearing presentation. The saved command remains unchanged.
	var c admission.Command
	raw, _ := os.ReadFile(command)
	json.Unmarshal(raw, &c)
	durable, err := f.store.Admit(f.token, c)
	if err == nil || durable.Outcome.Committed || !durable.Replayed {
		t.Fatal("credential export rejection changed server result")
	}
}

func TestRetainedCredentialGuardCoversDuplicateTrailingAndMalformedJSON(t *testing.T) {
	for _, kind := range []string{"duplicate-key", "trailing-value", "malformed-structure", "unterminated-string"} {
		t.Run(kind, func(t *testing.T) {
			f := newFixture(t, false)
			gate := httptest.NewServer(gatehttp.Handler(f.store))
			defer gate.Close()
			command := filepath.Join(f.root, "command.json")
			if f.prepare(gate.URL, "malformed-credential", command).ExitCode != 0 {
				t.Fatal("prepare failed")
			}
			original, _ := os.ReadFile(command)
			escaped := strings.ReplaceAll(f.token, "a", `\u0061`)
			var artifact string
			switch kind {
			case "duplicate-key":
				artifact = `{"x":"` + escaped + `","x":"safe"}`
			case "trailing-value":
				artifact = `{} "` + escaped + `"`
			case "malformed-structure":
				artifact = `not-json { "credential":"` + escaped + `" }`
			case "unterminated-string":
				artifact = `{"credential":"\z` + escaped
			}
			if os.WriteFile(f.artifact, []byte(artifact), 0600) != nil {
				t.Fatal("malformed retained credential fixture unavailable")
			}
			report := filepath.Join(f.root, "rejected-private-report.json")
			got := f.submit(gate.URL, command, report)
			stored, _ := os.ReadFile(report)
			unchanged, _ := os.ReadFile(command)
			if got.ExitCode != 2 || got.Summary.Code != "CREDENTIAL_ECHO_REJECTED" || len(stored) != 0 || !bytes.Equal(unchanged, original) {
				t.Fatal("malformed artifact hid recoverable credential or changed command")
			}
			var c admission.Command
			json.Unmarshal(original, &c)
			durable, err := f.store.Admit(f.token, c)
			if err == nil || durable.Outcome.Committed || !durable.Replayed {
				t.Fatal("presentation rejection lost durable original denial")
			}
		})
	}
}

func TestBoundedTransportCancellationAndResponses(t *testing.T) {
	token := strings.Repeat("b", 64)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		io.WriteString(w, strings.Repeat("x", 257))
	}))
	defer server.Close()
	status, raw, code := request(context.Background(), server.URL, token, "GET", "/api/state", nil, 256)
	if status != 200 || raw != nil || code != "RESPONSE_TOO_LARGE" {
		t.Fatal("response limit not enforced")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, _, code = request(ctx, server.URL, token, "POST", "/api/admit", []byte("{}"), 256)
	if code != "TRANSPORT_UNCERTAIN" {
		t.Fatal("canceled request did not report uncertainty")
	}
	if Deadline != 10*time.Second || MaxReportBytes != 64<<20 {
		t.Fatal("fixed contract bounds changed")
	}
}

func TestAuthenticationConflictAndTypedOutcomeConnections(t *testing.T) {
	f := newFixture(t, false)
	gate := httptest.NewServer(gatehttp.Handler(f.store))
	defer gate.Close()
	command := filepath.Join(f.root, "command.json")
	if f.prepare(gate.URL, "typed-key", command).ExitCode != 0 {
		t.Fatal("prepare failed")
	}
	rawCommand, _ := os.ReadFile(command)
	wrongToken := filepath.Join(f.root, "wrong-token")
	if os.WriteFile(wrongToken, []byte(strings.Repeat("c", 64)), 0600) != nil {
		t.Fatal("wrong-token fixture unavailable")
	}
	unauthorized := Submit(context.Background(), SubmitOptions{Server: gate.URL, TokenFile: wrongToken, CommandFile: command})
	if unauthorized.ExitCode != 2 || unauthorized.Summary.HTTPStatus != 401 || unauthorized.Summary.Code != "UNAUTHORIZED" || unauthorized.Summary.Status == "denied" {
		t.Fatal("authentication error confused with durable denial")
	}
	stale := bytes.Replace(rawCommand, []byte(`"expected_revision":1`), []byte(`"expected_revision":2`), 1)
	os.WriteFile(command, stale, 0600)
	conflict := f.submit(gate.URL, command, "")
	if conflict.ExitCode != 2 || conflict.Summary.HTTPStatus != 409 || conflict.Summary.Status != "conflict" {
		t.Fatal("stale command was reported as success")
	}
	os.WriteFile(command, rawCommand, 0600)
	report := filepath.Join(f.root, "actual-report.json")
	if f.submit(gate.URL, command, report).ExitCode != 0 {
		t.Fatal("actual approval unavailable for response tests")
	}
	raw, _ := os.ReadFile(report)
	for _, tc := range []struct {
		name   string
		change func(*admission.Result)
	}{
		{"command", func(r *admission.Result) { r.Outcome.Command.IdempotencyKey = "different-key" }},
		{"context", func(r *admission.Result) { r.Outcome.Preflight.Context.Command.RequestID = "other-request" }},
		{"revision", func(r *admission.Result) { r.Outcome.NewRevision = 1 }},
		{"v1", func(r *admission.Result) { r.Outcome.Schema = admission.OutcomeSchema }},
		{"private-reason", func(r *admission.Result) { r.Outcome.Preflight.Decision.Reason = "private-returned-value" }},
		{"commit", func(r *admission.Result) { r.Outcome.Committed = false }},
		{"counts", func(r *admission.Result) { r.Outcome.Preflight.Completion.Summary.Pass = 4 }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var result admission.Result
			if json.Unmarshal(raw, &result) != nil {
				t.Fatal("typed actual result unavailable")
			}
			tc.change(&result)
			result.Outcome.ID = ""
			result.Outcome.ID = digestJSON(result.Outcome)
			changed, _ := json.Marshal(result)
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				w.Write(changed)
			}))
			defer server.Close()
			output := filepath.Join(f.root, "invalid-report-"+tc.name)
			got := f.submit(server.URL, command, output)
			stored, _ := os.ReadFile(output)
			if got.ExitCode != 2 || got.Summary.Code != "RESPONSE_INVALID" || got.Summary.Reason != "" || len(stored) != 0 {
				t.Fatal("rehashing bypassed typed outcome connections")
			}
		})
	}
	for _, tc := range []struct {
		status     int
		body, code string
	}{
		{403, `{"error":"forbidden"}`, "FORBIDDEN"},
		{503, `{"error":"unavailable"}`, "UNAVAILABLE"},
		{403, `{"error":"policy_denied"}`, "RESPONSE_INVALID"},
		{200, `{"error":"policy_denied"}`, "RESPONSE_INVALID"},
	} {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(tc.status)
			io.WriteString(w, tc.body)
		}))
		got := f.submit(server.URL, command, "")
		server.Close()
		if got.ExitCode != 2 || got.Summary.Code != tc.code || got.Summary.Status == "denied" {
			t.Fatal("bare error envelope treated as durable outcome")
		}
	}
}
