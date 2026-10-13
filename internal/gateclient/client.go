// Package gateclient is a private-file machine client for the local v2 gate.
// It prepares a fixed four-field command, then submits those saved bytes once.
// Response checks provide presentation consistency, not issuer authentication.
package gateclient

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"mime"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/kimjooyoon/gooo-policy-studio/internal/admission"
	"github.com/kimjooyoon/gooo-policy-studio/internal/completion"
	"github.com/kimjooyoon/gooo-policy-studio/internal/jsoninput"
)

const (
	SummarySchema   = "policy-studio/gate-client-summary/v1"
	Scope           = "Local v2 admission only; no external target action or issuer authentication."
	Deadline        = 10 * time.Second
	MaxCommandBytes = 4096
	MaxStateBytes   = 1 << 20
	MaxReportBytes  = 64 << 20
)

type PrepareOptions struct {
	Server, TokenFile, RequestID, IdempotencyKey, CommandFile string
}

type SubmitOptions struct {
	Server, TokenFile, CommandFile, ReportFile string
}

// Summary deliberately excludes request facts, artifact bytes, predicate
// values, paths, credentials and arbitrary text returned by the server.
type Summary struct {
	Schema       string             `json:"schema"`
	Action       string             `json:"action"`
	Status       string             `json:"status"`
	HTTPStatus   int                `json:"http_status"`
	ServerSchema string             `json:"server_schema"`
	Replayed     bool               `json:"replayed"`
	OutcomeID    string             `json:"outcome_id"`
	Reason       string             `json:"reason"`
	ClaimCounts  *completion.Counts `json:"claim_counts,omitempty"`
	Code         string             `json:"code,omitempty"`
	Scope        string             `json:"scope"`
}

type Result struct {
	Summary  Summary
	ExitCode int
}

func LocalFailure(action, code string) Result {
	// Do not expose arbitrary caller-provided error codes through this helper.
	switch code {
	case "USAGE_INVALID", "OUTPUT_UNAVAILABLE":
	default:
		code = "CLIENT_ERROR"
	}
	return failure(action, 0, "error", code)
}

func summary(action string) Summary {
	if action != "prepare" && action != "submit" {
		action = "client"
	}
	return Summary{Schema: SummarySchema, Action: action, Scope: Scope}
}

func failure(action string, status int, category, code string) Result {
	s := summary(action)
	s.Status, s.HTTPStatus, s.Code = category, status, code
	return Result{s, 2}
}

func endpoint(raw string) (string, bool) {
	u, err := url.Parse(raw)
	if err != nil || u.Scheme != "http" || u.Host == "" || u.User != nil || u.Opaque != "" || u.Path != "" || u.RawPath != "" || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" || strings.ContainsAny(raw, "?#") {
		return "", false
	}
	host, port, err := net.SplitHostPort(u.Host)
	if err != nil || port == "" {
		return "", false
	}
	for _, b := range []byte(port) {
		if b < '0' || b > '9' {
			return "", false
		}
	}
	n, err := strconv.Atoi(port)
	addr, err2 := netip.ParseAddr(host)
	if err != nil || n < 1 || n > 65535 || err2 != nil || addr.Zone() != "" || !addr.IsLoopback() {
		return "", false
	}
	return "http://" + u.Host, true
}

func tokenAt(path string) (string, bool) {
	raw, err := readPrivate(path, 65)
	if err != nil {
		return "", false
	}
	if len(raw) == 65 && raw[64] == '\n' {
		raw = raw[:64]
	}
	if len(raw) != 64 || !lowerHex(string(raw)) {
		return "", false
	}
	return string(raw), true
}

// Each call uses a fresh connection and a non-replayable request body. No
// proxy, redirect, cookie jar, implicit credential source or automatic retry
// is enabled. A failed POST may already have committed at the gate.
func request(ctx context.Context, server, token, method, path string, raw []byte, limit int64) (int, []byte, string) {
	transport := &http.Transport{
		Proxy:                  nil,
		DialContext:            (&net.Dialer{Timeout: Deadline}).DialContext,
		DisableKeepAlives:      true,
		DisableCompression:     true,
		ResponseHeaderTimeout:  Deadline,
		MaxResponseHeaderBytes: 64 << 10,
	}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, Timeout: Deadline, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	ctx, cancel := context.WithTimeout(ctx, Deadline)
	defer cancel()
	var body io.Reader
	if raw != nil {
		body = io.NopCloser(bytes.NewReader(raw))
	}
	req, err := http.NewRequestWithContext(ctx, method, server+path, body)
	if err != nil {
		return 0, nil, "TRANSPORT_UNCERTAIN"
	}
	if raw != nil {
		req.ContentLength = int64(len(raw))
		req.GetBody = nil
		req.Header.Set("Content-Type", "application/json")
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Accept", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		return 0, nil, "TRANSPORT_UNCERTAIN"
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 && resp.StatusCode < 400 {
		return resp.StatusCode, nil, "REDIRECT_REJECTED"
	}
	media, params, err := mime.ParseMediaType(resp.Header.Get("Content-Type"))
	if err != nil || media != "application/json" || len(resp.Header.Values("Content-Type")) != 1 || resp.Header.Get("Content-Encoding") != "" {
		return resp.StatusCode, nil, "RESPONSE_INVALID"
	}
	for k, v := range params {
		if k != "charset" || !strings.EqualFold(v, "utf-8") {
			return resp.StatusCode, nil, "RESPONSE_INVALID"
		}
	}
	if resp.ContentLength > limit {
		return resp.StatusCode, nil, "RESPONSE_TOO_LARGE"
	}
	result, err := io.ReadAll(io.LimitReader(resp.Body, limit+1))
	if err != nil {
		return resp.StatusCode, nil, "TRANSPORT_UNCERTAIN"
	}
	if int64(len(result)) > limit {
		return resp.StatusCode, nil, "RESPONSE_TOO_LARGE"
	}
	if sensitiveJSON(result, token) {
		return resp.StatusCode, nil, "CREDENTIAL_ECHO_REJECTED"
	}
	return resp.StatusCode, result, ""
}

func Prepare(ctx context.Context, o PrepareOptions) Result {
	server, ok := endpoint(o.Server)
	if !ok {
		return failure("prepare", 0, "error", "SERVER_INVALID")
	}
	if o.TokenFile == "" || o.CommandFile == "" || !validText(o.RequestID) || !validKey(o.IdempotencyKey) {
		return failure("prepare", 0, "error", "PREPARE_INPUT_INVALID")
	}
	token, ok := tokenAt(o.TokenFile)
	if !ok {
		return failure("prepare", 0, "error", "TOKEN_FILE_INVALID")
	}
	if strings.Contains(o.RequestID, token) || strings.Contains(o.IdempotencyKey, token) {
		return failure("prepare", 0, "error", "COMMAND_CONTAINS_CREDENTIAL")
	}
	status, raw, code := request(ctx, server, token, http.MethodGet, "/api/state", nil, MaxStateBytes)
	if code != "" {
		return failure("prepare", status, "error", code)
	}
	if status != http.StatusOK {
		return classifyError("prepare", status, raw, nil)
	}
	var view admission.View
	if jsoninput.Decode(raw, &view, MaxStateBytes) != nil || !validView(view) {
		return failure("prepare", status, "error", "STATE_INVALID")
	}
	var found *admission.RequestState
	for i := range view.Requests {
		if view.Requests[i].Request.Key == o.RequestID {
			if found != nil {
				return failure("prepare", status, "error", "STATE_INVALID")
			}
			found = &view.Requests[i]
		}
	}
	if found == nil || found.Status != admission.Pending {
		return failure("prepare", status, "error", "REQUEST_NOT_PENDING")
	}
	command := admission.Command{RequestID: found.Request.Key, ExpectedRevision: found.Revision, PolicyVersion: view.PolicyVersion, IdempotencyKey: o.IdempotencyKey}
	commandRaw, err := json.Marshal(command)
	if err != nil || sensitiveCommand(command, token) {
		return failure("prepare", status, "error", "COMMAND_CONTAINS_CREDENTIAL")
	}
	commandRaw = append(commandRaw, '\n')
	out, err := createPrivate(o.CommandFile)
	if err != nil {
		return failure("prepare", status, "error", "COMMAND_FILE_UNAVAILABLE")
	}
	err = out.WriteAndSync(commandRaw)
	closed := out.Close()
	if err != nil || closed != nil {
		return failure("prepare", status, "error", "COMMAND_WRITE_FAILED")
	}
	s := summary("prepare")
	s.Status, s.HTTPStatus, s.ServerSchema = "prepared", status, admission.ViewSchemaV2
	return Result{s, 0}
}

func Submit(ctx context.Context, o SubmitOptions) Result {
	server, ok := endpoint(o.Server)
	if !ok {
		return failure("submit", 0, "error", "SERVER_INVALID")
	}
	if o.TokenFile == "" || o.CommandFile == "" {
		return failure("submit", 0, "error", "SUBMIT_INPUT_INVALID")
	}
	token, ok := tokenAt(o.TokenFile)
	if !ok {
		return failure("submit", 0, "error", "TOKEN_FILE_INVALID")
	}
	rawCommand, err := readPrivate(o.CommandFile, MaxCommandBytes)
	if err != nil {
		return failure("submit", 0, "error", "COMMAND_FILE_INVALID")
	}
	var command admission.Command
	if jsoninput.Decode(rawCommand, &command, MaxCommandBytes) != nil || !validCommand(command) {
		return failure("submit", 0, "error", "COMMAND_INVALID")
	}
	if bytes.Contains(rawCommand, []byte(token)) || sensitiveCommand(command, token) {
		return failure("submit", 0, "error", "COMMAND_CONTAINS_CREDENTIAL")
	}
	var out *privateOutput
	if o.ReportFile != "" {
		out, err = createPrivate(o.ReportFile)
		if err != nil {
			return failure("submit", 0, "error", "REPORT_FILE_UNAVAILABLE")
		}
		defer out.Close()
	}
	status, raw, code := request(ctx, server, token, http.MethodPost, "/api/admit", rawCommand, MaxReportBytes)
	if code != "" {
		return failure("submit", status, "error", code)
	}
	var result Result
	if status == http.StatusOK {
		var got admission.Result
		if jsoninput.Decode(raw, &got, MaxReportBytes) != nil || !validOutcome(got, command, true) {
			return failure("submit", status, "error", "RESPONSE_INVALID")
		}
		result = outcomeSummary(got, status)
	} else {
		result = classifyError("submit", status, raw, &command)
	}
	// Only strictly recognized bodies are exported. A reserved file remains
	// empty on transport or response failure; it is never silently overwritten.
	if out != nil && result.Summary.Code != "RESPONSE_INVALID" {
		if out.WriteAndSync(raw) != nil || out.Close() != nil {
			return failure("submit", status, "error", "REPORT_WRITE_FAILED")
		}
	}
	return result
}

type errorResponse struct {
	Error  string            `json:"error"`
	Result *admission.Result `json:"result,omitempty"`
}

func classifyError(action string, status int, raw []byte, command *admission.Command) Result {
	var body errorResponse
	if jsoninput.Decode(raw, &body, MaxReportBytes) != nil {
		return failure(action, status, "error", "RESPONSE_INVALID")
	}
	if status == http.StatusForbidden && body.Error == admission.PolicyDenied && command != nil && body.Result != nil {
		if !validOutcome(*body.Result, *command, false) {
			return failure(action, status, "error", "RESPONSE_INVALID")
		}
		return outcomeSummary(*body.Result, status)
	}
	if body.Result != nil {
		return failure(action, status, "error", "RESPONSE_INVALID")
	}
	category, code := "error", ""
	switch {
	case status == 401 && body.Error == admission.Unauthorized:
		code = "UNAUTHORIZED"
	case status == 403 && body.Error == admission.Forbidden:
		code = "FORBIDDEN"
	case status == 403 && body.Error == "MACHINE_CLIENT_REQUIRED":
		code = "MACHINE_CLIENT_REQUIRED"
	case status == 409 && body.Error == admission.Conflict:
		category, code = "conflict", "CONFLICT"
	case status == 503 && body.Error == admission.Unavailable:
		category, code = "unavailable", "UNAVAILABLE"
	case status == 422 && body.Error == admission.InvalidInput:
		code = "INPUT_REJECTED"
	case status == 400 && (body.Error == "INVALID_COMMAND_JSON" || body.Error == "COMMAND_READ_FAILED"):
		code = "COMMAND_REJECTED"
	case status == 408 && body.Error == "REQUEST_CANCELLED":
		code = "REQUEST_CANCELLED"
	case status == 413 && body.Error == "COMMAND_TOO_LARGE":
		code = "COMMAND_TOO_LARGE"
	case status == 415 && (body.Error == "CONTENT_TYPE_REQUIRED" || body.Error == "UNSUPPORTED_CONTENT_TYPE_PARAMETER"):
		code = "CONTENT_TYPE_REJECTED"
	case status == 500 && body.Error == "RESPONSE_ENCODING_FAILED":
		category, code = "unavailable", "UNAVAILABLE"
	default:
		return failure(action, status, "error", "RESPONSE_INVALID")
	}
	return failure(action, status, category, code)
}

func outcomeSummary(got admission.Result, status int) Result {
	s := summary("submit")
	s.Status, s.HTTPStatus, s.ServerSchema = "approved", status, admission.OutcomeSchemaV2
	s.Replayed, s.OutcomeID, s.Reason = got.Replayed, got.Outcome.ID, got.Outcome.Preflight.Decision.Reason
	counts := got.Outcome.Preflight.Completion.Summary.Counts()
	s.ClaimCounts = &counts
	exit := 0
	if !got.Outcome.Committed {
		s.Status, exit = "denied", 1
	}
	return Result{s, exit}
}
