package gateclient

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"reflect"
	"strconv"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/kimjooyoon/gooo-policy-studio/internal/admission"
	"github.com/kimjooyoon/gooo-policy-studio/internal/artifactnumeric"
	"github.com/kimjooyoon/gooo-policy-studio/internal/artifactpreflight"
	"github.com/kimjooyoon/gooo-policy-studio/internal/completion"
	"github.com/kimjooyoon/gooo-policy-studio/internal/policy"
)

func lowerHex(s string) bool {
	for _, b := range []byte(s) {
		if !(b >= '0' && b <= '9' || b >= 'a' && b <= 'f') {
			return false
		}
	}
	return true
}

func validDigest(s string) bool {
	return len(s) == 71 && strings.HasPrefix(s, "sha256:") && lowerHex(s[7:])
}

func validText(s string) bool {
	if len(s) < 1 || len(s) > 120 || !utf8.ValidString(s) || strings.TrimSpace(s) == "" {
		return false
	}
	for _, r := range s {
		if unicode.IsControl(r) {
			return false
		}
	}
	return true
}

func validKey(s string) bool {
	if len(s) < 1 || len(s) > 80 {
		return false
	}
	for i, b := range []byte(s) {
		if b >= 'a' && b <= 'z' || b >= 'A' && b <= 'Z' || b >= '0' && b <= '9' {
			continue
		}
		if i == 0 || !strings.ContainsRune("._:-", rune(b)) {
			return false
		}
	}
	return true
}

func validCommand(c admission.Command) bool {
	return validText(c.RequestID) && c.ExpectedRevision >= 1 && c.ExpectedRevision <= 2 && validDigest(c.PolicyVersion) && validKey(c.IdempotencyKey)
}

func sensitiveCommand(c admission.Command, token string) bool {
	return strings.Contains(c.RequestID, token) || strings.Contains(c.IdempotencyKey, token) || strings.Contains(c.PolicyVersion, token)
}

func validRequest(r policy.Request) bool {
	return validText(r.Key) && validText(r.Requester) && validText(r.Team) && r.Amount >= 0 && r.Amount <= policy.MaxAmount
}

func validView(v admission.View) bool {
	if v.Schema != admission.ViewSchemaV2 || !validDigest(v.PolicyVersion) || !validText(v.Principal.Key) || !validText(v.Principal.Team) || !v.Principal.Enabled || len(v.Requests) < 1 || len(v.Requests) > admission.MaxRequests {
		return false
	}
	seen := make(map[string]bool, len(v.Requests))
	for _, r := range v.Requests {
		if !validRequest(r.Request) || seen[r.Request.Key] {
			return false
		}
		seen[r.Request.Key] = true
		if !(r.Status == admission.Pending && r.Revision == 1 || r.Status == admission.Approved && r.Revision == 2) {
			return false
		}
	}
	return true
}

func digestJSON(v any) string {
	raw, err := json.Marshal(v)
	if err != nil {
		return ""
	}
	s := sha256.Sum256(raw)
	return "sha256:" + hex.EncodeToString(s[:])
}

// These are consistency checks on the received v2 presentation. The client
// rederives numeric proofs with the checked pure Gooo predicate, but does not
// load a server recipe, acquire artifacts, authenticate an issuer, refresh the
// command, or decide whether the overall operation is admissible.
func validOutcome(r admission.Result, c admission.Command, committed bool) bool {
	o := r.Outcome
	if o.Schema != admission.OutcomeSchemaV2 || o.Scope != admission.OutcomeScopeV2 || o.Preflight == nil || o.Command != c || o.PolicyVersion != c.PolicyVersion || !validDigest(o.ID) || !validText(o.PrincipalKey) || o.Committed != committed || o.PriorRevision != c.ExpectedRevision || c.ExpectedRevision != 1 {
		return false
	}
	newRevision := c.ExpectedRevision
	if committed {
		newRevision++
	}
	if o.NewRevision != newRevision {
		return false
	}
	id := o.ID
	o.ID = ""
	if id != digestJSON(o) {
		return false
	}
	if _, err := time.Parse(time.RFC3339Nano, o.CreatedAt); err != nil {
		return false
	}
	receipt := o.Receipt
	if receipt.Schema != "policy-studio/execution/v1" || receipt.Scope != policy.Scope || receipt.CreatedAt != o.CreatedAt || !validDigest(receipt.ID) || !validDigest(receipt.SourceDigest) || !validDigest(receipt.GeneratedDigest) || len(receipt.CompilerSource) != 40 || !lowerHex(receipt.CompilerSource) {
		return false
	}
	rid := receipt.ID
	receipt.ID = ""
	if rid != digestJSON(receipt) || receipt.Input.Before != receipt.Input.After || receipt.Result.Before != receipt.Result.After || receipt.Result.Change.Changed || receipt.Result.Change.ReasonChanged || receipt.Result.Change.Direction != "UNCHANGED" {
		return false
	}
	p := o.Preflight
	x := p.Context
	if p.Schema != admission.PreflightReportSchema || x.Domain != "policy-studio/artifact-context/v1" || x.Command != c || x.PolicyVersion != c.PolicyVersion || x.Request.Request.Key != c.RequestID || x.Request.Status != admission.Pending || x.Request.Revision != o.PriorRevision || x.Request.Request != receipt.Input.Request || !validRequest(x.Request.Request) || x.Principal.Key != o.PrincipalKey || !x.Principal.Enabled || !x.Principal.CanExecute || x.Principal.Key != receipt.Input.Reviewer.Key || x.Principal.Team != receipt.Input.Reviewer.Team || x.Principal.Active != receipt.Input.Reviewer.Active || !validText(x.Principal.Team) {
		return false
	}
	if x.Artifact.RequestID != c.RequestID || !validDigest(x.Artifact.ExpectedSHA256) || x.Artifact.DeadlineUnix <= 0 || p.ContextSHA256 != digestJSON(x) || p.DecisionUnix < 0 || p.DecisionUnix < p.Producer.ObservationUnix {
		return false
	}
	if x.Implementation.Schema != "policy-studio/artifact-admission-code/v1" || !validDigest(x.Implementation.HostSHA256) || !validDigest(x.Implementation.DecoderSHA256) || !validDigest(x.Implementation.AuditSHA256) || x.Implementation.Producer != p.Producer.Identity || x.Implementation.AuditSHA256 != p.Audit.Identity {
		return false
	}
	producer := p.Producer
	if producer.Schema != artifactpreflight.ReportSchema || (producer.ProducerID != artifactpreflight.ProducerID && producer.ProducerID != artifactpreflight.NewProducerID) || producer.Identity.Schema != "policy-studio/artifact-producer-source/v2" || producer.Identity.ProducerID != artifactpreflight.NewProducerID || producer.Identity.VerifierID != artifactpreflight.RegistryVerifierID || producer.ContextDigest != p.ContextSHA256 || producer.ExpectedSHA256 != x.Artifact.ExpectedSHA256 || !validDigest(producer.ActualSHA256) || producer.ObservationUnix < 0 {
		return false
	}
	numericBindings, err := artifactnumeric.SourceBindings()
	if err != nil || producer.Identity.NumericBindings != numericBindings {
		return false
	}
	retained, err := base64.StdEncoding.DecodeString(producer.ArtifactBase64)
	if err != nil || base64.StdEncoding.EncodeToString(retained) != producer.ArtifactBase64 || len(retained) > int(artifactpreflight.MaxBytes)+1 || producer.ByteCount != int64(len(retained)) {
		return false
	}
	d := sha256.Sum256(retained)
	if producer.ActualSHA256 != "sha256:"+hex.EncodeToString(d[:]) {
		return false
	}
	switch producer.AcquisitionStatus {
	case artifactpreflight.ReadSuccess, artifactpreflight.ReadError, artifactpreflight.Oversized, artifactpreflight.Skipped:
	default:
		return false
	}
	if !receipt.Result.After.Approved && (producer.AcquisitionStatus != artifactpreflight.Skipped || len(retained) != 0) {
		return false
	}
	co := p.Completion
	if co.Schema != completion.ReportSchema || completion.ValidatePolicy(co.Policy) != nil || completion.ValidateInput(co.Input) != nil || co.Input.RequestID != "req_"+strings.TrimPrefix(p.ContextSHA256, "sha256:") || !validDigest(co.Bindings.PolicySHA256) {
		return false
	}
	total := len(co.Policy.RequiredClaims)
	if len(producer.Observations) != total || len(p.Evidence) != total || len(co.Input.Records) != total || len(co.Steps) != total || len(co.MissingClaims) != 0 || len(co.UnexpectedClaims) != 0 {
		return false
	}
	counts := completion.Counts{Total: int64(total)}
	var admissible int64
	for i, claim := range producer.Observations {
		record, evidence := co.Input.Records[i], p.Evidence[i]
		if claim.ClaimID != co.Policy.RequiredClaims[i] || !validClaimObservation(claim, producer) || record.ClaimID != claim.ClaimID || record.Status != claim.Status || len(record.EvidenceIDs) != 1 || record.EvidenceIDs[0] != claim.EvidenceID || evidence.ClaimID != claim.ClaimID || co.Steps[i].Index != int64(i) || co.Steps[i].Status != claim.Status {
			return false
		}
		switch claim.Status {
		case "pass":
			counts.Pass++
		case "fail":
			counts.Fail++
		case "unsupported":
			counts.Unsupported++
		case "truncated":
			counts.Truncated++
		case "unknown":
			counts.Unknown++
		default:
			return false
		}
		facts := evidence.Facts
		if facts.Status != claim.Status || facts.ObservedBinding != p.ContextSHA256 || facts.RequiredBinding != p.ContextSHA256 || facts.ObservedArtifact != producer.ActualSHA256 || facts.RequiredArtifact != x.Artifact.ExpectedSHA256 || facts.ObservedPolicy != c.PolicyVersion || facts.RequiredPolicy != c.PolicyVersion || facts.ObservedAtUnix != producer.ObservationUnix || facts.NowUnix != p.DecisionUnix || facts.ExpiresAtUnix != x.Artifact.DeadlineUnix {
			return false
		}
		if evidence.Decision.Admissible {
			admissible++
		}
	}
	if co.Summary.Counts() != counts || !co.Summary.Valid || co.Summary.Complete != (counts.Pass == counts.Total) || co.Readiness.Ready != co.Summary.Complete || co.Coverage.RequiredCount != int64(total) || co.Coverage.MatchedCount != int64(total) || co.Coverage.ObservedCount != int64(total) || co.Coverage.UnexpectedCount != 0 {
		return false
	}
	f, decision := p.AdmissionFacts, p.Decision
	if f.BasePolicyApproved != receipt.Result.After.Approved || f.RequiredCount != int64(total) || f.ObservedCount != int64(total) || f.AdmissibleEvidenceCount != admissible || f.CompletionReady != co.Readiness.Ready || f.ApprovalEffectAdmissible != p.ApprovalEffects.Admissible || f.ControlPlaneEffectAdmissible != p.ControlPlaneEffects.Admissible || decision.Admitted != committed || decision.ProvenanceOK != f.ProvenanceOK || decision.BasePolicyOK != f.BasePolicyApproved || decision.CompletionOK != f.CompletionReady || decision.ApprovalEffectOK != f.ApprovalEffectAdmissible || decision.ControlPlaneEffectOK != f.ControlPlaneEffectAdmissible || !decision.CountsOK || decision.EvidenceOK != (admissible == int64(total)) {
		return false
	}
	if committed {
		return decision.Reason == "ADMITTED" && decision.ProvenanceOK && decision.BasePolicyOK && decision.EvidenceOK && decision.CompletionOK && decision.ApprovalEffectOK && decision.ControlPlaneEffectOK
	}
	switch decision.Reason {
	case "PROVENANCE_MISMATCH":
		return !decision.ProvenanceOK
	case "CONTROL_PLANE_EFFECT_DISALLOWED":
		return !decision.ControlPlaneEffectOK
	case "BASE_POLICY_DENIED":
		return !decision.BasePolicyOK
	case "EVIDENCE_REJECTED":
		return !decision.EvidenceOK
	case "CLAIMS_NOT_COMPLETE":
		return !decision.CompletionOK
	case "OPERATION_EFFECT_DISALLOWED":
		return !decision.ApprovalEffectOK
	default:
		return false
	}
}

func validClaimObservation(claim artifactpreflight.ClaimObservation, producer artifactpreflight.Report) bool {
	mandatory := producer.AcquisitionStatus == artifactpreflight.ReadSuccess && producer.DigestOK && producer.SchemaOK && producer.TypesOK
	switch claim.Verifier {
	case artifactpreflight.VerifierID:
		return claim.NativeProof == nil && (mandatory || claim.Status != "pass")
	case artifactpreflight.Int64LTEVerifierID, artifactpreflight.Int64GTEVerifierID:
		if producer.ProducerID != artifactpreflight.NewProducerID {
			return false
		}
		if !mandatory {
			return claim.NativeProof == nil && claim.Status != "pass"
		}
		if claim.NativeProof == nil {
			return false
		}
		value, err := strconv.ParseInt(claim.Actual, 10, 64)
		if err != nil || strconv.FormatInt(value, 10) != claim.Actual {
			return false
		}
		bound, err := strconv.ParseInt(claim.Expected, 10, 64)
		if err != nil || strconv.FormatInt(bound, 10) != claim.Expected {
			return false
		}
		operator := artifactnumeric.LTE
		if claim.Verifier == artifactpreflight.Int64GTEVerifierID {
			operator = artifactnumeric.GTE
		}
		derived, err := artifactnumeric.Evaluate(artifactnumeric.Facts{Value: value, Bound: bound, Operator: operator})
		if err != nil || !reflect.DeepEqual(*claim.NativeProof, derived) || derived.Bindings != producer.Identity.NumericBindings || claim.Reason != derived.Decision.Reason {
			return false
		}
		if derived.Decision.Matched {
			return claim.Status == "pass"
		}
		return claim.Status == "fail"
	default:
		return false
	}
}

// Inspect decoded JSON string values as well as raw bytes so escaped token
// and Bearer echoes cannot reach even an explicitly private report export.
func sensitiveJSON(raw []byte, token string) bool {
	if bytes.Contains(raw, []byte(token)) || bytes.Contains(bytes.ToLower(raw), []byte("bearer ")) {
		return true
	}
	var value any
	d := json.NewDecoder(bytes.NewReader(raw))
	d.UseNumber()
	if d.Decode(&value) != nil {
		return false
	}
	var walk func(any) bool
	walk = func(v any) bool {
		switch v := v.(type) {
		case string:
			return strings.Contains(v, token) || strings.Contains(strings.ToLower(v), "bearer ")
		case map[string]any:
			for key, child := range v {
				if strings.EqualFold(key, "authorization") || strings.EqualFold(key, "proxy-authorization") || walk(key) || walk(child) {
					return true
				}
			}
		case []any:
			for _, child := range v {
				if walk(child) {
					return true
				}
			}
		}
		return false
	}
	if walk(value) {
		return true
	}
	// Artifact bytes are intentionally represented as base64 in a v2 report.
	// This final check also prevents exporting an echoed credential that a
	// local endpoint placed inside the retained artifact representation.
	var artifactWalk func(any) bool
	artifactWalk = func(v any) bool {
		switch v := v.(type) {
		case map[string]any:
			for key, child := range v {
				if key == "artifact_base64" {
					if s, ok := child.(string); ok {
						if b, err := base64.StdEncoding.DecodeString(s); err == nil {
							if bytes.Contains(b, []byte(token)) || bytes.Contains(bytes.ToLower(b), []byte("bearer ")) {
								return true
							}
							if retainedStringEcho(b, token) {
								return true
							}
						}
					}
				}
				if artifactWalk(child) {
					return true
				}
			}
		case []any:
			for _, child := range v {
				if artifactWalk(child) {
					return true
				}
			}
		}
		return false
	}
	return artifactWalk(value)
}

// A rejected artifact can contain duplicate keys, trailing values, or broken
// JSON structure. Do not reduce its strings to a map or stop at the first
// value. Scan complete quoted JSON strings without trusting that structure.
// The additional conservative Unicode pass also detects the current ASCII
// hex token after a syntax error or inside an unterminated string. This is a
// credential-echo guard, not a claim to detect arbitrary encoded secrets.
func retainedStringEcho(raw []byte, token string) bool {
	for i := 0; i < len(raw); i++ {
		if raw[i] != '"' {
			continue
		}
		start := i
		closed := false
		for end := i + 1; end < len(raw); end++ {
			if raw[end] == '\\' {
				end++
				continue
			}
			if raw[end] != '"' {
				continue
			}
			var s string
			if json.Unmarshal(raw[start:end+1], &s) == nil {
				if strings.Contains(s, token) || strings.Contains(strings.ToLower(s), "bearer ") {
					return true
				}
				if strings.EqualFold(s, "authorization") || strings.EqualFold(s, "proxy-authorization") {
					j := end + 1
					for j < len(raw) && (raw[j] == ' ' || raw[j] == '\n' || raw[j] == '\r' || raw[j] == '\t') {
						j++
					}
					if j < len(raw) && raw[j] == ':' {
						return true
					}
				}
			}
			i = end
			closed = true
			break
		}
		if !closed {
			break
		}
	}
	// Normalize ASCII Unicode escapes without assuming valid JSON. Even an
	// earlier malformed escape or missing closing delimiter cannot hide a
	// contiguous current token written as \\uXXXX characters.
	normalized := make([]byte, 0, len(raw))
	hexNibble := func(b byte) (byte, bool) {
		switch {
		case b >= '0' && b <= '9':
			return b - '0', true
		case b >= 'a' && b <= 'f':
			return b - 'a' + 10, true
		case b >= 'A' && b <= 'F':
			return b - 'A' + 10, true
		default:
			return 0, false
		}
	}
	for i := 0; i < len(raw); i++ {
		if raw[i] == '\\' && i+5 < len(raw) && raw[i+1] == 'u' {
			var n uint16
			ok := true
			for j := i + 2; j < i+6; j++ {
				v, valid := hexNibble(raw[j])
				if !valid {
					ok = false
					break
				}
				n = n*16 + uint16(v)
			}
			if ok && n < 128 {
				normalized = append(normalized, byte(n))
				i += 5
				continue
			}
		}
		normalized = append(normalized, raw[i])
	}
	return bytes.Contains(normalized, []byte(token)) || bytes.Contains(bytes.ToLower(normalized), []byte("bearer "))
}
