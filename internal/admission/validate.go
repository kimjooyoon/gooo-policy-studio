package admission

import (
	"encoding/hex"
	"fmt"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/kimjooyoon/gooo-policy-studio/internal/policy"
)

func validText(text string, maxBytes int) bool {
	if strings.TrimSpace(text) == "" || len(text) > maxBytes || !utf8.ValidString(text) {
		return false
	}
	for _, r := range text {
		if unicode.IsControl(r) {
			return false
		}
	}
	return true
}

func validHex(text string, bytes int) bool {
	decoded, err := hex.DecodeString(text)
	return err == nil && len(decoded) == bytes && text == strings.ToLower(text)
}

func validToken(token string) bool {
	if len(token) < 32 || len(token) > 256 {
		return false
	}
	for i := range token {
		if token[i] < 33 || token[i] > 126 {
			return false
		}
	}
	return true
}

func validKey(key string) bool {
	if len(key) == 0 || len(key) > 80 {
		return false
	}
	for i := range key {
		b := key[i]
		alnum := b >= 'A' && b <= 'Z' || b >= 'a' && b <= 'z' || b >= '0' && b <= '9'
		if !alnum && (i == 0 || b != '.' && b != '_' && b != ':' && b != '-') {
			return false
		}
	}
	return true
}

// ValidateBootstrap is the same validation used by Init. Root-owned credential
// provisioning must fill the token digest before calling this function.
func ValidateBootstrap(b Bootstrap) error {
	if b.Schema == BootstrapSchemaV2 {
		return validateArtifactBootstrap(b)
	}
	if b.Preflight != nil || b.Artifacts != nil {
		return failure(InvalidInput, "v1 bootstrap cannot carry v2 artifact policy")
	}
	if b.Schema != BootstrapSchema || len(b.Principals) == 0 || len(b.Principals) > MaxPrincipals || len(b.Requests) == 0 || len(b.Requests) > MaxRequests {
		return failure(InvalidInput, "invalid bootstrap schema or inventory bounds")
	}
	keys, credentials := map[string]bool{}, map[string]bool{}
	probe := policy.Request{Key: "validation", Requester: "requester", Team: "team", Amount: 0, Submitted: true}
	for i, p := range b.Principals {
		if !validText(p.Key, 120) || !validText(p.Team, 120) || !validHex(p.TokenSHA256, 32) || keys[p.Key] || credentials[p.TokenSHA256] {
			return failure(InvalidInput, fmt.Sprintf("principals[%d]: invalid or duplicate principal identity or credential digest", i))
		}
		keys[p.Key], credentials[p.TokenSHA256] = true, true
		if err := policy.Validate(policy.Input{Request: probe, Reviewer: policy.Reviewer{Key: p.Key, Team: p.Team, Active: p.Active}, Before: b.Policy, After: b.Policy}); err != nil {
			return failure(InvalidInput, "invalid administrative policy or principal domain values")
		}
	}
	keys = map[string]bool{}
	reviewer := policy.Reviewer{Key: "reviewer", Team: "team", Active: true}
	for i, r := range b.Requests {
		if !validText(r.Key, 120) || !validText(r.Requester, 120) || !validText(r.Team, 120) || keys[r.Key] {
			return failure(InvalidInput, fmt.Sprintf("requests[%d]: invalid or duplicate request identity", i))
		}
		keys[r.Key] = true
		if err := policy.Validate(policy.Input{Request: r, Reviewer: reviewer, Before: b.Policy, After: b.Policy}); err != nil {
			return failure(InvalidInput, fmt.Sprintf("requests[%d]: invalid authoritative domain input", i))
		}
	}
	return nil
}

func validateCommand(c Command) error {
	if !validText(c.RequestID, 120) || c.ExpectedRevision < 1 || c.ExpectedRevision > 2 ||
		!strings.HasPrefix(c.PolicyVersion, "sha256:") || !validHex(strings.TrimPrefix(c.PolicyVersion, "sha256:"), 32) || !validKey(c.IdempotencyKey) {
		return failure(InvalidInput, "invalid command identity, revision, policy version, or idempotency key")
	}
	return nil
}

// Existing policy exports verified provenance through its finite batch API.
// This pure probe reuses that check, including the actual embedded adapter. Its
// derived expected observation is only schema admission, not a correctness test.
func currentProvenance() (policy.BatchProvenance, error) {
	rules := policy.Rules{Limit: 0, SameTeam: true, ActiveReviewer: true, PreventSelf: true}
	r := policy.Request{Key: "provenance-probe", Requester: "requester", Team: "team", Amount: 0, Submitted: true}
	reviewer := policy.Reviewer{Key: "reviewer", Team: "team", Active: true}
	receipt, err := policy.Simulate(policy.Input{Request: r, Reviewer: reviewer, Before: rules, After: rules})
	if err != nil {
		return policy.BatchProvenance{}, failure(Unavailable, "current compiled policy provenance is unavailable")
	}
	report, err := policy.SimulateBatch(policy.BatchInput{Schema: policy.BatchInputSchema, Label: "compiled policy provenance binding", Before: rules, After: rules,
		Cases: []policy.Case{{ID: "provenance", Request: r, Reviewer: reviewer, ExpectedAfter: receipt.Result.After}}})
	if err != nil {
		return policy.BatchProvenance{}, failure(Unavailable, "current compiled policy provenance is unavailable")
	}
	return report.Provenance, nil
}

type operationKey struct{ Principal, Idempotency string }

// validateSnapshot reconstructs the one-way request state machine in persisted
// outcome order and replays every receipt against current compiled Gooo. These
// consistency checks do not authenticate a trusted administrator's rewrite.
func validateSnapshot(saved snapshot, current policy.BatchProvenance) error {
	if saved.Schema == snapshotSchemaV2 {
		return validateArtifactSnapshot(saved, current)
	}
	if saved.Preflight != nil || saved.Artifacts != nil || saved.Implementation != nil {
		return failure(Unavailable, "v1 snapshot cannot carry v2 bindings")
	}
	if saved.Schema != snapshotSchema || saved.ID != snapshotID(saved) || saved.Provenance != current || saved.PolicyVersion != version(saved.Policy, current) || len(saved.Outcomes) > MaxOutcomes {
		return failure(Unavailable, "snapshot identity, code binding, or bounds do not match")
	}
	if _, err := time.Parse(time.RFC3339Nano, saved.CreatedAt); err != nil {
		return failure(Unavailable, "snapshot creation time is invalid")
	}
	bootstrap := Bootstrap{Schema: BootstrapSchema, Policy: saved.Policy, Principals: saved.Principals, Requests: make([]policy.Request, len(saved.Requests))}
	for i, r := range saved.Requests {
		bootstrap.Requests[i] = r.Request
	}
	if err := ValidateBootstrap(bootstrap); err != nil {
		return failure(Unavailable, "saved authoritative configuration is invalid")
	}
	principals := make(map[string]Principal, len(saved.Principals))
	for _, p := range saved.Principals {
		principals[p.Key] = p
	}
	requests := make(map[string]RequestState, len(saved.Requests))
	for _, r := range saved.Requests {
		requests[r.Request.Key] = RequestState{Request: r.Request, Status: Pending, Revision: 1}
	}
	seen := make(map[operationKey]bool, len(saved.Outcomes))
	for i, out := range saved.Outcomes {
		bad := func() error {
			return failure(Unavailable, fmt.Sprintf("outcomes[%d]: saved decision or state binding is invalid", i))
		}
		p, exists := principals[out.PrincipalKey]
		r, requestExists := requests[out.Command.RequestID]
		key := operationKey{out.PrincipalKey, out.Command.IdempotencyKey}
		if !exists || !requestExists || seen[key] || validateCommand(out.Command) != nil || out.Schema != OutcomeSchema || out.Scope != OutcomeScope || out.ID != outcomeID(out) ||
			out.PolicyVersion != saved.PolicyVersion || out.Command.PolicyVersion != saved.PolicyVersion || out.PriorRevision != r.Revision || out.Command.ExpectedRevision != r.Revision || r.Status != Pending ||
			out.CreatedAt != out.Receipt.CreatedAt {
			return bad()
		}
		if out.Preflight != nil {
			return bad()
		}
		if _, err := time.Parse(time.RFC3339Nano, out.CreatedAt); err != nil {
			return bad()
		}
		input := policy.Input{Request: r.Request, Reviewer: policy.Reviewer{Key: p.Key, Team: p.Team, Active: p.Active}, Before: saved.Policy, After: saved.Policy}
		if out.Receipt.Input != input || out.Receipt.SourceDigest != current.SourceDigest || out.Receipt.GeneratedDigest != current.GeneratedDigest || out.Receipt.CompilerSource != current.CompilerSource {
			return bad()
		}
		if _, err := policy.Replay(out.Receipt); err != nil {
			return bad()
		}
		if out.Committed != out.Receipt.Result.After.Approved || out.Receipt.Result.Before != out.Receipt.Result.After || out.Receipt.Result.Change != (policy.Change{Direction: "UNCHANGED"}) {
			return bad()
		}
		if out.Committed {
			if out.NewRevision != r.Revision+1 {
				return bad()
			}
			r.Status, r.Revision = Approved, out.NewRevision
			requests[r.Request.Key] = r
		} else if out.NewRevision != r.Revision {
			return bad()
		}
		seen[key] = true
	}
	for _, r := range saved.Requests {
		if r != requests[r.Request.Key] {
			return failure(Unavailable, "saved request state does not match its complete outcome history")
		}
	}
	return nil
}
