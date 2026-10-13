// Package admission admits server-owned requests using authenticated machine
// principals and compiled Gooo policy. Its atomic effect is a local request
// state transition, not an external API call or an immutable audit record.
package admission

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"

	"github.com/kimjooyoon/gooo-policy-studio/internal/policy"
)

const (
	BootstrapSchema  = "policy-studio/admission-bootstrap/v1"
	ViewSchema       = "policy-studio/admission-view/v1"
	OutcomeSchema    = "policy-studio/admission-outcome/v1"
	snapshotSchema   = "policy-studio/admission-snapshot/v1"
	MaxRequests      = 256
	MaxPrincipals    = 32
	MaxOutcomes      = 256
	maxSnapshotBytes = 4 << 20
	Pending          = "pending"
	Approved         = "approved"
	Unauthorized     = "unauthorized"
	Forbidden        = "forbidden"
	InvalidInput     = "invalid_input"
	Conflict         = "conflict"
	PolicyDenied     = "policy_denied"
	Unavailable      = "unavailable"
	OutcomeScope     = "Authenticated machine admission of one server-owned request; committed means its local pending-to-approved state transition. Denials are durably retained without changing request state. No external effect, signature, or immutable audit guarantee."
)

type Error struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}

func (e *Error) Error() string           { return e.Code + ": " + e.Message }
func failure(code, message string) error { return &Error{Code: code, Message: message} }

type Principal struct {
	Key         string `json:"key"`
	Team        string `json:"team"`
	Active      bool   `json:"active"`
	Enabled     bool   `json:"enabled"`
	CanExecute  bool   `json:"can_execute"`
	TokenSHA256 string `json:"token_sha256"`
}

// PrincipalView deliberately has no credential hash field.
type PrincipalView struct {
	Key        string `json:"key"`
	Team       string `json:"team"`
	Active     bool   `json:"active"`
	Enabled    bool   `json:"enabled"`
	CanExecute bool   `json:"can_execute"`
}

type Bootstrap struct {
	Schema     string                `json:"schema"`
	Policy     policy.Rules          `json:"policy"`
	Principals []Principal           `json:"principals"`
	Requests   []policy.Request      `json:"requests"`
	Preflight  *ArtifactPolicy       `json:"preflight,omitempty"`
	Artifacts  []ArtifactRequirement `json:"artifacts,omitempty"`
}

type Command struct {
	RequestID        string `json:"request_id"`
	ExpectedRevision int64  `json:"expected_revision"`
	PolicyVersion    string `json:"policy_version"`
	IdempotencyKey   string `json:"idempotency_key"`
}

type RequestState struct {
	Request  policy.Request `json:"request"`
	Status   string         `json:"status"`
	Revision int64          `json:"revision"`
}

type View struct {
	Schema        string         `json:"schema"`
	PolicyVersion string         `json:"policy_version"`
	Principal     PrincipalView  `json:"principal"`
	Requests      []RequestState `json:"requests"`
}

type Outcome struct {
	Schema        string           `json:"schema"`
	ID            string           `json:"id"`
	Command       Command          `json:"command"`
	PrincipalKey  string           `json:"principal_key"`
	PriorRevision int64            `json:"prior_revision"`
	NewRevision   int64            `json:"new_revision"`
	PolicyVersion string           `json:"policy_version"`
	Receipt       policy.Receipt   `json:"receipt"`
	Committed     bool             `json:"committed"`
	CreatedAt     string           `json:"created_at"`
	Scope         string           `json:"scope"`
	Preflight     *PreflightReport `json:"preflight,omitempty"`
}

type Result struct {
	Replayed bool    `json:"replayed"`
	Outcome  Outcome `json:"outcome"`
}

type snapshot struct {
	Schema         string                 `json:"schema"`
	ID             string                 `json:"id"`
	CreatedAt      string                 `json:"created_at"`
	Policy         policy.Rules           `json:"policy"`
	PolicyVersion  string                 `json:"policy_version"`
	Provenance     policy.BatchProvenance `json:"provenance"`
	Principals     []Principal            `json:"principals"`
	Requests       []RequestState         `json:"requests"`
	Outcomes       []Outcome              `json:"outcomes"`
	Preflight      *ArtifactPolicy        `json:"preflight,omitempty"`
	Artifacts      []ArtifactRequirement  `json:"artifacts,omitempty"`
	Implementation *PreflightProvenance   `json:"implementation,omitempty"`
}

func digest(raw []byte) string {
	sum := sha256.Sum256(raw)
	return "sha256:" + hex.EncodeToString(sum[:])
}

// TokenDigest returns the lowercase hex SHA-256 representation accepted in an
// administrative bootstrap. Token plaintext is never stored or logged here.
func TokenDigest(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])
}

func version(rules policy.Rules, provenance policy.BatchProvenance) string {
	raw, _ := json.Marshal(struct {
		Policy     policy.Rules           `json:"policy"`
		Provenance policy.BatchProvenance `json:"provenance"`
	}{rules, provenance})
	return digest(raw)
}

func outcomeID(out Outcome) string {
	out.ID = ""
	raw, _ := json.Marshal(out)
	return digest(raw)
}

func snapshotID(saved snapshot) string {
	saved.ID = ""
	raw, _ := json.Marshal(saved)
	return digest(raw)
}

func cloneSnapshot(saved snapshot) snapshot {
	return cloneValue(saved)
}

// Every nested value crossing the trusted state boundary has owned storage.
// These types contain only JSON-representable scalars and bounded slices.
func cloneValue[T any](value T) T {
	raw, err := json.Marshal(value)
	if err != nil {
		panic("internal state serialization invariant")
	}
	var result T
	if err := json.Unmarshal(raw, &result); err != nil {
		panic("internal state clone invariant")
	}
	return result
}
