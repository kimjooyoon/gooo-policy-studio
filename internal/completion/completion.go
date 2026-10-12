// Package completion checks separately configured claim coverage and folds all
// supplied verifier outcomes through compiled Gooo activities. Evidence labels
// identify supplied facts; this package does not authenticate those facts.
package completion

import (
	"crypto/sha256"
	"fmt"
	"reflect"
	"sort"

	"github.com/kimjooyoon/gooo-policy-studio/internal/jsoninput"
)

const (
	PolicySchema   = "policy-studio/completion-policy/v1"
	InputSchema    = "policy-studio/completion-input/v1"
	ReportSchema   = "policy-studio/completion-report/v1"
	MaxRecords     = 256
	MaxPolicyBytes = 65536
	MaxInputBytes  = 1048576
	MaxReplayBytes = 4194304
)

type Counts struct {
	Total       int64 `json:"total"`
	Pass        int64 `json:"pass"`
	Fail        int64 `json:"fail"`
	Unsupported int64 `json:"unsupported"`
	Truncated   int64 `json:"truncated"`
	Unknown     int64 `json:"unknown"`
}

type Decision struct {
	Total       int64  `json:"total"`
	Pass        int64  `json:"pass"`
	Fail        int64  `json:"fail"`
	Unsupported int64  `json:"unsupported"`
	Truncated   int64  `json:"truncated"`
	Unknown     int64  `json:"unknown"`
	Valid       bool   `json:"valid"`
	Complete    bool   `json:"complete"`
	Reason      string `json:"reason"`
}

// Counts copies the Gooo result into the input of the next compiled step.
func (d Decision) Counts() Counts {
	return Counts{d.Total, d.Pass, d.Fail, d.Unsupported, d.Truncated, d.Unknown}
}

type Coverage struct {
	RequiredCount   int64 `json:"required_count"`
	MatchedCount    int64 `json:"matched_count"`
	UnexpectedCount int64 `json:"unexpected_count"`
	ObservedCount   int64 `json:"observed_count"`
}

type Readiness struct {
	Ready      bool   `json:"ready"`
	Reason     string `json:"reason"`
	CountsOK   bool   `json:"counts_ok"`
	CoverageOK bool   `json:"coverage_ok"`
	SummaryOK  bool   `json:"summary_ok"`
	AllPassOK  bool   `json:"all_pass_ok"`
}

type Policy struct {
	Schema         string   `json:"schema"`
	PolicyID       string   `json:"policy_id"`
	Revision       int64    `json:"revision"`
	RequiredClaims []string `json:"required_claims"`
}

type Record struct {
	ClaimID     string   `json:"claim_id"`
	Status      string   `json:"status"`
	EvidenceIDs []string `json:"evidence_ids"`
}

type Input struct {
	Schema    string   `json:"schema"`
	RequestID string   `json:"request_id"`
	Records   []Record `json:"records"`
}

type Step struct {
	Index        int64    `json:"index"`
	CountsBefore Counts   `json:"counts_before"`
	Status       string   `json:"status"`
	Decision     Decision `json:"decision"`
}

type Bindings struct {
	PolicySHA256      string `json:"policy_sha256"`
	SourceSHA256      string `json:"source_sha256"`
	GeneratedSHA256   string `json:"generated_sha256"`
	BridgeSHA256      string `json:"bridge_sha256"`
	GenerationSHA256  string `json:"generation_sha256"`
	CompilerSourceSHA string `json:"compiler_source_sha"`
}

type Report struct {
	Schema           string    `json:"schema"`
	Policy           Policy    `json:"policy"`
	Input            Input     `json:"input"`
	Steps            []Step    `json:"steps"`
	Summary          Decision  `json:"summary"`
	Coverage         Coverage  `json:"coverage"`
	MissingClaims    []string  `json:"missing_claims"`
	UnexpectedClaims []string  `json:"unexpected_claims"`
	Readiness        Readiness `json:"readiness"`
	Bindings         Bindings  `json:"bindings"`
}

// DecodePolicy retains the binding to the actual operator-selected file bytes,
// including whitespace. The input payload cannot choose a required claim set.
func DecodePolicy(raw []byte) (Policy, string, error) {
	var policy Policy
	if err := jsoninput.Decode(raw, &policy, MaxPolicyBytes); err != nil {
		return Policy{}, "", fmt.Errorf("policy: %w", err)
	}
	if err := ValidatePolicy(policy); err != nil {
		return Policy{}, "", err
	}
	return clonePolicy(policy), digest(raw), nil
}

// Check validates complete policy and input JSON before executing any rule.
func Check(rawPolicy, rawInput []byte) (Report, error) {
	policy, policyDigest, err := DecodePolicy(rawPolicy)
	if err != nil {
		return Report{}, err
	}
	var input Input
	if err := jsoninput.Decode(rawInput, &input, MaxInputBytes); err != nil {
		return Report{}, fmt.Errorf("input: %w", err)
	}
	return Evaluate(policy, input, policyDigest)
}

// ValidatePolicy checks the operator-selected configuration. IDs are exact,
// portable ASCII identifiers; case and supplied policy order are preserved.
func ValidatePolicy(policy Policy) error {
	if policy.Schema != PolicySchema || !validID(policy.PolicyID) || policy.Revision <= 0 {
		return fmt.Errorf("policy schema, policy_id or positive revision is invalid")
	}
	if len(policy.RequiredClaims) < 1 || len(policy.RequiredClaims) > MaxRecords {
		return fmt.Errorf("policy required_claims must contain 1..%d IDs", MaxRecords)
	}
	seen := make(map[string]bool, len(policy.RequiredClaims))
	for i, claim := range policy.RequiredClaims {
		if !validID(claim) || seen[claim] {
			return fmt.Errorf("policy required_claims[%d]: invalid or duplicate claim ID", i)
		}
		seen[claim] = true
	}
	return nil
}

// ValidateInput rejects malformed facts and duplicates before folding. A
// missing required claim or an unexpected well-formed claim remains reportable.
func ValidateInput(input Input) error {
	if input.Schema != InputSchema || !validID(input.RequestID) {
		return fmt.Errorf("input schema or request_id is invalid")
	}
	if len(input.Records) > MaxRecords {
		return fmt.Errorf("records must contain 0..%d entries", MaxRecords)
	}
	claims := make(map[string]bool, len(input.Records))
	for i, record := range input.Records {
		if !validID(record.ClaimID) || claims[record.ClaimID] {
			return fmt.Errorf("records[%d]: invalid or duplicate claim ID", i)
		}
		claims[record.ClaimID] = true
		switch record.Status {
		case "pass", "fail", "unsupported", "truncated", "unknown":
		default:
			return fmt.Errorf("records[%d]: unsupported exact status label", i)
		}
		if len(record.EvidenceIDs) < 1 || len(record.EvidenceIDs) > MaxRecords {
			return fmt.Errorf("records[%d]: evidence_ids must contain 1..%d IDs", i, MaxRecords)
		}
		evidence := make(map[string]bool, len(record.EvidenceIDs))
		for j, id := range record.EvidenceIDs {
			if len(id) != 67 || id[:3] != "ev_" || !lowerHex(id[3:]) || evidence[id] {
				return fmt.Errorf("records[%d].evidence_ids[%d]: invalid or duplicate evidence ID", i, j)
			}
			evidence[id] = true
		}
	}
	return nil
}

// Evaluate folds every supplied record through compiled Gooo. Only ID set
// matching and report construction are implemented by the host.
func Evaluate(policy Policy, input Input, policyDigest string) (Report, error) {
	if err := ValidatePolicy(policy); err != nil {
		return Report{}, err
	}
	if err := ValidateInput(input); err != nil {
		return Report{}, err
	}
	if !validDigest(policyDigest) {
		return Report{}, fmt.Errorf("policy byte binding is invalid")
	}
	policy, input = clonePolicy(policy), cloneInput(input)
	bindings, err := sourceBindings()
	if err != nil {
		return Report{}, err
	}
	bindings.PolicySHA256 = policyDigest
	if !validBindings(bindings) {
		return Report{}, fmt.Errorf("embedded source bindings are invalid")
	}
	steps := make([]Step, 0, len(input.Records))
	counts := Counts{}
	for i, record := range input.Records {
		decision, err := stepNative(counts, record.Status)
		if err != nil {
			return Report{}, fmt.Errorf("completion step %d: %w", i, err)
		}
		if !decision.Valid {
			return Report{}, fmt.Errorf("completion step %d rejected valid input", i)
		}
		steps = append(steps, Step{int64(i), counts, record.Status, decision})
		counts = decision.Counts()
	}
	summary, err := finishNative(counts)
	if err != nil {
		return Report{}, fmt.Errorf("completion finish: %w", err)
	}
	// NO_RECORDS is the declared not-ready result for a valid empty input;
	// every other invalid native decision stops report construction.
	if !summary.Valid && !(len(input.Records) == 0 && summary.Reason == "NO_RECORDS") {
		return Report{}, fmt.Errorf("completion finish rejected accumulated counts")
	}
	coverage, missing, unexpected := matchClaims(policy, input)
	readiness, err := readyNative(summary, coverage)
	if err != nil {
		return Report{}, fmt.Errorf("completion readiness: %w", err)
	}
	return Report{ReportSchema, policy, input, steps, summary, coverage, missing, unexpected, readiness, bindings}, nil
}

// Replay recomputes the complete typed report using the current independently
// loaded policy and current embedded Gooo projections. Report.policy is never
// used as configuration. This establishes consistency, not issuer authenticity.
func Replay(policy Policy, policyDigest string, saved Report) (Report, error) {
	if saved.Schema != ReportSchema {
		return Report{}, fmt.Errorf("unsupported completion report schema")
	}
	current, err := Evaluate(policy, saved.Input, policyDigest)
	if err != nil {
		return Report{}, err
	}
	if !reflect.DeepEqual(saved, current) {
		return Report{}, fmt.Errorf("completion report differs from current policy, bindings or recomputed observations")
	}
	return current, nil
}

func matchClaims(policy Policy, input Input) (Coverage, []string, []string) {
	required := make(map[string]bool, len(policy.RequiredClaims))
	for _, claim := range policy.RequiredClaims {
		required[claim] = true
	}
	observed := make(map[string]bool, len(input.Records))
	unexpected := make([]string, 0)
	var matched int64
	for _, record := range input.Records {
		observed[record.ClaimID] = true
		if required[record.ClaimID] {
			matched++
		} else {
			unexpected = append(unexpected, record.ClaimID)
		}
	}
	missing := make([]string, 0)
	for _, claim := range policy.RequiredClaims {
		if !observed[claim] {
			missing = append(missing, claim)
		}
	}
	sort.Strings(missing)
	sort.Strings(unexpected)
	return Coverage{int64(len(policy.RequiredClaims)), matched, int64(len(unexpected)), int64(len(input.Records))}, missing, unexpected
}

func clonePolicy(policy Policy) Policy {
	policy.RequiredClaims = append([]string{}, policy.RequiredClaims...)
	return policy
}

func cloneInput(input Input) Input {
	records := make([]Record, len(input.Records))
	for i, record := range input.Records {
		record.EvidenceIDs = append([]string{}, record.EvidenceIDs...)
		records[i] = record
	}
	input.Records = records
	return input
}

func validID(id string) bool {
	if len(id) < 1 || len(id) > 80 || !asciiLetter(id[0]) {
		return false
	}
	for i := 1; i < len(id); i++ {
		b := id[i]
		if !asciiLetter(b) && !(b >= '0' && b <= '9') && b != '.' && b != '_' && b != '-' {
			return false
		}
	}
	return true
}

func asciiLetter(b byte) bool { return b >= 'A' && b <= 'Z' || b >= 'a' && b <= 'z' }

func lowerHex(value string) bool {
	for i := 0; i < len(value); i++ {
		b := value[i]
		if !(b >= '0' && b <= '9') && !(b >= 'a' && b <= 'f') {
			return false
		}
	}
	return true
}

func validDigest(value string) bool {
	return len(value) == 71 && value[:7] == "sha256:" && lowerHex(value[7:])
}

func validBindings(b Bindings) bool {
	return validDigest(b.PolicySHA256) && validDigest(b.SourceSHA256) && validDigest(b.GeneratedSHA256) &&
		validDigest(b.BridgeSHA256) && validDigest(b.GenerationSHA256) && len(b.CompilerSourceSHA) == 40 && lowerHex(b.CompilerSourceSHA)
}

func digest(raw []byte) string { return fmt.Sprintf("sha256:%x", sha256.Sum256(raw)) }
