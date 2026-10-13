// Package artifactpreflight produces observations from an operator-selected
// local file. It checks configured predicates, not issuer signatures or the
// truth of facts outside those predicates. HTTP callers never select its recipe
// or acquisition status.
package artifactpreflight

import "github.com/kimjooyoon/gooo-policy-studio/internal/artifactnumeric"

const (
	RecipeSchema       = "policy-studio/artifact-recipe/v1"
	NewRecipeSchema    = "policy-studio/artifact-recipe/v2"
	ReportSchema       = "policy-studio/artifact-preflight/v2"
	ProducerID         = "flat-json/v1"
	NewProducerID      = "flat-json/v2"
	VerifierID         = "field_equals/v1"
	Int64LTEVerifierID = "field_int64_lte/v1"
	Int64GTEVerifierID = "field_int64_gte/v1"
	RegistryVerifierID = "artifact-verifier-registry/v2"
	MaxBytes           = int64(65536)
	MaxClaims          = 256
)

type Field struct {
	Name string `json:"name"`
	Type string `json:"type"`
}

type Claim struct {
	ID       string `json:"id"`
	Verifier string `json:"verifier"`
	Field    string `json:"field"`
	Expected string `json:"expected"`
}

type Recipe struct {
	Schema         string  `json:"schema"`
	ProducerID     string  `json:"producer_id"`
	ArtifactSchema string  `json:"artifact_schema"`
	MaxBytes       int64   `json:"max_bytes"`
	Fields         []Field `json:"fields"`
	Claims         []Claim `json:"claims"`
}

type Requirement struct {
	Path           string `json:"path"`
	ExpectedSHA256 string `json:"expected_sha256"`
}

type AcquisitionStatus string

const (
	ReadSuccess AcquisitionStatus = "read_success"
	ReadError   AcquisitionStatus = "read_error"
	Oversized   AcquisitionStatus = "oversized"
	Skipped     AcquisitionStatus = "skipped"
)

// Acquisition is opaque so callers cannot label arbitrary bytes read_success.
// Only ReadArtifact, SkipArtifact and replay construct this state.
type Acquisition struct {
	status       AcquisitionStatus
	raw          []byte
	expectedSHA  string
	maxBytes     int64
	observedSize int64
}

func (a Acquisition) Status() AcquisitionStatus { return a.status }

type Identity struct {
	Schema            string                   `json:"schema"`
	ProducerID        string                   `json:"producer_id"`
	VerifierID        string                   `json:"verifier_id"`
	ModelSHA256       string                   `json:"model_sha256"`
	ValidationSHA256  string                   `json:"validation_sha256"`
	VerifierSHA256    string                   `json:"verifier_sha256"`
	ReaderSHA256      string                   `json:"reader_sha256"`
	ReaderUnixSHA256  string                   `json:"reader_unix_sha256"`
	ReaderOtherSHA256 string                   `json:"reader_other_sha256"`
	IdentitySHA256    string                   `json:"identity_sha256"`
	JSONInputSHA256   string                   `json:"json_input_sha256"`
	NumericBindings   artifactnumeric.Bindings `json:"numeric_bindings"`
}

type ClaimObservation struct {
	ClaimID    string `json:"claim_id"`
	Verifier   string `json:"verifier"`
	Field      string `json:"field"`
	Expected   string `json:"expected"`
	Actual     string `json:"actual"`
	Status     string `json:"status"`
	Reason     string `json:"reason"`
	EvidenceID string `json:"evidence_id"`
	// Absent for equality or any mandatory acquisition/schema/type failure.
	NativeProof *artifactnumeric.Proof `json:"native_proof,omitempty"`
}

type Report struct {
	Schema            string            `json:"schema"`
	ProducerID        string            `json:"producer_id"`
	Identity          Identity          `json:"identity"`
	RecipeSHA256      string            `json:"recipe_sha256"`
	ExpectedSHA256    string            `json:"expected_sha256"`
	ContextDigest     string            `json:"context_digest"`
	ObservationUnix   int64             `json:"observation_unix"`
	AcquisitionStatus AcquisitionStatus `json:"acquisition_status"`
	ArtifactBase64    string            `json:"artifact_base64"`
	// ActualSHA256 hashes retained observed bytes. A non-success acquisition
	// never asserts that those bytes are the entire artifact's content.
	ActualSHA256   string             `json:"actual_sha256"`
	ByteCount      int64              `json:"byte_count"`
	ObservedSize   int64              `json:"observed_size"`
	DigestOK       bool               `json:"digest_ok"`
	SchemaOK       bool               `json:"schema_ok"`
	TypesOK        bool               `json:"types_ok"`
	ArtifactReason string             `json:"artifact_reason"`
	Observations   []ClaimObservation `json:"observations"`
}

type Producer struct{ recipe Recipe }

func cloneRecipe(recipe Recipe) Recipe {
	recipe.Fields = append([]Field{}, recipe.Fields...)
	recipe.Claims = append([]Claim{}, recipe.Claims...)
	return recipe
}

// Recipe returns an owned copy of the immutable operator configuration.
func (p *Producer) Recipe() Recipe { return cloneRecipe(p.recipe) }
