// Package artifactnumeric transports three typed host facts through the
// compiled original Gooo Int64BoundDecision activity. It does not parse an
// artifact, select a bound, authenticate evidence or execute effects.
package artifactnumeric

const (
	BindingsSchema      = "policy-studio/artifact-int64-native-bindings/v1"
	GenerationSchema    = "policy-studio/artifact-int64-generation/v1"
	CompilerSourcePin   = "83928fa4538245abe33b08549da47f8cbdc50ed2"
	LTE                 = "lte"
	GTE                 = "gte"
	BoundMatch          = "BOUND_MATCH"
	BoundMismatch       = "BOUND_MISMATCH"
	UnsupportedOperator = "UNSUPPORTED_OPERATOR"
)

type Facts struct {
	Value    int64  `json:"value"`
	Bound    int64  `json:"bound"`
	Operator string `json:"operator"`
}

type Decision struct {
	AtMost     bool   `json:"at_most"`
	AtLeast    bool   `json:"at_least"`
	OperatorOK bool   `json:"operator_ok"`
	Matched    bool   `json:"matched"`
	Reason     string `json:"reason"`
}

// Bindings records checked actual embedded projection, hand-written transport,
// host validation and complete raw generator/compiler receipt byte identities.
// The executable remains trusted; these hashes are not an issuer signature.
type Bindings struct {
	Schema                 string `json:"schema"`
	SourceSHA256           string `json:"source_sha256"`
	GeneratedSHA256        string `json:"generated_sha256"`
	BridgeSHA256           string `json:"bridge_sha256"`
	ModelSHA256            string `json:"model_sha256"`
	BindingsSHA256         string `json:"bindings_sha256"`
	GeneratorSHA256        string `json:"generator_sha256"`
	GenerationSHA256       string `json:"generation_sha256"`
	CompilerIdentitySHA256 string `json:"compiler_identity_sha256"`
	ActivityReceiptSHA256  string `json:"activity_receipt_sha256"`
	CompilerSourceSHA      string `json:"compiler_source_sha"`
	JSONInputSHA256        string `json:"json_input_sha256"`
}

// Proof is emitted only after an actual native call. Both relations and the
// operator check remain visible independently of the selected result.
type Proof struct {
	Facts    Facts    `json:"facts"`
	Decision Decision `json:"decision"`
	Bindings Bindings `json:"bindings"`
}
