package artifactpreflight

import (
	_ "embed"

	"github.com/kimjooyoon/gooo-policy-studio/internal/jsoninput"
)

//go:embed model.go
var modelSource []byte

//go:embed validation.go
var validationSource []byte

//go:embed verifier.go
var verifierSource []byte

//go:embed reader.go
var readerSource []byte

//go:embed reader_unix.go
var readerUnixSource []byte

//go:embed reader_other.go
var readerOtherSource []byte

//go:embed identity.go
var identitySource []byte

// SourceIdentity binds the actual built-in verifier, parser, registry model,
// acquisition and shared strict JSON implementation compiled into this binary.
func SourceIdentity() Identity {
	return Identity{
		Schema: "policy-studio/artifact-producer-source/v1", ProducerID: ProducerID, VerifierID: VerifierID,
		ModelSHA256: digest(modelSource), ValidationSHA256: digest(validationSource),
		VerifierSHA256: digest(verifierSource), ReaderSHA256: digest(readerSource),
		ReaderUnixSHA256: digest(readerUnixSource), ReaderOtherSHA256: digest(readerOtherSource),
		IdentitySHA256: digest(identitySource), JSONInputSHA256: jsoninput.SourceIdentity(),
	}
}
