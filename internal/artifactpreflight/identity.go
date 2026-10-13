package artifactpreflight

import (
	_ "embed"

	"github.com/kimjooyoon/gooo-policy-studio/internal/artifactnumeric"
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
	identity, err := CheckedSourceIdentity()
	if err != nil {
		return Identity{}
	}
	return identity
}

// CheckedSourceIdentity propagates native binding failures without a panic.
// This is the current registry identity, distinct from a recipe's producer ID.
func CheckedSourceIdentity() (Identity, error) {
	numeric, err := artifactnumeric.SourceBindings()
	if err != nil {
		return Identity{}, err
	}
	return Identity{
		Schema: "policy-studio/artifact-producer-source/v2", ProducerID: NewProducerID, VerifierID: RegistryVerifierID,
		ModelSHA256: digest(modelSource), ValidationSHA256: digest(validationSource),
		VerifierSHA256: digest(verifierSource), ReaderSHA256: digest(readerSource),
		ReaderUnixSHA256: digest(readerUnixSource), ReaderOtherSHA256: digest(readerOtherSource),
		IdentitySHA256: digest(identitySource), JSONInputSHA256: jsoninput.SourceIdentity(),
		NumericBindings: numeric,
	}, nil
}
