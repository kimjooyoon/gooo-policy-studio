package artifactpreflight

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"path/filepath"
	"strconv"
	"strings"
	"unicode/utf8"
)

func New(recipe Recipe) (*Producer, error) {
	if err := ValidateRecipe(recipe); err != nil {
		return nil, err
	}
	return &Producer{cloneRecipe(recipe)}, nil
}

func ValidateRecipe(recipe Recipe) error {
	if recipe.Schema != RecipeSchema || recipe.ProducerID != ProducerID {
		return fmt.Errorf("unknown artifact recipe schema or producer ID")
	}
	if len(recipe.ArtifactSchema) < 1 || len(recipe.ArtifactSchema) > 128 || !utf8.ValidString(recipe.ArtifactSchema) {
		return fmt.Errorf("artifact_schema must be 1..128 valid UTF-8 bytes")
	}
	if recipe.MaxBytes < 1 || recipe.MaxBytes > MaxBytes {
		return fmt.Errorf("artifact max_bytes must be 1..%d", MaxBytes)
	}
	if len(recipe.Fields) < 1 || len(recipe.Fields) > 255 {
		return fmt.Errorf("artifact fields must contain 1..255 entries")
	}
	fields := make(map[string]string, len(recipe.Fields))
	for i, field := range recipe.Fields {
		if !validID(field.Name) || field.Name == "schema" || fields[field.Name] != "" {
			return fmt.Errorf("fields[%d]: invalid, reserved or duplicate name", i)
		}
		switch field.Type {
		case "text", "bool", "int64":
		default:
			return fmt.Errorf("fields[%d]: unsupported type", i)
		}
		fields[field.Name] = field.Type
	}
	if len(recipe.Claims) < 1 || len(recipe.Claims) > MaxClaims {
		return fmt.Errorf("artifact claims must contain 1..%d entries", MaxClaims)
	}
	claims := make(map[string]bool, len(recipe.Claims))
	for i, claim := range recipe.Claims {
		if !validID(claim.ID) || claims[claim.ID] || claim.Verifier != VerifierID {
			return fmt.Errorf("claims[%d]: invalid or duplicate ID or unknown verifier", i)
		}
		t, ok := fields[claim.Field]
		if !ok {
			return fmt.Errorf("claims[%d]: field is not configured", i)
		}
		if !validExpected(claim.Expected, t) {
			return fmt.Errorf("claims[%d]: expected value is invalid or not canonical for %s", i, t)
		}
		claims[claim.ID] = true
	}
	return nil
}

func ValidateRequirement(requirement Requirement) error {
	if requirement.Path == "" || !utf8.ValidString(requirement.Path) || !filepath.IsAbs(requirement.Path) || filepath.Clean(requirement.Path) != requirement.Path || strings.IndexByte(requirement.Path, 0) >= 0 {
		return fmt.Errorf("artifact path must be a clean absolute operator path")
	}
	if !validDigest(requirement.ExpectedSHA256) {
		return fmt.Errorf("artifact expected SHA-256 is invalid")
	}
	return nil
}

func validExpected(value, t string) bool {
	switch t {
	case "text":
		return utf8.ValidString(value) && len(value) <= int(MaxBytes)
	case "bool":
		return value == "true" || value == "false"
	case "int64":
		_, ok := canonicalInteger(value)
		return ok
	}
	return false
}

func canonicalInteger(value string) (int64, bool) {
	v, err := strconv.ParseInt(value, 10, 64)
	return v, err == nil && strconv.FormatInt(v, 10) == value
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

func validDigest(value string) bool {
	if len(value) != 71 || value[:7] != "sha256:" {
		return false
	}
	for i := 7; i < len(value); i++ {
		b := value[i]
		if !(b >= '0' && b <= '9') && !(b >= 'a' && b <= 'f') {
			return false
		}
	}
	return true
}

func digest(raw []byte) string { return fmt.Sprintf("sha256:%x", sha256.Sum256(raw)) }

func encodedDigest(value any) string {
	raw, err := json.Marshal(value)
	if err != nil {
		panic("artifactpreflight internal encoding: " + err.Error())
	}
	return digest(raw)
}
