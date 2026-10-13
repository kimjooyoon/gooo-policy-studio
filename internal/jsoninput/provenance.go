package jsoninput

import (
	"crypto/sha256"
	"embed"
	"encoding/hex"
	"encoding/json"
)

//go:embed strict.go provenance.go
var inputSource embed.FS

// SourceIdentity binds the actual decoder sources compiled into this binary.
// It is an implementation identity, not a signature or an authenticity claim.
func SourceIdentity() string {
	files := make(map[string]string)
	for _, name := range []string{"strict.go", "provenance.go"} {
		raw, err := inputSource.ReadFile(name)
		if err != nil {
			return ""
		}
		sum := sha256.Sum256(raw)
		files[name] = hex.EncodeToString(sum[:])
	}
	raw, _ := json.Marshal(struct {
		Domain string            `json:"domain"`
		Files  map[string]string `json:"files"`
	}{"policy-studio/strict-json-source/v1", files})
	sum := sha256.Sum256(raw)
	return "sha256:" + hex.EncodeToString(sum[:])
}
