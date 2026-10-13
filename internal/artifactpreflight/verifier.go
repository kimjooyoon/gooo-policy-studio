package artifactpreflight

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"reflect"

	"github.com/kimjooyoon/gooo-policy-studio/internal/artifactnumeric"
	"github.com/kimjooyoon/gooo-policy-studio/internal/jsoninput"
)

// Observe accepts only an opaque acquisition from the built-in reader. The host
// samples observationUnix after acquisition; callers cannot replace the recipe.
func (p *Producer) Observe(a Acquisition, expectedSHA256, contextDigest string, observationUnix int64) (Report, error) {
	if p == nil {
		return Report{}, fmt.Errorf("artifact producer is nil")
	}
	if err := ValidateRecipe(p.recipe); err != nil {
		return Report{}, err
	}
	if !validDigest(expectedSHA256) || !validDigest(contextDigest) || observationUnix <= 0 {
		return Report{}, fmt.Errorf("artifact expected digest, context digest or trusted observation time is invalid")
	}
	if a.expectedSHA != expectedSHA256 || a.maxBytes != p.recipe.MaxBytes {
		return Report{}, fmt.Errorf("acquisition does not match operator requirement or recipe limit")
	}
	if err := validateAcquisition(a); err != nil {
		return Report{}, err
	}
	owned := append([]byte{}, a.raw...)
	identity, err := CheckedSourceIdentity()
	if err != nil {
		return Report{}, err
	}
	r := Report{
		Schema: ReportSchema, ProducerID: p.recipe.ProducerID, Identity: identity,
		RecipeSHA256: encodedDigest(p.recipe), ExpectedSHA256: expectedSHA256,
		ContextDigest: contextDigest, ObservationUnix: observationUnix,
		AcquisitionStatus: a.status, ArtifactBase64: base64.StdEncoding.EncodeToString(owned),
		ActualSHA256: digest(owned), ByteCount: int64(len(owned)), ObservedSize: a.observedSize,
		Observations: make([]ClaimObservation, 0, len(p.recipe.Claims)),
	}
	values, schemaOK, typesOK, parseReason := parseArtifact(p.recipe, owned)
	r.SchemaOK, r.TypesOK = schemaOK, typesOK
	r.DigestOK = a.status == ReadSuccess && len(owned) > 0 && int64(len(owned)) <= p.recipe.MaxBytes && r.ActualSHA256 == expectedSHA256
	status := "fail"
	switch {
	case a.status == ReadError:
		status, r.ArtifactReason = "unknown", "ARTIFACT_READ_ERROR"
	case a.status == Skipped:
		status, r.ArtifactReason = "unknown", "ARTIFACT_READ_SKIPPED"
	case a.status == Oversized:
		status, r.ArtifactReason = "truncated", "ARTIFACT_OVERSIZED"
	case len(owned) == 0:
		r.ArtifactReason = "EMPTY_ARTIFACT"
	case !r.DigestOK:
		r.ArtifactReason = "ARTIFACT_DIGEST_MISMATCH"
	case !schemaOK || !typesOK:
		r.ArtifactReason = parseReason
	default:
		r.ArtifactReason = "ARTIFACT_VERIFIED"
	}
	// A single content-bound base digest avoids repeatedly encoding the retained
	// bytes per claim. Each claim additionally binds its ordered predicate/result.
	baseDigest := encodedDigest(struct {
		Domain string `json:"domain"`
		Report Report `json:"report"`
	}{"policy-studio/artifact-observation-base/v1", r})
	for _, claim := range p.recipe.Claims {
		o := ClaimObservation{ClaimID: claim.ID, Verifier: claim.Verifier, Field: claim.Field, Expected: claim.Expected, Actual: values[claim.Field], Status: status, Reason: r.ArtifactReason}
		if r.DigestOK && r.SchemaOK && r.TypesOK && a.status == ReadSuccess {
			switch claim.Verifier {
			case VerifierID:
				if o.Actual == claim.Expected {
					o.Status, o.Reason = "pass", "FIELD_EQUALS"
				} else {
					o.Status, o.Reason = "fail", "FIELD_MISMATCH"
				}
			case Int64LTEVerifierID, Int64GTEVerifierID:
				actual, okActual := canonicalInteger(o.Actual)
				bound, okBound := canonicalInteger(claim.Expected)
				if !okActual || !okBound {
					return Report{}, fmt.Errorf("numeric predicate facts are not canonical int64")
				}
				operator := artifactnumeric.LTE
				if claim.Verifier == Int64GTEVerifierID {
					operator = artifactnumeric.GTE
				}
				proof, err := artifactnumeric.Evaluate(artifactnumeric.Facts{Value: actual, Bound: bound, Operator: operator})
				if err != nil {
					return Report{}, err
				}
				o.NativeProof = &proof
				o.Status, o.Reason = "fail", proof.Decision.Reason
				if proof.Decision.OperatorOK && proof.Decision.Matched {
					o.Status = "pass"
				}
			default:
				return Report{}, fmt.Errorf("unknown configured predicate")
			}
		}
		claimDigest := encodedDigest(struct {
			Domain      string           `json:"domain"`
			BaseSHA256  string           `json:"base_sha256"`
			Observation ClaimObservation `json:"observation"`
		}{"policy-studio/artifact-claim/v1", baseDigest, o})
		o.EvidenceID = "ev_" + claimDigest[7:]
		r.Observations = append(r.Observations, o)
	}
	return r, nil
}

func validateAcquisition(a Acquisition) error {
	if a.maxBytes < 1 || a.maxBytes > MaxBytes || len(a.raw) > int(a.maxBytes+1) {
		return fmt.Errorf("invalid acquisition byte bound")
	}
	switch a.status {
	case ReadSuccess:
		if int64(len(a.raw)) > a.maxBytes || a.observedSize != int64(len(a.raw)) {
			return fmt.Errorf("incoherent successful acquisition")
		}
	case ReadError:
		if len(a.raw) != 0 || a.observedSize < -1 {
			return fmt.Errorf("incoherent failed acquisition")
		}
	case Skipped:
		if len(a.raw) != 0 || a.observedSize != -1 {
			return fmt.Errorf("incoherent skipped acquisition")
		}
	case Oversized:
		// Some virtual regular files report zero metadata size. Either the
		// metadata alone exceeded the bound, or an actual maxBytes+1 prefix did.
		if a.observedSize < 0 || !(len(a.raw) == 0 && a.observedSize > a.maxBytes || int64(len(a.raw)) == a.maxBytes+1) {
			return fmt.Errorf("incoherent oversized acquisition")
		}
	default:
		return fmt.Errorf("unknown acquisition status")
	}
	return nil
}

// Replay uses current operator recipe/digests and retained bytes, never opens
// the original artifact path. This is host consistency, not authentication of a
// report's publisher or an externally signed assertion.
func Replay(recipe Recipe, expectedSHA256, contextDigest string, saved Report) (Report, error) {
	p, err := New(recipe)
	if err != nil {
		return Report{}, err
	}
	if saved.Schema != ReportSchema || len(saved.ArtifactBase64) > int(((recipe.MaxBytes+1)+2)/3*4) {
		return Report{}, fmt.Errorf("invalid retained artifact encoding or report schema")
	}
	raw, err := base64.StdEncoding.Strict().DecodeString(saved.ArtifactBase64)
	if err != nil || base64.StdEncoding.EncodeToString(raw) != saved.ArtifactBase64 {
		return Report{}, fmt.Errorf("retained artifact is not canonical base64")
	}
	a := Acquisition{saved.AcquisitionStatus, append([]byte{}, raw...), expectedSHA256, recipe.MaxBytes, saved.ObservedSize}
	current, err := p.Observe(a, expectedSHA256, contextDigest, saved.ObservationUnix)
	if err != nil {
		return Report{}, err
	}
	if !reflect.DeepEqual(saved, current) {
		return Report{}, fmt.Errorf("artifact report differs from current recipe, source identity, bindings or actual retained-byte observations")
	}
	return current, nil
}

func parseArtifact(recipe Recipe, raw []byte) (map[string]string, bool, bool, string) {
	values := make(map[string]string, len(recipe.Fields))
	if len(raw) == 0 || int64(len(raw)) > recipe.MaxBytes {
		return values, false, false, "INVALID_ARTIFACT_SIZE"
	}
	if err := jsoninput.Validate(raw, reflect.TypeOf(map[string]json.RawMessage{})); err != nil {
		return values, false, false, "INVALID_ARTIFACT_JSON"
	}
	var object map[string]json.RawMessage
	if err := json.Unmarshal(raw, &object); err != nil || object == nil {
		return values, false, false, "INVALID_ARTIFACT_OBJECT"
	}
	var schema string
	schemaOK := json.Unmarshal(object["schema"], &schema) == nil && schema == recipe.ArtifactSchema && len(object) == len(recipe.Fields)+1
	typesOK := true
	for _, field := range recipe.Fields {
		value, ok := object[field.Name]
		if !ok {
			schemaOK, typesOK = false, false
			continue
		}
		canonical, ok := scalar(value, field.Type)
		if !ok {
			typesOK = false
			continue
		}
		values[field.Name] = canonical
	}
	if !schemaOK {
		return values, false, typesOK, "ARTIFACT_SCHEMA_MISMATCH"
	}
	if !typesOK {
		return values, true, false, "ARTIFACT_TYPE_MISMATCH"
	}
	return values, true, true, "ARTIFACT_VERIFIED"
}

func scalar(raw json.RawMessage, t string) (string, bool) {
	raw = bytes.TrimSpace(raw)
	if len(raw) == 0 || bytes.Equal(raw, []byte("null")) {
		return "", false
	}
	switch t {
	case "text":
		var v string
		if err := json.Unmarshal(raw, &v); err != nil {
			return "", false
		}
		return v, true
	case "bool":
		if bytes.Equal(raw, []byte("true")) || bytes.Equal(raw, []byte("false")) {
			return string(raw), true
		}
	case "int64":
		if _, ok := canonicalInteger(string(raw)); ok {
			return string(raw), true
		}
	}
	return "", false
}
