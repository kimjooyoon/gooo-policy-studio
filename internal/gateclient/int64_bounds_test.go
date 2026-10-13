package gateclient

import (
	"encoding/json"
	"testing"

	"github.com/kimjooyoon/gooo-policy-studio/internal/artifactnumeric"
	"github.com/kimjooyoon/gooo-policy-studio/internal/artifactpreflight"
)

func TestInt64BoundsClientRederivesWholeProof(t *testing.T) {
	identity, err := artifactpreflight.CheckedSourceIdentity()
	if err != nil {
		t.Fatal(err)
	}
	producer := artifactpreflight.Report{ProducerID: artifactpreflight.NewProducerID, Identity: identity, AcquisitionStatus: artifactpreflight.ReadSuccess, DigestOK: true, SchemaOK: true, TypesOK: true}
	proof, err := artifactnumeric.Evaluate(artifactnumeric.Facts{Value: 501, Bound: 500, Operator: "lte"})
	if err != nil {
		t.Fatal(err)
	}
	claim := artifactpreflight.ClaimObservation{Verifier: artifactpreflight.Int64LTEVerifierID, Actual: "501", Expected: "500", Status: "fail", Reason: "BOUND_MISMATCH", NativeProof: &proof}
	if !validClaimObservation(claim, producer) {
		t.Fatal("valid numeric denial rejected by client consistency check")
	}
	passing, err := artifactnumeric.Evaluate(artifactnumeric.Facts{Value: 500, Bound: 500, Operator: "lte"})
	if err != nil {
		t.Fatal(err)
	}
	allowed := artifactpreflight.ClaimObservation{Verifier: artifactpreflight.Int64LTEVerifierID, Actual: "500", Expected: "500", Status: "pass", Reason: "BOUND_MATCH", NativeProof: &passing}
	if !validClaimObservation(allowed, producer) {
		t.Fatal("valid numeric match rejected by client consistency check")
	}
	equality := allowed
	equality.Verifier = artifactpreflight.VerifierID
	if validClaimObservation(equality, producer) {
		t.Fatal("numeric proof fabricated for equality claim")
	}
	for _, mutate := range []func(*artifactpreflight.ClaimObservation){
		func(c *artifactpreflight.ClaimObservation) { c.NativeProof.Decision.AtMost = true },
		func(c *artifactpreflight.ClaimObservation) { c.NativeProof.Decision.AtLeast = false },
		func(c *artifactpreflight.ClaimObservation) { c.NativeProof.Decision.OperatorOK = false },
		func(c *artifactpreflight.ClaimObservation) {
			c.NativeProof.Decision.Matched = true
			c.NativeProof.Decision.Reason = "BOUND_MATCH"
			c.Status = "pass"
			c.Reason = "BOUND_MATCH"
		},
		func(c *artifactpreflight.ClaimObservation) { c.NativeProof.Facts.Value = 500 },
		func(c *artifactpreflight.ClaimObservation) { c.NativeProof.Facts.Bound = 501 },
		func(c *artifactpreflight.ClaimObservation) { c.NativeProof.Facts.Operator = "gte" },
		func(c *artifactpreflight.ClaimObservation) { c.NativeProof.Bindings.GeneratedSHA256 = "changed" },
		func(c *artifactpreflight.ClaimObservation) { c.NativeProof = nil },
		func(c *artifactpreflight.ClaimObservation) { c.Actual = "0501" },
		func(c *artifactpreflight.ClaimObservation) { c.Expected = "+500" },
		func(c *artifactpreflight.ClaimObservation) { c.Verifier = "unknown" },
	} {
		raw, _ := json.Marshal(claim)
		var changed artifactpreflight.ClaimObservation
		if json.Unmarshal(raw, &changed) != nil {
			t.Fatal("fixture clone")
		}
		mutate(&changed)
		if validClaimObservation(changed, producer) {
			t.Fatal("forged or incomplete numeric proof accepted by client")
		}
	}
	producer.ProducerID = artifactpreflight.ProducerID
	if validClaimObservation(claim, producer) {
		t.Fatal("legacy producer presented numeric proof")
	}
	producer.ProducerID = artifactpreflight.NewProducerID
	producer.DigestOK = false
	if validClaimObservation(claim, producer) {
		t.Fatal("mandatory failure presented executed numeric proof")
	}
	claim.NativeProof = nil
	claim.Reason = "ARTIFACT_DIGEST_MISMATCH"
	if !validClaimObservation(claim, producer) {
		t.Fatal("actual mandatory denial without native proof rejected")
	}
	claim.Status = "pass"
	if validClaimObservation(claim, producer) {
		t.Fatal("mandatory failure claimed a pass")
	}
}
