package artifactnumeric

import (
	"encoding/json"
	"errors"

	"github.com/kimjooyoon/gooo-policy-studio/internal/jsoninput"
)

// Evaluate obtains checked source bindings before executing Gooo. The host
// copies the native record through strict JSON transport and never compares
// Value and Bound or supplies a fallback truth value.
func Evaluate(facts Facts) (Proof, error) {
	bindings, err := SourceBindings()
	if err != nil {
		return Proof{}, err
	}
	output := Int64BoundDecision(facts.Value, facts.Bound, facts.Operator)
	raw, err := json.Marshal(output)
	if err != nil {
		return Proof{}, errors.New("numeric native transport unavailable")
	}
	var decision Decision
	if err := jsoninput.Decode(raw, &decision, 4096); err != nil {
		return Proof{}, errors.New("numeric native transport invalid")
	}
	return Proof{Facts: facts, Decision: decision, Bindings: bindings}, nil
}
