// Code generated from Gooo record metadata; DO NOT EDIT.
package completion

import "encoding/json"

func stepNative(counts Counts, status string) (Decision, error) {
	var a GoooRecord945e632a6326a7afa6dec046b2057c538c819fe0286879ebae4be35c24c15849
	if err := transport(counts, &a); err != nil {
		return Decision{}, err
	}
	var out Decision
	err := transport(CompletionStep(a, status), &out)
	return out, err
}
func finishNative(counts Counts) (Decision, error) {
	var a GoooRecord945e632a6326a7afa6dec046b2057c538c819fe0286879ebae4be35c24c15849
	if err := transport(counts, &a); err != nil {
		return Decision{}, err
	}
	var out Decision
	err := transport(CompletionFinish(a), &out)
	return out, err
}
func readyNative(summary Decision, coverage Coverage) (Readiness, error) {
	var a GoooRecordae266d3a02ce709c9a9058f75c7b409669747cfb7d7549d38fc56266e1ea3a9c
	var b GoooRecord6549d804fcdeadde441fe8a730add1adcb6bdc98ea4a497b88f92e7af7bcf1f4
	if err := transport(summary, &a); err != nil {
		return Readiness{}, err
	}
	if err := transport(coverage, &b); err != nil {
		return Readiness{}, err
	}
	var out Readiness
	err := transport(CompletionReady(a, b), &out)
	return out, err
}
func transport(in, out any) error {
	b, err := json.Marshal(in)
	if err != nil {
		return err
	}
	return json.Unmarshal(b, out)
}
