// Code generated from complete Gooo record metadata; DO NOT EDIT.
package final

import "encoding/json"

func Evaluate(in0 []byte) ([]byte, error) {
	var a0 GoooRecord02a1eeabb96966ca5870881c57356132b044ed80de5e70cf7133c6a31af56025
	if err := json.Unmarshal(in0, &a0); err != nil {
		return nil, err
	}
	return json.Marshal(ArtifactGateAdmits(a0))
}
