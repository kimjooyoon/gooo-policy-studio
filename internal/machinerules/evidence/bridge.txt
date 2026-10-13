// Code generated from complete Gooo record metadata; DO NOT EDIT.
package evidence

import "encoding/json"

func Evaluate(in0 []byte) ([]byte, error) {
	var a0 GoooRecord5fffa4d99b28f9b59cca3b476516da607c22de5545ab50459628ae863c8ee911
	if err := json.Unmarshal(in0, &a0); err != nil {
		return nil, err
	}
	return json.Marshal(GoooPackage2ActivityEvidenceAdmission(a0))
}
