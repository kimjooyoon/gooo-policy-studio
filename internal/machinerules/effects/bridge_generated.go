// Code generated from complete Gooo record metadata; DO NOT EDIT.
package effects

import "encoding/json"

func Evaluate(in0 []byte, in1 []byte) ([]byte, error) {
	var a0 GoooRecord2a1bd27fb100df5493d42a98307645dd178dbc2bf8fff1c67eec80c875768c4c
	if err := json.Unmarshal(in0, &a0); err != nil {
		return nil, err
	}
	var a1 GoooRecord2ee720b913a01268ca8064f2c5ff6eca244cacdc535b49417b517927fd732f06
	if err := json.Unmarshal(in1, &a1); err != nil {
		return nil, err
	}
	return json.Marshal(GoooPackage0ActivityEffectBudgetAccepts(a0, a1))
}
