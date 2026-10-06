// Code generated from Gooo record metadata; DO NOT EDIT.
package policy

import "encoding/json"

func evaluateNative(request Request, reviewer Reviewer, policy Rules) (Decision, error) {
	var a GoooRecord64b793f49a41ccb9c4c6d5e3046f49c6a91bacdb93a04fa32cb7bba9f2aa1d8f
	var b GoooRecord88669270d5070ac80b1753a4fdaea64d003135b476b7981bc97226387ed99f1d
	var c GoooRecordc34a4931657b32ca064c033136702023ca8f3d1375e3378a3acfd4e3e7ca6003
	if err := transport(request, &a); err != nil {
		return Decision{}, err
	}
	if err := transport(reviewer, &b); err != nil {
		return Decision{}, err
	}
	if err := transport(policy, &c); err != nil {
		return Decision{}, err
	}
	var out Decision
	err := transport(Evaluate(a, b, c), &out)
	return out, err
}
func compareNative(before, after Decision) (Change, error) {
	var a GoooRecord310f3795f70bb42930a8e3c9bccee22aa60fc9fe8c540f6e7155d6f3fbce373c
	var b GoooRecord310f3795f70bb42930a8e3c9bccee22aa60fc9fe8c540f6e7155d6f3fbce373c
	if err := transport(before, &a); err != nil {
		return Change{}, err
	}
	if err := transport(after, &b); err != nil {
		return Change{}, err
	}
	var out Change
	err := transport(Compare(a, b), &out)
	return out, err
}
func transport(in, out any) error {
	b, err := json.Marshal(in)
	if err != nil {
		return err
	}
	return json.Unmarshal(b, out)
}
