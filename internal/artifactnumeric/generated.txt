// Code generated from internal/artifactnumeric/source.gooo by Gooo; DO NOT EDIT.
package artifactnumeric

//gooo:generated:start id="gooo://artifact/int64-bound-decision/v1" kind="entity"
type GoooRecorda828a9c833799c0a95671dece71c4a16e5b14c995de83a7c24cb2db6e682df0a struct {
	GoooFieldce07e767b7029fa557328dff452debf3104fde1c3532a86f890932c60004ffb5 bool   `json:"at_most"`
	GoooField3bf66a21a6415778ac860ba1acb9d9048e17df8fa19b56c4e383991d82a3b405 bool   `json:"at_least"`
	GoooFieldd066eb081a73250edeab362c1638991a07f1ca6d0441f34366739c02ae517489 bool   `json:"operator_ok"`
	GoooField196e00b52f6e95503ae8dc979fdcaa7baf0d488684e2a4cf71c1d5fa5ff2fcd7 bool   `json:"matched"`
	GoooField934ebdc43a6dd0270d3d46b80f94b17494d9c4b639c371bca90ce8cf41c0e1c9 string `json:"reason"`
}

//gooo:generated:end id="gooo://artifact/int64-bound-decision/v1" kind="entity"
//gooo:generated:start id="gooo://artifact/int64-bound-decision" kind="activity"
func Int64BoundDecision(input0 int64, input1 int64, input2 string) GoooRecorda828a9c833799c0a95671dece71c4a16e5b14c995de83a7c24cb2db6e682df0a {

	var atMost = input0 <= input1
	var atLeast = input0 >= input1
	var operatorOK = input2 == "lte" || input2 == "gte"
	var matched = false
	if input2 == "lte" {
		matched = atMost
	}
	if input2 == "gte" {
		matched = atLeast
	}
	var reason = "UNSUPPORTED_OPERATOR"
	if operatorOK {
		reason = "BOUND_MISMATCH"
		if matched {
			reason = "BOUND_MATCH"
		}
	}
	return GoooRecorda828a9c833799c0a95671dece71c4a16e5b14c995de83a7c24cb2db6e682df0a{GoooFieldce07e767b7029fa557328dff452debf3104fde1c3532a86f890932c60004ffb5: atMost, GoooField3bf66a21a6415778ac860ba1acb9d9048e17df8fa19b56c4e383991d82a3b405: atLeast, GoooFieldd066eb081a73250edeab362c1638991a07f1ca6d0441f34366739c02ae517489: operatorOK, GoooField196e00b52f6e95503ae8dc979fdcaa7baf0d488684e2a4cf71c1d5fa5ff2fcd7: matched, GoooField934ebdc43a6dd0270d3d46b80f94b17494d9c4b639c371bca90ce8cf41c0e1c9: reason}

}

//gooo:generated:end id="gooo://artifact/int64-bound-decision" kind="activity"
