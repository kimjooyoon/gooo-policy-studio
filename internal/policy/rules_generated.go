// Code generated from policy/approval.gooo by Gooo; DO NOT EDIT.
package policy

//gooo:generated:start id="policy://decision/v1" kind="entity"
type GoooRecord310f3795f70bb42930a8e3c9bccee22aa60fc9fe8c540f6e7155d6f3fbce373c struct {
	GoooFieldde873cb3dddfcb3edae5441f6049a7912cb8875bedb3fd3aeae6b8724ba6e508 bool   `json:"approved"`
	GoooFielda476416bccd75dd2631bd2a791cb5e91ace0fed5474c00b3c96d2f92401628b4 string `json:"reason"`
	GoooFieldfa971c8c460407f92dd6d4c0ca83f830e58fa43e2f43117627386c65d7024261 bool   `json:"amount_ok"`
	GoooField590470b53a4308c466be316c9d56b503f45ffaa1caaa993cebdecdae51b0b908 bool   `json:"team_ok"`
	GoooField1e8065733202c275bf0bd40412c3bd94b7a055d138d78f8e0a8b012f40273c77 bool   `json:"reviewer_ok"`
	GoooField9e1cd04bb13dc2144f4d9f78276a00a3a5e6ce55fffd2746ff4f2a0941804b00 bool   `json:"self_ok"`
	GoooField855809df0f3656ff5ce465c3d1bd7402fce1232a38e5eb3c9224ac4f9efecfe8 bool   `json:"submitted_ok"`
}

//gooo:generated:end id="policy://decision/v1" kind="entity"

//gooo:generated:start id="policy://request/v1" kind="entity"
type GoooRecord64b793f49a41ccb9c4c6d5e3046f49c6a91bacdb93a04fa32cb7bba9f2aa1d8f struct {
	GoooFieldbbde5eb8ecd4d79fbc52e2c8dcc96c65517bc3aca8a2df94b1e54056171d4a03 string `json:"key"`
	GoooField0cfd221dd40a9f2b1d16855879f8e038cd6b595a2bac8e125d8ec883f591bf89 string `json:"requester"`
	GoooFielde1392d1c93459d29decdb95131776d1590400c8fcf4d1e39c1f8a320403b056e string `json:"team"`
	GoooFieldbed4498f53bef8107ce12afb9b244e4099a376516f54b04d3c650f09687120f6 int64  `json:"amount"`
	GoooFielda668bb08290b39a6c2324df0fd50e5ebfb263673e526c9b4381c4a13927282e9 bool   `json:"submitted"`
}

//gooo:generated:end id="policy://request/v1" kind="entity"

//gooo:generated:start id="policy://reviewer/v1" kind="entity"
type GoooRecord88669270d5070ac80b1753a4fdaea64d003135b476b7981bc97226387ed99f1d struct {
	GoooField31757449b8e2a9400080714eb99bc3abe03df81dc0c6194375f3def889c55e1e string `json:"key"`
	GoooField8a408d1f6b03be9cfdd26cb03236582604f99983c92eab738a5dcf83e1d38069 string `json:"team"`
	GoooField24c75c390f6a3d4c0dc03a6a19ca77368753b32f11fa9969fab0e68556e70a24 bool   `json:"active"`
}

//gooo:generated:end id="policy://reviewer/v1" kind="entity"

//gooo:generated:start id="policy://rules/v1" kind="entity"
type GoooRecordc34a4931657b32ca064c033136702023ca8f3d1375e3378a3acfd4e3e7ca6003 struct {
	GoooFieldda4f7ae5d193df488e7f5d75e3e8db111ec1a496f729ad43bc4896a00bb8a0d5 int64 `json:"limit"`
	GoooField3bb89bec89657bf30afd4c7993baa1ba00752723dce07c8384dfe867d2ac10ca bool  `json:"same_team"`
	GoooField69a36ac1107c6d4443bb27df469e3cf4a56cc9e2e62bf923d83931a638709c5e bool  `json:"active_reviewer"`
	GoooFieldd80b4eeb255aad366eaa83234dfbeffc6cb022a78990b09c504276dfc6439b3f bool  `json:"prevent_self"`
}

//gooo:generated:end id="policy://rules/v1" kind="entity"

//gooo:generated:start id="policy://activity/evaluate" kind="activity"
func Evaluate(input0 GoooRecord64b793f49a41ccb9c4c6d5e3046f49c6a91bacdb93a04fa32cb7bba9f2aa1d8f, input1 GoooRecord88669270d5070ac80b1753a4fdaea64d003135b476b7981bc97226387ed99f1d, input2 GoooRecordc34a4931657b32ca064c033136702023ca8f3d1375e3378a3acfd4e3e7ca6003) GoooRecord310f3795f70bb42930a8e3c9bccee22aa60fc9fe8c540f6e7155d6f3fbce373c {

	var amountOK = input0.GoooFieldbed4498f53bef8107ce12afb9b244e4099a376516f54b04d3c650f09687120f6 <= input2.GoooFieldda4f7ae5d193df488e7f5d75e3e8db111ec1a496f729ad43bc4896a00bb8a0d5
	var teamOK = !input2.GoooField3bb89bec89657bf30afd4c7993baa1ba00752723dce07c8384dfe867d2ac10ca || input0.GoooFielde1392d1c93459d29decdb95131776d1590400c8fcf4d1e39c1f8a320403b056e == input1.GoooField8a408d1f6b03be9cfdd26cb03236582604f99983c92eab738a5dcf83e1d38069
	var reviewerOK = !input2.GoooField69a36ac1107c6d4443bb27df469e3cf4a56cc9e2e62bf923d83931a638709c5e || input1.GoooField24c75c390f6a3d4c0dc03a6a19ca77368753b32f11fa9969fab0e68556e70a24
	var selfOK = !input2.GoooFieldd80b4eeb255aad366eaa83234dfbeffc6cb022a78990b09c504276dfc6439b3f || input0.GoooField0cfd221dd40a9f2b1d16855879f8e038cd6b595a2bac8e125d8ec883f591bf89 != input1.GoooField31757449b8e2a9400080714eb99bc3abe03df81dc0c6194375f3def889c55e1e
	var submittedOK = input0.GoooFielda668bb08290b39a6c2324df0fd50e5ebfb263673e526c9b4381c4a13927282e9
	var approved = submittedOK && reviewerOK && selfOK && teamOK && amountOK
	var reason = "APPROVED"
	if !submittedOK {
		reason = "NOT_SUBMITTED"
	} else {
		if !reviewerOK {
			reason = "REVIEWER_INACTIVE"
		} else {
			if !selfOK {
				reason = "SELF_APPROVAL"
			} else {
				if !teamOK {
					reason = "TEAM_MISMATCH"
				} else {
					if !amountOK {
						reason = "OVER_LIMIT"
					}
				}
			}
		}
	}
	return GoooRecord310f3795f70bb42930a8e3c9bccee22aa60fc9fe8c540f6e7155d6f3fbce373c{GoooFieldde873cb3dddfcb3edae5441f6049a7912cb8875bedb3fd3aeae6b8724ba6e508: approved, GoooFielda476416bccd75dd2631bd2a791cb5e91ace0fed5474c00b3c96d2f92401628b4: reason, GoooFieldfa971c8c460407f92dd6d4c0ca83f830e58fa43e2f43117627386c65d7024261: amountOK, GoooField590470b53a4308c466be316c9d56b503f45ffaa1caaa993cebdecdae51b0b908: teamOK, GoooField1e8065733202c275bf0bd40412c3bd94b7a055d138d78f8e0a8b012f40273c77: reviewerOK, GoooField9e1cd04bb13dc2144f4d9f78276a00a3a5e6ce55fffd2746ff4f2a0941804b00: selfOK, GoooField855809df0f3656ff5ce465c3d1bd7402fce1232a38e5eb3c9224ac4f9efecfe8: submittedOK}

}

//gooo:generated:end id="policy://activity/evaluate" kind="activity"

//gooo:generated:start id="policy://change/v1" kind="entity"
type GoooRecord76d615104097c6c65ad624c83a57ec0e780038903d8ee6b2bd7569a652e508f8 struct {
	GoooField03a7ba6e844ae3bcc3da9c275345e2996698c56846c1e5db2bca10a7ead991d2 bool   `json:"changed"`
	GoooFieldb6a430b2debb72e5e85d2545386670053cf81b39b2486b9f9a368843b8a0b770 string `json:"direction"`
	GoooFieldb3d03f15ccfb33124f454e9a9546f87694a2ea7ac60a76c6d8e77a5fee4ad847 bool   `json:"reason_changed"`
}

//gooo:generated:end id="policy://change/v1" kind="entity"

//gooo:generated:start id="policy://activity/compare" kind="activity"
func Compare(input0 GoooRecord310f3795f70bb42930a8e3c9bccee22aa60fc9fe8c540f6e7155d6f3fbce373c, input1 GoooRecord310f3795f70bb42930a8e3c9bccee22aa60fc9fe8c540f6e7155d6f3fbce373c) GoooRecord76d615104097c6c65ad624c83a57ec0e780038903d8ee6b2bd7569a652e508f8 {

	var changed = input0.GoooFieldde873cb3dddfcb3edae5441f6049a7912cb8875bedb3fd3aeae6b8724ba6e508 != input1.GoooFieldde873cb3dddfcb3edae5441f6049a7912cb8875bedb3fd3aeae6b8724ba6e508
	var direction = "UNCHANGED"
	if changed {
		if input1.GoooFieldde873cb3dddfcb3edae5441f6049a7912cb8875bedb3fd3aeae6b8724ba6e508 {
			direction = "NEWLY_APPROVED"
		} else {
			direction = "NEWLY_DENIED"
		}
	}
	return GoooRecord76d615104097c6c65ad624c83a57ec0e780038903d8ee6b2bd7569a652e508f8{GoooField03a7ba6e844ae3bcc3da9c275345e2996698c56846c1e5db2bca10a7ead991d2: changed, GoooFieldb6a430b2debb72e5e85d2545386670053cf81b39b2486b9f9a368843b8a0b770: direction, GoooFieldb3d03f15ccfb33124f454e9a9546f87694a2ea7ac60a76c6d8e77a5fee4ad847: input0.GoooFielda476416bccd75dd2631bd2a791cb5e91ace0fed5474c00b3c96d2f92401628b4 != input1.GoooFielda476416bccd75dd2631bd2a791cb5e91ace0fed5474c00b3c96d2f92401628b4}

}

//gooo:generated:end id="policy://activity/compare" kind="activity"
