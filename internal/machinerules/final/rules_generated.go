package final

//gooo:generated:start id="gooo://artifact-gate/admission-decision/v1" kind="entity"
type GoooRecord1e91235088ed76dd3c2e0d3defd655574ee9439b87b0abb02052868ca8a8a1bf struct {
	GoooFieldcb4069c51ae5c4ad01d1861435275581b543b32ff6a4dfc9f72b9d287ca9e0c2 bool   `json:"admitted"`
	GoooField84b438eef8645f3769b766d33377718797996253c1aede61b3080ef83193962c string `json:"reason"`
	GoooField7637c97d171473304df679f85972fbf515fc42ba9de2e45dcd4a84d016917da9 bool   `json:"counts_ok"`
	GoooFieldd17eca20a68e30fbbca32998ea843148790b99baa7131cdcdfea8acc7b99dcc9 bool   `json:"provenance_ok"`
	GoooField35ee45ceb443f5e3fb943454c983aebb6d22b7814c576f8fa6bc669573ccc27f bool   `json:"base_policy_ok"`
	GoooFieldc02a374fe5ea5cea3301af4822cb9d69626edbcadf28b659a868c2e3db39ee6c bool   `json:"evidence_ok"`
	GoooField19e8d7759e1cb8eb280ffa860080a238a909e83d24a16a56dd21f66e00096159 bool   `json:"completion_ok"`
	GoooField6500bb72e32788e2580f65a5870ad7ca8bd473c9ede1c7752ea22d5343f9a0bf bool   `json:"approval_effect_ok"`
	GoooField1c5f636c67481d4340b87fd1899b23a3125f8555257cf7089914d24760619e0c bool   `json:"control_plane_effect_ok"`
}

//gooo:generated:end id="gooo://artifact-gate/admission-decision/v1" kind="entity"
//gooo:generated:start id="gooo://artifact-gate/admission-facts/v1" kind="entity"
type GoooRecord02a1eeabb96966ca5870881c57356132b044ed80de5e70cf7133c6a31af56025 struct {
	GoooFielded28835c68ababd15c364c57e8a4bdc577599e949dc772f8a80994d296dbdb94 bool  `json:"provenance_ok"`
	GoooField2cc7f13e0ef9b8855e1c785d9d402c896b48927888bb1b05242a1edbaf1d2b56 bool  `json:"base_policy_approved"`
	GoooField237d2d6d580cc776ff9da089676726384540974f707098913f7cc3d3c5150d1e int64 `json:"required_count"`
	GoooField2df86e449d99ee8dbd51a72da69ae753694c9cc01e51da8d4d2a31e539ab9669 int64 `json:"observed_count"`
	GoooField056d76d6065421c5f4f3ad1a78e147b0dd508dd493dfedc81217417b536c7109 int64 `json:"admissible_evidence_count"`
	GoooField2edd4f7c9d33d8bec68808ded3eabf50195a8191bafaae8128533785bd9e175a bool  `json:"completion_ready"`
	GoooFieldd3e82411fff7c8701303c30a526919d52d382e7287d7a5181db5cd4e9b817ae3 bool  `json:"approval_effect_admissible"`
	GoooField44d72a204300e62f0adad158fc96457fdd07e11121a069774c49cd6e4f3c0862 bool  `json:"control_plane_effect_admissible"`
}

//gooo:generated:end id="gooo://artifact-gate/admission-facts/v1" kind="entity"
//gooo:generated:start id="gooo://artifact-gate/admits/v1" kind="activity"
func ArtifactGateAdmits(input GoooRecord02a1eeabb96966ca5870881c57356132b044ed80de5e70cf7133c6a31af56025) GoooRecord1e91235088ed76dd3c2e0d3defd655574ee9439b87b0abb02052868ca8a8a1bf {

	var countsOK = input.GoooField237d2d6d580cc776ff9da089676726384540974f707098913f7cc3d3c5150d1e >= 1 && input.GoooField237d2d6d580cc776ff9da089676726384540974f707098913f7cc3d3c5150d1e <= 256 && input.GoooField2df86e449d99ee8dbd51a72da69ae753694c9cc01e51da8d4d2a31e539ab9669 >= 0 && input.GoooField2df86e449d99ee8dbd51a72da69ae753694c9cc01e51da8d4d2a31e539ab9669 <= 256 && input.GoooField056d76d6065421c5f4f3ad1a78e147b0dd508dd493dfedc81217417b536c7109 >= 0 && input.GoooField056d76d6065421c5f4f3ad1a78e147b0dd508dd493dfedc81217417b536c7109 <= input.GoooField2df86e449d99ee8dbd51a72da69ae753694c9cc01e51da8d4d2a31e539ab9669
	var evidenceOK = countsOK && input.GoooField2df86e449d99ee8dbd51a72da69ae753694c9cc01e51da8d4d2a31e539ab9669 == input.GoooField237d2d6d580cc776ff9da089676726384540974f707098913f7cc3d3c5150d1e && input.GoooField056d76d6065421c5f4f3ad1a78e147b0dd508dd493dfedc81217417b536c7109 == input.GoooField2df86e449d99ee8dbd51a72da69ae753694c9cc01e51da8d4d2a31e539ab9669
	var admitted = countsOK && input.GoooFielded28835c68ababd15c364c57e8a4bdc577599e949dc772f8a80994d296dbdb94 && input.GoooField2cc7f13e0ef9b8855e1c785d9d402c896b48927888bb1b05242a1edbaf1d2b56 && evidenceOK && input.GoooField2edd4f7c9d33d8bec68808ded3eabf50195a8191bafaae8128533785bd9e175a && input.GoooFieldd3e82411fff7c8701303c30a526919d52d382e7287d7a5181db5cd4e9b817ae3 && input.GoooField44d72a204300e62f0adad158fc96457fdd07e11121a069774c49cd6e4f3c0862
	var reason = "ADMITTED"
	if !countsOK {
		reason = "INVALID_COUNTS"
	} else {
		if !input.GoooFielded28835c68ababd15c364c57e8a4bdc577599e949dc772f8a80994d296dbdb94 {
			reason = "PROVENANCE_MISMATCH"
		} else {
			if !input.GoooField44d72a204300e62f0adad158fc96457fdd07e11121a069774c49cd6e4f3c0862 {
				reason = "CONTROL_PLANE_EFFECT_DISALLOWED"
			} else {
				if !input.GoooField2cc7f13e0ef9b8855e1c785d9d402c896b48927888bb1b05242a1edbaf1d2b56 {
					reason = "BASE_POLICY_DENIED"
				} else {
					if !evidenceOK {
						reason = "EVIDENCE_REJECTED"
					} else {
						if !input.GoooField2edd4f7c9d33d8bec68808ded3eabf50195a8191bafaae8128533785bd9e175a {
							reason = "CLAIMS_NOT_COMPLETE"
						} else {
							if !input.GoooFieldd3e82411fff7c8701303c30a526919d52d382e7287d7a5181db5cd4e9b817ae3 {
								reason = "OPERATION_EFFECT_DISALLOWED"
							}
						}
					}
				}
			}
		}
	}
	return GoooRecord1e91235088ed76dd3c2e0d3defd655574ee9439b87b0abb02052868ca8a8a1bf{GoooFieldcb4069c51ae5c4ad01d1861435275581b543b32ff6a4dfc9f72b9d287ca9e0c2: admitted, GoooField84b438eef8645f3769b766d33377718797996253c1aede61b3080ef83193962c: reason, GoooField7637c97d171473304df679f85972fbf515fc42ba9de2e45dcd4a84d016917da9: countsOK, GoooFieldd17eca20a68e30fbbca32998ea843148790b99baa7131cdcdfea8acc7b99dcc9: input.GoooFielded28835c68ababd15c364c57e8a4bdc577599e949dc772f8a80994d296dbdb94, GoooField35ee45ceb443f5e3fb943454c983aebb6d22b7814c576f8fa6bc669573ccc27f: input.GoooField2cc7f13e0ef9b8855e1c785d9d402c896b48927888bb1b05242a1edbaf1d2b56, GoooFieldc02a374fe5ea5cea3301af4822cb9d69626edbcadf28b659a868c2e3db39ee6c: evidenceOK, GoooField19e8d7759e1cb8eb280ffa860080a238a909e83d24a16a56dd21f66e00096159: input.GoooField2edd4f7c9d33d8bec68808ded3eabf50195a8191bafaae8128533785bd9e175a, GoooField6500bb72e32788e2580f65a5870ad7ca8bd473c9ede1c7752ea22d5343f9a0bf: input.GoooFieldd3e82411fff7c8701303c30a526919d52d382e7287d7a5181db5cd4e9b817ae3, GoooField1c5f636c67481d4340b87fd1899b23a3125f8555257cf7089914d24760619e0c: input.GoooField44d72a204300e62f0adad158fc96457fdd07e11121a069774c49cd6e4f3c0862}

}

//gooo:generated:end id="gooo://artifact-gate/admits/v1" kind="activity"
