// Code generated from examples/completion-ledger/completion.gooo by Gooo; DO NOT EDIT.
package completion

//gooo:generated:start id="gooo://rea/completion-counts/v1" kind="entity"
type GoooRecord945e632a6326a7afa6dec046b2057c538c819fe0286879ebae4be35c24c15849 struct {
	GoooFieldcfec1396d2c33461d35beb1dd63b2a2e7ea1675f6828ec390df57425e0fd9245 int64 `json:"total"`
	GoooField47ae0efe727ae1e409f343a83ea6b6f8543617fba57e250c6e1e47c1a220e757 int64 `json:"pass"`
	GoooField3396049ea01bf09fd32d79d6598f9b135df598f29cbd8deccac87fc10b5532e4 int64 `json:"fail"`
	GoooFieldf8160ed07207cff03429aa919564fd4ef9bcd70b8d92ddd270744687e03fa51f int64 `json:"unsupported"`
	GoooField00c43916ec905a0584c32d017862f4b9d50a4e55c7994e588b95e9c5c5a4ce8e int64 `json:"truncated"`
	GoooField13dcd2e89f1e5dcad2271d70255d43cd28757dba57bdda3d5314ca1a459ebe1f int64 `json:"unknown"`
}

//gooo:generated:end id="gooo://rea/completion-counts/v1" kind="entity"

//gooo:generated:start id="gooo://rea/completion-decision/v1" kind="entity"
type GoooRecordae266d3a02ce709c9a9058f75c7b409669747cfb7d7549d38fc56266e1ea3a9c struct {
	GoooField134e3a29771d4acf2e9bfcc73e945a2ca75818e4501fa2be27bb20d2db28e190 int64  `json:"total"`
	GoooField86e55358d495aed5737aef30cb70edc649fcace8d38a17078581f0134a083606 int64  `json:"pass"`
	GoooField8956900c778f39986cba450487c8a5193bbf2aa3ea86aede06cbda9d8419e46c int64  `json:"fail"`
	GoooField40c4f08230432561e268b28cfb0f3d38b57b02c27b170a3349eab4b893568060 int64  `json:"unsupported"`
	GoooField09ac549d08904c1467c716062065988e9d1a8461833a6646fc11357920f0f11c int64  `json:"truncated"`
	GoooFieldeaecf572bce8de3157e2ef76caa01cf49ab98829f4c0c962b728b6f7d1d77233 int64  `json:"unknown"`
	GoooFieldc8ccb5ed3d5499d64538d232e84981c308637c612fb513cd0bc14bfc8c2e51a4 bool   `json:"valid"`
	GoooField11cac4269872fcd64909b040e805461e12fa6a24a71f8a11085d9c839ca09e19 bool   `json:"complete"`
	GoooFieldf8819988c07b5b5f478ca1ac0d633186a3068646ec50847ac5ee6f84f1878122 string `json:"reason"`
}

//gooo:generated:end id="gooo://rea/completion-decision/v1" kind="entity"

//gooo:generated:start id="gooo://rea/completion-step" kind="activity"
func CompletionStep(input0 GoooRecord945e632a6326a7afa6dec046b2057c538c819fe0286879ebae4be35c24c15849, input1 string) GoooRecordae266d3a02ce709c9a9058f75c7b409669747cfb7d7549d38fc56266e1ea3a9c {

	var counterOK = input0.GoooFieldcfec1396d2c33461d35beb1dd63b2a2e7ea1675f6828ec390df57425e0fd9245 >= 0 && input0.GoooField47ae0efe727ae1e409f343a83ea6b6f8543617fba57e250c6e1e47c1a220e757 >= 0 && input0.GoooField3396049ea01bf09fd32d79d6598f9b135df598f29cbd8deccac87fc10b5532e4 >= 0 && input0.GoooFieldf8160ed07207cff03429aa919564fd4ef9bcd70b8d92ddd270744687e03fa51f >= 0 && input0.GoooField00c43916ec905a0584c32d017862f4b9d50a4e55c7994e588b95e9c5c5a4ce8e >= 0 && input0.GoooField13dcd2e89f1e5dcad2271d70255d43cd28757dba57bdda3d5314ca1a459ebe1f >= 0
	var remaining = input0.GoooFieldcfec1396d2c33461d35beb1dd63b2a2e7ea1675f6828ec390df57425e0fd9245
	if counterOK {
		if input0.GoooField47ae0efe727ae1e409f343a83ea6b6f8543617fba57e250c6e1e47c1a220e757 > remaining {
			counterOK = false
		} else {
			remaining = remaining - input0.GoooField47ae0efe727ae1e409f343a83ea6b6f8543617fba57e250c6e1e47c1a220e757
		}
	}
	if counterOK {
		if input0.GoooField3396049ea01bf09fd32d79d6598f9b135df598f29cbd8deccac87fc10b5532e4 > remaining {
			counterOK = false
		} else {
			remaining = remaining - input0.GoooField3396049ea01bf09fd32d79d6598f9b135df598f29cbd8deccac87fc10b5532e4
		}
	}
	if counterOK {
		if input0.GoooFieldf8160ed07207cff03429aa919564fd4ef9bcd70b8d92ddd270744687e03fa51f > remaining {
			counterOK = false
		} else {
			remaining = remaining - input0.GoooFieldf8160ed07207cff03429aa919564fd4ef9bcd70b8d92ddd270744687e03fa51f
		}
	}
	if counterOK {
		if input0.GoooField00c43916ec905a0584c32d017862f4b9d50a4e55c7994e588b95e9c5c5a4ce8e > remaining {
			counterOK = false
		} else {
			remaining = remaining - input0.GoooField00c43916ec905a0584c32d017862f4b9d50a4e55c7994e588b95e9c5c5a4ce8e
		}
	}
	if counterOK {
		if input0.GoooField13dcd2e89f1e5dcad2271d70255d43cd28757dba57bdda3d5314ca1a459ebe1f > remaining {
			counterOK = false
		} else {
			remaining = remaining - input0.GoooField13dcd2e89f1e5dcad2271d70255d43cd28757dba57bdda3d5314ca1a459ebe1f
		}
	}
	if counterOK && remaining != 0 {
		counterOK = false
	}
	if !counterOK {
		return GoooRecordae266d3a02ce709c9a9058f75c7b409669747cfb7d7549d38fc56266e1ea3a9c{GoooField134e3a29771d4acf2e9bfcc73e945a2ca75818e4501fa2be27bb20d2db28e190: 0, GoooField86e55358d495aed5737aef30cb70edc649fcace8d38a17078581f0134a083606: 0, GoooField8956900c778f39986cba450487c8a5193bbf2aa3ea86aede06cbda9d8419e46c: 0, GoooField40c4f08230432561e268b28cfb0f3d38b57b02c27b170a3349eab4b893568060: 0, GoooField09ac549d08904c1467c716062065988e9d1a8461833a6646fc11357920f0f11c: 0, GoooFieldeaecf572bce8de3157e2ef76caa01cf49ab98829f4c0c962b728b6f7d1d77233: 0, GoooFieldc8ccb5ed3d5499d64538d232e84981c308637c612fb513cd0bc14bfc8c2e51a4: false, GoooField11cac4269872fcd64909b040e805461e12fa6a24a71f8a11085d9c839ca09e19: false, GoooFieldf8819988c07b5b5f478ca1ac0d633186a3068646ec50847ac5ee6f84f1878122: "INVALID_COUNTS"}
	}
	var statusOK = input1 == "pass" || input1 == "fail" || input1 == "unsupported" || input1 == "truncated" || input1 == "unknown"
	if !statusOK {
		return GoooRecordae266d3a02ce709c9a9058f75c7b409669747cfb7d7549d38fc56266e1ea3a9c{GoooField134e3a29771d4acf2e9bfcc73e945a2ca75818e4501fa2be27bb20d2db28e190: 0, GoooField86e55358d495aed5737aef30cb70edc649fcace8d38a17078581f0134a083606: 0, GoooField8956900c778f39986cba450487c8a5193bbf2aa3ea86aede06cbda9d8419e46c: 0, GoooField40c4f08230432561e268b28cfb0f3d38b57b02c27b170a3349eab4b893568060: 0, GoooField09ac549d08904c1467c716062065988e9d1a8461833a6646fc11357920f0f11c: 0, GoooFieldeaecf572bce8de3157e2ef76caa01cf49ab98829f4c0c962b728b6f7d1d77233: 0, GoooFieldc8ccb5ed3d5499d64538d232e84981c308637c612fb513cd0bc14bfc8c2e51a4: false, GoooField11cac4269872fcd64909b040e805461e12fa6a24a71f8a11085d9c839ca09e19: false, GoooFieldf8819988c07b5b5f478ca1ac0d633186a3068646ec50847ac5ee6f84f1878122: "INVALID_STATUS"}
	}
	if input0.GoooFieldcfec1396d2c33461d35beb1dd63b2a2e7ea1675f6828ec390df57425e0fd9245 == 9223372036854775807 {
		return GoooRecordae266d3a02ce709c9a9058f75c7b409669747cfb7d7549d38fc56266e1ea3a9c{GoooField134e3a29771d4acf2e9bfcc73e945a2ca75818e4501fa2be27bb20d2db28e190: 0, GoooField86e55358d495aed5737aef30cb70edc649fcace8d38a17078581f0134a083606: 0, GoooField8956900c778f39986cba450487c8a5193bbf2aa3ea86aede06cbda9d8419e46c: 0, GoooField40c4f08230432561e268b28cfb0f3d38b57b02c27b170a3349eab4b893568060: 0, GoooField09ac549d08904c1467c716062065988e9d1a8461833a6646fc11357920f0f11c: 0, GoooFieldeaecf572bce8de3157e2ef76caa01cf49ab98829f4c0c962b728b6f7d1d77233: 0, GoooFieldc8ccb5ed3d5499d64538d232e84981c308637c612fb513cd0bc14bfc8c2e51a4: false, GoooField11cac4269872fcd64909b040e805461e12fa6a24a71f8a11085d9c839ca09e19: false, GoooFieldf8819988c07b5b5f478ca1ac0d633186a3068646ec50847ac5ee6f84f1878122: "COUNTER_CAPACITY"}
	}

	var total = input0.GoooFieldcfec1396d2c33461d35beb1dd63b2a2e7ea1675f6828ec390df57425e0fd9245 + 1
	var passed = input0.GoooField47ae0efe727ae1e409f343a83ea6b6f8543617fba57e250c6e1e47c1a220e757
	var failed = input0.GoooField3396049ea01bf09fd32d79d6598f9b135df598f29cbd8deccac87fc10b5532e4
	var unsupported = input0.GoooFieldf8160ed07207cff03429aa919564fd4ef9bcd70b8d92ddd270744687e03fa51f
	var truncated = input0.GoooField00c43916ec905a0584c32d017862f4b9d50a4e55c7994e588b95e9c5c5a4ce8e
	var unknown = input0.GoooField13dcd2e89f1e5dcad2271d70255d43cd28757dba57bdda3d5314ca1a459ebe1f
	if input1 == "pass" {
		passed = passed + 1
	}
	if input1 == "fail" {
		failed = failed + 1
	}
	if input1 == "unsupported" {
		unsupported = unsupported + 1
	}
	if input1 == "truncated" {
		truncated = truncated + 1
	}
	if input1 == "unknown" {
		unknown = unknown + 1
	}
	return GoooRecordae266d3a02ce709c9a9058f75c7b409669747cfb7d7549d38fc56266e1ea3a9c{GoooField134e3a29771d4acf2e9bfcc73e945a2ca75818e4501fa2be27bb20d2db28e190: total, GoooField86e55358d495aed5737aef30cb70edc649fcace8d38a17078581f0134a083606: passed, GoooField8956900c778f39986cba450487c8a5193bbf2aa3ea86aede06cbda9d8419e46c: failed, GoooField40c4f08230432561e268b28cfb0f3d38b57b02c27b170a3349eab4b893568060: unsupported, GoooField09ac549d08904c1467c716062065988e9d1a8461833a6646fc11357920f0f11c: truncated, GoooFieldeaecf572bce8de3157e2ef76caa01cf49ab98829f4c0c962b728b6f7d1d77233: unknown, GoooFieldc8ccb5ed3d5499d64538d232e84981c308637c612fb513cd0bc14bfc8c2e51a4: true, GoooField11cac4269872fcd64909b040e805461e12fa6a24a71f8a11085d9c839ca09e19: passed == total, GoooFieldf8819988c07b5b5f478ca1ac0d633186a3068646ec50847ac5ee6f84f1878122: "ACCUMULATED"}

}

//gooo:generated:end id="gooo://rea/completion-step" kind="activity"

//gooo:generated:start id="gooo://rea/completion-finish" kind="activity"
func CompletionFinish(input GoooRecord945e632a6326a7afa6dec046b2057c538c819fe0286879ebae4be35c24c15849) GoooRecordae266d3a02ce709c9a9058f75c7b409669747cfb7d7549d38fc56266e1ea3a9c {

	var counterOK = input.GoooFieldcfec1396d2c33461d35beb1dd63b2a2e7ea1675f6828ec390df57425e0fd9245 >= 0 && input.GoooField47ae0efe727ae1e409f343a83ea6b6f8543617fba57e250c6e1e47c1a220e757 >= 0 && input.GoooField3396049ea01bf09fd32d79d6598f9b135df598f29cbd8deccac87fc10b5532e4 >= 0 && input.GoooFieldf8160ed07207cff03429aa919564fd4ef9bcd70b8d92ddd270744687e03fa51f >= 0 && input.GoooField00c43916ec905a0584c32d017862f4b9d50a4e55c7994e588b95e9c5c5a4ce8e >= 0 && input.GoooField13dcd2e89f1e5dcad2271d70255d43cd28757dba57bdda3d5314ca1a459ebe1f >= 0
	var remaining = input.GoooFieldcfec1396d2c33461d35beb1dd63b2a2e7ea1675f6828ec390df57425e0fd9245
	if counterOK {
		if input.GoooField47ae0efe727ae1e409f343a83ea6b6f8543617fba57e250c6e1e47c1a220e757 > remaining {
			counterOK = false
		} else {
			remaining = remaining - input.GoooField47ae0efe727ae1e409f343a83ea6b6f8543617fba57e250c6e1e47c1a220e757
		}
	}
	if counterOK {
		if input.GoooField3396049ea01bf09fd32d79d6598f9b135df598f29cbd8deccac87fc10b5532e4 > remaining {
			counterOK = false
		} else {
			remaining = remaining - input.GoooField3396049ea01bf09fd32d79d6598f9b135df598f29cbd8deccac87fc10b5532e4
		}
	}
	if counterOK {
		if input.GoooFieldf8160ed07207cff03429aa919564fd4ef9bcd70b8d92ddd270744687e03fa51f > remaining {
			counterOK = false
		} else {
			remaining = remaining - input.GoooFieldf8160ed07207cff03429aa919564fd4ef9bcd70b8d92ddd270744687e03fa51f
		}
	}
	if counterOK {
		if input.GoooField00c43916ec905a0584c32d017862f4b9d50a4e55c7994e588b95e9c5c5a4ce8e > remaining {
			counterOK = false
		} else {
			remaining = remaining - input.GoooField00c43916ec905a0584c32d017862f4b9d50a4e55c7994e588b95e9c5c5a4ce8e
		}
	}
	if counterOK {
		if input.GoooField13dcd2e89f1e5dcad2271d70255d43cd28757dba57bdda3d5314ca1a459ebe1f > remaining {
			counterOK = false
		} else {
			remaining = remaining - input.GoooField13dcd2e89f1e5dcad2271d70255d43cd28757dba57bdda3d5314ca1a459ebe1f
		}
	}
	if counterOK && remaining != 0 {
		counterOK = false
	}
	if !counterOK {
		return GoooRecordae266d3a02ce709c9a9058f75c7b409669747cfb7d7549d38fc56266e1ea3a9c{GoooField134e3a29771d4acf2e9bfcc73e945a2ca75818e4501fa2be27bb20d2db28e190: 0, GoooField86e55358d495aed5737aef30cb70edc649fcace8d38a17078581f0134a083606: 0, GoooField8956900c778f39986cba450487c8a5193bbf2aa3ea86aede06cbda9d8419e46c: 0, GoooField40c4f08230432561e268b28cfb0f3d38b57b02c27b170a3349eab4b893568060: 0, GoooField09ac549d08904c1467c716062065988e9d1a8461833a6646fc11357920f0f11c: 0, GoooFieldeaecf572bce8de3157e2ef76caa01cf49ab98829f4c0c962b728b6f7d1d77233: 0, GoooFieldc8ccb5ed3d5499d64538d232e84981c308637c612fb513cd0bc14bfc8c2e51a4: false, GoooField11cac4269872fcd64909b040e805461e12fa6a24a71f8a11085d9c839ca09e19: false, GoooFieldf8819988c07b5b5f478ca1ac0d633186a3068646ec50847ac5ee6f84f1878122: "INVALID_COUNTS"}
	}
	if input.GoooFieldcfec1396d2c33461d35beb1dd63b2a2e7ea1675f6828ec390df57425e0fd9245 == 0 {
		return GoooRecordae266d3a02ce709c9a9058f75c7b409669747cfb7d7549d38fc56266e1ea3a9c{GoooField134e3a29771d4acf2e9bfcc73e945a2ca75818e4501fa2be27bb20d2db28e190: 0, GoooField86e55358d495aed5737aef30cb70edc649fcace8d38a17078581f0134a083606: 0, GoooField8956900c778f39986cba450487c8a5193bbf2aa3ea86aede06cbda9d8419e46c: 0, GoooField40c4f08230432561e268b28cfb0f3d38b57b02c27b170a3349eab4b893568060: 0, GoooField09ac549d08904c1467c716062065988e9d1a8461833a6646fc11357920f0f11c: 0, GoooFieldeaecf572bce8de3157e2ef76caa01cf49ab98829f4c0c962b728b6f7d1d77233: 0, GoooFieldc8ccb5ed3d5499d64538d232e84981c308637c612fb513cd0bc14bfc8c2e51a4: false, GoooField11cac4269872fcd64909b040e805461e12fa6a24a71f8a11085d9c839ca09e19: false, GoooFieldf8819988c07b5b5f478ca1ac0d633186a3068646ec50847ac5ee6f84f1878122: "NO_RECORDS"}
	}
	var complete = input.GoooField47ae0efe727ae1e409f343a83ea6b6f8543617fba57e250c6e1e47c1a220e757 == input.GoooFieldcfec1396d2c33461d35beb1dd63b2a2e7ea1675f6828ec390df57425e0fd9245
	var reason = "NON_PASS_RESULTS"
	if complete {
		reason = "ALL_PASS"
	}
	return GoooRecordae266d3a02ce709c9a9058f75c7b409669747cfb7d7549d38fc56266e1ea3a9c{GoooField134e3a29771d4acf2e9bfcc73e945a2ca75818e4501fa2be27bb20d2db28e190: input.GoooFieldcfec1396d2c33461d35beb1dd63b2a2e7ea1675f6828ec390df57425e0fd9245, GoooField86e55358d495aed5737aef30cb70edc649fcace8d38a17078581f0134a083606: input.GoooField47ae0efe727ae1e409f343a83ea6b6f8543617fba57e250c6e1e47c1a220e757, GoooField8956900c778f39986cba450487c8a5193bbf2aa3ea86aede06cbda9d8419e46c: input.GoooField3396049ea01bf09fd32d79d6598f9b135df598f29cbd8deccac87fc10b5532e4, GoooField40c4f08230432561e268b28cfb0f3d38b57b02c27b170a3349eab4b893568060: input.GoooFieldf8160ed07207cff03429aa919564fd4ef9bcd70b8d92ddd270744687e03fa51f, GoooField09ac549d08904c1467c716062065988e9d1a8461833a6646fc11357920f0f11c: input.GoooField00c43916ec905a0584c32d017862f4b9d50a4e55c7994e588b95e9c5c5a4ce8e, GoooFieldeaecf572bce8de3157e2ef76caa01cf49ab98829f4c0c962b728b6f7d1d77233: input.GoooField13dcd2e89f1e5dcad2271d70255d43cd28757dba57bdda3d5314ca1a459ebe1f, GoooFieldc8ccb5ed3d5499d64538d232e84981c308637c612fb513cd0bc14bfc8c2e51a4: true, GoooField11cac4269872fcd64909b040e805461e12fa6a24a71f8a11085d9c839ca09e19: complete, GoooFieldf8819988c07b5b5f478ca1ac0d633186a3068646ec50847ac5ee6f84f1878122: reason}

}

//gooo:generated:end id="gooo://rea/completion-finish" kind="activity"

//gooo:generated:start id="gooo://automation/completion-coverage/v1" kind="entity"
type GoooRecord6549d804fcdeadde441fe8a730add1adcb6bdc98ea4a497b88f92e7af7bcf1f4 struct {
	GoooField68cd167779d9ce0e2fe1d8f5c32ba4dfe8267c1f73a64ff07d15517ffe1ebf5f int64 `json:"required_count"`
	GoooField23ce1396a5896a3c03af2fc5dcbf1a1c80b6d0e5e8297cd945b612b85e1c0126 int64 `json:"matched_count"`
	GoooFieldfaaf48b1cf0f05026e4ca8a1042099bc427d2608f8066e0db52c310359ba7bd8 int64 `json:"unexpected_count"`
	GoooField2367cffd6af31a3798418d75b85f8d00663b098f6d6e9fb4661ce6785b8ec427 int64 `json:"observed_count"`
}

//gooo:generated:end id="gooo://automation/completion-coverage/v1" kind="entity"

//gooo:generated:start id="gooo://automation/completion-readiness/v1" kind="entity"
type GoooRecord582089d1ba3f008184dd00f83bf149bff0346f4310d03ccd5290b0c5039f3abf struct {
	GoooField0e05a1691a6c4fcaa5a1e93b5f49319a59b1b0f0f0eb2d0be5643b02ae2dc51d bool   `json:"ready"`
	GoooField3175a1ea97cfa3d1fa09562f3a38a65e0933c4373f956b63fd7b7f37d2f1f5f1 string `json:"reason"`
	GoooFieldb0440cbcb2d132b60a2c6031eba7aa2a3b5a915097d6f4f24cc19e04790bf0f5 bool   `json:"counts_ok"`
	GoooField06276e6f3b803e9ddd97e5b8759861fce525c1094bf633f0141fc3a800ea5000 bool   `json:"coverage_ok"`
	GoooField899aa64a7caec49fe933c833b3858e7c86b9798beabc752dcfd17dd36122f159 bool   `json:"summary_ok"`
	GoooField93d152c9b86fc2de5477a4ccd70cf53417c7958b22ebdfeac43edf99fd14c756 bool   `json:"all_pass_ok"`
}

//gooo:generated:end id="gooo://automation/completion-readiness/v1" kind="entity"

//gooo:generated:start id="gooo://automation/completion-ready" kind="activity"
func CompletionReady(input0 GoooRecordae266d3a02ce709c9a9058f75c7b409669747cfb7d7549d38fc56266e1ea3a9c, input1 GoooRecord6549d804fcdeadde441fe8a730add1adcb6bdc98ea4a497b88f92e7af7bcf1f4) GoooRecord582089d1ba3f008184dd00f83bf149bff0346f4310d03ccd5290b0c5039f3abf {

	var counterOK = input0.GoooField134e3a29771d4acf2e9bfcc73e945a2ca75818e4501fa2be27bb20d2db28e190 >= 0 && input0.GoooField86e55358d495aed5737aef30cb70edc649fcace8d38a17078581f0134a083606 >= 0 && input0.GoooField8956900c778f39986cba450487c8a5193bbf2aa3ea86aede06cbda9d8419e46c >= 0 && input0.GoooField40c4f08230432561e268b28cfb0f3d38b57b02c27b170a3349eab4b893568060 >= 0 && input0.GoooField09ac549d08904c1467c716062065988e9d1a8461833a6646fc11357920f0f11c >= 0 && input0.GoooFieldeaecf572bce8de3157e2ef76caa01cf49ab98829f4c0c962b728b6f7d1d77233 >= 0
	var remaining = input0.GoooField134e3a29771d4acf2e9bfcc73e945a2ca75818e4501fa2be27bb20d2db28e190
	if counterOK {
		if input0.GoooField86e55358d495aed5737aef30cb70edc649fcace8d38a17078581f0134a083606 > remaining {
			counterOK = false
		} else {
			remaining = remaining - input0.GoooField86e55358d495aed5737aef30cb70edc649fcace8d38a17078581f0134a083606
		}
	}
	if counterOK {
		if input0.GoooField8956900c778f39986cba450487c8a5193bbf2aa3ea86aede06cbda9d8419e46c > remaining {
			counterOK = false
		} else {
			remaining = remaining - input0.GoooField8956900c778f39986cba450487c8a5193bbf2aa3ea86aede06cbda9d8419e46c
		}
	}
	if counterOK {
		if input0.GoooField40c4f08230432561e268b28cfb0f3d38b57b02c27b170a3349eab4b893568060 > remaining {
			counterOK = false
		} else {
			remaining = remaining - input0.GoooField40c4f08230432561e268b28cfb0f3d38b57b02c27b170a3349eab4b893568060
		}
	}
	if counterOK {
		if input0.GoooField09ac549d08904c1467c716062065988e9d1a8461833a6646fc11357920f0f11c > remaining {
			counterOK = false
		} else {
			remaining = remaining - input0.GoooField09ac549d08904c1467c716062065988e9d1a8461833a6646fc11357920f0f11c
		}
	}
	if counterOK {
		if input0.GoooFieldeaecf572bce8de3157e2ef76caa01cf49ab98829f4c0c962b728b6f7d1d77233 > remaining {
			counterOK = false
		} else {
			remaining = remaining - input0.GoooFieldeaecf572bce8de3157e2ef76caa01cf49ab98829f4c0c962b728b6f7d1d77233
		}
	}
	if counterOK && remaining != 0 {
		counterOK = false
	}
	var coverageFactsOK = input1.GoooField68cd167779d9ce0e2fe1d8f5c32ba4dfe8267c1f73a64ff07d15517ffe1ebf5f > 0 && input1.GoooField23ce1396a5896a3c03af2fc5dcbf1a1c80b6d0e5e8297cd945b612b85e1c0126 >= 0 && input1.GoooFieldfaaf48b1cf0f05026e4ca8a1042099bc427d2608f8066e0db52c310359ba7bd8 >= 0 && input1.GoooField2367cffd6af31a3798418d75b85f8d00663b098f6d6e9fb4661ce6785b8ec427 >= 0 && input1.GoooField23ce1396a5896a3c03af2fc5dcbf1a1c80b6d0e5e8297cd945b612b85e1c0126 <= input1.GoooField68cd167779d9ce0e2fe1d8f5c32ba4dfe8267c1f73a64ff07d15517ffe1ebf5f && input1.GoooField2367cffd6af31a3798418d75b85f8d00663b098f6d6e9fb4661ce6785b8ec427 >= input1.GoooField23ce1396a5896a3c03af2fc5dcbf1a1c80b6d0e5e8297cd945b612b85e1c0126
	if coverageFactsOK {
		coverageFactsOK = input1.GoooField2367cffd6af31a3798418d75b85f8d00663b098f6d6e9fb4661ce6785b8ec427-input1.GoooField23ce1396a5896a3c03af2fc5dcbf1a1c80b6d0e5e8297cd945b612b85e1c0126 == input1.GoooFieldfaaf48b1cf0f05026e4ca8a1042099bc427d2608f8066e0db52c310359ba7bd8
	}
	var countsOK = counterOK && coverageFactsOK
	var coverageOK = coverageFactsOK && input1.GoooField23ce1396a5896a3c03af2fc5dcbf1a1c80b6d0e5e8297cd945b612b85e1c0126 == input1.GoooField68cd167779d9ce0e2fe1d8f5c32ba4dfe8267c1f73a64ff07d15517ffe1ebf5f && input1.GoooFieldfaaf48b1cf0f05026e4ca8a1042099bc427d2608f8066e0db52c310359ba7bd8 == 0
	var summaryOK = input0.GoooFieldc8ccb5ed3d5499d64538d232e84981c308637c612fb513cd0bc14bfc8c2e51a4 && input0.GoooField134e3a29771d4acf2e9bfcc73e945a2ca75818e4501fa2be27bb20d2db28e190 > 0 && input0.GoooField134e3a29771d4acf2e9bfcc73e945a2ca75818e4501fa2be27bb20d2db28e190 == input1.GoooField2367cffd6af31a3798418d75b85f8d00663b098f6d6e9fb4661ce6785b8ec427 && input0.GoooField11cac4269872fcd64909b040e805461e12fa6a24a71f8a11085d9c839ca09e19 == (input0.GoooField86e55358d495aed5737aef30cb70edc649fcace8d38a17078581f0134a083606 == input0.GoooField134e3a29771d4acf2e9bfcc73e945a2ca75818e4501fa2be27bb20d2db28e190)
	var allPassOK = counterOK && input0.GoooField134e3a29771d4acf2e9bfcc73e945a2ca75818e4501fa2be27bb20d2db28e190 > 0 && input0.GoooField86e55358d495aed5737aef30cb70edc649fcace8d38a17078581f0134a083606 == input0.GoooField134e3a29771d4acf2e9bfcc73e945a2ca75818e4501fa2be27bb20d2db28e190 && input0.GoooField11cac4269872fcd64909b040e805461e12fa6a24a71f8a11085d9c839ca09e19
	var ready = countsOK && coverageOK && summaryOK && allPassOK
	var reason = "READY"
	if !countsOK {
		reason = "INVALID_COUNTS"
	} else {
		if !coverageOK {
			reason = "INCOMPLETE_CLAIM_COVERAGE"
		} else {
			if !summaryOK {
				reason = "INVALID_COMPLETION_SUMMARY"
			} else {
				if !allPassOK {
					reason = "NON_PASS_RESULTS"
				}
			}
		}
	}
	return GoooRecord582089d1ba3f008184dd00f83bf149bff0346f4310d03ccd5290b0c5039f3abf{GoooField0e05a1691a6c4fcaa5a1e93b5f49319a59b1b0f0f0eb2d0be5643b02ae2dc51d: ready, GoooField3175a1ea97cfa3d1fa09562f3a38a65e0933c4373f956b63fd7b7f37d2f1f5f1: reason, GoooFieldb0440cbcb2d132b60a2c6031eba7aa2a3b5a915097d6f4f24cc19e04790bf0f5: countsOK, GoooField06276e6f3b803e9ddd97e5b8759861fce525c1094bf633f0141fc3a800ea5000: coverageOK, GoooField899aa64a7caec49fe933c833b3858e7c86b9798beabc752dcfd17dd36122f159: summaryOK, GoooField93d152c9b86fc2de5477a4ccd70cf53417c7958b22ebdfeac43edf99fd14c756: allPassOK}

}

//gooo:generated:end id="gooo://automation/completion-ready" kind="activity"
