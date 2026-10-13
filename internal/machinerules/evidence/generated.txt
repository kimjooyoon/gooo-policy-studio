package evidence

//gooo:generated:start id="gooo://evidence/admission-decision/v1" kind="entity"
type GoooRecordf8f2dfd8e18fbecc01d27e037a375c52c9e207994c5efb486734f9d2fefe0681 struct {
	GoooFieldece08fae0c0be6f079609f2c93a17939eef0d134dd5c2e49dbb5f77439879706 bool   `json:"admissible"`
	GoooField165006c7850615b592826ac11dd77bc4e9d96ed88aaca7f02c0cab912ba2fbf1 string `json:"reason"`
	GoooFieldbd61b46cfe6b094a7aae95cdc3f957a52489c7e017b272fe3e3db51b6bbf93f9 bool   `json:"provider_ok"`
	GoooField6aa9d384faef399a1d2d3b93c7ff12c705353fab38a364c55411d3acdc5e2e4d bool   `json:"evidence_ok"`
	GoooField9452d72eb1153f15ccff157d9ded95d1c91b72153806b2d5102bc0e3cf83ccdb bool   `json:"authority_ok"`
	GoooField8b48ba2d3ad6878d6b11caad150062fa06efe8576fb2fb23822873fcf4145f0f bool   `json:"binding_ok"`
	GoooField954e5041a8aebe0b23bf5283e1e216be4162a53f6ed892dc1f13c7a5c2452171 bool   `json:"artifact_ok"`
	GoooField39a905e09c4c9b0e97ec80451fdc8dd677200bce08045cb351fdd057df920b55 bool   `json:"policy_ok"`
	GoooFieldae58be9986d9d9196bba7398103cdd01d3e1b4a059013cc07813d9db385ca40f bool   `json:"freshness_ok"`
	GoooField21713b659cfe5f93499c66e2b67e11b6911ba99e92a622a19d3bce02b0c5d184 bool   `json:"deadline_ok"`
}

//gooo:generated:end id="gooo://evidence/admission-decision/v1" kind="entity"
//gooo:generated:start id="gooo://evidence/admission-facts/v1" kind="entity"
type GoooRecord5fffa4d99b28f9b59cca3b476516da607c22de5545ab50459628ae863c8ee911 struct {
	GoooField01e8615de57bbecc588df6927d84e990dde1aca7c896ee46c1d1e2b1fd425b7d string `json:"actual_authority"`
	GoooField86099ed58b3d0441de2eddaef5c784afe54bec25e5eada98ed7276e74ab75fcf string `json:"required_authority"`
	GoooField0796e30ddfe662a78f6a595adadeb8994f1af64aec4ce73523e5a282fb2395f4 string `json:"status"`
	GoooFieldb0d97c186c27214166bc76810e8ba3f220f831f6b01e0f51cb7e78cad180a33b string `json:"confidence"`
	GoooFieldbc52f5e8e115bb4b1385d539e7899eb3afd8a782d2dc2344dd1fddd5207d26ea bool   `json:"provider_verified"`
	GoooField50309b5ef49680750288a99e396f573739e4400facc0eabf06a17ef570d13480 string `json:"observed_binding"`
	GoooFieldfcc00b5b9fca2fb2c07346b75e25e9f4d8c7aefa05b1ea601b917ddf8e6a1b93 string `json:"required_binding"`
	GoooField79a55257712096fbb1118531d2ab52f4bac773ce32880224180a7827aaa4e922 string `json:"observed_artifact"`
	GoooField71dcc36ce8fd559067b61b123fbab013f37fb0f2bd6de8ab438befdc89080f43 string `json:"required_artifact"`
	GoooFielde1d347f9ba44c8399e14c0d0006b281c3c0970bc7b8d8dc9cbd9f0323b4e5a05 string `json:"observed_policy"`
	GoooField75882040f3e59e78b8ab42d10555f2ccf7d9d0219e3b956edffab13644f79fef string `json:"required_policy"`
	GoooField4a1bdd40ab13ca26a6f235d029cfa240fb4910e47c73bdc7f005830352e6c0a4 int64  `json:"observed_at_unix"`
	GoooField7f9c6b3b6fb20a239c20ccd4e7311a8a348a691a8a4ebe106e994fd4a3909f3c int64  `json:"now_unix"`
	GoooFieldbcc5d03da8c7a3389df6af66b6c8a9527aed059fe71005e6a0f5a42e4d1b4759 int64  `json:"max_age_seconds"`
	GoooFieldb6994fc62065ee53f5edbd39c674942686c0ae6200038123ea622021d650821e int64  `json:"expires_at_unix"`
}

//gooo:generated:end id="gooo://evidence/admission-facts/v1" kind="entity"
//gooo:generated:start id="gooo://evidence/admission" kind="activity"
func GoooPackage2ActivityEvidenceAdmission(input GoooRecord5fffa4d99b28f9b59cca3b476516da607c22de5545ab50459628ae863c8ee911) GoooRecordf8f2dfd8e18fbecc01d27e037a375c52c9e207994c5efb486734f9d2fefe0681 {

	var providerOK = input.GoooFieldbc52f5e8e115bb4b1385d539e7899eb3afd8a782d2dc2344dd1fddd5207d26ea
	var evidenceOK = input.GoooFieldb0d97c186c27214166bc76810e8ba3f220f831f6b01e0f51cb7e78cad180a33b == "observed" && input.GoooField0796e30ddfe662a78f6a595adadeb8994f1af64aec4ce73523e5a282fb2395f4 == "pass"
	var authorityOK = GoooPackage0ActivityProofAuthoritySatisfies(input.GoooField01e8615de57bbecc588df6927d84e990dde1aca7c896ee46c1d1e2b1fd425b7d, input.GoooField86099ed58b3d0441de2eddaef5c784afe54bec25e5eada98ed7276e74ab75fcf)
	var bindingOK = GoooPackage1ActivityValidDigest(input.GoooField50309b5ef49680750288a99e396f573739e4400facc0eabf06a17ef570d13480) && GoooPackage1ActivityValidDigest(input.GoooFieldfcc00b5b9fca2fb2c07346b75e25e9f4d8c7aefa05b1ea601b917ddf8e6a1b93) && input.GoooField50309b5ef49680750288a99e396f573739e4400facc0eabf06a17ef570d13480 == input.GoooFieldfcc00b5b9fca2fb2c07346b75e25e9f4d8c7aefa05b1ea601b917ddf8e6a1b93
	var artifactOK = GoooPackage1ActivityValidDigest(input.GoooField79a55257712096fbb1118531d2ab52f4bac773ce32880224180a7827aaa4e922) && GoooPackage1ActivityValidDigest(input.GoooField71dcc36ce8fd559067b61b123fbab013f37fb0f2bd6de8ab438befdc89080f43) && input.GoooField79a55257712096fbb1118531d2ab52f4bac773ce32880224180a7827aaa4e922 == input.GoooField71dcc36ce8fd559067b61b123fbab013f37fb0f2bd6de8ab438befdc89080f43
	var policyOK = GoooPackage1ActivityValidDigest(input.GoooFielde1d347f9ba44c8399e14c0d0006b281c3c0970bc7b8d8dc9cbd9f0323b4e5a05) && GoooPackage1ActivityValidDigest(input.GoooField75882040f3e59e78b8ab42d10555f2ccf7d9d0219e3b956edffab13644f79fef) && input.GoooFielde1d347f9ba44c8399e14c0d0006b281c3c0970bc7b8d8dc9cbd9f0323b4e5a05 == input.GoooField75882040f3e59e78b8ab42d10555f2ccf7d9d0219e3b956edffab13644f79fef
	var freshnessOK = false

	if input.GoooField4a1bdd40ab13ca26a6f235d029cfa240fb4910e47c73bdc7f005830352e6c0a4 >= 0 && input.GoooField7f9c6b3b6fb20a239c20ccd4e7311a8a348a691a8a4ebe106e994fd4a3909f3c >= 0 && input.GoooFieldbcc5d03da8c7a3389df6af66b6c8a9527aed059fe71005e6a0f5a42e4d1b4759 >= 0 && input.GoooField4a1bdd40ab13ca26a6f235d029cfa240fb4910e47c73bdc7f005830352e6c0a4 <= input.GoooField7f9c6b3b6fb20a239c20ccd4e7311a8a348a691a8a4ebe106e994fd4a3909f3c {
		freshnessOK = input.GoooField7f9c6b3b6fb20a239c20ccd4e7311a8a348a691a8a4ebe106e994fd4a3909f3c-input.GoooField4a1bdd40ab13ca26a6f235d029cfa240fb4910e47c73bdc7f005830352e6c0a4 <= input.GoooFieldbcc5d03da8c7a3389df6af66b6c8a9527aed059fe71005e6a0f5a42e4d1b4759
	}
	var deadlineOK = input.GoooField7f9c6b3b6fb20a239c20ccd4e7311a8a348a691a8a4ebe106e994fd4a3909f3c >= 0 && input.GoooFieldb6994fc62065ee53f5edbd39c674942686c0ae6200038123ea622021d650821e >= 0 && input.GoooField7f9c6b3b6fb20a239c20ccd4e7311a8a348a691a8a4ebe106e994fd4a3909f3c < input.GoooFieldb6994fc62065ee53f5edbd39c674942686c0ae6200038123ea622021d650821e
	var admissible = providerOK && evidenceOK && authorityOK && bindingOK && artifactOK && policyOK && freshnessOK && deadlineOK
	var reason = "ADMISSIBLE"
	if !providerOK {
		reason = "PROVIDER_UNVERIFIED"
	} else {
		if !evidenceOK {
			reason = "EVIDENCE_INCOMPLETE"
		} else {
			if !authorityOK {
				reason = "AUTHORITY_INSUFFICIENT"
			} else {
				if !bindingOK {
					reason = "BINDING_MISMATCH"
				} else {
					if !artifactOK {
						reason = "ARTIFACT_MISMATCH"
					} else {
						if !policyOK {
							reason = "POLICY_MISMATCH"
						} else {
							if !freshnessOK {
								reason = "EVIDENCE_STALE"
							} else {
								if !deadlineOK {
									reason = "DEADLINE_EXPIRED"
								}
							}
						}
					}
				}
			}
		}
	}
	return GoooRecordf8f2dfd8e18fbecc01d27e037a375c52c9e207994c5efb486734f9d2fefe0681{GoooFieldece08fae0c0be6f079609f2c93a17939eef0d134dd5c2e49dbb5f77439879706: admissible, GoooField165006c7850615b592826ac11dd77bc4e9d96ed88aaca7f02c0cab912ba2fbf1: reason, GoooFieldbd61b46cfe6b094a7aae95cdc3f957a52489c7e017b272fe3e3db51b6bbf93f9: providerOK, GoooField6aa9d384faef399a1d2d3b93c7ff12c705353fab38a364c55411d3acdc5e2e4d: evidenceOK, GoooField9452d72eb1153f15ccff157d9ded95d1c91b72153806b2d5102bc0e3cf83ccdb: authorityOK, GoooField8b48ba2d3ad6878d6b11caad150062fa06efe8576fb2fb23822873fcf4145f0f: bindingOK, GoooField954e5041a8aebe0b23bf5283e1e216be4162a53f6ed892dc1f13c7a5c2452171: artifactOK, GoooField39a905e09c4c9b0e97ec80451fdc8dd677200bce08045cb351fdd057df920b55: policyOK, GoooFieldae58be9986d9d9196bba7398103cdd01d3e1b4a059013cc07813d9db385ca40f: freshnessOK, GoooField21713b659cfe5f93499c66e2b67e11b6911ba99e92a622a19d3bce02b0c5d184: deadlineOK}

}

//gooo:generated:end id="gooo://evidence/admission" kind="activity"
//gooo:generated:start id="gooo://rea/proof-authority-satisfies" kind="activity"
func GoooPackage0ActivityProofAuthoritySatisfies(input0 string, input1 string) bool {

	if input0 != "unit" && input0 != "integration" && input0 != "protocol" && input0 != "renderer" && input0 != "packaged-process" && input0 != "native-abi" && input0 != "live-observation" && input0 != "external" {
		return false
	}
	if input1 == "unit" {
		return true
	}
	if input1 == "integration" {
		return input0 == "integration" || input0 == "protocol" || input0 == "renderer" || input0 == "packaged-process" || input0 == "native-abi" || input0 == "live-observation"
	}
	if input1 == "protocol" {
		return input0 == "protocol" || input0 == "packaged-process" || input0 == "live-observation"
	}
	if input1 == "renderer" {
		return input0 == "renderer" || input0 == "packaged-process" || input0 == "live-observation"
	}
	if input1 == "packaged-process" {
		return input0 == "packaged-process" || input0 == "live-observation"
	}
	if input1 == "native-abi" {
		return input0 == "native-abi"
	}
	if input1 == "live-observation" {
		return input0 == "live-observation"
	}
	if input1 == "external" {
		return input0 == "external"
	}
	return false

}

//gooo:generated:end id="gooo://rea/proof-authority-satisfies" kind="activity"
//gooo:generated:start id="gooo://evidence/canonical-sha256-text" kind="activity"
func GoooPackage1ActivityValidDigest(input string) bool {

	if int64(len(input)) != 71 {
		return false
	}
	if input[0:7] != "sha256:" {
		return false
	}
	var offset int64 = 0
	for offset = 0; offset < 64; offset = offset + 1 {
		var digit = int64(input[7+offset])
		if !((digit >= 48 && digit <= 57) || (digit >= 97 && digit <= 102)) {
			return false
		}
	}
	return true

}

//gooo:generated:end id="gooo://evidence/canonical-sha256-text" kind="activity"
