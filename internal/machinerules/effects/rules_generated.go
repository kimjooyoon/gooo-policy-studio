package effects

//gooo:generated:start id="gooo://automation/effect-budget-decision/v1" kind="entity"
type GoooRecord251e4cdb974620f5ae894a894dd0239cd53b45b0e7a7a1162c3575f3bc6ec124 struct {
	GoooFielde92bf9cbf5569f8c7791a3e3257b256d461abb15ccce5461df1a20c4b0e53a27 bool   `json:"admissible"`
	GoooField1a08eeec5fecbc842b02155712c297cb2189d8c2b99fb7dbc0014bd3c9f0e840 string `json:"reason"`
	GoooField91996034635dbb0865679a8b97d2c8ed1712fed3ec5fcb9ff0e99d91973f62ac bool   `json:"target_ok"`
	GoooField6cd2f154b9aa922766f64063b9026a6525439c55d507911dc9f81cd37fe0c5d2 bool   `json:"session_ok"`
	GoooFieldad1c839186f9435996468c2f53ca06e1bf0b6bd7648c81cbae6795f5fab2c1cb bool   `json:"filesystem_ok"`
	GoooField52d50e039e73ebad964309f7ec54ba1f30341cb846f088c48b9f8eeb44d62bf0 bool   `json:"process_ok"`
	GoooFieldc63d552504f2aa28d07fd3de2644328a4fee09803d6a0868dadb45ecd0265ca4 bool   `json:"network_ok"`
	GoooField688a8a4917cd687ad6080ac699075d4ef3e1f310ed5f6fe67856eb0702f045be bool   `json:"ui_ok"`
	GoooField73b0dcc18be070377a40af7e3506875c52d20b01254667784ed330be1a98de6d bool   `json:"discard_ok"`
	GoooField769198127ac63cac8f7785c5c82e2b88ae80e5fce7795fac4120de929a78771d bool   `json:"foreign_code_ok"`
	GoooFieldf68f8bbdb27d1ad66414b41aadfd36b8f54ec4cb40344124be3574e9ad57412c bool   `json:"device_ok"`
	GoooField13b313d8731c8938a3fd33c80ae9ad165b9981d3cba652b1898ab7a6f75cd954 bool   `json:"idempotency_ok"`
}

//gooo:generated:end id="gooo://automation/effect-budget-decision/v1" kind="entity"
//gooo:generated:start id="gooo://automation/effect-budget/v1" kind="entity"
type GoooRecord2ee720b913a01268ca8064f2c5ff6eca244cacdc535b49417b517927fd732f06 struct {
	GoooFieldf73a5d15b766e1f5cfa2e26109325f0e251359b49b6ca9b60b8ef6361147f4d2 bool `json:"allow_target"`
	GoooField61ba69f3a2eb9833b6963985774ed6e850ab44310a1fa207a66477f8893ab009 bool `json:"allow_session"`
	GoooField4c8cff411bba36568aec8f987c530892f494b6d96a03aa201aba67cb370ce452 bool `json:"allow_filesystem"`
	GoooField523261722e73868ac96a8242324f9245fe06756c9a70d8a09c4d4c9229afa18b bool `json:"allow_process"`
	GoooFieldcec8b116034606c5fe9675cdb202b452b08027fc084ad161c7c736906d965ce2 bool `json:"allow_network"`
	GoooField22f7e1852cbcfbab8f1c838f3a9b91fbcea726b22deee2fa6cfeb55e0d081557 bool `json:"allow_ui"`
	GoooFieldc643bc0f07608e8edc266cdf7717695bfbe09f1fc47419591f10d1ecbee886af bool `json:"allow_discard"`
	GoooField0a3b32e164159c2eab2cc28757615fd1d87e5f4dbbc0b0338af1f2503020fe34 bool `json:"allow_foreign_code"`
	GoooField01e617a7fe5a4f7955576010fd4aa11a9df78562f99f3681f2a9f50f976ec9a6 bool `json:"allow_device"`
	GoooField16e42e1b43710272c247d44e50d97a6a949245b4f60e475df4086119f6d040e9 bool `json:"require_idempotent"`
}

//gooo:generated:end id="gooo://automation/effect-budget/v1" kind="entity"
//gooo:generated:start id="gooo://rea/tool-effects/v1" kind="entity"
type GoooRecord2a1bd27fb100df5493d42a98307645dd178dbc2bf8fff1c67eec80c875768c4c struct {
	GoooField44f69a40182fd4622d76c9671f1dcdc119526c6a9a554662f5a6c21a71666df5 bool `json:"mutatesTarget"`
	GoooField4ad13a6eb00bc2ce820fca483ff6fd7b80d2b000ec97992e875600f7a7ad9120 bool `json:"mutatesSession"`
	GoooField850bc8b510b314179e8bc5d6e3e4e95d62d1415ab758e1c9b4c403bce3d07fc9 bool `json:"writesFilesystem"`
	GoooField2bc2281b0802dd48610fbe7161077478f20e68c47f315eb9aafe8693fd28a7c2 bool `json:"launchesProcess"`
	GoooField1594a0980b808cdf8bbde1fa27d4c7aaa38ebc29fcc0efcc58801df1bc83d5d7 bool `json:"accessesNetwork"`
	GoooField57baf9b42bf0f423bd6ae5d183ab315a704ae9d4ee90464a26293cf60d2ba225 bool `json:"changesUiState"`
	GoooFieldcc751d2e270f7ae6596ddfff7e29e5aeb422b0a1f394daeb5326a1fe17657bd4 bool `json:"mayDiscardData"`
	GoooField513e23fa627cec16efbc0698c8b9d6274b645a7bbb23768a84823f8b0cb5282b bool `json:"executesForeignCode"`
	GoooFieldd389342e5b884e09ce5ee190a448e442af7374ed3329e430660a6c07c65415d4 bool `json:"mutatesDevice"`
	GoooField0e1fc3e2032d9adad316034ec68af6bfa871205dccd503d1fc889fc0ecbfc420 bool `json:"idempotent"`
}

//gooo:generated:end id="gooo://rea/tool-effects/v1" kind="entity"
//gooo:generated:start id="gooo://automation/effect-budget-accepts" kind="activity"
func GoooPackage0ActivityEffectBudgetAccepts(input0 GoooRecord2a1bd27fb100df5493d42a98307645dd178dbc2bf8fff1c67eec80c875768c4c, input1 GoooRecord2ee720b913a01268ca8064f2c5ff6eca244cacdc535b49417b517927fd732f06) GoooRecord251e4cdb974620f5ae894a894dd0239cd53b45b0e7a7a1162c3575f3bc6ec124 {

	var targetOK = !input0.GoooField44f69a40182fd4622d76c9671f1dcdc119526c6a9a554662f5a6c21a71666df5 || input1.GoooFieldf73a5d15b766e1f5cfa2e26109325f0e251359b49b6ca9b60b8ef6361147f4d2
	var sessionOK = !input0.GoooField4ad13a6eb00bc2ce820fca483ff6fd7b80d2b000ec97992e875600f7a7ad9120 || input1.GoooField61ba69f3a2eb9833b6963985774ed6e850ab44310a1fa207a66477f8893ab009
	var filesystemOK = !input0.GoooField850bc8b510b314179e8bc5d6e3e4e95d62d1415ab758e1c9b4c403bce3d07fc9 || input1.GoooField4c8cff411bba36568aec8f987c530892f494b6d96a03aa201aba67cb370ce452
	var processOK = !input0.GoooField2bc2281b0802dd48610fbe7161077478f20e68c47f315eb9aafe8693fd28a7c2 || input1.GoooField523261722e73868ac96a8242324f9245fe06756c9a70d8a09c4d4c9229afa18b
	var networkOK = !input0.GoooField1594a0980b808cdf8bbde1fa27d4c7aaa38ebc29fcc0efcc58801df1bc83d5d7 || input1.GoooFieldcec8b116034606c5fe9675cdb202b452b08027fc084ad161c7c736906d965ce2
	var uiOK = !input0.GoooField57baf9b42bf0f423bd6ae5d183ab315a704ae9d4ee90464a26293cf60d2ba225 || input1.GoooField22f7e1852cbcfbab8f1c838f3a9b91fbcea726b22deee2fa6cfeb55e0d081557
	var discardOK = !input0.GoooFieldcc751d2e270f7ae6596ddfff7e29e5aeb422b0a1f394daeb5326a1fe17657bd4 || input1.GoooFieldc643bc0f07608e8edc266cdf7717695bfbe09f1fc47419591f10d1ecbee886af
	var foreignCodeOK = !input0.GoooField513e23fa627cec16efbc0698c8b9d6274b645a7bbb23768a84823f8b0cb5282b || input1.GoooField0a3b32e164159c2eab2cc28757615fd1d87e5f4dbbc0b0338af1f2503020fe34
	var deviceOK = !input0.GoooFieldd389342e5b884e09ce5ee190a448e442af7374ed3329e430660a6c07c65415d4 || input1.GoooField01e617a7fe5a4f7955576010fd4aa11a9df78562f99f3681f2a9f50f976ec9a6
	var idempotencyOK = !input1.GoooField16e42e1b43710272c247d44e50d97a6a949245b4f60e475df4086119f6d040e9 || input0.GoooField0e1fc3e2032d9adad316034ec68af6bfa871205dccd503d1fc889fc0ecbfc420
	var admissible = targetOK && sessionOK && filesystemOK && processOK && networkOK && uiOK && discardOK && foreignCodeOK && deviceOK && idempotencyOK
	var reason = "WITHIN_EFFECT_BUDGET"
	if !targetOK {
		reason = "TARGET_MUTATION_DISALLOWED"
	} else {
		if !sessionOK {
			reason = "SESSION_MUTATION_DISALLOWED"
		} else {
			if !filesystemOK {
				reason = "FILESYSTEM_WRITE_DISALLOWED"
			} else {
				if !processOK {
					reason = "PROCESS_LAUNCH_DISALLOWED"
				} else {
					if !networkOK {
						reason = "NETWORK_ACCESS_DISALLOWED"
					} else {
						if !uiOK {
							reason = "UI_CHANGE_DISALLOWED"
						} else {
							if !discardOK {
								reason = "DATA_DISCARD_DISALLOWED"
							} else {
								if !foreignCodeOK {
									reason = "FOREIGN_CODE_DISALLOWED"
								} else {
									if !deviceOK {
										reason = "DEVICE_MUTATION_DISALLOWED"
									} else {
										if !idempotencyOK {
											reason = "IDEMPOTENCY_REQUIRED"
										}
									}
								}
							}
						}
					}
				}
			}
		}
	}
	return GoooRecord251e4cdb974620f5ae894a894dd0239cd53b45b0e7a7a1162c3575f3bc6ec124{GoooFielde92bf9cbf5569f8c7791a3e3257b256d461abb15ccce5461df1a20c4b0e53a27: admissible, GoooField1a08eeec5fecbc842b02155712c297cb2189d8c2b99fb7dbc0014bd3c9f0e840: reason, GoooField91996034635dbb0865679a8b97d2c8ed1712fed3ec5fcb9ff0e99d91973f62ac: targetOK, GoooField6cd2f154b9aa922766f64063b9026a6525439c55d507911dc9f81cd37fe0c5d2: sessionOK, GoooFieldad1c839186f9435996468c2f53ca06e1bf0b6bd7648c81cbae6795f5fab2c1cb: filesystemOK, GoooField52d50e039e73ebad964309f7ec54ba1f30341cb846f088c48b9f8eeb44d62bf0: processOK, GoooFieldc63d552504f2aa28d07fd3de2644328a4fee09803d6a0868dadb45ecd0265ca4: networkOK, GoooField688a8a4917cd687ad6080ac699075d4ef3e1f310ed5f6fe67856eb0702f045be: uiOK, GoooField73b0dcc18be070377a40af7e3506875c52d20b01254667784ed330be1a98de6d: discardOK, GoooField769198127ac63cac8f7785c5c82e2b88ae80e5fce7795fac4120de929a78771d: foreignCodeOK, GoooFieldf68f8bbdb27d1ad66414b41aadfd36b8f54ec4cb40344124be3574e9ad57412c: deviceOK, GoooField13b313d8731c8938a3fd33c80ae9ad165b9981d3cba652b1898ab7a6f75cd954: idempotencyOK}

}

//gooo:generated:end id="gooo://automation/effect-budget-accepts" kind="activity"
