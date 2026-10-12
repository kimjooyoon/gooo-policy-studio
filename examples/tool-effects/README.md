# Gooo Tool Effects and Effect Budget

**도구가 일으킬 수 있는 효과를 Gooo로 기술하고, 자동화 정책이 허용한 효과와
비교하는 독립 예제입니다.** 사람의 건별 승인을 입력 조건으로 요구하지
않습니다. 호스트가 소유한 도구 감사와 정책으로 기계가 판단할 수 있도록
순수 판정 부분을 분리했습니다.

English: Two pinned REA pure functions are ported to Gooo. An original Gooo
composition compares all audited tool effects against a host-owned policy
budget and returns every condition plus a stable first failure reason. There is
no per-call human approval condition. This example does not execute a tool,
authenticate a caller, grant permission, or enforce a sandbox.

## Rea에서 가져온 부분

원본은 [`morluto/rea`의 `toolEffects.ts`](https://github.com/morluto/rea/blob/8fc2043eb8bcedbf34dce064f977e455438635d6/src/contracts/toolEffects.ts)이며,
리비전을 `8fc2043eb8bcedbf34dce064f977e455438635d6`로 고정했습니다.
[`tool_effects.gooo`](tool_effects.gooo)는 두 순수 함수를 옮깁니다.

- `AnnotationsFromEffects`: 필수 Boolean 열 개를 받아 MCP 힌트 네 개를 계산합니다.
  세션 기록·프로세스 실행·네트워크 접근도 `readOnlyHint`를 거짓으로 만듭니다.
  외부 코드 실행이나 기기 변경은 데이터 폐기 표시가 없어도 `destructiveHint`를
  참으로 만듭니다. `idempotentHint`는 멱등성 사실을 그대로 반환하며,
  `openWorldHint`는 프로세스 실행 또는 네트워크 접근 여부입니다.
- `ToolReturnsTargetContent`: 이름이 정확히 `export_evidence_bundle` 또는
  `record_unknown`일 때만 거짓입니다. 알 수 없는 이름과 대소문자·공백이 다른
  이름은 참으로 남겨 대상에서 유래한 텍스트가 있을 가능성을 표시합니다.

입력 `ToolEffects`의 필드는 `mutatesTarget`, `mutatesSession`,
`writesFilesystem`, `launchesProcess`, `accessesNetwork`, `changesUiState`,
`mayDiscardData`, `executesForeignCode`, `mutatesDevice`, `idempotent`입니다.
지원하는 모든 입력, 임시 작업, 성공 및 실패 경로의 가능한 효과를 표현합니다.
MCP 힌트는 설명용 메타데이터입니다. 실행 권한이나 격리 기능으로 사용하지
않습니다. 대상 텍스트 표시가 거짓이어도 해당 도구의 실행을 허용한다는 뜻은
아닙니다.

## Gooo로 새로 구성한 효과 예산 판정

[`effect_budget.gooo`](effect_budget.gooo)의 `EffectBudgetAccepts`는 원본에 없는
Gooo 구성입니다. `ToolEffects`와 정책의 `EffectBudget`을 입력 두 개로 받아,
각 효과가 허용 범위에 있는지 판단합니다. 입력은 각각 열 개의 필수 Boolean
필드이며, 출력은 허용 여부·이유·조건 열 개를 포함한 필수 필드 열두 개입니다.

| 감사된 효과 | 정책 필드 | 출력 조건 |
|---|---|---|
| `mutatesTarget` | `allow_target` | `target_ok` |
| `mutatesSession` | `allow_session` | `session_ok` |
| `writesFilesystem` | `allow_filesystem` | `filesystem_ok` |
| `launchesProcess` | `allow_process` | `process_ok` |
| `accessesNetwork` | `allow_network` | `network_ok` |
| `changesUiState` | `allow_ui` | `ui_ok` |
| `mayDiscardData` | `allow_discard` | `discard_ok` |
| `executesForeignCode` | `allow_foreign_code` | `foreign_code_ok` |
| `mutatesDevice` | `allow_device` | `device_ok` |
| `idempotent` | `require_idempotent` | `idempotency_ok` |

처음 아홉 조건은 해당 효과가 없거나 정책이 허용할 때 참입니다. 멱등성 조건은
정책이 멱등성을 요구하지 않거나 도구가 멱등적일 때 참입니다. **열 개 조건이
모두 참일 때만** `admissible`이 참이며, 성공 이유는 `WITHIN_EFFECT_BUDGET`입니다.
하나 이상 실패하면 표의 순서로 최초 실패 이유를 정하지만 모든 조건의 결과를
함께 반환합니다. 실패 코드 전체와 정확한 타입은 [`contract.json`](contract.json)에
기록했습니다.

예를 들어 API 분석 자동화는 세션에 근거를 추가하는 작업을 허용하면서 대상
변경·파일 쓰기·외부 코드 실행·기기 변경을 거절할 수 있습니다. 세션 변경을
허용한 이 정책은 MCP의 읽기 전용 힌트와 별개이며, 원래의 효과 사실을 직접
비교합니다. 멱등성을 요구하는 정책은 다른 효과가 허용되어도 비멱등 도구를
거절합니다.

## 재현하기

저장소 루트에서 **Go 1.27.2**, Python 3, Node.js를 사용합니다. Gooo 컴파일러는
[`compiler-version.txt`](compiler-version.txt)의
`83928fa4538245abe33b08549da47f8cbdc50ed2` (`0.6.32-dev`)로 고정합니다.
이미 같은 리비전으로 빌드한 [Evidence Admission 컴파일러](../evidence-admission/README.md#재현하기)를
재사용할 수 있습니다. 실행 파일을 `.tools/evidence-gooo`에 두거나 아래
`--compiler`를 실제 파일 경로로 바꾸세요. 기존 Studio의 컴파일러·생성 코드·
기계 게이트와 이전에 배포한 실행 파일은 이 독립 예제와 별개입니다.

```sh
tool_effects_go="$(go env GOROOT)/bin/go"
"$tool_effects_go" version
python3 -I tools/verify-tool-effects.py \
  --compiler .tools/evidence-gooo \
  --go "$tool_effects_go" \
  --out out/tool-effects
```

선택한 Go 실행 파일은 Go 1.27.2여야 하며 `--go`에는 절대 경로를 전달합니다.
다시 실행할 때는 기존 결과를 덮어쓰지 않는 새 `--out` 경로를 선택합니다.
작업 공간의 패키지 경로는 `gooo/tool-effects`이고, 세 진입점은
[`annotations.workspace.json`](annotations.workspace.json),
[`content.workspace.json`](content.workspace.json),
[`budget.workspace.json`](budget.workspace.json)입니다. 각 manifest는 두 Gooo
소스를 모두 포함하므로 같은 패키지와 계약을 기준으로 검증합니다.

## 검증 범위

주석 힌트는 열 개 Boolean의 전체 조합 **1,024개**를 대상으로 네 개 출력
필드 전체를 비교합니다. 대상 텍스트 표시는 정확한 두 제외 이름과 독립적으로
작성한 유한 Text 사례를 검사합니다. 새 예산 판정도 독립적으로 작성한 유한
기대값을 사용하여 개별 거절, 복수 조건과 실패 이유 우선순위를 검사합니다.
예산 입력 전체 `2^20` 조합이나 모든 Text 값을 검증했다고 주장하지 않습니다.

검증 도구는 모든 사례와 필드를 유지하면서 컴파일러의 **32 KiB JSON 입력
제한** 안에서 **30,000바이트 이하** 배치로 나눕니다. 배치의 시작 위치·사례 수·
바이트 해시를 기록하며, 순서나 사례를 줄여서 성공시키지 않습니다. 보관한
TypeScript에서 두 순수 함수를 분리해 원본 비교에 사용하며, Rea 전체 실행이나
설치 스크립트·대상 프로그램 실행은 필요하지 않습니다.

실제 생성된 Go의 네이티브 실행, 모든 입력과 출력, 컴파일러·Go 실행 파일·
작업 공간·소스·사례 바이트의 연결 및 전체 기록 재실행을 확인합니다.
**계약과 기대값 자체는 실행 성공의 증거가 아닙니다.** 실제 수행 여부와 결과는
해당 실행의 `observations.json`과 배치별 실행·재실행 기록에서 확인합니다.

## 실제 자동화 호스트가 확립할 사실

호스트는 도구 구현·버전에 연결된 완전한 감사 목록을 소유해야 합니다. 호출자나
모델이 보낸 안전 표시, 도구 이름 추정, 도구의 자기 설명으로 허용 범위를 정하면
이 예제의 전제가 성립하지 않습니다. 감사가 없거나 낡은 도구는 입력을 만들기
전에 거절합니다. 원본의 `toolContractMetadata`도 누락된 감사를 오류로 처리하며,
이 예제는 그 메타데이터 조회 함수나 전체 도구 목록을 구현하지 않습니다.

호스트가 열 개 필수 Boolean을 엄격하게 해석하고 현재 정책의 예산을 설정합니다.
누락 필드·문자열 Boolean·추가 필드를 기본값으로 조용히 통과시키지 않습니다.
주체 인증, 실제 실행 권한, 요청과 작업, 정책 및 도구 revision을 같은 집행 경계에
연결하고 변경 가능한 상태를 다시 확인해야 합니다. 파일·프로세스·네트워크·UI·
기기 제한을 실제로 강제할 호스트 통제와 중복 실행 처리도 필요합니다.

이 예제의 `idempotent=true`는 입력된 감사 사실입니다. 원격 효과의 정확히 한 번
실행을 증명하지 않습니다. 저장된 실행 기록의 재실행도 현재의 새 실행 권한을
주지 않습니다. [Evidence Admission](../evidence-admission/)의 근거 완전성·출처·
요청 연결·시간 조건을 함께 적용하려면 호스트가 두 판정의 검증된 입력을 구성하고
실제 집행에 연결해야 합니다. 현재 예제는 기존 인증된 기계 게이트에 연결하지
않았으며 외부 API 효과를 수행하지 않습니다.

## 출처와 라이선스

원본 [`upstream/toolEffects.ts`](upstream/toolEffects.ts)와
[`LICENSE-REA`](LICENSE-REA)를 바이트 그대로 보관했습니다. 고정 리비전,
원본 소스·라이선스의 SHA-256과 Git blob 식별자는 [`upstream.json`](upstream.json)에
있습니다. Rea에서 가져온 부분은 **MIT**, 저작권 표시는 **Copyright (c) 2026
morluto**입니다. 새 Gooo 구성은 저장소의 [`MIT 라이선스`](../../LICENSE)를 따릅니다.
이 두 순수 함수를 옮겼다는 결과를 Rea 전체 도구·프로바이더·MCP 런타임의
포팅이나 전체 자율 시스템의 안전 증명으로 확대하지 않습니다.
