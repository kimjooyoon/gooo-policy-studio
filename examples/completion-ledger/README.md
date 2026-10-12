# Gooo completion ledger core and required-claim check

REA의 검증 결과 집계 규칙을 Gooo의 세 활동으로 나누고, **현재 정책이 요구하는 모든 claim을 실제로 관측했는가**를 별도 판단합니다. `pass` 하나가 있다고 전체 작업이 완료되는 것은 아닙니다. `fail`, `unsupported`, `truncated`, `unknown`이 남아 있거나 필수 claim이 빠지면 `ready=false`가 됩니다.

이 판단에는 건별 사람 승인 필드가 없습니다. 자동화 호스트가 현재 정책과 인증된 검증 사실을 제공하고, Gooo가 집계·완료·필수 claim 충족 조건을 계산합니다. 결과는 후속 실행의 허가나 증거의 진위 확인을 대신하지 않습니다.

## 무엇을 가져왔는가

원본은 [morluto/rea의 evidenceCompletionLedger.ts](https://github.com/morluto/rea/blob/8fc2043eb8bcedbf34dce064f977e455438635d6/src/domain/evidenceCompletionLedger.ts)입니다. 정확한 원문은 [upstream/evidenceCompletionLedger.ts](upstream/evidenceCompletionLedger.ts), MIT 고지는 [LICENSE-REA](LICENSE-REA), 고정 revision과 원문 해시는 [upstream.json](upstream.json)에 보존합니다.

원본의 다섯 terminal status와 `complete = pass == total` 집계 의미를 가져왔습니다. Gooo에서는 임의 길이 배열을 네 개의 고정 슬롯으로 축소하지 않고, **일반적인 int64 counter fold**로 표현합니다. 호스트는 실제로 받은 각 record를 `CompletionStep`에 한 번씩 전달하고 `CompletionFinish`로 닫습니다. `CompletionReady`는 필수 claim coverage를 결합한 독자 구성입니다.

| 활동 | 입력 | 결과 |
| --- | --- | --- |
| `CompletionStep` | 여섯 counter와 정확한 status 문자열 | 갱신된 counter, `valid`, `complete`, `reason` |
| `CompletionFinish` | 여섯 counter | 비어 있지 않은 최종 집계 또는 거절 |
| `CompletionReady` | 집계와 네 가지 coverage fact | `ready`, 최초 거절 이유, 네 가지 조건별 결과 |

세 workspace는 동일한 [completion.gooo](completion.gooo)를 사용합니다. 필드·activity ID·실패 우선순위는 [contract.json](contract.json)에 선언되어 있습니다.

## 집계 규칙과 수치 경계

counter는 `total`, `pass`, `fail`, `unsupported`, `truncated`, `unknown`입니다. 전부 음수가 아니어야 하고 다섯 category의 합이 `total`과 정확히 일치해야 합니다. 코드에서는 이 합을 직접 더하지 않습니다. 남은 `total`에서 각 category를 차례로 빼되, 빼기 전에 해당 값이 남은 수보다 크지 않은지 검사합니다. 따라서 악의적인 int64 합이 overflow하여 정상처럼 보일 수 없습니다.

`CompletionStep`의 거절 우선순위는 다음과 같습니다.

1. counter의 부호 또는 partition이 틀리면 `INVALID_COUNTS`.
2. status가 정확히 `pass`, `fail`, `unsupported`, `truncated`, `unknown` 중 하나가 아니면 `INVALID_STATUS`.
3. `total`이 `9223372036854775807`이면 `COUNTER_CAPACITY`.

거절 결과는 여섯 counter가 모두 0이고 `valid=false`, `complete=false`입니다. 정상일 때만 `total`과 선택된 category를 1씩 증가시킵니다. 각 category가 이미 `total` 이하임을 확인한 뒤 증가하므로 category 증가도 보호됩니다.

`CompletionFinish`는 partition을 다시 확인합니다. 잘못된 partition은 `INVALID_COUNTS`, 유효하지만 비어 있는 집계는 `NO_RECORDS`로 거절합니다. 유효한 비어 있지 않은 집계는 counter를 그대로 보존하고, 전부 pass이면 `ALL_PASS`, 아니면 `NON_PASS_RESULTS`를 반환합니다.

**빈 입력의 차이를 의도적으로 명시합니다.** REA의 private `summarize([])`는 `0 == 0`이므로 `complete=true`를 계산하지만, public ledger schema는 records와 summary total에 최소 1을 요구합니다. 이 예제의 Finish는 public nonempty 경계를 적용합니다. 따라서 private 빈 배열 함수와 완전히 동일하다고 주장하지 않습니다. int64 수치 영역도 JavaScript Number 영역 및 RFC 8785와 동일하다는 주장이 아닙니다.

## 필수 claim coverage

호스트는 별도 정책의 `required_claims`와 실제 record의 unique claim ID를 비교하여 다음 값을 구성합니다.

- `required_count`: 현재 정책의 필수 claim 수.
- `matched_count`: 실제 관측 record와 일치한 필수 claim 수.
- `unexpected_count`: 현재 정책에 없는 실제 관측 claim 수.
- `observed_count`: 실제 관측 record 수.

`CompletionReady`는 다음 네 조건을 각각 계산하여 모두 반환합니다. 앞선 조건이 실패해도 뒤 조건을 생략하지 않습니다.

| 결과 flag | 조건 |
| --- | --- |
| `counts_ok` | summary partition과 coverage fact가 모두 유효하다. 필수 수는 양수이고, 나머지는 음수가 아니며, matched는 required 이하이고, `observed - matched == unexpected`이다. |
| `coverage_ok` | coverage fact가 유효하고 `matched == required`, `unexpected == 0`이다. |
| `summary_ok` | `summary.valid`, 양수 total, `total == observed`, `complete == (pass == total)`이다. |
| `all_pass_ok` | summary counter partition이 유효하고, 양수 total, `pass == total`, `summary.complete`이다. |

`ready`는 이 네 flag의 AND입니다. 최초 실패 이유는 `INVALID_COUNTS` → `INCOMPLETE_CLAIM_COVERAGE` → `INVALID_COMPLETION_SUMMARY` → `NON_PASS_RESULTS` 순서이며, 전부 통과하면 `READY`입니다. `summary.reason` 문자열을 근거로 통과시키지 않습니다.

## completion-check 입력과 재실행

저장소의 `completion-check` 호스트는 **운영자가 선택한 정책 파일**과 검증 결과 입력을 따로 읽습니다. 일반 입력 payload 안에 policy를 넣어 요구사항을 바꿀 수 없습니다.

정책의 schema는 `policy-studio/completion-policy/v1`이며 `policy_id`, 양수 int64 `revision`, 1..256개의 unique ASCII `required_claims`를 갖습니다. 입력의 schema는 `policy-studio/completion-input/v1`이며 `request_id`와 0..256개의 records를 갖습니다. 각 record는 `claim_id`, 정확한 status, 1..256개의 unique `evidence_ids`를 갖습니다. evidence ID는 `ev_` 뒤에 64개의 lowercase hex 문자가 오는 형식입니다. 형식은 진위 확인이 아닙니다. 서로 다른 claim에서 같은 evidence ID를 사용하는 것은 허용됩니다.

JSON 구조, 누락·추가 field, 중복 key, 잘못된 문자열이나 정수는 입력 오류입니다. duplicate claim ID와 같은 record 안의 duplicate evidence ID도 입력 오류입니다. 필수 claim 누락·예상 밖 claim·빈 관측 목록은 정상 구조의 `not-ready` 보고서로 반환합니다. 입력 record 순서는 그대로 보존합니다. 정책과 원본 입력, 모든 Step의 이전 counter와 전체 결과, 최종 집계, coverage, 정렬된 missing/unexpected claim 목록, readiness, 실제 source/generated/bridge/generation 및 정책 byte binding을 보고서에 남깁니다.

호스트 파일 크기 제한은 정책 64 KiB, 입력 1 MiB, report replay 4 MiB입니다. **Gooo core 자체는 256개 record로 제한되지 않습니다.** 이 수는 호스트 입력 한도이고, fixture의 길이 1..4도 검증용 유한 영역일 뿐 API 한도가 아닙니다.

저장소 루트에서 다음과 같이 실행합니다. 현재 배포된 기존 portable preview에 이 명령이 들어 있다고 가정하지 마십시오.

```sh
go build -o completion-check ./cmd/completion-check

./completion-check \
  --policy examples/completion-ledger/policy.json \
  --input examples/completion-ledger/input-ready.json > completion-report.json

./completion-check \
  --policy examples/completion-ledger/policy.json \
  --replay \
  --input completion-report.json
```

`--input -` 또는 `--input` 생략은 표준 입력을 사용합니다. replay에서도 **현재 policy 파일을 독립적으로 다시 읽고**, 그 byte와 report 안의 policy를 확인하며 모든 Step·summary·coverage·readiness·binding을 다시 계산하여 typed complete report가 정확히 같은지 검사합니다. 과거 report에 담긴 policy가 현재 policy를 대신하지 않습니다. 위에서 빌드한 `completion-check` 바이너리의 종료 코드는 ready `0`, 정상 구조의 not-ready `1`, 입력·정책·replay·실행 오류 `2`입니다.

## 검증 범위와 한계

독립 expectation corpus는 작은 counter partition, status 조합, int64 경계, 잘못된 status, coverage와 summary의 조건·실패 우선순위를 포함합니다. 호스트 fixture의 ordered status sequence 길이 1..4와 256-record 경계는 유한 검증 자료입니다. 실제 실행 상태와 count는 helper의 observations 및 CI에서 확인하십시오. 이 문서와 contract는 그 자체로 PASS 증거가 아닙니다.

이 예제는 REA의 full canonical ledger builder/parser, 정렬된 canonical record 형식, RFC 8785 canonicalization이나 `ecl_` ledger ID를 구현하지 않습니다. 인증되지 않은 verifier가 주장한 pass를 인증된 pass로 바꾸지도 않습니다. machine workflow는 실행 주체, 최신 정책, evidence provenance·freshness·request binding을 먼저 확정해야 합니다. 이후의 권한 부여, 파일·네트워크·프로세스 효과, durable idempotency는 해당 호스트의 책임입니다.

The three Gooo activities implement a generic checked-int64 status fold, a public nonempty completion boundary, and an original required-claim coverage relation. The CLI folds every accepted record through compiled Gooo and loads operator policy separately. This is an unsigned check of supplied verifier outcomes, not full REA ledger compatibility, evidence authentication, permission or effect execution. Finite fixtures and replay are reproducibility evidence within their observed scope.
