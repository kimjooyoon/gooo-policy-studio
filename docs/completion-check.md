# Completion Check

`completion-check`는 별도 정책 파일의 필수 claim과 제공된 검증 결과를 비교합니다. 모든 결과를 컴파일된 Gooo 활동으로 누적하고, 누락·추가 claim·비통과 결과를 보고서에 남깁니다. 제공된 항목이 전부 `pass`여도 필수 claim 하나가 빠지면 ready가 되지 않습니다.

```sh
go build -o completion-check ./cmd/completion-check
./completion-check --policy examples/completion-ledger/policy.json --input examples/completion-ledger/input-ready.json > completion-report.json
./completion-check --policy examples/completion-ledger/policy.json --replay --input completion-report.json
```

빌드한 실행 파일은 Gooo 컴파일러나 모델 서버 없이 동작합니다. 일반 입력은 정책을 포함할 수 없습니다. `--policy`는 실행하는 시스템이 선택하는 별도 로컬 파일이며 필수입니다. 입력 파일을 지정하지 않으면 표준 입력에서 읽습니다.

누락 예제를 확인하려면 다음 입력을 사용합니다. 정상적인 not-ready 보고서가 출력되고 종료 코드는 `1`입니다.

```sh
./completion-check --policy examples/completion-ledger/policy.json --input examples/completion-ledger/input-missing.json
```

종료 코드 `0`은 현재 정책을 충족하는 ready 보고서, `1`은 완성된 not-ready 보고서, `2`는 잘못된 입력·정책·재실행 또는 실행/출력 오류입니다. `fail`, `unsupported`, `truncated`, `unknown`은 통과로 바뀌지 않습니다. 빈 관측 목록도 정상 입력이며 `NO_RECORDS` 요약과 전체 누락 claim을 반환합니다.

보고서는 원래 정책과 입력, 입력 순서대로 수행한 모든 단계, 여섯 개 상태 개수, coverage, 정렬된 누락/추가 claim 목록, Gooo readiness 결과와 바이트 연결값을 포함합니다. claim과 evidence ID는 임의로 정렬하거나 줄이지 않습니다. 누락/추가 목록만 정렬합니다. 예제 evidence ID는 합성 데이터입니다.

호스트는 JSON 구조와 ID·상태를 검증하고 필수 claim 집합을 대조합니다. 상태 개수, 완료 여부와 readiness는 Gooo의 `CompletionStep`, `CompletionFinish`, `CompletionReady`가 계산합니다. 핵심 활동은 일관된 int64 개수를 받으며 네 개 항목으로 제한되지 않습니다. CLI는 관측 결과 `0..256`개와 필수 claim `1..256`개를 지원합니다. evidence ID도 claim마다 `1..256`개를 지원하며 여러 claim에서 같은 ID를 사용할 수 있습니다.

정책 파일은 최대 65,536바이트, 일반 입력은 1,048,576바이트, 재실행 보고서는 4,194,304바이트입니다. 각 배열의 항목 제한과 바이트 제한이 함께 적용됩니다. 중복 JSON 키, 누락/추가 필드, 대소문자 별칭, null, 잘못된 Unicode, 중복 claim, 같은 claim 안의 중복 evidence ID와 유효하지 않은 상태를 거부합니다. ID는 `[A-Za-z][A-Za-z0-9._-]{0,79}`, evidence ID는 `ev_` 뒤에 소문자 16진수 64자리입니다. 정책 revision은 양의 int64입니다.

재실행은 현재 `--policy` 파일을 다시 읽습니다. 보고서에 들어 있는 정책을 설정으로 신뢰하지 않으며, 현재 정책의 원본 바이트·임베드된 소스와 생성 코드·어댑터·생성 기록·컴파일러 연결값을 확인하고 전체 보고서를 다시 계산합니다. 정책 파일의 공백만 바뀌어도 원본 바이트 연결값이 달라져 이전 보고서의 재실행은 거부됩니다.

이 보고서는 서명되지 않은 일관성 검사입니다. 유효한 evidence ID는 제공된 사실의 이름이며 인증된 증거라는 뜻은 아닙니다. 일관되게 수정한 입력 사실은 다시 계산될 수 있습니다. 실행 시스템은 정책 선택을 통제하고, 인증된 검증 사실을 확보한 뒤 입력을 만들어야 합니다. 이 도구는 외부 작업 실행이나 권한 부여를 수행하지 않습니다.

Rea의 private `summarize`가 사용하는 다섯 상태의 개수와 all-pass 의미를 가져왔으며, 빈 입력 거부와 정책 coverage는 명시한 확장입니다. RFC 8785 canonicalization, Rea의 `ecl_` ledger ID와 전체 public ledger parser의 호환성을 구현한 것은 아닙니다.

## English

Completion Check folds every supplied verifier outcome through compiled Gooo and compares claim IDs with a separately selected operator policy. Missing or unexpected claims and any non-pass outcome produce a complete not-ready report. The standalone binary requires no runtime compiler or model. Replay reloads the current policy and recomputes every observation and byte binding. It checks unsigned consistency of supplied facts; it does not authenticate evidence, grant permission, execute target tools, or implement the full RFC 8785 Rea ledger format.
