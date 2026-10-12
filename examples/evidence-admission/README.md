# Gooo Evidence Admission

**검증 근거가 현재 자동화 요청에 사용 가능한지 Gooo로 판단하는 독립 예제입니다.**

API·자동화 정책을 바꾸기 전에, 검증의 종류뿐 아니라 관측 상태·요청 연결·대상
산출물·정책·유효 시간을 함께 확인합니다. 사람의 건별 승인을 입력 조건으로
요구하지 않습니다. 이 예제의 결과는 근거의 사용 가능 여부이며, 실제 실행
권한은 이를 사용하는 호스트가 판단하고 집행해야 합니다.

English: A separately pinned Gooo example combines REA's proof-authority relation
with evidence status, request binding, artifact and policy identity, freshness,
and expiry. It has no per-call human approval condition. The pure decision does
not authenticate a provider, grant execution permission, or perform an effect.

## Rea에서 가져온 부분과 Gooo로 구성한 부분

[`morluto/rea`](https://github.com/morluto/rea)의
[`proofAuthoritySatisfies`](https://github.com/morluto/rea/blob/8fc2043eb8bcedbf34dce064f977e455438635d6/src/application/ReconstructionObligationAuthority.ts)
순수 함수를 고정한 뒤 [`proof_authority.gooo`](proof_authority.gooo)로 옮겼습니다.
기준 리비전은 `8fc2043eb8bcedbf34dce064f977e455438635d6`입니다.

원본의 여덟 라벨은 `unit`, `integration`, `protocol`, `renderer`,
`packaged-process`, `native-abi`, `live-observation`, `external`입니다.
이 관계는 단순한 순위가 아닙니다. 예를 들어 `native-abi` 검증이 모든 종류의
검증을 대체하지 않습니다. [`cases-73.json`](cases-73.json)은 유효한 64개 조합
(참 25개·거짓 39개)과 알 수 없는 라벨을 거절하는 9개 확장 사례를 담습니다.
원본 TypeScript의 타입 밖에서 발생할 수 있는 예외까지 보존한 포팅은 아닙니다.

[`admission.gooo`](admission.gooo)는 이 관계를 가져와 여덟 조건을 결합한
새로운 Gooo 구성입니다. 입력 `ObservationFacts`는 15개 필수 필드,
출력 `EvidenceDecision`은 허용 여부·최초 실패 이유·모든 조건의 관측값을
포함한 10개 필수 필드를 가집니다. 정확한 타입과 조건은
[`admission-contract.json`](admission-contract.json)에 있습니다.

| 조건 | 판정 |
|---|---|
| 제공자 | 호스트가 확립한 `provider_verified`가 참 |
| 관측 상태 | `confidence == "observed"`이며 `status == "pass"` |
| 검증 종류 | 실제 authority가 요구 authority를 충족 |
| 요청 연결 | 관측 binding과 요구 binding이 올바른 해시 문자열이며 동일 |
| 대상 산출물 | 관측 artifact와 요구 artifact가 올바른 해시 문자열이며 동일 |
| 정책 | 관측 policy와 요구 policy가 올바른 해시 문자열이며 동일 |
| 최신성 | 음수·미래 관측을 거절한 뒤, 관측 나이가 최대 허용 나이 이하 |
| 만료 | 현재 시각이 만료 시각보다 엄격히 작음 |

허용하려면 여덟 조건이 모두 참이어야 합니다. 여러 조건이 실패해도 출력은
모든 조건을 보여주며, 최초 이유는 표의 순서로 선택합니다. 최대 허용 나이와
같은 관측은 최신성 조건을 통과하지만, 만료 시각과 같은 현재 시각은 거절합니다.
시간 차이는 음수·순서 검사를 마친 뒤 계산하여 부호 있는 정수의 뺄셈 넘침을
피합니다.

## 재현하기

저장소 루트에서 **Go 1.27.2**, Python 3, Node.js, Git을 사용합니다.
이 예제의 Gooo 컴파일러는 `compiler-version.txt`에 고정한
`83928fa4538245abe33b08549da47f8cbdc50ed2` (`0.6.32-dev`)입니다.
기존 Studio의 컴파일러 `be4ef88cca4bc3df1e78ae91c8fe8388413f05c9`,
생성 코드와 기계 실행 게이트는 이 예제를 추가하면서 변경하지 않습니다.

아래는 컴파일러를 별도 임시 작업 트리에 만들고 새 출력 디렉터리에 기록하는
예입니다. `evidence_go`가 선택한 실행 파일은 반드시 Go 1.27.2여야 합니다.

```sh
evidence_go="$(go env GOROOT)/bin/go"
"$evidence_go" version
evidence_pin="$(cat examples/evidence-admission/compiler-version.txt)"
evidence_tools="$(mktemp -d)"
git clone --quiet --filter=blob:none --no-checkout \
  https://github.com/kimjooyoon/meta-ontology-go.git \
  "$evidence_tools/compiler-repository"
git -C "$evidence_tools/compiler-repository" fetch --quiet --depth=1 origin "$evidence_pin"
git -C "$evidence_tools/compiler-repository" worktree add --quiet --detach \
  "$evidence_tools/compiler-worktree" "$evidence_pin"
env GOTOOLCHAIN=local GOENV=off GOWORK=off GOFLAGS= CGO_ENABLED=0 \
  "$evidence_go" -C "$evidence_tools/compiler-worktree" build -trimpath \
  -o "$evidence_tools/gooo" ./cmd/gooo
python3 -I tools/verify-evidence-admission.py \
  --compiler "$evidence_tools/gooo" \
  --go "$evidence_go" \
  --out out/evidence-admission
```

다시 실행할 때는 기존 결과를 덮어쓰지 않는 새 `--out` 경로를 선택합니다.
Node.js는 보관한 TypeScript에서 순수 authority 함수 하나만 분리해 실행하며,
타입 표기와 export만 제거합니다. Rea의 설치 스크립트·전체 애플리케이션·대상
프로그램은 실행하지 않습니다. 컴파일러가 생성한 Go를 실제 실행하고 기록을
재실행하며, 모델 호출은 요구하지 않습니다.

## 무엇을 검사하는가

[`cases/admission-cases.json`](cases/admission-cases.json)의 100개 사례는
유효 authority 조합 64개와 해시 형식·시간 경계·관측 상태·복수 실패 등
36개 집중 사례입니다. 기대값 작성자는 후보 Gooo 본문이나 실제 실행 결과를
읽지 않고 입력 15개와 기대 출력 10개를 작성했습니다.
[`사례 목록`](cases/admission-case-catalog.json)에 각 사례의 목적을 기록했습니다.

검증 도구는 authority 73개와 admission 100개를 모두 유지합니다. 컴파일러의
32 KiB JSON 입력 제한을 넓히지 않고, 큰 사례 파일을 30,000바이트 이하의
배치로 나눕니다. 원본의 사례 순서와 모든 필드가 그대로 남았는지 확인하고,
각 배치의 시작 위치·사례 수·바이트 해시를 기록합니다.

실행 기록에서는 컴파일러·Go 실행 파일·소스·입력 바이트의 연결, 각 사례의
순서와 실제 입력, 10개 출력 필드 전체, 두 네이티브 실행과 전체 기록의
재실행을 검사합니다. 변조한 기록의 거절 여부도 확인합니다. 요약 숫자나
`PASS` 문자열 하나만으로 결과를 인정하지 않습니다.

실제 실행 여부와 결과는 해당 실행이 생성한 `observations.json`과
`*-execution.json`, `*-replay.json`에서 확인하세요. 계약 파일과 독립 기대값은
실행 성공의 증거가 아닙니다. CI는 캐시 재사용 없이 두 작업 공간을 실행하고
결과를 `evidence-admission-observations` 아티팩트로 보관합니다.

로컬에서만 `--authority-receipts DIRECTORY`를 추가하여 변경하지 않은
authority 작업의 `execution-73.json`·`replay-73.json`을 재사용할 수 있습니다.
입력·소스·컴파일러·Go 실행 파일과 실제 결과의 연결 검사를 모두 통과해야 하며,
보고서는 이번 호출에서 새로 실행한 작업인지 구분합니다. 이 옵션은 admission
100개 실행을 생략하지 않습니다. 기본 CI 재현 절차에는 사용하지 않습니다.

## 자동화 호스트가 맡아야 하는 경계

실제 API 정책 변경에 사용하려면 호스트가 다음 사실을 확립해야 합니다.

1. 기계 주체를 인증하고 검증 제공자를 실제 관측 경로나 검증된 자격 증명으로
   확인합니다. 호출자가 보낸 `provider_verified=true`는 제공자 인증이 아닙니다.
2. 관측 결과의 타입, 전체 필수 검증 사례, 소스·산출물·생성자와 내용을 검사합니다.
   요청 주체·요청 ID·작업·요청 revision·전체 검증 사례를 모호하지 않은 방식으로
   연결하고 관측/요구 binding을 직접 계산합니다.
3. 현재 산출물, 정책 값 전체, 요구 authority, 최대 나이와 만료 시각을 소유하고
   호스트 시계에서 `now_unix`를 얻습니다. 호출자가 요구값이나 시계를 정하면
   이 판단의 전제가 성립하지 않습니다.
4. Gooo가 근거를 허용해도 실제 게이트에서 현재 인증·실행 권한·요청 revision·
   정책 version을 같은 직렬화 경계 안에서 확인하고, 효과와 중복 실행 방지
   결과를 원자적으로 저장합니다.

`ValidDigest`는 `sha256:` 뒤의 소문자 ASCII 16진수 64자리라는 문자열 형식만
검사합니다. 해시 계산·서명 검증·제공자 인증·관측 내용의 진위 확인을 구현하지
않습니다. 일치하는 미서명 해시는 내용 일관성의 조건이며 발행자 인증이 아닙니다.
저장된 기록의 재실행도 현재 시점의 새 권한을 주지 않습니다. 이미 완료한
요청의 재시도는 원래 결과를 유지해야 합니다.

이 작업 공간은 합성된 관측 사실을 받는 순수 정책 예제입니다. 기존 인증된
기계 게이트와 아직 연결하지 않았으며, 실제 외부 API 작업이나 정책 변경을
수행하지 않습니다. 유한 사례를 통과했다는 결과로 전체 입력이나 자율 시스템의
안전을 증명하지는 않습니다.

## 출처와 라이선스

원본 TypeScript를 [`upstream/ReconstructionObligationAuthority.ts`](upstream/ReconstructionObligationAuthority.ts)에
그대로 보관했습니다. 고정 리비전과 원본 소스·라이선스 바이트의 SHA-256은
[`upstream.json`](upstream.json), 원본 관계는
[`upstream-relation.json`](upstream-relation.json)에 있습니다.

Rea에서 가져온 부분은 **MIT**, 저작권 표시는 **Copyright (c) 2026 morluto**이며
[`LICENSE-REA`](LICENSE-REA)의 원문을 함께 배포합니다. 새 Gooo 구성은 이
저장소의 [`MIT 라이선스`](../../LICENSE)를 따릅니다. Rea 전체의 원장,
프로바이더, MCP, 정규화·해시 처리까지 포팅했다는 의미는 아닙니다.
