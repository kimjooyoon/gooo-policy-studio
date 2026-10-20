# Gooo Policy Studio

## English quick start

Compare an automation policy change with the same inputs, then inspect why its
judgment changed. The core policy decisions use compiled rules from
[Gooo, an experimental language with a Go compiler](https://github.com/kimjooyoon/meta-ontology-go).
The Go host handles input validation, authentication and local storage.
The configured local machine gate makes decisions automatically under its
server-owned policy, without a person approving each request.

Choose an English walkthrough:

1. **Download and try comparison/replay without building.** The
   [fixed `policy-impact-v0.1.0-preview.1` kit](https://github.com/kimjooyoon/gooo-policy-studio/releases/tag/policy-impact-v0.1.0-preview.1)
   has archives for **macOS arm64** and **Linux amd64**. Follow the
   [kit walkthrough](docs/policy-impact-first-use.md) to verify the archive and
   run its four synthetic comparison/replay calls. It needs ZIP extraction,
   a POSIX shell and the listed standard tools; no Go, server, account or token.
   This sealed kit uses exact-equality artifact recipes and **excludes integer
   bounds and `explain`**. Read the walkthrough's build and download limits
   before running it.
2. **Try a numeric bounds preview without building.** Download the
   [fixed `policy-impact-bounds-v0.1.0-preview.1` kit](https://github.com/kimjooyoon/gooo-policy-studio/releases/tag/policy-impact-bounds-v0.1.0-preview.1)
   for **macOS arm64** or **Linux amd64**. The
   [bounds kit walkthrough](docs/artifact-bounds-first-use.md) describes the
   separately versioned `artifact-bounds/v1` profile: compare a limit change,
   delete the copied inputs, replay the report and save a private HTML
   explanation. Its three calls use the included executable and standard
   shell tools, without Go, Python, a server, account or token. The sealed kit
   above remains an equality-only walkthrough.
3. **Build the current source for integer bounds and private explanations.**
   Start with the [integer bounds example](docs/artifact-int64-bounds.md), using
   **Go 1.27.3** and **Python 3** for its copied-fixture setup. Then follow
   [the explanation walkthrough](docs/artifact-policy-explain.md) to turn the
   saved comparison into a private, local HTML explanation. Generated Gooo code
   is included; these examples need no compiler regeneration. The HTML keeps
   the historical judgments and needs no JavaScript or running server.

These paths use synthetic examples. A saved comparison, replay or explanation
preserves unsigned historical judgments; it does not grant current API/export
permission or change a running policy. The reports and HTML contain private
case values.

If your first run gets stuck, [report the problem](https://github.com/kimjooyoon/gooo-policy-studio/issues/new)
with the chosen walkthrough, OS/architecture, release or commit, and the command
and error you observed. Use minimal synthetic examples; omit tokens and complete
private reports. To explore or contribute to the language itself, start at
[meta-ontology-go](https://github.com/kimjooyoon/meta-ontology-go).

---

**Gooo 정책의 변경 영향을 재현하고, 인증된 자동화 요청을 서버 정책으로 판단하는 도구.**

같은 입력으로 현재/변경 정책을 비교하고 기대 결과를 자동 검사합니다. 별도의 기계 실행 게이트는 서버가 보관한 정책과 요청으로 로컬 상태 변경을 판단·저장하며 사람이 요청마다 승인하는 절차를 요구하지 않습니다. 기본 예제는 금액 한도·팀·활성 상태·자기 검증·제출 상태의 다섯 규칙이며, 실제 실행의 입력·결과·소스 해시를 JSON으로 확인할 수 있습니다.

업무 규칙은 **Gooo**, 서버와 실행 연결은 **Go 표준 라이브러리**, 화면은 **HTML/CSS/Vanilla JavaScript**로 구현했습니다. 웹 프레임워크, UI 라이브러리, npm 의존성, CDN, 외부 폰트가 없습니다. `go.mod`에도 외부 런타임 의존성이 없습니다.

![승인 정책 비교 화면](docs/screenshots/studio.png)

## 바로 실행하기

Go **1.27.3 이상**이 있으면 Gooo 설치 없이 실행됩니다. 생성된 코드와 웹 파일을 저장소에 포함했습니다.

```sh
git clone https://github.com/kimjooyoon/gooo-policy-studio.git
cd gooo-policy-studio
go run ./cmd/server
```

[http://127.0.0.1:8080](http://127.0.0.1:8080)에 접속하세요. 기본 요청은 750,000원이며 현재 한도 500,000원에서는 거절, 변경 한도 1,000,000원에서는 승인됩니다.

```sh
go build -trimpath -o bin/policy-studio ./cmd/server
./bin/policy-studio -addr 127.0.0.1:8080
```

`go:embed`로 웹 파일·Gooo 소스·생성 코드·생성 근거를 실행 파일에 포함합니다. 실행 파일 하나를 다른 폴더로 옮겨도 동작합니다. [Releases](https://github.com/kimjooyoon/gooo-policy-studio/releases)에서 역할별 실행 파일과 [시작 안내](docs/START-HERE.txt)를 확인하세요. 각 릴리스의 근거에서 실제 실행한 타깃과 교차 컴파일한 타깃을 구분합니다.

## Gooo로 검증 근거 판단하기

[Evidence Admission 예제](examples/evidence-admission/README.md)는 Rea의 검증 종류
호환성 판정을 Gooo로 옮기고, 관측 상태·요청 연결·산출물·정책·최신성·만료를
결합합니다. 사람의 건별 승인 없이 사용할 근거를 판단하며, 원본과 비교하는
73개 사례 및 별도로 작성한 100개 복합 사례를 실제 실행·재실행하는 CI를 제공합니다.
15개 입력과 10개 결과 전체를 검사합니다. 별도 컴파일러 리비전을 사용하는
순수 예제이며, 산출물 검증 게이트 v2에서는 그 판단을 실제 파일 관측에 연결합니다.
Studio 웹 서버·기존 v1 게이트·배포 미리보기 실행 파일에는 연결하지 않았습니다.

## Gooo로 도구 효과 범위 판단하기

[Tool Effects 예제](examples/tool-effects/README.md)는 Rea의 도구 부작용 힌트와
대상 텍스트 표시 판정을 Gooo로 옮깁니다. 힌트의 열 개 Boolean 입력은 전체
1,024개 조합을 원본과 비교합니다. 여기에 독자적 `EffectBudgetAccepts`를
구성하여 감사된 효과와 정책을 비교하고, 허용 여부·이유·열 개 조건을 반환합니다.
대상 텍스트 73개, 예산 218개 유한 사례도 전체 입력과 결과를 실행·재실행합니다.
사람의 건별 승인 조건 없이 판단하지만, 실제 도구 감사·인증·효과 제한은
호스트가 확립해야 합니다. 산출물 검증 게이트 v2에서는 감사된 로컬 상태 변경과
거절 기록의 효과 예산을 연결합니다. Studio 웹 서버와 기존 v1 게이트는 그대로입니다.

## Gooo로 필수 검증의 완료 판단하기

[`completion-check`](docs/completion-check.md)는 운영자가 별도 파일로 지정한
필수 검증 목록과 제공된 결과를 비교합니다. Rea의 다섯 상태 집계를 Gooo의
누적 활동으로 옮기고, 필수 검증의 누락·예상하지 않은 검증·완료 요약을 확인하는
독자적 `CompletionReady`를 구성했습니다. 중간의 실패·미지원·잘림·미확인 결과는
뒤따르는 성공으로 지워지지 않으며, 필수 목록을 입력에서 줄여 통과시킬 수 없습니다.

```sh
go build -trimpath -o bin/completion-check ./cmd/completion-check
./bin/completion-check --policy examples/completion-ledger/policy.json \
  --input examples/completion-ledger/input-ready.json > completion-report.json
./bin/completion-check --policy examples/completion-ledger/policy.json \
  --replay --input completion-report.json > completion-replay.json
```

Gooo 설치나 네트워크 호출 없이 최대 256개 결과를 처리하며, 각 누적 단계와
전체 결과·정책·소스 연결을 보고서에 보존합니다. 현재 정책을 다시 읽어 보고서를
재계산하므로, 필수 검증이 빠진 보고서도 거절 상태로 재현됩니다. 사람의 건별
승인 조건은 없습니다. 종료 코드 0만 다음 자동화 단계의 실행 조건으로 사용하세요.
이 명령은 제공된 검증 결과의 일관성을 검사하며, 근거의 실제 출처 인증과
실행 권한·외부 효과 제한은 호출 파이프라인이 확립해야 합니다. 산출물 검증 게이트
v2에서는 내장 생산자의 관측과 필수 검증 완료를 연결합니다. Studio 웹 서버·기존
v1 게이트와 배포된 미리보기 실행 파일에는 연결하지 않았습니다.

## 화면에서 할 수 있는 일

1. **정책 비교:** 건별 금액 한도, 같은 팀 제한, 활성 검토자 필수, 본인 승인 방지를 현재/변경 정책에 각각 설정합니다.
2. **구매 요청:** 요청자·팀·금액·제출 여부, 검토자·팀·활성 상태를 입력합니다. 한도 초과/다른 팀/본인 승인/비활성/미제출 프리셋을 제공합니다.
3. **실행 결과:** 두 정책의 승인 여부와 이유, 모든 조건의 통과 여부를 나란히 표시합니다. 입력을 바꾸면 이전 결과를 무효화하고 재실행을 안내합니다.
4. **사례 영향:** 12개 사례를 실제 API로 실행해 승인 상태가 바뀐 사례를 표시합니다. 각 사례의 상세 결과를 열 수 있습니다.
5. **실행 기록:** 최근 30개를 브라우저 `localStorage`에 저장합니다. JSON을 내려받거나 가져와 재실행합니다. 서버에는 요청·기록을 저장하지 않습니다.
6. **소스 & 근거:** 실행 파일에 들어 있는 `.gooo`, 생성된 Go, 컴파일러 JSON 기록을 열고 내려받습니다.

기본 정책의 금액은 정수 원(KRW)입니다. 외부 효과를 실행하지 않으며 실제 구매 승인·결재·송금 서비스가 아닙니다.

## API·자동화 정책의 자동 검사

`API·자동화 자동 검증` 화면에서는 사용자가 제공한 **1~256개 작업 요청**에
현재/변경 정책을 적용합니다. 담당 팀, 검증 주체의 활성 상태, 자기 검증 제한,
제출 상태와 실행 예산 한도를 기존 Gooo 활동으로 계산합니다. 검증 주체는
서비스나 정책 엔진일 수 있으며, 사람이 요청마다 승인하는 절차를 요구하지 않습니다.

각 사례의 `expected_after`에는 독립적으로 정한 기대 판단과 다섯 조건의 관측을
넣습니다. 실제 결과는 기대값과 관계없이 컴파일된 Gooo에서 계산합니다.
일곱 반환 필드를 모두 비교하고 하나라도 다르면 **FAIL**입니다. 실패하더라도
모든 사례의 실제 결과와 불일치를 담은 보고서를 제공합니다.

보고서는 새 승인·새 거절, 승인 상태를 유지한 이유 변경, 개별 조건의 변화와
승인 가능한 요청 예산 합계를 보여줍니다. 입력 순서, 사례 ID, 두 정책, 기대값,
실제 결과, 요약, Gooo 소스·생성 코드·전달 어댑터·컴파일 근거의 해시를 연결합니다.
보고서를 가져오면 모든 사례를 다시 실행하고 요약과 자동 검사 결과까지 비교합니다.
재현 일치는 기대 결과가 통과했다는 뜻과 다릅니다. FAIL 보고서도 FAIL로 재현됩니다.

브라우저 없이 CI나 자동화에서 검사할 수 있습니다. 고정된 생성 코드를 포함하므로
이 명령에 Gooo 설치나 네트워크 호출은 필요하지 않습니다.

```sh
go build -trimpath -o bin/policy-check ./cmd/policy-check
./bin/policy-check --input examples/automation-policy/impact-input.json > impact-report.json
./bin/policy-check --replay --input impact-report.json > impact-replay.json
```

실행 파일의 종료 코드는 **0: 모든 유한 기대값 일치**, **1: 완전한 보고서의
기대값 불일치**, **2: 입력·실행·출력 오류**입니다. `go run`을 사용하면 Go 실행기가
프로그램의 1/2 종료를 모두 자신의 비정상 종료로 전달할 수 있습니다.
예제는 실제 고객 자료가 아닌, 별도로 작성한 다섯 개의 합성 API·자동화 사례입니다.

| HTTP 경로 | 본문 | 크기 제한 | 결과 |
| --- | --- | --- | --- |
| `POST /api/impact/corpus` | `{"cases": [...]}` | 256 KiB | 전체 사례의 형식과 범위를 검증, 규칙 실행 없음 |
| `POST /api/impact` | `policy-studio/impact-input/v1` | 1 MiB | 모든 실제 결과와 자동 검사 보고서; 불일치도 관측 결과로 반환 |
| `POST /api/impact/check` | 같은 입력 | 1 MiB | 자동화용 검사; 일치 시 200, 불일치 시 완전한 FAIL 보고서와 **409** |
| `POST /api/impact/replay` | `policy-studio/impact-report/v1` | 4 MiB | 모든 입력·관측·근거·요약·검사를 다시 확인 |

모든 JSON 필드는 정확한 이름과 타입으로 제공해야 합니다. 생략·null·중복 키,
대소문자 별칭, 잘못된 UTF-8, 짝 없는 UTF-16 escape, 16단계 초과 중첩을 거절합니다.
사례 ID는 중복 없는 1~80바이트 ASCII 식별자이고, 도메인 텍스트는 최대 120 UTF-8
바이트, 예산과 한도는 기존 정수 원 범위입니다. 최대 256건의 예산 합계도 JavaScript의
정확한 정수 범위 안에 있습니다. 가져온 파일의 원문을 서버에서 검사하므로
브라우저가 중복 키를 먼저 덮어쓰지 않습니다.

서버는 사례나 보고서를 저장하지 않으며, 배치 화면도 이를 `localStorage`에
자동 보관하지 않습니다. 내려받은 보고서에는 제공한 사례와 기대값이 모두 포함됩니다.
브라우저에서 새 입력으로 바꾸면 이전 결과를 무효화하며, 뒤늦게 끝난 작업이
새 입력을 덮어쓰거나 오래된 보고서를 현재 결과로 내려받지 않도록 합니다.

사람의 건별 확인을 제거하려면 자동 검사에 사용할 제약과 실패 처리를 명시해야 합니다.
이 기능은 **제공된 유한 사례의 회귀 검사**를 수행합니다. 아직 임의의 입력에 대한
안전 증명, 실제 API 인증·권한, 최신성, 외부 작업의 원자성·중복 실행 방지를 구현하지
않습니다. 해시는 내용 일관성과 재현성을 검사하며 발행자를 인증하는 서명이 아닙니다.
전체 보고서를 일관되게 다시 만든 제3자의 진위를 구분하지 못합니다.

## 사람이 건별 승인하지 않는 로컬 실행 게이트

별도의 `policy-gate` 실행 파일은 인증된 자동화 주체가 **서버에 보관된 정책과
요청**으로 로컬 요청 상태를 바꾸도록 합니다. API 호출자는 요청 ID, 기대한
요청 revision과 정책 version, idempotency key만 보냅니다. 정책·팀·금액·
검증 주체를 호출자가 덮어쓸 수 없습니다. Gooo가 허용한 전이와 결과 기록을
같은 영속 상태에 저장하며, 같은 명령의 재시도는 재시작 뒤에도 원래 결과를
돌려줍니다. 인증·권한·버전 검사가 실패하면 해당 전이를 거절하고,
저장 결과가 불확실하면 그 프로세스의 추가 실행을 중단합니다.

실행 효과는 로컬 상태의 `pending → approved` 전이 하나입니다. 외부 API 작업이나
송금을 실행하지 않습니다. [초기 설정·API·저장 경계와 검증 범위](docs/machine-gate.md)를
확인하세요. 기존 Studio의 사례 PASS나 저장된 보고서는 실행 권한을 주지 않습니다.

명시적으로 선택하는 [산출물 검증 게이트 v2](docs/artifact-gate.md)는 이 흐름에
실제 파일 검증을 연결합니다. 운영자가 지정한 SHA-256·스키마·필드 조건으로
파일을 직접 읽고, 필수 검증 1~256개의 관측·출처·유효기간·완료 여부와
승인 및 거절 기록의 효과 예산을 Gooo에서 판단합니다. 호출자는 성공 결과나
시각·경로·예산을 제출할 수 없습니다. 판단에 사용한 바이트와 각 결과를 보존하여
파일이 사라진 뒤에도 과거 결과를 재현합니다. 기본 정책이 거절하면 파일은 읽지
않습니다. 현재 소스에서 빌드하는 기능이며 기존 배포 미리보기에는 포함되지 않습니다.

[`policy-client`](docs/policy-client.md)는 v2 서버의 실제 상태로 네 필드의 명령을
먼저 저장하고, 제출·재시도에 그 원문을 그대로 사용합니다. 토큰은 비공개 파일에서
읽고 기본 출력은 판단 요약만 표시합니다. 응답이 끊겨도 새 키나 revision으로
자동 재실행하지 않습니다. [두 요청 예제](examples/gate-client/README.md)에서
승인과 산출물 변경의 거절, 같은 명령의 재시도를 직접 실행할 수 있습니다.

## 같은 산출물로 두 검증 정책의 영향 비교하기

[`policy-impact compare`](docs/artifact-policy-impact.md)는 산출물을 한 번 읽어
두 제안 정책에 적용합니다. 필수 조건·효과 예산이 달라질 때 새 허용과 새 거절,
추가·삭제·변경된 검증을 보여주며 양쪽의 전체 Gooo 판단을 비공개 보고서에 남깁니다.
[실행 예제](examples/artifact-impact/README.md)는 같은 내보내기 계획의 목적지
조건을 바꾸고 순서를 반대로 비교하여 허용 범위의 확대도 확인합니다.

운영자가 제공한 요청·주체·두 정책의 로컬 시뮬레이션이며, 실행 권한을 부여하거나
기존 게이트의 정책을 변경하지 않습니다. 종료 코드 0은 비교 보고서가 저장되었다는
뜻입니다. 실제 자동화 요청은 기존 v2 게이트가 인증된 서버 상태와 Gooo 규칙으로
판단하며, 건별 사람 승인 절차를 추가하지 않습니다. 기존 `policy-studio`,
`policy-check`, `policy-gate` 배포 미리보기에는 이 명령이 포함되지 않습니다.
아래 체험 패키지는 별도의 `policy-impact` 실행 파일을 제공합니다.

[`policy-impact replay --report FILE`](docs/artifact-policy-replay.md)는 저장된
비교 보고서의 바이트·관측 시각으로 양쪽의 모든 판단을 다시 확인합니다. 원래
산출물이나 요청·정책 파일을 다시 열지 않으므로 파일 삭제 후에도 검증할 수
있습니다. 성공은 과거 기록의 내부 일관성을 뜻하며 현재 실행 권한이나 서명 없는
기록의 진위를 보증하지 않습니다. 보고서를 만든 Go 버전·운영체제·구조와 비교
구현이 일치해야 하며, 원본 입력 JSON의 바이트는 보존되지 않아 그 해시의 원문을
확인할 수는 없습니다.

[`policy-impact explain`](docs/artifact-policy-explain.md)은 저장된 비교 전체를
검증한 뒤 비공개 HTML로 판단 이유를 보여줍니다. 양쪽의 필수 조건·증거 유효기간·
완료 상태·효과 예산을 함께 확인하며, 기존 정책이나 현재 실행 권한을 변경하지
않습니다. 이 기능은 현재 소스에서 빌드해 사용합니다.

[빌드 없이 실행하는 체험 패키지](docs/policy-impact-first-use.md)는 macOS ARM64와
Linux AMD64용 비교·재현 명령, 공개 합성 입력, 출처와 라이선스를 묶습니다.
별도 Go 설치 없이 같은 산출물의 목적지 정책을 양방향으로 비교하고, 복사한 입력을
삭제한 뒤 저장된 보고서를 재현합니다. 실제 시스템의 실행 권한을 부여하지 않는
시뮬레이션이며, 플랫폼·빌드 정보와 다운로드 보안 관련 제한은 안내문을 확인하세요.

## Gooo로 정수 범위 조건 판단하기

[정수 범위 예제](docs/artifact-int64-bounds.md)는 같은 내보내기 계획에서
`row_limit == 500` 대신 `0 ≤ row_limit ≤ 500`을 두 필수 조건으로 검증합니다.
Gooo가 정수 비교·통과 여부·이유를 계산하며, 모든 입력·다섯 결과·생성 근거를
보고서에 남깁니다. 타입이나 파일 무결성 검사가 실패하면 숫자 판단을 실행하지
않습니다. 상한을 1000에서 500으로 변경하면 이 예제의 501인 입력은 새로 거절되고,
그 판단은 저장된 바이트로 재현할 수 있습니다.

새 recipe v2는 기존 자동 게이트·비교·재현에 연결됩니다. 건별 사람 승인 절차를
추가하지 않습니다. 이전 소스의 보고서·실행 상태는 원래 바이너리와 보존하거나
새 설정으로 시작해야 하며 자동 변환하지 않습니다. 기존
`policy-impact-v0.1.0-preview.1` 체험 패키지는 이전 동등 비교 버전입니다.
이 기능은 위 안내에 따라 새 소스에서 빌드해 사용하세요.

## Gooo와 Go가 각각 구현한 부분

| 기능 | 원본 소유자 | 파일 | 구체적 역할 |
|---|---|---|---|
| 도메인 스키마 | Gooo | [`policy/approval.gooo`](policy/approval.gooo) | Request, Reviewer, Policy, Decision, Change의 필드·타입·안정 ID |
| 승인 조건 | Gooo | 같은 파일의 `Evaluate` | 제출, 활성, 자기 승인, 팀, 한도 조건의 계산 |
| 거절 이유 | Gooo | `Evaluate` | 다중 실패에서 최초 이유의 우선순위 결정 |
| 조건별 관측 | Gooo | `Evaluate` | `submitted_ok` 등 5개 불리언 결과를 반환 |
| 정책 변화 분류 | Gooo | `Compare` | 새 승인/새 거절/승인 상태 유지, 이유 변경 여부 |
| 실제 업무 규칙 실행 | Gooo에서 생성된 Go | [`rules_generated.go`](internal/policy/rules_generated.go) | Gooo가 타입 검사·생성한 함수가 네이티브 Go 코드로 실행 |
| 컴파일러 연결 | 수작업 Go | [`cmd/generate/main.go`](cmd/generate/main.go) | 두 활동을 컴파일, 타입 중복 제거, 생성 영역 보존, 기록 저장 |
| JSON 타입 전달 | 메타데이터에서 생성된 Go | [`bridge_generated.go`](internal/policy/bridge_generated.go) | 사람이 읽는 HTTP 타입 ↔ 안정 ID 기반 생성 타입, 업무 조건 없음 |
| API 입출력 타입 | 수작업 Go | [`policy.go`](internal/policy/policy.go) | HTTP 경계용 구조체, 금액 범위·문자열 입력 검증 |
| 실행 기록·재실행 | 수작업 Go | 같은 파일 | 소스/코드/기록 SHA-256 계산, 현재 출처 비교, 입력 재실행과 결과 비교 |
| 기계 권한·영속 상태 전이 | 수작업 Go | [`store.go`](internal/admission/store.go) | 인증·정책/요청 최신성 확인, Gooo 판단 호출, 단일 writer·원자적 저장·원래 결과 재시도 |
| 기계 API 경계 | 수작업 Go | [`server.go`](internal/gatehttp/server.go) | Bearer 인증 경계, 정확한 명령 JSON·오류 코드, 로컬 실행 게이트 라우트 |
| HTTP·JSON 경계 | 수작업 Go | [`server.go`](internal/httpapp/server.go), [`json.go`](internal/httpapp/json.go) | 라우팅, 크기 제한, 필수 필드·null·중복 키·타입 검증, 동일 출처 제한 |
| 서버 수명 | 수작업 Go | [`cmd/server/main.go`](cmd/server/main.go) | 주소 설정, HTTP 시간 제한, 종료 신호·graceful shutdown |
| 정적 파일 배포 | Go | [`web/embed.go`](web/embed.go) | HTML/CSS/JS를 바이너리에 포함하고 표준 파일 서버로 제공 |
| 화면 구조·스타일 | HTML/CSS | [`index.html`](web/index.html), [`style.css`](web/style.css) | 반응형 폼, 정책 카드, 결과 표, 모바일 내비게이션 |
| 화면 동작 | Vanilla JS | [`app.js`](web/app.js) | 폼 수집, API 호출, 결과 표시, 프리셋·기록·파일 내보내기 |
| 독립 기대값 검증 | 수작업 Go 테스트 | [`policy_test.go`](internal/policy/policy_test.go) | 승인 조건의 독립 오라클, 이유·경계·변경·재실행 검증 |

**Go나 JavaScript에서 승인 규칙을 다시 구현하지 않습니다.** 브라우저는 표시 문구와 사례 입력을 만들지만 승인 여부를 계산하지 않습니다. 수작업 Go는 입력을 검증하고 생성 함수를 호출합니다. 테스트에만 별도의 기대값 오라클이 있습니다.

### Gooo 구현 상세

원본의 `Evaluate(Request, Reviewer, Policy) -> Decision`은 세 레코드를 받습니다.

```text
amountOK    = request.amount <= policy.limit
teamOK      = !policy.same_team || request.team == reviewer.team
reviewerOK  = !policy.active_reviewer || reviewer.active
selfOK      = !policy.prevent_self || request.requester != reviewer.key
submittedOK = request.submitted
approved    = submittedOK && reviewerOK && selfOK && teamOK && amountOK
```

위 조건은 설명용 표현이며 실제 구현은 `.gooo`의 `computes` 안에 있습니다. 비활성화한 규칙은 통과하며 제출 조건은 항상 필수입니다. 여러 조건이 실패하면 **미제출 → 검토자 비활성 → 본인 승인 → 팀 불일치 → 금액 초과** 순으로 최초 거절 이유를 정합니다. 첫 실패만 이유로 선택하되 다른 조건의 관측도 모두 보존합니다.

`Compare(Decision, Decision) -> Change`는 승인 상태를 비교해 `NEWLY_APPROVED`, `NEWLY_DENIED`, `UNCHANGED`를 반환합니다. 승인 상태가 같아도 거절 이유가 바뀌면 `reason_changed`가 true입니다.

엔티티와 필드에는 `policy://…` 안정 ID가 있습니다. 컴파일러는 ID에서 생성한 Go 타입/필드 이름을 사용하고 JSON 태그는 읽기 쉬운 Gooo 필드 이름을 유지합니다. 예를 들어 `amount`는 Go `int64`, `active`는 `bool`로 생성됩니다. 상세 이름은 생성 파일에서 확인할 수 있습니다.

이 버전은 **명시적으로 작성한 순수 활동 본문을 보존하는 결정론 생성 경로**를 사용합니다. 모델 추론, 학습, 후보 합성은 실행하지 않습니다. 생성 기록의 `PASS`는 해당 컴파일러의 제한된 타입 검사·생성·재생 검사 결과이며 모든 입력의 업무 정확성을 뜻하지 않습니다.

### Go 구현 상세

- `net/http`의 메서드별 `ServeMux` 라우트와 `http.FileServerFS`로 서버를 구성합니다.
- `encoding/json`으로 전달하며 생성 어댑터는 JSON 필드명을 통해 입출력 타입을 연결합니다. 이 방식은 직접 필드 매핑보다 비용이 있지만 ID 기반 이름에 의존하는 수작업 코드를 없앱니다. 성능 우위를 주장하지 않습니다.
- 건별 `/api/simulate`·`/api/replay` 입력은 필수 필드가 모두 있어야 합니다. 중복 키, null, 알 수 없는 필드, 소수 금액, JSON 객체 여러 개, 128KiB 초과 입력은 거부합니다. 배치 경로의 한도는 위 표와 같습니다.
- 금액/한도는 `0..9,000,000,000,000` 정수입니다. JavaScript 안전 정수 범위 안에서 브라우저와 Go 값을 일치시킵니다. 이름·팀·요청 ID는 공백만 있는 값과 120바이트 초과 값을 거부합니다.
- 기록은 JSON을 정규 Go 구조체로 직렬화해 SHA-256을 계산합니다. ID 계산 시 ID 자신은 빈 문자열입니다. 시각은 UTC RFC3339Nano이며 화면에서 브라우저 현지 시각으로 표시합니다.
- 재실행 시 스키마·범위·기록 해시, 현재 Gooo 소스/생성 코드 해시, 컴파일러 출처와 결과를 확인합니다. 새 기록에는 새 실행 시각과 ID가 부여됩니다.
- 해시는 **전자서명이 아닙니다**. 파일 작성자가 입력과 해시를 함께 바꿀 수 있습니다. 따라서 이는 발급자 인증이 아닌 내용 일관성과 현재 코드에서의 재현 확인입니다.
- Studio 서버(`cmd/server`)는 기본 `127.0.0.1` 바인딩이며 `-addr`로 주소를 바꿀 수 있습니다. 이 시뮬레이터 서버에는 인증·TLS·영구 감사 저장이 없습니다. 별도 기계 게이트(`cmd/policy-gate`)는 Bearer 인증과 영속 상태를 구현하며 리터럴 loopback IP만 허용합니다. 게이트의 계약은 [별도 안내](docs/machine-gate.md)에 있습니다.

### 화면 구현 상세

외부 라이브러리 없이 시맨틱 HTML, CSS Grid/Flex와 DOM 이벤트를 사용합니다. 체크박스가 정책 토글 역할을 하며 네이티브 폼 검증을 사용합니다. 요청자 입력은 HTML에 넣기 전에 이스케이프하고 소스 표시는 `textContent`로 처리합니다. 서버는 CSP로 자체 스크립트·스타일만 허용합니다.

모바일에서는 사이드바가 상단 메뉴로 전환되고 정책/요청 카드가 한 열로 배치됩니다. 표는 필요한 영역만 가로 스크롤합니다. `aria-live` 실행 알림, 라벨 연결, 키보드 포커스와 reduced-motion 설정을 제공합니다.

실행 중 입력이 바뀌면 이전 요청 결과를 현재 폼의 결과로 표시하지 않습니다. 이전 요청의 실행은 기록에 남기고 재실행을 안내합니다. 사례 비교 도중 정책이 바뀌어도 이전 정책의 표를 새 정책 결과로 표시하지 않습니다.

## 소스에서 실행까지

```mermaid
flowchart LR
  A[approval.gooo] --> B[Gooo 타입 검사 · body-codegen]
  B --> C[생성된 Go 규칙 · 타입]
  B --> D[생성 근거 JSON]
  C --> E[Go 빌드 · 단일 실행 파일]
  F[HTML · CSS · Vanilla JS] --> E
  G[브라우저 입력] --> H[Go HTTP · 입력 검증]
  H --> I[Evaluate 현재 · Evaluate 변경]
  I --> J[Compare]
  J --> K[실행 기록 · 전후 결과]
  K --> G
```

1. Gooo의 `Evaluate`, `Compare`를 각각 `body-codegen --json`으로 생성합니다.
2. 생성 도구가 중복 엔티티 타입을 한 번만 포함하고 원래 생성 영역 마커와 함수 본문을 유지합니다.
3. 컴파일러의 `record_types` 메타데이터로 전달 어댑터를 생성합니다.
4. 원본/생성 코드/어댑터 해시와 컴파일러 정체성·활동별 원본 응답을 저장합니다.
5. 일반 Go 빌드가 규칙과 웹 파일을 실행 파일에 포함합니다. 서버 실행 중 컴파일러·모델·셸 명령을 호출하지 않습니다.
6. 브라우저 요청마다 두 번의 `Evaluate`와 한 번의 `Compare`를 실제로 실행합니다.

웹 UI에서 수정하는 것은 **정책 매개변수**입니다. Gooo 본문이나 규칙 우선순위를 수정하려면 아래 재생성·테스트·재빌드가 필요합니다. 브라우저에서 임의 Gooo/Go 코드를 컴파일하는 기능은 없습니다.

## Gooo 코드 재생성

컴파일러 리비전은 [`tools/compiler-version.txt`](tools/compiler-version.txt)의 **`be4ef88cca4bc3df1e78ae91c8fe8388413f05c9`**로 고정합니다. 컴파일러 자체의 요구사항은 **Go 1.27.2**입니다. `GOTOOLCHAIN=auto` 환경에서는 Go가 해당 도구체인을 준비합니다.

깨끗한 Git 체크아웃에서 컴파일러를 빌드해야 버전 기록에 정확한 소스 SHA가 들어갑니다. `go install …@SHA`로 빌드하면 모듈 버전은 고정돼도 이 컴파일러가 VCS 출처를 `UNBOUND_LOCAL_SOURCE`로 기록할 수 있으므로, 이 도구는 그런 컴파일러를 거부합니다.

```sh
mkdir -p .tools
git clone --filter=blob:none https://github.com/kimjooyoon/meta-ontology-go.git .tools/compiler
git -C .tools/compiler checkout "$(cat tools/compiler-version.txt)"
go -C .tools/compiler build -o "$(pwd)/.tools/gooo" ./cmd/gooo

go run ./cmd/generate --compiler .tools/gooo
go test -race ./...
go vet ./...
```

프로젝트 루트에서 실행하세요. 도구는 외부 `GOOO_LAYA_URL` 설정을 전달하지 않으며 결정론 경로를 유지합니다. 수정한 컴파일러는 출처 SHA가 고정 리비전과 일치하지 않아 거부됩니다.

다음 명령은 파일을 쓰지 않고 Gooo에서 다시 생성한 코드·어댑터·내장 소스가 현재 파일과 같은지 확인합니다.

```sh
go run ./cmd/generate --compiler .tools/gooo --check
```

`generation.json`에는 생성 환경/컴파일러 기록이 포함되므로 다른 OS에서 JSON 전체의 바이트 일치를 요구하지 않습니다. `--check`는 실행 코드와 소스 사본의 바이트 일치를 검증하고 현재 컴파일러의 PASS·소스 SHA를 확인합니다. 저장된 근거 JSON의 파일 연결은 별도의 Go 테스트가 검사합니다.

생성 도구가 관리하는 파일은 다음과 같습니다. 직접 수정하지 마세요.

- `internal/policy/rules_generated.go`: 컴파일러가 생성한 레코드와 두 함수
- `internal/policy/bridge_generated.go`: 메타데이터 기반 타입 전달 어댑터
- `internal/policy/approval.gooo`, `generated.txt`: 실행 파일에 넣는 원본/생성 코드 사본
- `evidence/generation.json`, `internal/policy/generation.json`: 활동별 원본 응답과 해시·컴파일러 정체성

## API

| 메서드 | 경로 | 역할 |
|---|---|---|
| GET | `/api/source` | 내장 Gooo·생성 Go·생성 근거 |
| POST | `/api/simulate` | 요청·검토자·두 정책 실행, 실행 기록 반환 |
| POST | `/api/replay` | 실행 기록의 출처와 내용 검증 후 실제 재실행 |
| GET | `/`, `/app.js`, `/style.css` | 내장 정적 화면 |

POST는 `Content-Type: application/json`을 사용합니다.

```sh
curl http://127.0.0.1:8080/api/simulate \
  -H 'Content-Type: application/json' \
  -d '{
    "request":{"key":"REQ-1","requester":"김민수","team":"제품팀","amount":750000,"submitted":true},
    "reviewer":{"key":"이지원","team":"제품팀","active":true},
    "before":{"limit":500000,"same_team":true,"active_reviewer":true,"prevent_self":true},
    "after":{"limit":1000000,"same_team":true,"active_reviewer":true,"prevent_self":true}
  }' > receipt.json

curl http://127.0.0.1:8080/api/replay \
  -H 'Content-Type: application/json' --data-binary @receipt.json
```

재실행 응답의 `matched: true`와 `receipt`를 확인하세요. 입력 형식 오류는 400, Content-Type 오류는 415, 유효하지 않은 도메인 입력/기록은 422, 교차 출처 요청은 403입니다.

## 검증 범위

```sh
go test -race ./...
go vet ./...
node --check web/app.js
```

- **256개 조합:** 다섯 조건의 32개 조합 × 정책 토글의 8개 조합을 별도 Go 오라클과 비교합니다. 승인 상태와 동일 정책의 변경 없음 여부를 확인합니다.
- **13개 명시적 도메인 사례:** 한도 일치·초과·0원, 비활성·팀·본인 승인 제한과 완화, 미제출 우선순위, 더 엄격한 정책, 승인 상태가 같은 이유 변경을 확인합니다.
- **기록:** 정상 재실행, 내용 해시 불일치, 다시 해시한 잘못된 결과, 다른 소스의 기록을 확인합니다.
- **파일 연결:** 원본 Gooo, 실제 생성 파일, 어댑터, 내장 사본과 생성 근거 해시를 확인합니다.
- **HTTP:** 실제 핸들러에서 정상 실행/재실행, JSON 누락·중복·null·소수·음수·알 수 없는 필드·과대 입력, 정적 파일·CSP·출처를 확인합니다.

화면의 **12개 사례 영향 비교**는 사용자가 설정한 정책을 관찰하는 기능이며 위 자동 테스트와 별개입니다. 한도가 0 또는 최대값이면 경계 사례 일부가 같은 값으로 제한됩니다. 어느 점수도 모든 문자열·금액·업무 정책에 대한 정확성을 뜻하지 않습니다.

GitHub Actions는 형식·vet·race 테스트·바이너리 빌드·JS 문법 검사 후 고정 Gooo로 소스의 생성 코드 일치를 확인합니다. 태그 릴리스는 테스트 후 Linux/macOS/Windows 바이너리와 SHA256SUMS를 게시합니다.

실제 브라우저 확인과 환경별 관측은 [검증 기록](docs/verification.md)에 정리했습니다.

## 저장소 구조

```text
policy/approval.gooo          업무 의미의 원본
cmd/generate/                Gooo 컴파일·메타데이터 전달 도구
cmd/server/                  표준 HTTP 서버 실행
internal/policy/             생성된 규칙·어댑터, 기록·재실행
internal/httpapp/            HTTP 라우트·엄격한 JSON 경계
web/                         순수 HTML/CSS/JS + embed
evidence/generation.json    실제 컴파일러 출력과 출처
tools/compiler-version.txt  고정 컴파일러 SHA
docs/screenshots/           실제 웹 화면
.github/workflows/          검증·릴리스
```

## 현재 범위와 다음 확장

이 프로젝트는 이름·팀 문자열, 정수 원, 불리언 상태로 표현되는 단일 요청 정책을 다룹니다. 자유로운 자연어 정책 해석, AI 선택, 여러 단계 결재, 사용자 인증, DB, 서명된 감사 기록, 실제 외부 효과는 구현하지 않았습니다. 문자열 비교는 Gooo의 정확한 동등 비교이며 조직 ID 정규화나 권한 시스템을 대신하지 않습니다.

다음 확장은 Gooo 규칙에 대한 별도 사례·생성·실행 근거를 추가하는 방식으로 진행할 수 있습니다. 예: 품목/팀별 한도, 2인 검토 규칙, 변경 정책의 버전 저장. 우선 새로운 실제 업무 사례를 확보하고 현재와 같은 전후 비교를 유지합니다.

Gooo 자체의 언어·실험 범위는 [meta-ontology-go](https://github.com/kimjooyoon/meta-ontology-go)에서 확인하세요.

MIT License.
