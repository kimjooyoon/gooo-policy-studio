# 명령을 준비하고 그대로 재시도하기

`policy-client`는 실제 산출물 검증 게이트 **v2**의 로컬 클라이언트입니다.
토큰 파일을 직접 읽고, 서버에서 읽은 정책 version과 요청 revision으로 명령을
먼저 저장합니다. 제출과 재시도는 그 파일의 원문을 그대로 사용합니다.
사람에게 건별 승인을 묻지 않으며, 허용 여부는 기존 서버의 Gooo가 판단합니다.
현재 소스에서 빌드하는 기능입니다. 기존 배포 미리보기에는 포함되지 않습니다.

두 명령의 역할은 다음과 같습니다.

| 명령 | 실제 동작 | 성공의 의미 |
| --- | --- | --- |
| `prepare` | 인증된 `GET /api/state`로 선택한 pending 요청을 읽고 새 명령 파일을 저장 | 파일 준비 완료. 요청을 승인하거나 제출하지 않음 |
| `submit` | 저장된 네 필드의 원문을 `POST /api/admit`으로 한 번 전송 | 서버의 승인 또는 거절 결과 수신 |

`submit`은 상태를 다시 읽거나 새 키를 만들지 않습니다. 연결이 끊기면 성공·거절을
추정하지 않고 종료 코드 2를 반환합니다. 원래 명령 파일을 보존한 뒤 같은 명령으로
명시적으로 다시 `submit`해야 합니다. 서버는 동일 주체·키·내용의 저장된 결과를
돌려줍니다. 과거 승인의 재현은 현재 시각에 새 작업을 허용했다는 뜻이 아닙니다.

## 처음부터 실행하기

Go 1.27.2 이상으로 저장소 루트에서 두 실행 파일을 빌드합니다. 새 데모 디렉터리를
만들고 합성 입력만 복사합니다. 이미 존재하는 데모 디렉터리를 덮어쓰지 마세요.

```sh
go build -trimpath -o bin/policy-gate ./cmd/policy-gate
go build -trimpath -o bin/policy-client ./cmd/policy-client
mkdir -m 700 -p "$HOME/.local/state/gooo-policy-studio"
mkdir -m 700 "$HOME/.local/state/gooo-policy-studio/client-demo"
cp examples/gate-client/*.json "$HOME/.local/state/gooo-policy-studio/client-demo/"
./bin/policy-gate \
  -init "$HOME/.local/state/gooo-policy-studio/client-demo/bootstrap.json" \
  -state "$HOME/.local/state/gooo-policy-studio/client-demo/state" \
  -token-file "$HOME/.local/state/gooo-policy-studio/client-demo/client.token"
./bin/policy-gate \
  -state "$HOME/.local/state/gooo-policy-studio/client-demo/state" \
  -addr 127.0.0.1:8092
```

마지막 명령은 서버를 실행하므로 다음 명령은 다른 터미널의 같은 저장소에서
실행합니다. 토큰은 초기화 명령이 만든 0600 파일에만 보관하며 출력하지 않습니다.

```sh
./bin/policy-client prepare \
  --server http://127.0.0.1:8092 \
  --token-file "$HOME/.local/state/gooo-policy-studio/client-demo/client.token" \
  --request-id req-client-allow \
  --idempotency-key client-allow-1 \
  --command-file "$HOME/.local/state/gooo-policy-studio/client-demo/allow.command.json"
./bin/policy-client submit \
  --server http://127.0.0.1:8092 \
  --token-file "$HOME/.local/state/gooo-policy-studio/client-demo/client.token" \
  --command-file "$HOME/.local/state/gooo-policy-studio/client-demo/allow.command.json"
./bin/policy-client submit \
  --server http://127.0.0.1:8092 \
  --token-file "$HOME/.local/state/gooo-policy-studio/client-demo/client.token" \
  --command-file "$HOME/.local/state/gooo-policy-studio/client-demo/allow.command.json"
```

첫 제출은 `200` 승인, 같은 파일의 다음 제출은 원래 승인 결과의 재시도입니다.
결과 ID는 같으며 `replayed`만 달라집니다. `prepare`로 새 명령을 다시 만들지 않습니다.
명령 파일에는 `request_id`, `expected_revision`, `policy_version`, `idempotency_key`
네 필드만 있습니다. 토큰·파일 경로·검증 결과·예산을 명령에 넣을 수 없습니다.

## 파일이 변경된 요청의 거절

데모의 두 요청은 처음에는 동일한 유효 산출물과 예상 SHA-256을 가집니다.
두 번째 명령을 먼저 준비한 뒤 **새 데모 디렉터리의 복사본**을 변경합니다.
기존 산출물 예제나 실행 중인 서버의 snapshot은 수정하지 않습니다.

```sh
./bin/policy-client prepare \
  --server http://127.0.0.1:8092 \
  --token-file "$HOME/.local/state/gooo-policy-studio/client-demo/client.token" \
  --request-id req-client-deny \
  --idempotency-key client-deny-1 \
  --command-file "$HOME/.local/state/gooo-policy-studio/client-demo/deny.command.json"
cp "$HOME/.local/state/gooo-policy-studio/client-demo/artifact-changed.json" \
  "$HOME/.local/state/gooo-policy-studio/client-demo/artifact-deny.json"
./bin/policy-client submit \
  --server http://127.0.0.1:8092 \
  --token-file "$HOME/.local/state/gooo-policy-studio/client-demo/client.token" \
  --command-file "$HOME/.local/state/gooo-policy-studio/client-demo/deny.command.json"
./bin/policy-client submit \
  --server http://127.0.0.1:8092 \
  --token-file "$HOME/.local/state/gooo-policy-studio/client-demo/client.token" \
  --command-file "$HOME/.local/state/gooo-policy-studio/client-demo/deny.command.json"
```

SHA-256이 설정과 다르므로 첫 제출은 저장된 `403 policy_denied` 결과를 반환합니다.
다음 제출도 같은 결과 ID의 원래 거절을 돌려줍니다. 두 명령 모두 종료 코드는 1입니다.

## 결과와 종료 코드

기본 출력은 HTTP 상태, 승인·거절·충돌·실패 구분, 재시도 여부, 결과 ID,
Gooo 이유와 검증 수의 요약입니다. 토큰, 인증 헤더, 원문 산출물, 개별 조건의
값은 출력하지 않습니다. 오류 응답의 임의 텍스트도 그대로 출력하지 않습니다.

| 종료 코드 | 의미 |
| --- | --- |
| `0` | `prepare`의 파일 저장 성공 또는 `submit`의 `200` 로컬 승인·원래 승인 재현 |
| `1` | `submit`의 `403 policy_denied`와 저장된 거절 결과 |
| `2` | 인증·권한·충돌·서버 불가·형식·로컬 파일·연결·출력 오류. 승인 성공으로 처리하지 않음 |

`401 unauthorized`, `403 forbidden`, `409 conflict`, `503 unavailable`은 정책 거절과
구분합니다. 연결·파일 쓰기·출력 오류는 이미 저장된 서버 결과의 유무를 단정하지
못합니다. 명령 파일과 키를 보존하고 실제 상태·결과로 복구해야 합니다.

전체 응답을 보관할 때만 `submit`에 `--report-file`과 **새 경로**를 지정합니다.
파일은 0600으로 배타적으로 생성하며 기존 보고서를 덮어쓰지 않습니다.
보고서는 실제 산출물 바이트·조건 값·주체·정책 판단을 포함할 수 있는 비공개 자료입니다.
보고서 저장 실패도 코드 2이며, 서버에서 처리된 명령을 되돌리지 않습니다.
보고서 경로는 제출 전에 예약합니다. 연결·응답 검사 실패로 비어 있는 파일이
남아도 자동 삭제하지 않습니다. 다시 제출할 때는 보고서 옵션을 빼거나 새 보고서
경로를 사용하며, 원래 명령 파일은 그대로 유지합니다.

```sh
./bin/policy-client submit \
  --server http://127.0.0.1:8092 \
  --token-file "$HOME/.local/state/gooo-policy-studio/client-demo/client.token" \
  --command-file "$HOME/.local/state/gooo-policy-studio/client-demo/allow.command.json" \
  --report-file "$HOME/.local/state/gooo-policy-studio/client-demo/allow.private-report.json"
```

## 연결과 신뢰 경계

클라이언트는 명시적인 `http://127.0.0.1:<port>` 또는 `http://[::1]:<port>`와 같은
리터럴 loopback IP·유효 포트만 허용합니다. DNS 이름, 원격 주소, URL 자격증명,
경로 접두사, query·fragment를 거절합니다. 환경 프록시를 사용하지 않고
리다이렉트를 따라가지 않으며 응답 크기와 실행 시간을 제한합니다.

토큰은 지원하는 Linux·macOS 로컬 파일 시스템의 0600 일반 파일에서만 읽습니다.
토큰 파일의 symlink, FIFO, 읽기 중 교체·변경, 잘못된 64자리 소문자 16진 토큰을
거절합니다. 운영자가 선택한 부모 디렉터리의 별칭은 한 번 해석한 뒤 열린
디렉터리에 고정하고 읽기·쓰기 중 물리 경로의 교체 여부를 확인합니다.
새 명령·보고서는 파일과 부모 디렉터리를 동기화한 뒤 저장 완료로 처리합니다.
지원하지 않는 파일 시스템의 동기화나 잠금 보장은 제공하지 않습니다.

준비 파일은 네 필드의 명령을 고정하지만 서버·세션·주체를 암호학적으로 인증하는
증명은 아닙니다. 운영자가 로컬 서버 주소와 자격증명을 선택하며 서버가 권한,
정책·출처·revision과 원래 명령을 확인합니다. 원래 명령을 다른 서버·주체에
전송하지 마세요. 원격 TLS 배포, 토큰 lifecycle, 외부 API의 정확히 한 번 실행,
실제 고객 도입이나 모든 입력의 안전성을 이 클라이언트가 증명하지 않습니다.

## 실제 실행 검증

[`verify-policy-client.py`](../tools/verify-policy-client.py)는 새 자격증명과 실제
클라이언트·게이트 실행 파일을 사용하는 제한된 loopback 검증입니다. 준비 시
전이 없음, 승인·거절·동일 원문 재시도, 산출물 변경과 정상 재시작, 인증·충돌,
비공개 파일·출력과 응답이 끊긴 뒤 원래 결과 복구를 검사합니다.
강제 전원 장애나 외부 작업의 중복 방지를 검증하는 시험은 아닙니다.
커밋별 실행 결과는 [Verify Actions](https://github.com/kimjooyoon/gooo-policy-studio/actions/workflows/ci.yml)에서 확인합니다.
