# 검증 관측 — 2026-10-07

## 로컬 자동 검증

- `go test -race ./...`: 통과. 256개 조건/정책 토글 조합, 13개 명시적 도메인 사례, 기록 재실행·변조·출처, 금액 범위, HTTP 입력·출처 검증.
- `go vet ./...`: 통과.
- `node --check web/app.js`: 통과.
- `go run ./cmd/generate --compiler <clean-pinned-gooo> --check`: 통과. 고정 리비전에서 생성한 코드/전달 어댑터/내장 사본 일치.
- `go build -trimpath -o bin/policy-studio ./cmd/server`: 통과. 해당 실행 파일로 화면과 API 확인.

컴파일러: clean Git revision `49f5a8c46507bed813a1eae4f7b10e7436eeb3ba`, Gooo `0.6.4-dev`, Go `1.27.1`. 애플리케이션 로컬 빌드: Go `1.26.5`, macOS arm64. 당시 출력은 해당 리비전의 `evidence/generation.json`에 저장되어 있습니다.

## 브라우저에서 직접 확인

- 기본 750,000원 요청: 현재 500,000원 한도에서 `OVER_LIMIT`, 변경 1,000,000원에서 `APPROVED`, `NEWLY_APPROVED` 표시.
- 다섯 조건의 전후 결과: 금액 한도만 현재 미충족, 변경 통과.
- 12개 고정 입력의 영향 비교: 기본 두 정책에서 승인 상태 변경 2개, 변경 정책 승인 6개. 이는 해당 사례와 정책의 관측이며 일반화 점수가 아님.
- JSON 파일 가져오기: 별도 API 실행 기록을 파일로 가져와 실제 재실행, 출처·결과 일치 알림과 요청 입력 복원 확인.
- Gooo 소스 탭: 서버에 내장된 `.gooo` 선언 표시 확인.
- 브라우저 콘솔: 확인한 흐름에서 error/warn 없음.
- 모바일 폭: 375px 실제 레이아웃에서 문서 너비/스크롤 너비 모두 375px, 페이지 가로 넘침 없음. 모바일/데스크톱 전체 화면을 `docs/screenshots`에 보관.

JSON 내보내기는 표준 Blob/Object URL 방식입니다. 자동화의 다운로드 이벤트는 포착되지 않았지만 실제 Downloads 폴더의 `gooo-policy-receipt.json`을 읽어 `policy-studio/execution/v1` 스키마, 실행 시각과 화면에서 생성한 기록 ID의 일치를 확인했습니다. 파일 가져오기·실제 재실행도 별도로 확인했습니다.

## CI

공개 저장소의 `Verify` 워크플로가 형식·vet·race·빌드·JS 문법과 Linux의 고정 Gooo 재생성을 검사합니다. 공개 저장소의 [Linux CI](https://github.com/kimjooyoon/gooo-policy-studio/actions/runs/37545335161)가 위 검사를 모두 통과했습니다. 이 문서의 로컬 관측과 GitHub Actions 결과는 별도로 확인합니다.

## Go 1.27.2 전환 — 2026-10-09

현재 모듈과 CI·릴리스 빌드는 Go 1.27.2를 사용합니다. 컴파일러 소스는
`be4ef88cca4bc3df1e78ae91c8fe8388413f05c9` (Gooo 0.6.17-dev)로 고정했습니다.
이 깨끗한 소스로 다시 생성했고 `--check`도 통과했습니다. 생성된 두 정책 함수와
전달 어댑터의 바이트는 그대로이며, 두 `generation.json`은 새 컴파일러의 실제
응답과 빌드 정보를 담습니다. Go 1.27.2에서 race·vet와 서버 빌드가 통과했습니다.
이 관측은 위의 10월 7일 브라우저 검사를 다시 수행했다는 뜻으로 확장하지 않습니다.
