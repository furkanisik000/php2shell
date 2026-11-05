# CoreGuard Phase 1 — 요청 소유권: 잔류 탐지(observe 전용) (2026-10-24)

> 근거: 계획 §13.5 Phase 1, 사전 등록 v1 §4 "선언된 공백"(8.4.27에서 재현되는 요청 수명 사례가 없어 hold-out이 없음 → **성공 주장 불가**, 탐지·회귀 확인으로만 보고).

## 1. 범위

- 불변조건: 요청이 소유한 (un)serialize 상태(`BG(serialize)`, `BG(unserialize)`, `BG(serialize_lock)`)는 다음 요청 시작 시점에 살아 있지 않다(CVE-2026-109619 부류, P17).
- 검사 지점: `php_basic_early_rinit()`의 첫 문장. 요청 데이터를 처리하기 전이라, 여기서 0이 아닌 값은 모두 이전 요청의 잔류다.
- 동작: 이벤트 `COREGUARD event=request_state_residue …`만 기록한다. 바로 뒤의 공식 리셋(8.4.27)이 값을 지운다. observe와 enforce의 동작은 같다. **enforce를 따로 두지 않는다**: 강제는 공식 리셋이 이미 하고 있어서, 따로 만들면 공식 수정의 재구현이다.
- 제외: `PS(id)`·`PS(mod_data)`. 같은 요청의 업로드 진행 핸들러가 RINIT 전에 정당하게 설정할 수 있어서, 잔류인지 정상인지 이 지점에서 구분할 수 없다. `request_epoch`·`allocation_owner`를 쓰는 일반 소유권 추적은 비용이 커서 하지 않는다.
- 구현: `linux/coreguard/patches/0003-phase1-request-residue-observe.patch`(`ext/standard/basic_functions.c`).

## 2. 검증

- 개발: `linux/coreguard/phase1-tests.py`. 정상 실행에서는 이벤트가 없어야 한다. 양성 대조는 gdb로 잔류를 주입한다(진입점에서 `basic_globals.unserialize.level = 1`).
- 회귀 대조(성공 분모 아님): 8.4.27 위 수명주기 탐색(observe)에서 이벤트 수를 센다. 8.4.27이 잔류를 남기지 않는다면 0이어야 한다. 0이 아니면 공식 수정이 다른 경로로 막고 있는 잔류가 있다는 뜻이고, 그 자체가 기록할 관측이다.

## 3. 한계

- hold-out이 없으므로 보호 효과는 주장하지 않는다. 이 단계의 의미는 "공식 이중 방어(조기 리셋)가 실제로 일한 순간을 보이게 하는 계측"이다.
- 대상 필드는 3개다. 다른 모듈 전역(세션·출력·URL rewriter)의 잔류는 보지 않는다.
