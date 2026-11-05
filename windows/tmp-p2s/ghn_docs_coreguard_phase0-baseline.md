# CoreGuard Phase 0 — 기준선: 공식 수정이 막는 것과 남는 것 (2026-10-23)

> 근거: 계획 §13.5 Phase 0, Issue #3, findings §10.11·§10.12·§11.3. 평가 사전 등록은 `evaluation-preregistration.md` v1(hold-out 고정)에 있다.
> 이 문서는 **CoreGuard가 추가로 다룰 공백**을 정하기 위한 기준선이다. 공식 패치를 재구현하지 않는다.

## 1. 공식 8.4.27이 이미 막는 것 (관측·소스 근거)

| 보호 | 위치(8.4.27) | 막는 경로 | 이 랩의 관측 |
|---|---|---|---|
| 지연 soft OOM(`ZEND_HAS_OOM`) + fallible 할당 | `Zend/zend_alloc.h:63`(`ZEND_HAS_OOM`), `zend_alloc.c`(`zend_mm_delayed_error`), unserializer의 `zend_string_falloc(.., fallible)`·`goto failure` | 109618(부분 초기화 HashTable 소비), 109619 생산자 측 잔류 | P15 `delivery_blocked`(파서가 한도 전에 멈춤). 트리아지: 8.4.27 생산자 요청에서만 `php_var_(un)serialize_destroy`가 실행된다(계측 차분, `validated`) |
| hard limit(`memory_hard_limit_percent`) | `zend_alloc.c` | 지연 OOM 중 무한 증가 | R57: 일부 할당 API에서 `_exit(137)` — 가용성 회귀 기록(공개) |
| `php_basic_early_rinit()` | `main/main.c:1869` → `basic_functions.c:491` | 잔류 BG(serialize/unserialize) 재사용 | 이 랩의 시퀀스에서는 잔류가 생기지 않아 **실행될 대상이 없는 이중 방어**다(트리아지) |
| `php_url_scanner_early_rinit()` | `url_scanner_ex.c:1101` | url_scanner 잔류 | Phase 5 B에서 8.4.27 소멸 |
| 세션 전역 조기 리셋(`php_rinit_session_globals`, MULTIPART_EVENT_START) | `ext/session/session.c` | Path B(PS 잔류) | P16 소멸, Path B 교착 소멸 |
| `PS(in_rfc1867_update)` + `incomplete_classes_only` | `ext/session/session.c` | 업로드 진행 중 재진입 | Phase 4 Diff |

**정리:** 공식 수정의 핵심은 OOM을 **즉시 longjmp에서 지연 오류로 바꿔 실패 경로가 정상 해제를 수행하게 한 것**이다. 요청 간 잔류는 생기지 않거나 조기 리셋으로 지워진다.

## 2. 8.4.27에서 남는 구조적 공백 (H2 재현, 모두 공개 기록)

| 공백 | 사례(용도) | 불변조건 후보 | CoreGuard 단계 |
|---|---|---|---|
| bailout을 잡고 실행을 재개하면 GC 보호 상태가 복구되지 않음 | R23 GH-10026(**hold-out**), R49 GH-24361(튜닝) | "잡힌 bailout 뒤 `gc_protect` 등 엔진 전역 보호 상태는 진입 전 값으로 복구된다" | Phase 2b(복구 상태 원자성, 신설 제안) |
| 컨테이너 정리 중 소멸자 bailout → 이미 소멸된 슬롯이 다시 소비됨 | R46 PR #22710(**hold-out**) | "정리 루프가 중단돼도 소멸이 끝난 슬롯은 teardown에 다시 노출되지 않는다" | Phase 2(실패 원자성) |
| 연산 중 소멸자 재진입으로 객체가 reset·해제됨 | R51 GH-24455(**hold-out**) | "연산이 쥔 객체는 소멸자 재진입으로 무효화되지 않거나, 무효화가 감지된다" | Phase 2/3(재진입 감지·격리) |
| GC 이중 해제 회귀 | R55 GH-24488(튜닝) | GC 루트·참조 수 불변 | 튜닝·회귀 |
| 요청 간 소유권 | — (8.4.27 재현 사례 없음) | `request_epoch`·`allocation_owner` | Phase 1 — **hold-out 없음 → 성공 주장 불가**(사전 등록 공백 선언) |

## 3. 개발자 지식 누출 위험과 통제

- **위험:** 개발자(이 세션)는 hold-out R46·R23·R51의 원인과, R46의 경우 공개 수정 PR의 접근을 이미 알고 있다. hold-out의 독립성은 "개발·튜닝에 쓰지 않았다"로만 보장되며 "모른다"로는 보장되지 않는다.
- **통제:**
  1. CoreGuard 불변조건은 §2처럼 **사례가 아니라 부류**로 정의하고, 튜닝 세트(R49·R55)와 합성 단위 테스트로만 개발한다.
  2. hold-out 스크립트는 개발 중에 실행하지 않는다. 평가는 1회만 하고 결과를 그대로 기록한다.
  3. R46의 공개 수정(PR #22710: 슬롯을 비운 뒤 소멸자를 실행)을 **그대로 옮기면 공식 수정 재구현**이므로 성공으로 세지 않는다. CoreGuard는 그 PR이 다루지 않는 다른 정리 루프에도 적용되는 일반 규칙이어야 하며, 적용 범위를 소스 위치 목록으로 명시한다.
  4. 평가 보고에는 이 위험과 통제를 그대로 적는다.

## 4. 측정 기준선 (B = 8.4.27, `asanext`)

- hold-out 3건의 B 결과: 모두 재현(H2 2차 증적 `corpus-h2-20261023T132556-asanext`).
- 성능·호환 기준선: **측정 완료(2026-10-23)**. 빌드 `8.4.27-normalext`, `linux/coreguard/perf-baseline.py`·`phpt-baseline.sh`. 수치는 findings §11.8에 있다(health 약 9.5k req/s, PHPT 7 디렉터리 7,922건 중 통과 7,744 / 건너뜀 174 / XFAIL 4 / 실패 0). C는 같은 스크립트로 측정한다.
