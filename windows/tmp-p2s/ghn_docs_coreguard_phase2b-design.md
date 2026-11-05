# CoreGuard Phase 2b — 잡힌 bailout 뒤 GC 보호 상태 (2026-10-23)

> 근거: Phase 0 기준선 §2(첫 행), 사전 등록 v1. 개발에는 **튜닝 세트 R49와 합성 테스트만** 쓴다. hold-out R23은 같은 계열이라 이 단계의 평가 대상이지만 개발 중에는 실행하지 않는다.

## 1. 불변조건(부류)

> bailout 뒤에는 실행이 "GC 보호" 상태로 **계속되지 않는다**.

- 8.4.27 `_zend_bailout()`(`Zend/zend.c:1262`)은 항상 `gc_protect(1)`을 호출한다. 힙이 일관되지 않을 수 있으니 정리 중 순환 수집을 막는 것이다.
- `zend_try`로 bailout을 잡고 실행을 재개하는 지점(opcache `opcache_compile_file`, ext/soap 오류 변환 등)에서 보호가 풀리지 않는다. 그러면 이후 `gc_possible_root()`가 모든 루트를 조용히 거부하고(`zend_gc.c:704`) 순환이 수집되지 않는다(R49·R23). 결과는 요청 안의 메모리 증가와 OOM이다.

## 2. 설계 선택

| 안 | 내용 | 판단 |
|---|---|---|
| A. 일괄 복구 | `zend_catch`에서 보호를 진입 전 값으로 되돌린다 | **기각.** 상류 PR #24338의 공개 테스트 `gh10026_engine_fatal.phpt`는 엔진 fatal(OOM)이 SoapFault로 바뀐 뒤에는 보호가 **유지**되기를 기대한다(`bool(true)`). 엔진 fatal 뒤의 힙에서 GC를 다시 돌리는 것은 상류가 피하려는 위험이다. 또 `zend_try`만 쓰는 사이트(catch 없음)에서는 종료형과 재개형을 매크로 수준에서 구분할 수 없다 |
| B. 원인별 복구 | 확장 자체 오류에서만 복구한다 | **보류.** 사이트별 판단이 필요하고, 결과적으로 상류 PR(미병합)의 정책을 재구현하게 된다(Phase 0 §3-3). 이 랩은 PR 코드를 읽지 않았다(테스트 블록만 받음) |
| **C. 피해 지점 탐지 + fail-stop** | 보호 때문에 루트가 거부되는 첫 순간(**피해가 시작되는 지점**)에 조건을 검사한다. `observe`는 기록만 한다. `enforce`는 다음 **인터럽트 검사 지점**(함수 호출 계열 핸들러 `ZEND_DO_FCALL`·`ZEND_DO_FCALL_BY_NAME`·`ZEND_DO_ICALL`·`ZEND_FRAMELESS_ICALL`과 루프 점프 — 8.4.27 `Zend/zend_execute.c:4093-4110`, 2026-10-24 검토 정정: "다음 opcode 경계"는 부정확했다)에서 요청을 E_ERROR로 끊는다(`max_execution_time`과 같은 안전 지점). **탐지 범위 한계: 잡힌 bailout 뒤 인터럽트 검사 지점을 지나지 않고 끝나는 코드(직선 실행·즉시 return)에서는 이벤트가 없다.** 보호는 끝까지 풀지 않는다 | **채택.** 엔진의 판단("이 힙에서 GC 금지")을 존중하면서, 그 상태로 사용자 코드가 계속 도는 것만 막는다. 가용성 비용(요청 종료)은 평가에서 잰다 |

## 3. 구현 (`linux/coreguard/patches/0001-phase2b-gc-resume-guard.patch`, `Zend/zend_gc.c`만 변경)

- 조건: `gc_protected` 상태에서 루트 거부 ∧ shutdown 밖(`EG_FLAGS_IN_SHUTDOWN` 아님) ∧ 이 요청에서 bailout이 있었음(`CG(unclean_shutdown)`) ∧ 루트 버퍼 overflow 보호가 아님(`gc_full` 아님) ∧ 실행 중(`EG(current_execute_data)`). 요청당 1회만 보고한다.
- 모드: 환경 변수 `COREGUARD_MODE=disabled`(기본) / `observe` / `enforce`. 이벤트 형식은 stderr의 `COREGUARD event=gc_protected_after_caught_bailout mode=… pid=…`이다.
- enforce: `zend_interrupt_function`을 연쇄 설치하고 `EG(vm_interrupt)`를 세운다. 인터럽트에서 `zend_error_noreturn(E_ERROR, "CoreGuard: …")`를 호출한다. 루트 거부 지점(refcount 감소 한가운데)에서 바로 bailout하지 않는다.
- 요청 시작(`gc_reset`)에서 플래그를 초기화한다.

## 4. 한계(평가 보고에 그대로 적는다)

- 대상은 GC 보호 상태 하나다. 다른 엔진 전역(예: `EG(current_execute_data)`, 출력 버퍼, 세션 상태)의 회복 원자성은 다루지 않는다.
- 탐지는 "루트 거부"가 일어나야 된다. 재개 뒤 순환 후보를 만들지 않는 코드에서는 이벤트가 없다(피해도 없다).
- enforce는 R23류 요청을 **종료**시킨다. 판정 어휘상 `prevented_before_invalid_access`가 아니라 `worker_contained`나 가용성 비용으로 보고될 수 있다. 판정은 사전 등록 §3을 따른다.
- R23(hold-out)과 R49(튜닝)는 같은 계열이다. 사전 등록이 이 분리를 의도했지만, 이 단계의 R23 결과는 "부류 일반화"의 약한 증거일 뿐이다.

## 5. 개발 검증(튜닝·합성만) — `linux/coreguard/phase2b-tests.py`

| 테스트 | 기대(disabled / observe / enforce) |
|---|---|
| T1 R49 재현(튜닝) | 이벤트 없음·GC 정지 / 이벤트·GC 정지 / 이벤트·요청 종료(CoreGuard E_ERROR), ASAN 0 |
| T2 순환 생성 + `gc_collect_cycles`(정상) | 세 모드 모두 이벤트 없음, 출력 동일 |
| T3 종료형 fatal(미정의 함수 호출) | 세 모드 모두 이벤트 없음 |
| T4 잡힌 bailout 뒤 순환을 만들지 않는 코드 | 이벤트 없음(탐지 한계 확인) |
| T5 `disabled`의 출력이 B(공식 8.4.27)와 같음 | T1~T4 stdout이 B와 일치 |
