# CoreGuard Phase 3 — 소멸자 안 bailout 뒤 격리 (2026-10-24)

> 근거: 계획 §13.5 Phase 3(`clean / suspect / poisoned`, 위험한 정리 **이전** 격리, 재시작 DoS 증폭 측정), Phase 0 §2(R46·R51 행), 사전 등록 v1.1. 개발에는 **합성 테스트만** 쓴다. 이 부류에는 튜닝 사례가 없다.

## 1. 부류와 불변조건

> 엔진이 정리 작업(배열 정리, 객체 저장소 정리, GC) 중에 호출한 소멸자 안에서 bailout이 나면, 그 정리는 중간에 끊긴다. 끊긴 상태에서 teardown을 이어 가지 않는다.

- bailout은 longjmp라 정리 루프의 나머지가 실행되지 않는다. 이미 소멸된 슬롯이나 절반만 바뀐 컨테이너가 남는다. 이어지는 shutdown(세션 쓰기, 나머지 소멸자, 출력 핸들러)이 그 상태를 다시 소비할 수 있다.
- 판별: `_zend_bailout()` 진입 시 실행 프레임 체인에 사용자 소멸자(`func == func->common.scope->destructor`)가 있으면 워커를 `poisoned`로 본다.

## 2. 설계

| 상태 | 조건 | 동작 |
|---|---|---|
| clean | 기본 | 없음 |
| poisoned | 소멸자 안에서 bailout | observe: 이벤트 기록(`COREGUARD event=bailout_in_destructor`, `in_shutdown` 포함). enforce: 이벤트 기록 뒤 **더 이상의 정리 없이** `_exit(70)`. FPM에서는 마스터가 워커를 교체하고, 그 요청의 응답은 잃는다 |

- `suspect`(의심) 단계는 두지 않았다. 판별 조건 하나로 바로 poisoned다. 단계를 나눌 근거가 될 관측이 없다.
- 일반 fatal·OOM은 조건에 들지 않는다. 소멸자 밖에서 일어나기 때문이다. 따라서 쉬운 OOM 유발이 워커 재시작 DoS로 증폭되지 않는다(S5로 확인). 단, **소멸자 안의 OOM**은 조건에 든다(한계 §5).
- 구현: `linux/coreguard/patches/0002-phase3-dtor-bailout-containment.patch`(`Zend/zend.c`, 0001 위에 적용). 원본 소스는 바꾸지 않는다.

## 3. 공식 수정과의 관계

- 8.4.27은 이 부류에 일반 대책이 없다(H2: R46이 8.4.27에서 재현됨).
- 상류 PR #22710(R46, 미병합)은 특정 정리 루프에서 "슬롯을 비운 뒤 소멸자 실행"으로 고친다(제목·테스트로만 앎, 코드는 읽지 않음). Phase 3은 루프를 고치지 않는다. **모든 소멸자 bailout에 적용되는 격리**이므로 그 PR의 재구현이 아니다.

## 4. 개발 검증 — `linux/coreguard/phase3-tests.py`

| 테스트 | 기대 |
|---|---|
| S1 배열 unset 중 소멸자 fatal | 이벤트, enforce rc 70 |
| S2 shutdown 중 소멸자 fatal | 이벤트(`in_shutdown=1`), enforce rc 70 |
| S3 소멸자 예외(bailout 아님) | 이벤트 없음 |
| S4 소멸자 밖 fatal | 이벤트 없음 |
| S5 소멸자 밖 OOM(재시작 DoS 증폭 확인) | 이벤트 없음 |
| S6 정상 소멸자 | 이벤트 없음, 출력 B와 같음 |

공통: disabled는 B와 같다(stdout, rc). 새 ASAN 보고가 없다.

## 5. 한계 (평가 보고에 그대로 적는다)

- **지식 누출:** R46의 원인(세션 정리 중 소멸자 bailout → 세션 인코더가 소멸된 슬롯 소비)은 이미 알고 있다. 부류 정의는 이 사례에서 출발했으므로, R46 평가는 "알고 있는 사례에 대한 부류 일반화"이지 독립적인 입증이 아니다.
- enforce는 요청을 잃는다. 사전 등록 v1.1에 따르면 최선의 판정은 `worker_contained`이고 `prevented`는 될 수 없다.
- 판별은 PHP 사용자 소멸자 프레임만 본다. 내부(C) 소멸자 안의 bailout과 소멸자가 아닌 콜백(출력 핸들러, 세션 핸들러, `__toString`) 안의 bailout은 다루지 않는다.
- 소멸자 안의 OOM도 poisoned로 처리한다. 공격자가 소멸자 안에서 OOM을 일으킬 수 있으면 워커 재시작을 유도할 수 있다. 재시작률을 성능 측정에서 함께 본다.
- R51(재진입)은 bailout 없이 일어날 수 있다. 그 경우 이 가드는 개입하지 않는다(`not_protected` 예상).
