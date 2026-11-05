# CoreGuard Phase 5 — 평가 보고 (2026-10-24)

> 사전 등록 `evaluation-preregistration.md` v1(hold-out 고정, 목록 SHA-256 `acf42610…`)과 v1.1(CLI 판정 매핑, 사례별 1회 평가)에 따른 결과다. 근거 수치와 증적 경로는 findings §11.8~§11.12에 있다.

## 1. 평가 질문에 대한 답

> 공식 수정(8.4.27)이 막지 않은 실패 경로에서, 개발에 쓰지 않은 hold-out에 대해, **유효 요청을 유지하면서** 잘못된 접근 이전에 차단했는가?

**아니다. `prevented_before_invalid_access`는 hold-out 3건 × 3모드 × 3회에서 0건이다.**

| hold-out | 패턴 | disabled | observe | enforce |
|---|---|---|---|---|
| R23 GH-10026 | bailout 뒤 GC 보호 잔류 | `not_protected` ×3 | `detected_only` ×3 | `worker_contained` ×3 |
| R46 PR #22710 | 정리 중 소멸자 bailout → 이중 정리 | `not_protected` ×3 | `detected_only` ×3 | `worker_contained` ×3(ASAN 0, rc 70) |
| R51 GH-24455 | 소멸자 재진입(lazy object reset) | `not_protected` ×3 | `not_protected` ×3 | `not_protected` ×3 |

- enforce는 R23·R46에서 피해가 나기 **전에** 작업 단위를 끝냈다(R23: GC 정지 전, R46: 세션 인코더 진입 전). 그러나 그 요청은 잃는다. v1.1 규칙에 따라 성공(`prevented`)이 아니라 `worker_contained`다.
- R51은 bailout이 없는 재진입이라 어떤 가드도 개입하지 않았다.

## 2. 독립성에 대한 정직한 평가

- R23은 튜닝 사례 R49와 같은 계열이다(사전 등록이 의도한 분리). R23 결과는 "같은 부류의 다른 진입점(opcache → soap)으로 일반화된다"는 근거일 뿐이다.
- R46은 원인과 수정 PR의 접근을 개발 전부터 알고 있었다. Phase 3 부류 정의("소멸자 안 bailout")도 이 지식에서 출발했다. 따라서 R46 결과는 **독립적인 입증이 아니다.** 입증하려면 개발에 관여하지 않은 새 hold-out(예: #2 탐색이 찾은 미공개 사례, D1 절차 후)이 필요하다.
- 결론적으로 이 평가가 보인 것은 "알려진 부류에 대한 탐지(observe)와, 요청을 희생하는 격리(enforce)가 작동한다"까지다.

## 3. Phase별 Go/No-Go

| Phase | 내용 | 판정 | 근거 |
|---|---|---|---|
| 0 | 기준선·사전 등록 | 완료 | `phase0-baseline.md`, B 성능·PHPT 기준선 |
| 1 | 요청 소유권(잔류 탐지, observe 전용) | **detect-only, 성공 주장 불가** | hold-out 없음(선언된 공백). 양성 대조 4/4. 8.4.27 탐색·PHPT 이벤트 0(공식 조기 리셋이 지울 잔류가 생기지 않음) |
| 2 | 할당 실패 원자성 | **No-Go(중복)** | 할당 실패 주입 10개 부류에서 모든 실패가 지연 OOM fatal로 끝남. 메모리 오류 0. 공식 수정과 중복이라 구현하지 않음 |
| 2b | 잡힌 bailout 뒤 GC 보호 | observe **Go(detect-only)** / enforce **No-Go** | observe: PHPT 회귀 0, 성능 노이즈 안, R23 탐지 3/3. enforce: PHPT 회귀 19(SOAP 정상 흐름 종료). **탐지 범위 한계(§7 T5 교정 참조): 재개 후 인터럽트 검사 지점(함수 호출 계열 핸들러·루프 점프)을 지나는 코드에 한함 — 그 지점을 지나지 않고 끝나면 이벤트 없음** |
| 3 | 소멸자 bailout 격리 | observe **Go(detect-only)** / enforce **조건부(가용성 대가)** | observe: 회귀 0, R46 탐지 3/3. enforce: 추가 PHPT 회귀 0, R46 피해 전 종료 3/3, 정상 부하에서 워커 종료 0. 단 소멸자 안의 OOM도 종료를 일으켜 재시작 유도가 가능하다(설계 §5) |
| 4 | 할당기·HW | 낮은 우선순위 유지 | 이중 해제(R55)만 결정적으로 검출. R41·R42는 검출 없음. GWP-ASan 추가 이득 없음 |
| 5 | 반증 가능한 평가 | 이 문서 | `prevented` 0 |

## 4. 측정하지 못한 것 (평가 범위의 공백)

- hold-out 평가는 CLI에서만 했다. Apache(mod_php)·FPM에서의 hold-out 동작은 재지 않았다. 단, FPM 워커 교체 뒤의 다음 요청 처리는 CG-2(§6)에서 측정했다(교체 후 헬스 100% 회복).
- JIT 빌드와의 호환성은 시험하지 않았다.
- PHPT는 7개 디렉터리(7,922건)다. 전체 테스트 스위트가 아니다.
- 성능은 단일 호스트(WSL2, 6코어)에서 잰 상대값이다. 측정 간 변동이 크다(같은 B 빌드의 health가 7.7k~9.5k req/s).

## 5. 다음 단계 제안

1. hold-out v2: 개발에 관여하지 않은 사례를 확보한다. #2 탐색에서 부류를 겨냥한 입력 생성(H2.5 남은 과제)을 하고, 새 메모리 오류는 D1 절차를 먼저 밟는다.
2. FPM에서 enforce의 가용성 비용을 잰다. 소멸자 안 OOM을 반복 유발했을 때의 워커 재시작률이 대상이다. **→ CG-2(§6)에서 측정(2026-10-24): 소멸자 fatal(S1) 반복 주입 — 증폭 음성. OOM-유발 변형은 동일 `_exit(70)` 경로를 공유하나 별도로 재지 않았다.**
3. Phase 2b enforce의 SOAP 회귀는 상류 PR #24338이 정리될 때 다시 판단한다(상류가 WSDL 오류에서 보호를 풀면, 이 가드는 그 경로에서 이벤트를 내지 않는다).

## 6. CG-2 — FPM 격리 매트릭스 (2026-10-24, 계획 §14.2 #3 CG-2)

> 하네스 `linux/coreguard/cg2-fpm-isolation.py` — fail-closed 셀 기동(포트 리스너 선점 검사 + pidfile 신원 검증 + `daemonize=no` 결정적 정리). 결함은 phase3 S1 형태(실행 중 `unset()`이 소멸자 fatal을 본문 중간에 발화, 512회 유계 루프). **인용 근거: 증적 `evidence/cg2-fpm-20261024T070908`(8셀, faults=10, `source_commit 9a6128e`, `citable: true`)** — 커밋판 하네스로 R12에 따라 재실행한 것이다. 선행 `…T055632`·`…T055719`은 미커밋 하네스 실행(`citable: false`)으로 각 디렉터리에 `NON-CITABLE.md` 표지 — 판정은 동일(노이즈 내). 백그라운드 `/health` 프로버(50ms 간격)로 기저선 창(3초)과 폴트 창을 분리 측정했다.

**질문: enforce의 반복 워커 종료(`_exit(70)`)가 재시작 증폭(DoS 공격면)으로 이어지는가?**

| mc | 모드 | fault 결과 | 워커 교체 | 이벤트 | 기저선 p99 | 폴트창 p50/p99 (ms) | 폴트창 프로버 |
|---|---|---|---|---|---|---|---|
| 1 | B | 200×10 | 0 | 0 | 1.4 | 257/260 | 10/10 |
| 1 | disabled | 200×10 | 0 | 0 | 1.3 | 262/269 | 10/10 |
| 1 | observe | 200×10 | 0 | 10 | 1.7 | 261/263 | 11/11 |
| 1 | enforce | **reset×10** | **10회(~310ms/회)** | 10 | 1.7 | 263/307 | 10/10 |
| 4 | B | 200×10 | 0 | 0 | 1.5 | 0.8/1.5 | 60/60 |
| 4 | disabled | 200×10 | 0 | 0 | 1.4 | 0.8/1.7 | 59/59 |
| 4 | observe | 200×10 | 0 | 10 | 1.5 | 0.8/1.5 | 61/61 |
| 4 | enforce | **reset×10** | **10회(폴트당 정확히 1워커)** | 10 | 1.5 | 0.8/1.9 | 60/60 |

판정(단위: ms, p50/p99는 서비스된 프로브 기준):

- **재시작 증폭 없음** — 워커 교체는 결함당 정확히 1회(연쇄 0), listen queue 최대 깊이 0(FPM backlog 4096·nginx 511 대비), 결함 직후 헬스 100% 회복(전 셀 `health_failures` 0).
- **비용의 위치는 풀이 아니라 요청** — enforce에서 손실되는 것은 결함 요청 본인(reset, 본문 중단)이며, 이는 §1의 `worker_contained`(요청을 잃는 격리) 정의와 일치한다. mc=1에서도 대기 중 프로브는 교체 뒤 즉시 서비스됐다(폴트창 p50 263ms는 결함이 단일 워커를 점유한 시간 자체이며 모드 무관 — enforce 추가 지연 0).
- **disabled·observe는 B와 전 지표 동치**(observe는 이벤트 로그 10건만 추가) — 관측 오버헤드는 이 부하 프로파일에서 측정 불능.
- 한계: 부하 프로파일이 단일 프로버(≈20 rps) + 순차 결함이다. 큐 깊이 0과 "증폭 없음"은 이 프로파일의 결과이며, 지속 스트림·고동시 부하·`pm.max_children` 고갈 상황은 미측정. PHP-FPM `pm = static` 한정. 셀당 결함 10개·매트릭스 1회 실행(미커밋 선행 실행과 판정 일치 확인) — 반복 분산은 미측정.

## 7. CG-3 — Phase 2b 훅 수명·ZTS·연쇄 검증 (2026-10-24, 계획 §14.2 CG-3)

> 질문: Phase 2b VM 인터럽트 훅이 ZTS에서 컴파일·동작하는가, 원본 인터럽트 경로가 보존되는가, 반복 요청 생명주기에서 훅이 살아있는가, disabled/observe는 동치인가, enforce PHPT 19건 회귀는 그대로인가.

- **ZTS 빌드**: 신규 플레이버 `ztsnormalext`(normalext+`--enable-zts`)로 B·C 쌍 빌드 — **패치 0001~0003이 ZTS에서 문제없이 컴파일**(빌드 증적 `builds/8.4.27-ztsnormalext`·`…-coreguard-ztsnormalext`의 build-manifest). 참고: ZTS FPM 워커는 요청당 단일 스레드 — 검증은 요청 단위 TSRM 생명주기 한정(다중 스레드 동시성 SAPI=Apache worker는 미측정).
- **배터리**: `phase2b-tests.py` 확장(T5 + 동치 검사) — **NTS 43/43, ZTS 43/43 모두 통과**(증적 `coreguard-p2b-tests-20261024T074127-asanext`·`…T075708-ztsnormalext`, citable). T1 탐지·봉쇄는 ZTS에서 NTS와 동일.
- **훅 연쇄 — 무장 상태(T6)와 비무장 기저선(T5)**: T6(리뷰 16:45 설계: 잡힌 컴파일 bailout+거부 루트로 훅을 설치·무장한 뒤 `set_time_limit`)에서 observe는 이벤트 1건 + 원본 타임아웃(rc 255) — **무장된 훅이 인터럽트를 원본 핸들러로 통과시키는 공존 증명**. enforce는 가드 fatal이 타임아웃보다 먼저. T5(무장 없음)는 가드 비활성 상태에서 원본 타임아웃이 보존됨만 보이는 기저선(컴파일 fatal 처리 중 소멸자는 스킵 — 2026-10-24 리뷰로 주장 수위 교정). NTS·ZTS 모두.
- **Phase 2b 훅 수명(FPM 같은 워커 5단계, 리뷰 17:11 설계)**: `phase2b-fpm-lifetime.py` — ① R49형 아밍 요청 → `gc_protected_after_caught_bailout` **정확히 1건** ② 정상 요청 5개 → 이벤트 0(훅 잔존·비무장) ③ 재아밍 → 2건째(요청별 `cg_armed` 리셋 후 재무장) ④ `set_time_limit(2)` 요청이 **설치된 훅을 통과해 2.0s에 원본 타임아웃 발화**(하네스 타임아웃 아님=연쇄 결함 없음, 이벤트 추가 없음) ⑤ 다음 요청 정상·워커 생존(프로세스 전역 `cg_prev_interrupt`가 다음 요청을 오염하지 않음). **NTS·ZTS 모두 16/16**(증적 `cg3-p2b-fpm-lifetime-20261024T082955`, citable).
- **Phase 3 봉쇄의 요청 간 결정성(귀속 교정)**: ZTS FPM 런 `cg2-fpm-20261024T075732`의 guard_events 20건은 전부 `bailout_in_destructor`(Phase 3)다 — 이 실행이 보이는 것은 **Phase 3 봉쇄 이벤트가 반복 요청에서 결함당 정확히 1건씩 발화**한다는 것(2026-10-24 17:11 리뷰로 귀속 교정, 이벤트 이름별 집계 도입으로 재확인). Phase 2b 수명 근거는 위의 전용 하네스다.
- **disabled/observe 동치**: 배터리 전 테스트에서 observe의 stdout·rc가 disabled와 동일(이벤트 로그만 추가) — NTS·ZTS 모두. disabled는 B stdout과 동일(기존 검사 유지).
- **PHPT 19건 회귀 No-Go 유지**: enforce 재실행 `coreguard-phpt-20261024T075348`(citable) — counts 19/7725 동일, **비통과 23개 이름 집합이 기존 런과 완전 동일(차이 0)** → 회귀는 결정론적이며 해소되지 않음, enforce No-Go 판정 유지.

## 8. CG-4 — 불변조건 A~D 공통 대조군 (2026-10-24, 사전등록 `cg4-invariant-design.md`)

> 5셀(V=8.4.4-asanext·F=8.4.27-asanext·C disabled/observe/enforce) × 6레코드(트리거 R46·R23·R49 + 특이성 R01·R26·R35) = 30셀, 동결 기대표 평가. **동결 평가 29/30 — 기대표 오기 1건(R23/C-enforce rc 70→255), 정정 후 재실행 30/30**(근거 실행: 정정 후 `cg4-invariants-20261024T090149` citable, 첫 실행 `…T085932` 29/30 보존). **측정 범위: A·D는 트리거 대조 측정(V/F/C×3), B는 특이성(침묵)만, C는 기존 P16 V/F 차등 증적 인용(CoreGuard 셀 측정 없음)** — "A~D 전부 측정"이 아니다.

| 불변조건 | 레코드 | V | F | C-disabled | C-observe | C-enforce |
|---|---|---|---|---|---|---|
| A 실패 원자성 | R46(#22710) | ASAN | **ASAN(수정 아님)** | ASAN | ASAN+**탐지** | **rc 70 차단·ASAN 없음** |
| D caught-bailout | R23(#10026) | 기능회귀 | 기능회귀 | 기능회귀 | 회귀+**탐지** | 회귀 관측 후 **가드 fatal(rc 255)** |
| D caught-bailout | R49(#24361) | custom | custom | custom | custom+**탐지** | **가드 fatal 우선** |
| B·특이성 | R01·R26·R35 | — | — | — | **전 셀 이벤트 0(침묵)** | 침묵 |

- **이벤트 이름 구분(계측 결과)**: R46 → `bailout_in_destructor`(Phase 3, rc 70 경로), R23·R49 → `gc_protected_after_caught_bailout`(Phase 2b, E_ERROR 경로) — 불변조건별 가드 경로가 이름으로 구분된다.
- **차단의 시간순서**: C-enforce에서 이벤트 + ASAN 부재 + 종료 서명(70/255) — 피해 이전 차단은 R46(접근 이전 종료, Phase 5 판정 재확인), R23은 발산 관측 후 종료(worker_contained≠prevented 유지).
- **특이성**: 비대상 부류(R01·R26·R35)에서 관측·강제 모드 이벤트 0 — 오탐 없음(음성 대조).
- **정정 기록**: 사전등록이 R23/C-enforce를 rc 70으로 오기(R46의 Phase 3 서명 과잉 일반화) — 실측이 정확했고 등록을 정정 후 재실행(§3 정정각).
- **범위 정렬**(설계문서 §5): Phase 1은 관측 전용으로 "완료" 주장 금지, Phase 2 스윕은 10부류 표본 한계, 무조건 gc_protect 해제 위험(상류 논거) 대비 경로별·보수적 격리 방향 부합. C 불변조건의 차등은 기존 P16 증적 인용(8.4.4 3/3 vs 8.4.27 소멸). hold-out 노출: R23·R46 3회 접촉(전부 문서화), **R51 미실행 유지**.
