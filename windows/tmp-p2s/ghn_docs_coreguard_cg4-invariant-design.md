# CG-4 — 불변조건 A~D 공통 대조군 사전등록 (2026-10-24, 계획 §14.2 #3-4)

> 이 문서는 대조군 실행 **이전에 평가기를 동결**한다(프로젝트 사전등록 원칙). 하네스 `linux/coreguard/cg4-invariant-controls.py`에 같은 기대표가 코드로 삽입되며, 실행은 커밋 후 이루어진다(R12).

## 1. 불변조건 정의와 근거 매핑

| 불변조건 | 정의(위반 시) | 상류 근거 → 코퍼스 레코드 | H2 기록 결과(8.4.4 / 8.4.27, asanext) |
|---|---|---|---|
| **A 실패 원자성** | 실패한 연산의 부분 초기화 상태를 이후 연산이 소비 | #76846→R10, #12073→R26, #22710→R46 | R10: no_reproducer / R26: abnormal_exit_no_oracle 양측 / **R46: memory_error(ASAN) 양측** |
| **B 재진입 안전점** | 안전점(재진입 금지 구간) 없이 같은 상태에 재진입 | #72530→R01, #16726→R35, #20018→R40 | R01: abnormal_exit_no_oracle / R35: completed_no_oracle / R40: 실행 행 없음 |
| **C 요청 수명 소유권** | 요청 소유 상태가 경계 없이 다음 요청으로 이월 | #76167→R08, GHSA-109619→R53 | R08·R53: no_reproducer. 단 **P16 Path B(109619)**가 8.4.4 3/3 vs 8.4.27 소멸 차등을 이미 증명(커밋 `87bce97`, findings §8) — C의 차등 근거는 이 기존 증적을 인용하고 재측정하지 않는다 |
| **D caught-bailout 복구** | 잡힌 bailout 이후 보호 상태가 복구 없이 잔류 | #79760→R18, #10026→R23, #24361→R49, PR#24366(맥락) | R18: no_reproducer / R23: functional_regression 양측 / R49: custom 양측 |

## 2. 대조군 구성 (공통 5셀)

- **V** = `8.4.27` 이전 시대 취약 빌드 `8.4.4-asanext`, **F** = 공식 수정 `8.4.27-asanext`, **C-disabled/observe/enforce** = `8.4.27-coreguard-asanext`(공식 수정 위 패치).
- 계측 대상(실행 가능): **R46, R23, R49**(트리거 컨트롤) + **R01, R26, R35**(특이성 음성 컨트롤 — 비대상 부류에서 가드 이벤트 0이어야 함). R08·R10·R18·R40은 no_reproducer/미집행으로 문서화만.
- 계측: 요청별 시작/종료 시각, rc, ASAN 보고(종류+프레임) 생성 시점, `COREGUARD_LOG` 이벤트(이름·pid·행 순서) — **이벤트-PID-시간순서**: enforce 셀에서 "이벤트 선행·ASAN 부재·rc 70"이 차단의 시간순서 증거로 기록된다.

## 3. 동결 기대표 (실행 전 확정)

| 레코드 | 셀 | 결과 기대(동결) | 이벤트 | ASAN | rc |
|---|---|---|---|---|---|
| R46 | V | memory_error | — | 있음 | 신호/134/139 |
| R46 | F | memory_error(#22710 미병합 — 수정 아님) | 없음 | 있음 | 신호 |
| R46 | C-disabled | F와 동일 | 없음 | 있음 | 신호 |
| R46 | C-observe | memory_error + 탐지 | **≥1** | 있음 | 신호 |
| R46 | C-enforce | 가드 종료(차단) | **≥1** | **없음** | **70** |
| R23 | V/F/C-disabled | functional_regression | 없음 | 없음 | 0 |
| R23 | C-observe | functional_regression + 탐지 | **≥1** | 없음 | 0 |
| R23 | C-enforce | 가드 종료(차단) | **≥1** | 없음 | **70** ~~70~~ → **정정(실행 후)**: **255 + cg_fatal** |
| R49 | V/F/C-disabled | custom | 없음 | 없음 | 255 |
| R49 | C-observe | custom + 탐지 | **≥1** | 없음 | 255 |
| R49 | C-enforce | CoreGuard fatal 선행 | **≥1** | 없음 | 255 |
| R01 | 전 5셀 | abnormal_exit_no_oracle | **0** | 없음 | 255 |
| R26 | 전 5셀 | abnormal_exit_no_oracle | **0** | 없음 | 255 |
| R35 | 전 5셀 | completed_no_oracle | **0** | 없음 | 0 |

근거: H2 reclassified(§1 표), Phase 5 hold-out 1회 평가(R46·R23 enforce=worker_contained rc 70, observe=detected_only), phase2b T1(R49 observe/enforce). 평가기: 어느 셀이든 기대 외 결과·미분류·계측 누락은 **실패(fail-closed)**, 종료 코드 비영.

> **§3 정정(2026-10-24, 첫 실행 `cg4-invariants-20261024T085932` 이후 — 해당 실행은 보존)**: R23/C-enforce의 rc를 70으로 등록한 것은 R46의 Phase 3 `_exit(70)` 서명을 과잉 일반화한 사전등록 오기다. **근거 확 인 실수: R23의 홀드아웃 근거 증적(`coreguard-holdout-20261023T164640`, enforce rc=255)을 읽지 않고 R46 값(`…T231409`, rc=70)을 일반화했다.** 실측: 이벤트 `gc_protected_after_caught_bailout` + cg_fatal(E_ERROR) + rc 255 + ASAN 없음 — Phase 2b enforce의 정상 경로(R49에 동결했던 것과 동일). 기능 발산이 가드 종료 이전에 관측됨(worker_contained≠prevented, Phase 5 동결 판정과 일치). 측정은 정확했고 등록이 틀렸다. 기대표는 위 행과 하네스 주석에서 정정 후 재실행한다.

## 4. hold-out 동결·노출 기록

- Phase 5 hold-out(R23/R46/R51)의 **평가 판정은 1회 원칙대로 동결** — CG-4는 이들을 *대조군 계측*으로만 재사용(계획 §14.2 CG-4 명시 근거). 맹목성은 Phase 5 시점에 이미 소진(known-class, non-blind 공개).
- **R51은 CG-4에서 실행하지 않는다**(근거 목록에 없음 — 미노출 상태 유지).
- 노출 요약: R23·R46 = 튜닝·홀드아웃·CG-4 계측으로 3회 접촉(전부 문서화됨), R49 = 튜닝·CG-4, R51 = 홀드아웃 1회만.

## 5. 범위 정렬 선언 (계획 §14.2 지시)

1. **Phase 1(잔류 감지)은 관측 전용** — 성공 주장 불가, "완료"로 오기 금지. 양성 대조와 이벤트 0 관측만이 근거다.
2. **Phase 2 스윕은 10개 결함 부류 표본** — 전수 아님, 음성은 "이 프로파일에서 못 찾음".
3. 상류 논거: 무조건 `gc_protect` 해제는 위험(PHP 개발자 지적) — 경로별 처리·보수적 격리가 상류 방향과 부합하며, CoreGuard의 탐지-후-선택적 격리 구조는 이 방향의 실험적 확인이다.

## 6. 한계

- 취약 빌드 대리: 취약 시점이 8.4.4 외 버전인 근거(R10 #76846 등)는 랩 빌드 부재로 no_reproducer — 대조군은 8.4.4/8.4.27 구간만 커버.
- C 불변조건의 차등은 기존 P16 증적 인용(재측정 없음) — CG-4 계측은 CLI 세션이며, C의 본질(요청 경계 이월)은 FPM/아파치 경로에서만 완전히 관측됨(P15~P17 참조).
- 이벤트 이름(R46·R23이 어느 패치에서 발화하는지)은 기대표에서 지정하지 않고 **계측 결과로 기록**한다(이름별 집계 원칙).
