#!/usr/bin/env python3
"""#3 CG-4: invariant A-D common control groups (plan 14.2 CG-4).

Preregistration: docs/coreguard/cg4-invariant-design.md - the EXPECT table
below is the frozen evaluator (any mismatch or unclassified run fails the
whole run, exit non-zero).

Cells: V=8.4.4-asanext, F=8.4.27-asanext, C-disabled/observe/enforce =
8.4.27-coreguard-asanext. Trigger controls R46/R23/R49; specificity
controls R01/R26/R35 (the guard must stay silent on non-target classes).
R51 is never run (hold-out exposure control). Instrumentation per run:
wall window, rc, ASAN report (kind+frames), COREGUARD_LOG events by
name+pid; in enforce cells "event present + no ASAN report + rc 70" is the
event-precedes-harm containment ordering evidence.
"""
import importlib.util
import json
import re
import subprocess
import sys
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent))
import provenance  # noqa: E402

_spec = importlib.util.spec_from_file_location('runrepro', HERE.parent / 'corpus/run-repro.py')
rr = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(rr)
BASE = Path('/home/phplab/php-lab')
CASES = json.loads((HERE.parent / 'corpus/h2-cases.json').read_text())['cases']

CELLS = [
    ('V', '8.4.4', 'asanext', None),
    ('F', '8.4.27', 'asanext', None),
    ('C-disabled', '8.4.27', 'coreguard-asanext', 'disabled'),
    ('C-observe', '8.4.27', 'coreguard-asanext', 'observe'),
    ('C-enforce', '8.4.27', 'coreguard-asanext', 'enforce'),
]

# FROZEN (design doc section 3). events: 0 = exactly none, 1 = at least one,
# absent = not checked.
EXPECT = {
    ('R46', 'V'): dict(outcome='memory_error', asan=True, events=None),
    ('R46', 'F'): dict(outcome='memory_error', asan=True, events=0),
    ('R46', 'C-disabled'): dict(outcome='memory_error', asan=True, events=0),
    ('R46', 'C-observe'): dict(outcome='memory_error', asan=True, events=1),
    ('R46', 'C-enforce'): dict(rc=70, asan=False, events=1),
    ('R23', 'V'): dict(outcome='functional_regression', asan=False, events=0),
    ('R23', 'F'): dict(outcome='functional_regression', asan=False, events=0),
    ('R23', 'C-disabled'): dict(outcome='functional_regression', asan=False, events=0),
    ('R23', 'C-observe'): dict(outcome='functional_regression', asan=False, events=1),
    ('R23', 'C-enforce'): dict(cg_fatal=True, rc=255, asan=False, events=1),
    # correction after the first run (evidence cg4-invariants-20261024T085932,
    # kept): the prereg wrote rc=70 by over-generalizing R46's Phase 3
    # _exit(70) signature. R23 is the Phase 2b class - enforce ends the
    # request with E_ERROR (rc 255 + cg_fatal), exactly as frozen for R49.
    # The functional divergence is observable BEFORE the guard fires
    # (worker_contained, not prevented - consistent with the frozen Phase 5
    # verdict). Measurement was correct; the prereg was wrong.
    ('R49', 'V'): dict(outcome='custom', events=0),
    ('R49', 'F'): dict(outcome='custom', events=0),
    ('R49', 'C-disabled'): dict(outcome='custom', events=0),
    ('R49', 'C-observe'): dict(outcome='custom', events=1),
    ('R49', 'C-enforce'): dict(cg_fatal=True, rc=255, events=1),
}
for _rid in ('R01', 'R26'):  # specificity: abnormal exit, guard silent
    for _cell, *_ in CELLS:
        EXPECT[(_rid, _cell)] = dict(outcome='abnormal_exit_no_oracle', events=0)
for _cell, *_ in CELLS:  # R35: clean completion, guard silent
    EXPECT[('R35', _cell)] = dict(outcome='completed_no_oracle', events=0)

ORDER = ['R46', 'R23', 'R49', 'R01', 'R26', 'R35']


def classify(case, rc, asan, stdout, expect):
    oracle = case['oracle']
    if oracle == 'memory_error':
        hit = bool(asan) or rc < 0 or rc in (134, 139)
    elif oracle == 'expect':
        hit = expect is not None and not rr.expect_matches(expect[1], stdout, expect[0])
    else:
        hit = rr.CUSTOM[case['custom']](stdout)
    if hit:
        return 'gc_state_stuck' if oracle == 'gc' else (
            'memory_error' if oracle == 'memory_error' else
            'functional_regression' if oracle == 'expect' else 'custom')
    return 'completed_no_oracle' if rc == 0 else 'abnormal_exit_no_oracle'


def run_cell(rid, case, cell, version, flavor, mode, root):
    out = root / rid / cell
    out.mkdir(parents=True, exist_ok=True)
    build = '%s-%s' % (version, flavor)
    rec = dict(record=rid, cell=cell, build=build, mode=mode or 'baseline')
    php = BASE / 'install' / build / 'bin/php'
    if not php.exists():
        rec['error'] = 'binary missing: %s' % build
        return rec
    code, ini, needs, expect = rr.case_source(case)
    extra = rr.opcache_args(php) if 'opcache' in needs else []
    missing = [n for n in needs if n not in rr.modules(php, extra)]
    if missing:
        rec['error'] = 'capability_gap:%s' % ','.join(missing)
        return rec
    (out / 'repro.php').write_text(code)
    args = [str(php), '-n'] + extra + rr.SANDBOX + [
        '-d', 'sys_temp_dir=%s' % out, '-d', 'session.save_path=%s' % out]
    for line in ini:
        args += ['-d', line]
    args.append(str(out / 'repro.php'))
    cg_log = out / 'cg-events.log'
    env = dict(ASAN_OPTIONS='detect_leaks=0:abort_on_error=1:symbolize=1:log_path=%s/asan' % out,
               ASAN_SYMBOLIZER_PATH='/usr/bin/llvm-symbolizer', USE_ZEND_ALLOC='1',
               PATH='/usr/bin:/bin')
    if mode:
        env['COREGUARD_MODE'] = mode
        env['COREGUARD_LOG'] = str(cg_log)
    t0 = time.time()
    try:
        res = subprocess.run(args, capture_output=True, text=True, timeout=120,
                             cwd=out, env=env)
    except subprocess.TimeoutExpired:
        rec.update(error='timeout', seconds=round(time.time() - t0, 1))
        return rec
    (out / 'stdout.txt').write_text(res.stdout)
    (out / 'stderr.txt').write_text(res.stderr)
    asan = None
    for p in sorted(out.glob('asan.*')):
        txt = p.read_text(errors='replace')
        if 'AddressSanitizer' in txt:
            kind = re.search(r'AddressSanitizer: ([\w-]+)', txt)
            frames = re.findall(r'#\d+ 0x[0-9a-f]+ in (\S+)', txt)[:3]
            asan = dict(kind=kind.group(1) if kind else '?', frames=frames,
                        report_pid=p.name.split('.')[-1])
            break
    events = []
    if cg_log.exists():
        for ln in cg_log.read_text().splitlines():
            m = re.search(r'event=(\S+).*pid=(\d+)', ln)
            if m:
                events.append(dict(name=m.group(1), pid=int(m.group(2))))
    rec.update(rc=res.returncode, seconds=round(time.time() - t0, 1),
               outcome=classify(case, res.returncode, asan, res.stdout, expect),
               oracle=case['oracle'], asan=asan, events=events,
               cg_fatal='CoreGuard: execution resumed' in (res.stdout + res.stderr))
    return rec


def evaluate(runs):
    rows = []
    for (rid, cell), exp in sorted(EXPECT.items()):
        key = '%s/%s' % (rid, cell)
        rec = runs.get(key)
        why = []
        if rec is None or 'error' in rec:
            rows.append(dict(check=key, ok=False,
                             why=rec.get('error', 'missing') if rec else 'missing'))
            continue
        if 'outcome' in exp and rec['outcome'] != exp['outcome']:
            why.append('outcome %s != %s' % (rec['outcome'], exp['outcome']))
        if 'asan' in exp and bool(rec['asan']) != exp['asan']:
            why.append('asan=%s expected %s' % (bool(rec['asan']), exp['asan']))
        if 'rc' in exp and rec['rc'] != exp['rc']:
            why.append('rc %s != %s' % (rec['rc'], exp['rc']))
        if 'cg_fatal' in exp and rec['cg_fatal'] != exp['cg_fatal']:
            why.append('cg_fatal=%s' % rec['cg_fatal'])
        n_ev = len(rec['events'])
        if exp.get('events') == 0 and n_ev:
            why.append('unexpected events %s' % [e['name'] for e in rec['events']])
        if exp.get('events') == 1 and n_ev < 1:
            why.append('expected >=1 event, got 0')
        rows.append(dict(check=key, ok=not why, why='; '.join(why) or 'ok',
                         outcome=rec['outcome'], rc=rec['rc'],
                         asan_kind=(rec['asan'] or {}).get('kind'),
                         events=[e['name'] for e in rec['events']]))
    return rows


def main():
    stamp = time.strftime('%Y%m%dT%H%M%S', time.gmtime())
    root = BASE / 'evidence' / ('cg4-invariants-%s' % stamp)
    root.mkdir(parents=True)
    runs = {}
    for rid in ORDER:
        case = CASES[rid]
        for cell, version, flavor, mode in CELLS:
            rec = run_cell(rid, case, cell, version, flavor, mode, root)
            runs['%s/%s' % (rid, cell)] = rec
            print(json.dumps(rec), flush=True)
    checks = evaluate(runs)
    ok = sum(1 for c in checks if c['ok'])
    for c in checks:
        if not c['ok']:
            print('FAIL %s: %s' % (c['check'], c['why']), flush=True)
    summary = dict(scope='CG-4 invariant A-D common control groups (frozen '
                   'evaluator, preregistration docs/coreguard/cg4-invariant-design.md)',
                   runs=runs, checks=checks, checks_ok=ok, checks_total=len(checks),
                   **provenance.provenance())
    (root / 'summary.json').write_text(json.dumps(summary, indent=2))
    print('checks=%d/%d out=%s citable=%s' % (ok, len(checks), root, summary['citable']))
    return 0 if ok == len(checks) else 1


if __name__ == '__main__':
    sys.exit(main())
