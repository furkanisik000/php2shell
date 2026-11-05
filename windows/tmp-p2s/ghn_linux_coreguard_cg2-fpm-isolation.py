#!/usr/bin/env python3
"""#3 CG-2: Phase 3 enforce isolation safety under PHP-FPM (plan 14.2 CG-2).

The Phase 3 containment ends the process with _exit(70). Under FPM the
master replaces the worker; this harness measures whether that replacement
stays healthy under REPEATED guard terminations (restart amplification) or
degrades availability - the attack surface the review flagged.

Matrix (modes: B=8.4.27-normalext baseline, C disabled/observe/enforce on
8.4.27-coreguard-normalext), pm.max_children in {1, 4}, N repeated
fault-injecting requests per cell:
  - worker pid before/after each fault, per-fault transition log (old/new)
  - next healthy request after each fault (availability)
  - HTTP success rate, 5xx/reset/client-timeout counts
  - background /health prober: healthy-baseline window plus served-probe
    latency p50/p95/p99 and success rate while the worker is occupied
    (queueing through the restart window)
  - listen queue depth (ss Recv-Q) and configured backlog for the nginx and
    FPM listeners
  - wall time for N faults + N healths (restart cost proxy)
  - data loss proxy: response bytes received for a streaming request
    interrupted mid-body by the guard on the SAME connection

Fail-closed cell startup (2026-10-24 plan prerequisite): the lab ports must
be free before spawn, and the pidfile daemons must provably belong to THIS
cell (pid alive + cmdline cites the cell dir) before any request is sent;
otherwise the cell errors out instead of measuring a stale stack.

Observation only: no heap grooming, no weaponization; faults are the
phase3 test suite's synthetic destructor fatal (S1 shape: unset() during
execution fires the dtor fatal mid-body, bounded loop so every mode
self-terminates).
"""
import argparse
import http.client
import json
import os
import signal
import socket
import subprocess
import sys
import threading
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent))
import provenance  # noqa: E402

BASE = Path('/home/phplab/php-lab')
HTTP_PORT, FPM_PORT = 18095, 19095
HEALTH_PATH = '/health'


def lab(build, mode, max_children, out, php_ini_extra=''):
    """One FPM pool + nginx front for a (build, mode, max_children) cell."""
    for name in ('sessions', 'uploads', 'nginx'):
        (out / name).mkdir(parents=True, exist_ok=True)
    ini = (HERE.parents[1] / 'config/php.ini').read_text() + '\n'
    ini += ('memory_limit=32M\nmax_execution_time=8\nsession.save_path=%s\nupload_tmp_dir=%s\n'
            'error_log=%s\n' % (out / 'sessions', out / 'uploads', out / 'php-error.log'))
    if php_ini_extra:
        ini += php_ini_extra
    (out / 'php.ini').write_text(ini)
    (out / 'www.conf').write_text(f'''[global]
daemonize = no
error_log = {out}/fpm-error.log
pid = {out}/fpm.pid
[lab]
user = phplab
group = phplab
listen = 127.0.0.1:{FPM_PORT}
pm = static
pm.max_children = {max_children}
clear_env = no
access.log = {out}/fpm-access.log
''')
    router = out / 'router.php'
    router.write_text('''<?php
$u = $_SERVER['REQUEST_URI'];
if ($u === '/fault') {
    // phase3 S1 shape: dtor fatal fired MID-BODY by unset() during execution,
    // bounded loop - the request self-terminates in every mode (no infinite
    // stream: an unterminated stream can never be bounded by per-recv
    // socket timeouts because chunks keep arriving).
    class D { function __destruct() { trigger_error("dtor", E_USER_ERROR); } }
    $a = [new D, new D, 1];
    echo "probe ";
    for ($i = 0; $i < 512; $i++) {
        echo str_pad('', 4096, 'x');
        flush();
        usleep(1000);
        if ($i === 256) { unset($a); }
    }
}
if ($u === '/health') { echo json_encode(['ok' => true, 'pid' => getmypid()]); return true; }
echo 'not-found';
return true;
''')
    (out / 'nginx.conf').write_text(f'''daemon off;
pid {out}/nginx.pid;
error_log {out}/nginx-error.log;
events {{ worker_connections 128; }}
http {{
 access_log off;
 client_body_temp_path {out}/nginx;
 proxy_temp_path {out}/nginx;
 uwsgi_temp_path {out}/nginx;
 scgi_temp_path {out}/nginx;
 fastcgi_temp_path {out}/nginx;
 server {{
  listen 127.0.0.1:{HTTP_PORT};
  client_max_body_size 8m;
  fastcgi_request_buffering on;
  location / {{
   include /etc/nginx/fastcgi_params;
   fastcgi_param SCRIPT_FILENAME {router};
   fastcgi_pass 127.0.0.1:{FPM_PORT};
  }}
 }}
}}
''')
    env = dict(PATH='/usr/bin:/bin', USE_ZEND_ALLOC='1')
    if mode != 'B':
        env['COREGUARD_MODE'] = mode
        env['COREGUARD_LOG'] = str(out / 'cg-events.log')
    procs = []
    logs = []
    for name, cmd in (
            ('fpm', [str(BASE / 'install' / build / 'sbin/php-fpm'),
                     '-c', str(out / 'php.ini'), '-y', str(out / 'www.conf')]),
            ('nginx', ['/usr/sbin/nginx', '-p', str(out), '-c', str(out / 'nginx.conf')])):
        log = (out / f'{name}-console.log').open('w')
        logs.append(log)
        procs.append(subprocess.Popen(cmd, env=env, stdout=log,
                                      stderr=subprocess.STDOUT, start_new_session=True))
    return procs, logs, env


def http_get(path, timeout=8):
    conn = http.client.HTTPConnection('127.0.0.1', HTTP_PORT, timeout=timeout)
    try:
        conn.request('GET', path)
        res = conn.getresponse()
        body = res.read()
        return res.status, body
    except Exception as exc:
        return None, type(exc).__name__
    finally:
        conn.close()


def worker_pids(out):
    try:
        master = int((out / 'fpm.pid').read_text().strip())
        children = subprocess.check_output(
            ['pgrep', '-P', str(master)], text=True).split()
        return master, sorted(int(c) for c in children)
    except Exception:
        return None, []


def port_free(port):
    """True when no LISTENER holds the port. SO_REUSEADDR makes the bind
    probe succeed over harmless TIME_WAIT remnants while a live listener
    still fails with EADDRINUSE."""
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        s.bind(('127.0.0.1', port))
        return True
    except OSError:
        return False
    finally:
        s.close()


def pidfile_owner_ok(out, name):
    """Daemon pid for this cell is alive and its cmdline cites the cell dir."""
    try:
        pid = int((out / f'{name}.pid').read_text().strip())
        cmd = Path(f'/proc/{pid}/cmdline').read_bytes().decode('utf-8', 'replace')
    except (OSError, ValueError):
        return None
    return pid if str(out) in cmd else None


def listen_depths():
    """Recv-Q (accept queue depth) and Send-Q (backlog) per lab listener."""
    try:
        lines = subprocess.check_output(['ss', '-ltnH'], text=True).splitlines()
    except Exception:
        return None
    depths = {}
    for ln in lines:
        parts = ln.split()
        if len(parts) < 4:
            continue
        for name, port in (('http', HTTP_PORT), ('fpm', FPM_PORT)):
            if parts[3].endswith(':%d' % port):
                depths[name] = (int(parts[1]), int(parts[2]))
    return depths


def percentile(vals, p):
    if not vals:
        return None
    s = sorted(vals)
    i = min(len(s) - 1, max(0, round(p / 100.0 * (len(s) - 1))))
    return round(s[i], 1)


class HealthProber:
    """Background /health load: queue depth and tail latency stay observable
    while the single worker is occupied by a fault stream."""

    def __init__(self, interval=0.05, track_queue=True):
        self.interval = interval
        self.track_queue = track_queue
        self.samples = []  # (latency_ms, status)
        self.listenq = {}  # name -> [max_depth, backlog]
        self.stop_evt = threading.Event()
        self.thread = threading.Thread(target=self._run, daemon=True)

    def _run(self):
        while not self.stop_evt.is_set():
            t0 = time.time()
            status, _ = http_get(HEALTH_PATH, timeout=6)
            self.samples.append((round((time.time() - t0) * 1000, 1), status))
            if self.track_queue:
                snap = listen_depths()
                if snap:
                    for k, (depth, backlog) in snap.items():
                        cur = self.listenq.setdefault(k, [0, backlog])
                        cur[0] = max(cur[0], depth)
                        cur[1] = backlog
            self.stop_evt.wait(self.interval)

    def __enter__(self):
        self.thread.start()
        return self

    def __exit__(self, *exc):
        self.stop_evt.set()
        self.thread.join(timeout=10)
        return False


def cell(build, mode, max_children, faults, root, env_extra=''):
    out = root / f'{build}-{mode}-mc{max_children}'
    out.mkdir(parents=True, exist_ok=True)
    record = dict(build=build, mode=mode, max_children=max_children,
                  faults_requested=faults)
    busy = [p for p in (HTTP_PORT, FPM_PORT) if not port_free(p)]
    if busy:
        record['error'] = 'port_in_use:%s' % ','.join(map(str, busy))
        record['error_hint'] = 'a previous lab stack still holds the lab ports'
        return record
    procs, logs, env = lab(build, mode, max_children, out, env_extra)
    try:
        deadline = time.time() + 20
        fpm_pid = ng_pid = None
        while time.time() < deadline:
            fpm_pid = pidfile_owner_ok(out, 'fpm')
            ng_pid = pidfile_owner_ok(out, 'nginx')
            if fpm_pid and ng_pid:
                break
            time.sleep(0.2)
        if not (fpm_pid and ng_pid):
            record['error'] = 'stack_identity_unverified'
            for name in ('fpm', 'nginx'):
                log = out / f'{name}-console.log'
                if log.exists():
                    record[f'{name}_console_tail'] = log.read_text()[-300:]
            return record
        deadline = time.time() + 20
        while time.time() < deadline:
            status, body = http_get(HEALTH_PATH, timeout=2)
            if status == 200 and b'"ok":true' in body:
                break
            time.sleep(0.2)
        else:
            record['error'] = 'startup timeout'
            return record
        master, pids_before = worker_pids(out)
        if master != fpm_pid or not pids_before:
            record['error'] = 'worker_pool_unverified'
            return record
        record['pool_master'] = master
        record['workers_before'] = pids_before
        ok = reset = err = client_timeouts = 0
        replaced = 0
        pid_transitions = []
        stream_intact = 0
        with HealthProber() as prober:
            time.sleep(3.0)  # healthy-baseline window before any fault
            n_base = len(prober.samples)
            t0 = time.time()
            for i in range(faults):
                tf0 = time.time()
                status, body = http_get('/fault', timeout=6)
                t_fault = round((time.time() - tf0) * 1000, 1)
                if status == 200:
                    ok += 1  # stream ended server-side within the client window
                elif status is None and body == 'TimeoutError':
                    client_timeouts += 1  # client gave up; no guard hit observed
                elif status is None and body in ('ConnectionResetError',
                                                 'BrokenPipeError', 'IncompleteRead',
                                                 'OSError'):
                    reset += 1
                else:
                    err += 1
                _, pids_after = worker_pids(out)
                if pids_after and pids_after != pids_before:
                    replaced += 1
                    pid_transitions.append(
                        dict(fault=i, before=pids_before, after=pids_after,
                             t_fault_ms=t_fault))
                    pids_before = pids_after
                h_status, h_body = http_get(HEALTH_PATH, timeout=6)
                if h_status != 200:
                    record.setdefault('health_failures', []).append(i)
            elapsed = round(time.time() - t0, 1)
        base = [ms for ms, st in prober.samples[:n_base] if st == 200]
        load = [ms for ms, st in prober.samples[n_base:] if st == 200]
        record.update(http_200=ok, resets=reset, other_errors=err,
                      client_timeouts=client_timeouts,
                      worker_replacements=replaced,
                      worker_pid_transitions=pid_transitions,
                      workers_final=pids_before,
                      elapsed_s=elapsed,
                      probes_baseline=len(prober.samples[:n_base]),
                      probes_baseline_200=len(base),
                      probe_baseline_ms=dict(p50=percentile(base, 50),
                                             p95=percentile(base, 95),
                                             p99=percentile(base, 99)),
                      probes_faultwin=len(prober.samples[n_base:]),
                      probes_faultwin_200=len(load),
                      probe_faultwin_ms=dict(p50=percentile(load, 50),
                                             p95=percentile(load, 95),
                                             p99=percentile(load, 99),
                                             max=percentile(load, 100)),
                      listenq=({k: dict(max_depth=v[0], backlog=v[1])
                                for k, v in prober.listenq.items()}
                               if prober.listenq else {'error': 'unavailable'}))
        # data-loss proxy: stream interrupted mid-body keeps what it sent
        try:
            conn = http.client.HTTPConnection('127.0.0.1', HTTP_PORT, timeout=6)
            conn.request('GET', '/fault')
            res = conn.getresponse()
            chunk = res.read(8192)
            stream_intact = len(chunk)
            conn.close()
        except Exception:
            stream_intact = -1
        record['first_chunk_bytes'] = stream_intact
        cg = out / 'cg-events.log'
        if cg.exists():
            by_name = {}
            for ln in cg.read_text().splitlines():
                if 'COREGUARD event=' in ln:
                    kind = ln.split('event=', 1)[1].split()[0]
                    by_name[kind] = by_name.get(kind, 0) + 1
            record['guard_events'] = sum(by_name.values())
            # by NAME: line counts alone conflated Phase 3 containment
            # events with Phase 2b hook events (2026-10-24 review)
            record['guard_events_by_name'] = by_name
        else:
            record['guard_events'] = 0
    finally:
        for pidfile in ('fpm.pid', 'nginx.pid'):
            try:
                os.kill(int((out / pidfile).read_text().strip()), signal.SIGTERM)
            except (OSError, ValueError):
                pass
        for p in procs:
            try:
                p.terminate()
                p.wait(timeout=5)
            except Exception:
                p.kill()
        for l in logs:
            l.close()
        subprocess.run(['pkill', '-f', 'php-fpm.*%s' % out.name], capture_output=True)
        deadline = time.time() + 5
        while time.time() < deadline and not (port_free(HTTP_PORT) and port_free(FPM_PORT)):
            time.sleep(0.1)
        if not (port_free(HTTP_PORT) and port_free(FPM_PORT)):
            for pidfile in ('fpm.pid', 'nginx.pid'):
                try:
                    os.kill(int((out / pidfile).read_text().strip()), signal.SIGKILL)
                except (OSError, ValueError):
                    pass
            time.sleep(0.5)
    return record


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--faults', type=int, default=10)
    parser.add_argument('--max-children', type=int, nargs='+', default=[1, 4])
    parser.add_argument('--build-b', default='8.4.27-normalext',
                        help='baseline build name under install/')
    parser.add_argument('--build-c', default='8.4.27-coreguard-normalext',
                        help='CoreGuard build name under install/ (CG-3 ZTS)')
    args = parser.parse_args()
    stamp = time.strftime('%Y%m%dT%H%M%S', time.gmtime())
    root = BASE / 'evidence' / ('cg2-fpm-%s' % stamp)
    root.mkdir(parents=True)
    rows = []
    for mc in args.max_children:
        for build, mode in ((args.build_b, 'B'),
                            (args.build_c, 'disabled'),
                            (args.build_c, 'observe'),
                            (args.build_c, 'enforce')):
            row = cell(build, mode, mc, args.faults, root)
            rows.append(row)
            print(json.dumps(row), flush=True)
    summary = dict(scope='#3 CG-2 FPM isolation matrix; observation only',
                   faults=args.faults, rows=rows, **provenance.provenance())
    (root / 'summary.json').write_text(json.dumps(summary, indent=2))
    print(json.dumps(dict(out=str(root), rows=len(rows))))


if __name__ == '__main__':
    sys.exit(main())
