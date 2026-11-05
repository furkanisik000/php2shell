import difflib, re

def read(p):
    with open(p, "r", encoding="utf-8", errors="replace") as f:
        return f.read().splitlines()

a = read(r"C:\Users\<USER>\.qwen\tmp\p2s\php-8.2.34\ext\session\session.c")
b = read(r"C:\Users\<USER>\.qwen\tmp\p2s\php-8.4.26\ext\session\session.c")
print(f"8.2.34 session.c: {len(a)} lines", flush=True)
print(f"8.4.26 session.c: {len(b)} lines", flush=True)

def extract(lines, start_pat, end_pat):
    start = None
    for i, l in enumerate(lines):
        if re.search(start_pat, l) and start is None:
            start = i
    if start is None:
        return None
    for j in range(start, len(lines)):
        if re.search(end_pat, lines[j]) and j > start + 2:
            return lines[start:j+1]
    return lines[start:start+200]

for name, sp, ep in [
    ("php_session_rfc1867_update", r"php_session_rfc1867_update\(void\)", r"^\}"),
    ("php_session_initialize", r"php_session_initialize\(void\)", r"^\}"),
    ("php_session_track_init", r"php_session_track_init\(void\)", r"^\}"),
]:
    fa = extract(a, sp, ep)
    fb = extract(b, sp, ep)
    if fa is None and fb is None:
        print(f"\n[{name}: not found in either]", flush=True); continue
    if fa is None:
        print(f"\n[{name}: only in 8.4.26, {len(fb)} lines]", flush=True); continue
    if fb is None:
        print(f"\n[{name}: only in 8.2.34, {len(fa)} lines]", flush=True); continue
    diff = list(difflib.unified_diff(fa, fb, fromfile=f"8.2.34 {name}", tofile=f"8.4.26 {name}", lineterm="", n=1))
    if not diff:
        print(f"\n[{name}: IDENTICAL ({len(fa)} lines)]", flush=True)
    else:
        print(f"\n[{name}: DIFFERS]", flush=True)
        for line in diff[:200]:
            print(line, flush=True)
