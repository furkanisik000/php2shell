import difflib

def read(p):
    with open(p, "r", encoding="utf-8", errors="replace") as f:
        return f.read().splitlines()

a = read(r"C:\Users\<USER>\.qwen\tmp\p2s\php-8.2.34\main\rfc1867.c")
b = read(r"C:\Users\<USER>\.qwen\tmp\p2s\php-8.4.26\main\rfc1867.c")
print(f"8.2.34 rfc1867.c: {len(a)} lines", flush=True)
print(f"8.4.26 rfc1867.c: {len(b)} lines", flush=True)
print("\n=== DIFF (8.2.34 -> 8.4.26) ===\n", flush=True)
diff = list(difflib.unified_diff(a, b, fromfile="8.2.34", tofile="8.4.26", lineterm="", n=1))
for line in diff:
    print(line, flush=True)
