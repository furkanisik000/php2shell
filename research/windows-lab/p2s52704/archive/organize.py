"""Organize p2s52704: move old scripts to archive/, keep exploit.py + STATUS.md."""
import os, shutil

BASE = os.path.dirname(os.path.abspath(__file__))
ARCHIVE = os.path.join(BASE, "archive")
os.makedirs(ARCHIVE, exist_ok=True)

# Files to keep in the main folder
KEEP = {"exploit.py", "STATUS.md", "poc", "results", "archive"}

moved = 0
for f in os.listdir(BASE):
    full = os.path.join(BASE, f)
    if f in KEEP:
        continue
    if os.path.isdir(full):
        continue
    # Move to archive
    dest = os.path.join(ARCHIVE, f)
    try:
        shutil.move(full, dest)
        moved += 1
    except Exception as e:
        print(f"  SKIP {f}: {e}")

print(f"Moved {moved} files to archive/", flush=True)

# List what's left in the main folder
print("\nMain folder now contains:", flush=True)
for f in sorted(os.listdir(BASE)):
    full = os.path.join(BASE, f)
    tag = "/" if os.path.isdir(full) else ""
    print(f"  {f}{tag}", flush=True)
