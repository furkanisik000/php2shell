import difflib, io, os

BASE = r'C:\Users\likat\.qwen\tmp\p2s'
PAIRS = [
    ('php-8.4.26', 'php-8.4.27', '8.4'),
    ('php-8.5.11', 'php-8.5.12', '8.5'),
]
SUBDIRS = ['main', 'Zend', 'ext/session']

out = io.open(os.path.join(BASE, 'patch.diff'), 'w', encoding='utf-8')
for a, b, tag in PAIRS:
    for sub in SUBDIRS:
        da = os.path.join(BASE, a, sub)
        db = os.path.join(BASE, b, sub)
        if not os.path.isdir(da) or not os.path.isdir(db):
            continue
        files_a = set()
        for root, _, fs in os.walk(da):
            for f in fs:
                if f.endswith(('.phpt', '.inc', '.json')):
                    continue
                files_a.add(os.path.relpath(os.path.join(root, f), da))
        files_b = set()
        for root, _, fs in os.walk(db):
            for f in fs:
                if f.endswith(('.phpt', '.inc', '.json')):
                    continue
                files_b.add(os.path.relpath(os.path.join(root, f), db))
        changed = []
        for f in sorted(files_a | files_b):
            fa = os.path.join(da, f)
            fb = os.path.join(db, f)
            if not (os.path.isfile(fa) and os.path.isfile(fb)):
                changed.append(f + ' (only in ' + (a if os.path.isfile(fa) else b) + ')')
                continue
            ha = io.open(fa, 'rb').read()
            hb = io.open(fb, 'rb').read()
            if ha != hb:
                changed.append(f)
        if not changed:
            continue
        out.write('#' * 25 + ' %s -> %s : %s  (%d changed)\n' % (a, b, sub, len(changed)))
        for f in changed:
            out.write('CHANGED: ' + f + '\n')
        # emit diffs for non-test files only
        for f in changed:
            if 'tests' in f:
                continue
            fa = os.path.join(da, f)
            fb = os.path.join(db, f)
            if not (os.path.isfile(fa) and os.path.isfile(fb)):
                continue
            la = io.open(fa, encoding='utf-8', errors='replace').readlines()
            lb = io.open(fb, encoding='utf-8', errors='replace').readlines()
            d = list(difflib.unified_diff(la, lb, a + '/' + sub + '/' + f, b + '/' + sub + '/' + f, n=4, lineterm=''))
            if d:
                out.write('--- 8.4/8.5 ' + f + ' (%d diff lines)\n' % len(d))
                for line in d:
                    out.write(line + '\n')
out.close()
print('done')
