import os
import re, sys, os
BASE = r"C:\lab\.qwen\tmp\p2s"

def extract(fn, funcs):
    src = open(fn, encoding='utf-8', errors='replace').read()
    out = {}
    for f in funcs:
        m = re.search(r'\n((?:static |PHPAPI |SAPI_API )?[A-Za-z_][\w \*]*\b' + f + r'\s*\()', src)
        if not m:
            out[f] = '<NOT FOUND>'
            continue
        start = m.start() + 1
        i = src.index('{', start)
        depth = 0
        for j in range(i, len(src)):
            if src[j] == '{':
                depth += 1
            elif src[j] == '}':
                depth -= 1
                if depth == 0:
                    out[f] = src[start:j+1]
                    break
    return out

funcs = ['php_session_rfc1867_callback', 'php_session_rfc1867_update',
         'php_session_rfc1867_cleanup', 'php_session_initialize',
         'php_session_track_init', 'php_rshutdown_session_globals',
         'php_session_destroy', 'php_session_flush']

a = extract(os.path.join(BASE, 'php-8.3.35/ext/session/session.c'), funcs)
b = extract(os.path.join(BASE, 'php-8.4.26/ext/session/session.c'), funcs)
print(f'{"function":40s} status')
print('-' * 60)
for f in funcs:
    same = a[f] == b[f]
    print(f'{f:40s} {"IDENTICAL" if same else "DIFFERENT":10s} 8.3={len(a[f])}b 8.4={len(b[f])}b')

# Save the differing functions for detailed review
for f in funcs:
    if a[f] != b[f]:
        with open(os.path.join(os.path.dirname(__file__), f'fn_83_{f}.c'), 'w', encoding='utf-8') as fa:
            fa.write(a[f])
        with open(os.path.join(os.path.dirname(__file__), f'fn_84_{f}.c'), 'w', encoding='utf-8') as fb:
            fb.write(b[f])
print("\nSaved differing functions to fn_83_*.c / fn_84_*.c")
