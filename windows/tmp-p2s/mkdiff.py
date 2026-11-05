import os
import difflib, io

a = r'C:\Users\<USER>\.qwen\tmp\p2s\php-8.4.26\ext\session'
b = r'C:\Users\<USER>\.qwen\tmp\p2s\php-8.5.11\ext\session'
out = io.open(os.path.join(os.path.expanduser('~'), '.qwen', 'tmp', 'p2s', 'session.diff'), 'w', encoding='utf-8')
for f in ['session.c', 'php_session.h', 'mod_mm.c', 'mod_user_class.c']:
    la = io.open(a + '\\' + f, encoding='utf-8', errors='replace').readlines()
    lb = io.open(b + '\\' + f, encoding='utf-8', errors='replace').readlines()
    d = list(difflib.unified_diff(la, lb, '8.4.26/' + f, '8.5.11/' + f, n=3, lineterm=''))
    out.write('=' * 20 + ' ' + f + ' diff lines: %d\n' % len(d))
    for line in d:
        out.write(line + '\n')
out.close()
print('done')
