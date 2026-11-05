set pagination off
set confirm off
attach 482
echo \n=== ps_globals dump (0x180 bytes) ===\n
x/48gx 0x740cf51a8820
echo \n=== PS(id) at +0x10 ===\n
x/gx 0x740cf51a8830
echo \n=== PS(http_session_vars) at +0x160 ===\n
x/gx 0x740cf51a8980
echo \n=== PS(mod) at +0x50 ===\n
x/gx 0x740cf51a8870
echo \n=== PS(session_status) at +0x68 ===\n
x/wx 0x740cf51a8888
echo \n=== PS(serializer) at +0x158 ===\n
x/gx 0x740cf51a8978
detach
quit
