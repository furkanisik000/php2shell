# gdb script: attach to the 8.2.34 apache worker, break at php_session_encode,
# inspect PS(http_session_vars) after the OOM (reqA) + reqB.
set pagination off
set confirm off
attach 982
# php_session_encode is at 0x343290 in libphp.so (8.2.34)
b *(0x343290)
commands
silent
printf "=== BREAK at php_session_encode ===\n"
# PS(http_session_vars) is in the session globals (ps_globals).
# Find it via the session module's globals. Print the zval.
info proc mappings | grep libphp
continue
end
continue
