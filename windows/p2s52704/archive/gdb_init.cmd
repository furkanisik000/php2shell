set pagination off
set confirm off
attach 42
# php_session_initialize at 0x723bb940dcd0
break *(0x723bb940dcd0)
commands
silent
echo \n=== php_session_initialize ENTER ===\n
echo "--- ps_globals first 40 bytes (id@0, status, http_session_vars) ---\n
x/5gx (void*)0x723bba001120
end
# php_session_encode at 0x723bb9408290
break *(0x723bb9408290)
commands
silent
echo \n=== php_session_encode ENTER ===\n
x/5gx (void*)0x723bba001120
end
continue
