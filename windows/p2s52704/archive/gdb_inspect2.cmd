set pagination off
set confirm off
attach 42
break *(0x723bb9408290)
commands
silent
echo \n=== BREAK php_session_encode (rfc1867 path) ===\n
echo "--- ps_globals raw (first 64 bytes) ---\n
x/8gx (void*)0x723bba001120
echo "--- ps_globals.http_session_vars zval (offset to be found) ---\n
print/x *(int*)((void*)0x723bba001120 + 0)
print/x *(int*)((void*)0x723bba001120 + 4)
echo "--- scan ps_globals for pointer values (0x70..-0x80..) ---\n
x/68gx (void*)0x723bba001120
end
continue
