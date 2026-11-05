set pagination off
set confirm off
attach 42
# ps_globals at 0x723bba001120; PS(mod)@0, PS(id)@8, PS(session_status)@? (scan)
# php_session_rfc1867_callback at 0x723bb940f320
break *(0x723bb940f320)
commands
silent
echo \n=== rfc1867_callback ENTER ===\n
echo "PS(mod)="
print/x *(void**)((void*)0x723bba001120 + 0)
echo "PS(id)="
print/x *(void**)((void*)0x723bba001120 + 8)
end
# php_session_start at 0x723bb940e2a0
break *(0x723bb940e2a0)
commands
silent
echo \n=== php_session_start ENTER ===\n
end
# php_session_decode at 0x723bb940b6c0
break *(0x723bb940b6c0)
commands
silent
echo \n=== php_session_decode ENTER ===\n
end
continue
