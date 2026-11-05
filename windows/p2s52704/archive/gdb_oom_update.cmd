set pagination off
set confirm off
attach 42
# php_session_rfc1867_update at 0x723bb940f0d0
break *(0x723bb940f0d0)
commands
silent
echo \n=== rfc1867_update ENTER (during reqA OOM) ===\n
echo "PS(mod)="
print/x *(void**)((void*)0x723bba001120 + 0)
echo "PS(id)="
print/x *(void**)((void*)0x723bba001120 + 8)
echo "PS(session_status)="
# scan ps_globals for small int (session_status)
x/40wx (void*)0x723bba001120
end
continue
