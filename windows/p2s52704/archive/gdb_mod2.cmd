set pagination off
set confirm off
attach 42
# php_session_rfc1867_update at 0x723bb940f0d0 (ALWAYS fires when rfc1867 active)
break *(0x723bb940f0d0)
commands
silent
echo \n=== rfc1867_update ENTER: PS state (correct offsets) ===\n
echo "PS(mod)@0x50 = "
print/x *(void**)(0x723bba001170)
echo "PS(default_mod)@0x58 = "
print/x *(void**)(0x723bba001178)
echo "PS(id)@0x10 = "
print/x *(void**)(0x723bba001130)
echo "PS(session_status)@0x68 = "
print *(int*)(0x723bba001188)
echo "PS(serializer)@0x158 = "
print/x *(void**)(0x723bba001278)
echo "PS(rfc1867_enabled)@? = "
x/40gx 0x723bba001120
end
continue
