set pagination off
set confirm off
attach 42
# CORRECT offsets (struct layout): mod@0x50, id@0x10, session_status@0x68,
# serializer@0x158, http_session_vars@0x160
break *(0x723bb940b290)
commands
silent
echo \n=== php_session_encode ENTER (correct offsets) ===\n
echo "PS(mod)@0x50 = "
print/x *(void**)(0x723bba001170)
echo "PS(id)@0x10 = "
print/x *(void**)(0x723bba001130)
echo "PS(session_status)@0x68 = "
print *(int*)(0x723bba001188)
echo "PS(default_mod)@0x58 = "
print/x *(void**)(0x723bba001178)
echo "PS(serializer)@0x158 = "
print/x *(void**)(0x723bba001278)
echo "PS(http_session_vars)@0x160 = "
x/2gx 0x723bba001280
end
continue
