set pagination off
set confirm off
set width 0
break *0x77cf70ff36c0
commands
silent
echo [HIT] php_session_flush\nset $R = *(unsigned long*)0x77cf71cdf3e0
if $R != 0
print/x $R
echo === PS(http_session_vars) zval ===\nx/2gx 0x77cf71cdf3e0
echo === R-0x80 .. R+0x80 ===\nx/40gx $R-0x80
echo === R struct (gc.refcount,gc.type,val.value,val.type) ===\nx/4gx $R
end
detach
end
continue
