set pagination off
set confirm off
set width 0
break *0x77cf70ff36c0
commands
silent
echo [HIT] php_session_flush\necho === PS(http_session_vars) zval (value, type_info) ===\nx/2gx 0x77cf71cdf3e0
echo === session_status (ps_globals+0x68) ===\nx/1wx 0x77cf71cdf308
detach
end
continue
