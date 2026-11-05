set pagination off
set confirm off
attach 42
break *(0x723bb9408290)
commands
silent
echo \n=== BREAK php_session_encode ===\n
echo "--- backtrace ---\n
bt 8
echo "--- ps_globals.http_session_vars (zval) ---\n
print/x ps_globals.http_session_vars
echo "--- PS(id) ---\n
print ps_globals.id
echo "--- PS(name) ---\n
print ps_globals.name
end
continue
