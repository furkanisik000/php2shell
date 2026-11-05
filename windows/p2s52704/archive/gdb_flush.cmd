set pagination off
set confirm off
attach 42
# php_session_flush at 0x723bb940e810
break *(0x723bb940e810)
commands
silent
echo \n=== php_session_flush ENTER (full backtrace) ===\n
bt 15
echo "--- ps_globals ---\n
x/4gx (void*)0x723bba001120
end
continue
