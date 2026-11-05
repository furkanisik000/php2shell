set pagination off
set confirm off
set width 0
break *0x77684826e430
commands
silent
echo [HIT] rfc1867_post_handler\n
bt 4
continue
end
break *0x7768481883a0
commands
silent
echo [HIT] php_session_rfc1867_callback\n
frame
info args
bt 4
continue
end
continue
