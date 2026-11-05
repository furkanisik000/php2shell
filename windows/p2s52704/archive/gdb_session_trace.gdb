set pagination off
set confirm off
set width 0
break *0x776848186a30
commands
  silent
  echo [HIT] php_session_initialize\n
  bt 5
  detach
end
break *0x776848184500
commands
  silent
  echo [HIT] php_session_destroy\n
  bt 5
  detach
end
break *0x7768481876c0
commands
  silent
  echo [HIT] php_session_flush\n
  bt 5
  detach
end
break *0x7768481883a0
commands
  silent
  echo [HIT] php_session_rfc1867_callback\n
  bt 5
  detach
end
break *0x7768482e47d0
commands
  silent
  echo [HIT] zend_hash_graceful_reverse_destroy\n
  bt 5
  detach
end
continue
