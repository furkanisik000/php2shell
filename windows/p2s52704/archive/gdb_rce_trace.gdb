set pagination off
set confirm off
set width 0
break *0x7a4ef208d080
commands
silent
echo [HIT] zif_system(RCE)\nbt 3
continue
end
break *0x7a4ef2195370
commands
silent
echo [HIT] zend_hash_graceful_destroy\nbt 3
continue
end
break *0x7a4ef21957d0
commands
silent
echo [HIT] zend_hash_graceful_reverse_destroy\nbt 3
continue
end
break *0x7a4ef2033ec0
commands
silent
echo [HIT] php_rshutdown_session_globals\nbt 3
continue
end
break *0x7a4ef2031df0
commands
silent
echo [HIT] php_session_track_init\nbt 3
continue
end
break *0x7a4ef2037a30
commands
silent
echo [HIT] php_session_initialize\nbt 3
continue
end
continue
