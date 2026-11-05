set pagination off
set confirm off
set width 0
set logging file /tmp/allocs.log
set logging overwrite on
set logging enabled on
break *0x7024b58eab7c
commands
silent
printf "ALLOC48 ret=0x%lx\n", $rax
continue
end
continue
