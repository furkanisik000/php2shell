set pagination off
set confirm off
set width 0
attach 56
break *0x7c700de53080
commands
  silent
  echo \n\n===== ZIF_SYSTEM CALLED (rdi=execute_data) =====\n
  printf "rdi=0x%lx rsi=0x%lx rdx=0x%lx\n", $rdi, $rsi, $rdx
  x/4gx $rdi
  bt 15
  echo ===== END =====\n
  detach
end
continue
