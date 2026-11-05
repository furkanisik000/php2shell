set pagination off
set confirm off
set width 0
break *0x70bf7e029080
commands
  silent
  echo ===== ZIF_SYSTEM CALLED =====\n
  bt 15
  info registers rdi rsi rdx rax
  echo ===== end =====\n
  detach
end
continue
