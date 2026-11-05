set pagination off
set confirm off
set width 0
catch signal SIGSEGV
commands
  silent
  echo \n\n===== SIGSEGV backtrace =====\n
  bt 22
  echo ===== regs =====\n
  info registers rdi rsi rdx rax rbp
  echo ===== end =====\n
  detach
end
continue
