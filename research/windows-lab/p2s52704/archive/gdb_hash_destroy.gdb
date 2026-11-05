set pagination off
set confirm off
set width 0
break *0x7bdb275027d0
commands
  silent
  echo ===== zend_hash_graceful_reverse_destroy HIT =====\n
  printf "HashTable ptr (rdi) = ", rdi
  printf "pDestructor at rdi+0x30 = ", *(unsigned long*)(rdi+0x30)
  printf "nNumUsed at rdi+0x18 = ", *(unsigned int*)(rdi+0x18)
  printf "nNumOfElements at rdi+0x1c = ", *(unsigned int*)(rdi+0x1c)
  printf "arData at rdi+0x10 = ", *(unsigned long*)(rdi+0x10)
  printf "zif_system expected = 0x7bdb273fa080\n"
  bt 10
  echo ===== end =====\n
  detach
end
continue
