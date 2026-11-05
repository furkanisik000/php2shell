set pagination off
set $p = (void*)&ps_globals
printf "session_status(0x68) = 0x%x\n", (unsigned int)*(unsigned int*)((char*)$p + 0x68)
printf "use_cookies(0x151)   = 0x%x\n", (unsigned int)*(unsigned char*)((char*)$p + 0x151)
printf "send_cookie(0x168)   = 0x%x\n", (unsigned int)*(unsigned char*)((char*)$p + 0x168)
printf "define_sid(0x169)    = 0x%x\n", (unsigned int)*(unsigned char*)((char*)$p + 0x169)
printf "use_strict_mode(0x1A0)= 0x%x\n", (unsigned int)*(unsigned char*)((char*)$p + 0x1A0)
