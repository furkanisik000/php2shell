set pagination off
set confirm off
attach 482
echo \n=== session-vars HashTable (PS(http_session_vars) = 0x740cf51a13b8) ===\n
# HashTable: arData@0x10, arBuckets@0x18, nNumUsed@0x20, pDestructor@0x38
x/12gx 0x740cf51a13b8
echo \n=== arData (at +0x10) ===\n
x/gx 0x740cf51a13c8
echo \n=== arBuckets (at +0x18) ===\n
x/gx 0x740cf51a13d0
echo \n=== pDestructor (at +0x38) ===\n
x/gx 0x740cf51a13f0
echo \n=== zval_ptr_dtor expected at libphp+0x65eb60 ===\n
# libphp base = ps_globals (0x740cf51a8820) is in libphp; find libphp base
info proc mappings
detach
quit
