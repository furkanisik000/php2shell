set pagination off
set confirm off
attach 589
echo \n=== Find libphp base (ps_globals is in libphp) ===\n
# ps_globals at 0x740cf51a8820; find the libphp.so mapping that contains it
info symbol ps_globals
echo \n=== zval_ptr_dtor symbol ===\n
info symbol zval_ptr_dtor
echo \n=== zif_system symbol ===\n
info symbol zif_system
detach
quit
