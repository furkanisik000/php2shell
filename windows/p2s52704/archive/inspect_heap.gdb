set pagination off
set confirm off
attach 589
echo \n=== LEAKED structure (chunk+0x8e1b0 = 0x7a43d748e1b0) ===\n
x/24gx 0x7a43d748e1b0
echo \n=== ZVAL_PTR_DTOR structure (chunk+0x2068 = 0x7a43d7402068) ===\n
x/16gx 0x7a43d7402068
echo \n=== around zval_ptr_dtor (chunk+0x2000 .. +0x2100) ===\n
x/20gx 0x7a43d7402000
echo \n=== ps_globals (find PS(id), PS(http_session_vars)) ===\n
# ps_globals is a libphp BSS symbol; resolve via libphp base 0x7a43d9480000
info symbol 0x7a43d9480000+0xf3a120
end
detach
