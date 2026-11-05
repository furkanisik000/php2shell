set pagination off
attach 42
echo session_module_entry @ 0x723bba001040:\n
x/20gx (void*)0x723bba001040
detach
