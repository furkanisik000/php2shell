set pagination off
set confirm off
attach 152
python
base = 0x7a43d7400000
liblo = 0x7a43d9480000
libhi = 0x7a43da000000
libphp_base = 0x7a43d9480000
found = []
inferior = gdb.selected_inferior()
for off in range(0, 0x200000, 8):
    addr = base + off
    try:
        v = int.from_bytes(inferior.read_memory(addr, 8).tobytes(), 'little')
        if liblo <= v < libhi:
            found.append((off, v))
    except Exception:
        pass
print("FOUND %d libphp-range pointers in Zend MM chunk" % len(found))
for off, v in found[:50]:
    print("  chunk+0x%x = 0x%x  (libphp+0x%x)" % (off, v, v - libphp_base))
end
detach
