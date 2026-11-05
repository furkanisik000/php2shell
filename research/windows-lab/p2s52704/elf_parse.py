"""Parse ELF .so file to find RCE-capable function symbols.
Uses Python's ctypes + manual ELF parsing.
"""
import struct, sys, os

def parse_elf_symbols(path):
    """Parse ELF64 symbols and return list of (name, value, size, type)."""
    with open(path, "rb") as f:
        data = f.read()

    # ELF header
    if data[:4] != b"\x7fELF":
        print("Not an ELF file", flush=True)
        return []

    ei_class = data[4]  # 1=32bit, 2=64bit
    if ei_class != 2:
        print("Only ELF64 supported", flush=True)
        return []

    # Section header table offset and count
    e_shoff = struct.unpack_from("<Q", data, 0x28)[0]
    e_shentsize = struct.unpack_from("<H", data, 0x3A)[0]
    e_shnum = struct.unpack_from("<H", data, 0x3C)[0]
    e_shstrndx = struct.unpack_from("<H", data, 0x3E)[0]

    # Read section headers
    sections = []
    for i in range(e_shnum):
        off = e_shoff + i * e_shentsize
        sh_name = struct.unpack_from("<I", data, off)[0]
        sh_type = struct.unpack_from("<I", data, off + 4)[0]
        sh_offset = struct.unpack_from("<Q", data, off + 0x18)[0]
        sh_size = struct.unpack_from("<Q", data, off + 0x20)[0]
        sh_link = struct.unpack_from("<I", data, off + 0x28)[0]
        sh_entsize = struct.unpack_from("<Q", data, off + 0x38)[0]
        sections.append({
            "name_off": sh_name, "type": sh_type, "offset": sh_offset,
            "size": sh_size, "link": sh_link, "entsize": sh_entsize,
        })

    # Find .symtab (type 2) and .strtab
    symtab = None
    strtab = None
    for s in sections:
        if s["type"] == 2:  # SHT_SYMTAB
            symtab = s
        if s["type"] == 3:  # SHT_STRTAB
            # Check if it's linked from symtab
            if symtab and s["offset"] == 0:
                pass

    if not symtab:
        print("No .symtab found", flush=True)
        return []

    # The string table is at symtab.link
    strtab_sec = sections[symtab["link"]]
    str_off = strtab_sec["offset"]
    str_size = strtab_sec["size"]

    def get_string(name_off):
        end = data.index(b"\x00", str_off + name_off)
        return data[str_off + name_off:end].decode("latin1")

    # Parse symbols
    symbols = []
    n_syms = symtab["size"] // symtab["entsize"]
    for i in range(n_syms):
        off = symtab["offset"] + i * symtab["entsize"]
        st_name = struct.unpack_from("<I", data, off)[0]
        st_info = data[off + 4]
        st_type = st_info & 0xF
        st_bind = (st_info >> 4) & 0xF
        st_value = struct.unpack_from("<Q", data, off + 8)[0]
        st_size = struct.unpack_from("<Q", data, off + 16)[0]
        name = get_string(st_name) if st_name else ""
        if name and st_type == 2:  # STT_FUNC
            symbols.append((name, st_value, st_size))

    return symbols

def find_rce_functions(symbols):
    """Find RCE-capable functions."""
    rce_patterns = ["zif_system", "zif_passthru", "zif_exec", "zif_shell_exec",
                    "zif_popen", "zif_proc_open", "zif_putenv", "zif_pcntl_exec",
                    "php_system", "php_passthru", "php_exec", "php_shell_exec",
                    "php_popen", "php_proc_open", "php_putenv",
                    "zval_ptr_dtor", "zend_hash_graceful_destroy",
                    "zif_unserialize", "zif_include", "zif_require"]
    found = []
    for name, value, size in symbols:
        for pat in rce_patterns:
            if pat in name.lower():
                found.append((name, value, size))
                break
    return found

if __name__ == "__main__":
    path = sys.argv[1] if len(sys.argv) > 1 else r"research/windows-lab/p2s52704\archive\libphp7_7433.so"
    print(f"Parsing {path} ...", flush=True)
    symbols = parse_elf_symbols(path)
    print(f"Found {len(symbols)} function symbols", flush=True)

    rce = find_rce_functions(symbols)
    print(f"\n=== RCE-capable functions ({len(rce)}) ===", flush=True)
    for name, value, size in sorted(rce):
        print(f"  0x{value:08x}  size={size:6d}  {name}", flush=True)

    # Also find ps_globals
    for name, value, size in symbols:
        if "ps_globals" in name:
            print(f"\n  ps_globals: 0x{value:08x}  size={size}", flush=True)
