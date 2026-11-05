import idaapi, idautils, idc, ida_bytes, ida_funcs, ida_ua
import sys

# Find and disassemble key functions
def disasm_func(name, max_lines=400):
    ea = idc.get_name_ea_simple(name)
    if ea == idc.BADADDR:
        print(f"[!] {name}: not found", flush=True)
        return
    func = ida_funcs.get_func(ea)
    if not func:
        print(f"[!] {name}: no function at 0x{ea:x}", flush=True)
        return
    print(f"\n=== {name} @ 0x{ea:x} (size 0x{func.end-ea.start:x}) ===", flush=True)
    lines = 0
    for addr in range(func.start, min(func.end, func.start + 0x4000), 1):
        line = idc.generate_disasm_line(addr, 0)
        if line:
            print(f"  0x{addr:x}: {line}", flush=True)
            lines += 1
            if lines >= max_lines:
                print("  ... (truncated)", flush=True)
                break

def main():
    print(f"[*] Analyzing: {idaapi.get_input_file_path()}", flush=True)
    # List all session/rfc1867 related functions
    print("\n=== session/rfc1867/variable functions ===", flush=True)
    for ea in idautils.Functions():
        name = idc.get_func_name(ea)
        if any(k in name for k in ["rfc1867", "register_variable", "session_initialize",
                                    "session_track_init", "php_session_rfc1867",
                                    "input_filter", "parse_post", "rfc1867_post"]):
            print(f"  0x{ea:x}: {name}", flush=True)

    print("\n\n=== DISASSEMBLY ===", flush=True)
    disasm_func("php_session_rfc1867_update", 200)
    disasm_func("php_session_rfc1867_callback", 200)
    disasm_func("php_register_variable_ex", 300)
    disasm_func("php_session_initialize", 200)
    disasm_func("php_session_track_init", 200)

    print("\n[*] Done.", flush=True)
    idaapi.qexit(0)

main()
