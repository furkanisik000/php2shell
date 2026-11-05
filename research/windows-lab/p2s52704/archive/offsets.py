#!/usr/bin/env python3
"""Extract zif_system / zval_ptr_dtor offsets from libphp.so (ELF .dynsym/.symtab)."""
import struct
import sys

WANT = ("zif_system", "zval_ptr_dtor")


def main(path):
    with open(path, "rb") as f:
        data = f.read()
    assert data[:4] == b"\x7fELF", "not an ELF"
    ei_class = data[4]
    assert ei_class == 2, "expected 64-bit ELF"
    e_shoff = struct.unpack_from("<Q", data, 0x28)[0]
    e_shentsize = struct.unpack_from("<H", data, 0x3A)[0]
    e_shnum = struct.unpack_from("<H", data, 0x3C)[0]
    e_shstrndx = struct.unpack_from("<H", data, 0x3E)[0]

    shdrs = []
    for i in range(e_shnum):
        off = e_shoff + i * e_shentsize
        shdrs.append(struct.unpack_from("<IIQQQQIIQQ", data, off))

    def name(sh):
        shstr = shdrs[e_shstrndx]
        off = shstr[4] + sh[0]
        end = data.index(b"\0", off)
        return data[off:end].decode()

    for sh in shdrs:
        sh_name = name(sh)
        if sh_name in (".dynsym", ".symtab"):
            st_size = sh[5]
            shoff = sh[4]
            link = sh[6]  # strtab section index
            if link >= len(shdrs):
                continue
            strtab = shdrs[link]
            stroff = strtab[4]
            n = st_size // 24
            for i in range(n):
                so = shoff + i * 24
                st_name, st_info, st_other, st_shndx, st_value, st_size = (
                    struct.unpack_from("<IBBHQQ", data, so))
                end = data.index(b"\0", stroff + st_name)
                sym = data[stroff + st_name:end].decode()
                if sym in WANT:
                    print(f"{sym} = 0x{st_value:x}  [{sh_name}]")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1]))
