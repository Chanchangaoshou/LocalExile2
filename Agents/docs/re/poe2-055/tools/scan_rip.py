import struct, sys
data = open('PathOfExile.exe','rb').read()
def va2raw(va): return va - 0x140000C00
def raw2va(raw): return raw + 0x140000C00
TEXT_START, TEXT_END = 0x400, 0x400 + (0x142e89000 - 0x140001000)
for t in [int(x,16) for x in sys.argv[1:]]:
    print(f"refs to {t:#x}:")
    for raw in range(TEXT_START+4, TEXT_END):
        disp = struct.unpack_from('<i', data, raw)[0]
        end_va = raw2va(raw+4)
        if end_va + disp == t:
            print(f"  disp32 ends at {end_va:#x} (insn starts ~{end_va-7:#x}..{end_va-4:#x})")
