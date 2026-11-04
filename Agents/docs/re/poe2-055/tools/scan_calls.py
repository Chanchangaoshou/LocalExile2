import struct, sys
data = open('PathOfExile.exe','rb').read()
# .text: VA 0x140001000 raw 0x400 -> raw = va - 0x140000C00
def va2raw(va): return va - 0x140000C00
def raw2va(raw): return raw + 0x140000C00
TEXT_RAW_START, TEXT_RAW_END = 0x400, 0x400 + (0x142e89000 - 0x140001000)
def scan(target):
    hits = []
    for raw in range(TEXT_RAW_START, TEXT_RAW_END - 5):
        op = data[raw]
        if op in (0xE8, 0xE9):
            rel = struct.unpack_from('<i', data, raw + 1)[0]
            insn_va = raw2va(raw)
            if insn_va + 5 + rel == target:
                hits.append((insn_va, 'call' if op == 0xE8 else 'jmp'))
    return hits
for t in [int(x, 16) for x in sys.argv[1:]]:
    print(f"target {t:#x}:")
    for va, kind in scan(t):
        print(f"  {kind} at {va:#x}")
