import struct
from capstone import Cs, CS_ARCH_X86, CS_MODE_64
data = open('PathOfExile.exe','rb').read()
def q(va): return struct.unpack_from('<Q', data, va - 0x140001200)[0]
def va2raw(va): return va - 0x140000C00
SLOT0 = {0x14015c940, 0x1408a3250}
classes = []
for base in (0x1434e5000, 0x14350a000):
    for off in range(0, 0x2000, 0x10):
        vt = base + off
        try: s0, s1, s2 = q(vt), q(vt+8), q(vt+0x10)
        except struct.error: break
        if s0 in SLOT0 and 0x140001000 <= s2 < 0x142e89000 and 0x140001000 <= s1 < 0x142e89000:
            classes.append((vt, s1, s2))
md = Cs(CS_ARCH_X86, CS_MODE_64); md.skipdata = True
print(f"{len(classes)} candidate classes")
for vt, wr, rd in classes:
    callees = {}
    n = 0
    for i in md.disasm(data[va2raw(rd):va2raw(rd)+0x500], rd):
        n += 1
        if i.mnemonic == 'call':
            try: t = int(i.op_str, 16); callees[t] = callees.get(t, 0) + 1
            except ValueError: pass
        if i.mnemonic == 'ret': break
    rd_calls = callees.get(0x142197e80, 0)
    print(f"vt {vt:#x} write {wr:#x} read {rd:#x} insns~{n} readBytesCalls={rd_calls} distinctCallees={len(callees)}")
