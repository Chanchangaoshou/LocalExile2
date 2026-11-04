import struct
from capstone import Cs, CS_ARCH_X86, CS_MODE_64
data = open('PathOfExile.exe','rb').read()
RDATA_RAW, RDATA_VA, RDATA_SIZE = 0x2e87e00, 0x142e89000, 0x143a50000 - 0x142e89000
def q(raw): return struct.unpack_from('<Q', data, raw)[0]
def va2raw_text(va): return va - 0x140000C00
md = Cs(CS_ARCH_X86, CS_MODE_64); md.skipdata = True
hits = []
scanned = 0
for off in range(0, RDATA_SIZE - 0x20, 8):
    raw = RDATA_RAW + off
    s1, s2 = q(raw+8), q(raw+0x10)
    if not (0x140001000 <= s1 < 0x142e89000 and 0x140001000 <= s2 < 0x142e89000): continue
    scanned += 1
    n_read = n_wstr = 0
    for i in md.disasm(data[va2raw_text(s2):va2raw_text(s2)+0x1400], s2):
        if i.mnemonic == 'call':
            if i.op_str == '0x142197e80': n_read += 1
            elif i.op_str == '0x14087cd70': n_wstr += 1
        if i.mnemonic == 'ret': break
    if n_wstr >= 1:
        hits.append((n_read, n_wstr, RDATA_VA + off, s1, s2))
print("pairs scanned:", scanned)
for n_read, n_wstr, vt, s1, s2 in sorted(hits, reverse=True):
    print(f"vt {vt:#x} write {s1:#x} read {s2:#x} readCalls={n_read} wstr={n_wstr}")
