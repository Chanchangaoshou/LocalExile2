import struct, bisect, sys
from capstone import Cs, CS_ARCH_X86, CS_MODE_64

EXE = '/home/hatch/workspace/localexile2-re/PathOfExile.exe'
data = open(EXE, 'rb').read()
pe = struct.unpack_from('<I', data, 0x3c)[0]
nsec = struct.unpack_from('<H', data, pe + 6)[0]
opt_size = struct.unpack_from('<H', data, pe + 20)[0]
image_base = struct.unpack_from('<Q', data, pe + 24 + 24)[0]
sec_off = pe + 24 + opt_size
secs = {}
for i in range(nsec):
    o = sec_off + i * 40
    name = data[o:o + 8].rstrip(b'\0').decode()
    vsize, vaddr, rsize, raddr = struct.unpack_from('<IIII', data, o + 8)
    secs[name] = (image_base + vaddr, raddr, rsize)

tva, traw, tsize = secs['.text']
pva, praw, psize = secs['.pdata']
funcs = []
for o in range(praw, praw + psize, 12):
    b, e, _u = struct.unpack_from('<III', data, o)
    if b and e and b < e:
        funcs.append((image_base + b, image_base + e))
funcs.sort()
starts = [f[0] for f in funcs]

def func_of(va):
    i = bisect.bisect_right(starts, va) - 1
    if i >= 0 and funcs[i][0] <= va < funcs[i][1]:
        return funcs[i][0]
    return None

lo = int(sys.argv[1], 16)
hi = int(sys.argv[2], 16)
md = Cs(CS_ARCH_X86, CS_MODE_64)
md.detail = True
blob = data[traw:traw + tsize]
# scan for RIP-relative lea/mov: decode only candidate bytes is expensive; instead
# disassemble every function that could contain refs is too slow. Use byte-pattern
# scan for modrm RIP-relative (mod=00, rm=101) with rex prefixes.
hits = []
for i in range(len(blob) - 7):
    b = blob[i]
    # optional REX
    j = i
    if 0x40 <= b <= 0x4F:
        j = i + 1
        b = blob[j]
    if b in (0x8D, 0x8B, 0x89, 0xC7):  # lea / mov load / mov store / mov imm
        modrm = blob[j + 1]
        if modrm & 0xC7 == 0x05:  # mod=00 rm=101 RIP-relative
            # opcode length varies; disp32 follows modrm (no SIB for rm=101 mod=00)
            disp = struct.unpack_from('<i', blob, j + 2)[0]
            insn_len = (j - i) + 2 + 4
            if b == 0xC7:
                insn_len += 4
            target = tva + i + insn_len + disp
            if lo <= target < hi:
                hits.append((tva + i, target, b))
for addr, target, op in hits:
    print(f'{addr:#x} (func {func_of(addr):#x}) op={op:#x} -> {target:#x}')
print(f'{len(hits)} hits')
