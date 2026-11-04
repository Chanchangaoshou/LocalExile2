import struct
import sys

from capstone import Cs, CS_ARCH_X86, CS_MODE_64

EXE = '/home/hatch/workspace/localexile2-re/PathOfExile.exe'
data = open(EXE, 'rb').read()
pe = struct.unpack_from('<I', data, 0x3c)[0]
nsec = struct.unpack_from('<H', data, pe + 6)[0]
opt_size = struct.unpack_from('<H', data, pe + 20)[0]
image_base = struct.unpack_from('<Q', data, pe + 24 + 24)[0]
sec_off = pe + 24 + opt_size
text = None
for i in range(nsec):
    o = sec_off + i * 40
    name = data[o:o + 8].rstrip(b'\0').decode()
    if name == '.text':
        vaddr, raddr = struct.unpack_from('<II', data, o + 12)[0], struct.unpack_from('<I', data, o + 20)[0]
        text = (image_base + vaddr, raddr)

base_va, base_raw = text


def off(va):
    return base_raw + (va - base_va)


start = int(sys.argv[1], 16)
end = int(sys.argv[2], 16)
md = Cs(CS_ARCH_X86, CS_MODE_64)
md.detail = False
code = data[off(start):off(end)]
for ins in md.disasm(code, start):
    print(f'{ins.address:#x}: {ins.mnemonic:8s} {ins.op_str}')
