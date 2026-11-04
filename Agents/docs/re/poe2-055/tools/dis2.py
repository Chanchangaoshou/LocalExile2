import sys
from capstone import Cs, CS_ARCH_X86, CS_MODE_64
data = open('PathOfExile.exe','rb').read()
def va2raw(va): return va - 0x140000C00
start, end = int(sys.argv[1],16), int(sys.argv[2],16)
md = Cs(CS_ARCH_X86, CS_MODE_64); md.skipdata = True
for i in md.disasm(data[va2raw(start):va2raw(end)], start):
    print(f"{i.address:#x}: {i.mnemonic:8s} {i.op_str}")
