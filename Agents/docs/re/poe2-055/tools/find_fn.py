import sys
from capstone import Cs, CS_ARCH_X86, CS_MODE_64
data = open('PathOfExile.exe','rb').read()
def va2raw(va): return va - 0x140000C00
def raw2va(raw): return raw + 0x140000C00
# find function start: scan backwards for int3 run (0xCC padding) before target
t = int(sys.argv[1], 16)
raw = va2raw(t)
i = raw
while i > 0x400:
    if data[i] == 0xCC and data[i-1] == 0xCC:
        # start is after the padding run
        j = i
        while data[j] == 0xCC: j += 1
        print(f"function start ~ {raw2va(j):#x}")
        break
    i -= 1
