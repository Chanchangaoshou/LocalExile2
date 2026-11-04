import struct, bisect, sys

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
        return funcs[i]
    return None

def va_to_off(va):
    for name, (sva, raw, size) in secs.items():
        if sva <= va < sva + size:
            return raw + (va - sva)
    return None

center = int(sys.argv[1], 16)
span = int(sys.argv[2], 16) if len(sys.argv) > 2 else 0x100
for va in range(center - span, center + span, 8):
    off = va_to_off(va)
    if off is None:
        continue
    q = struct.unpack_from('<Q', data, off)[0]
    f = func_of(q)
    tag = ''
    if f:
        tag = f' -> func {f[0]:#x}..{f[1]:#x} ({f[1]-f[0]} B)' + (' ENTRY' if f[0] == q else ' (mid)')
    print(f'{va:#x}: {q:#018x}{tag}')
