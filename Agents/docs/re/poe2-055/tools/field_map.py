#!/usr/bin/env python3
"""For each instance-factory case, walk the read fn and extract
(size, obj_offset) pairs for direct stream reads whose destination is
lea rdx,[basereg+off]. Report the dominant base register's sequence."""
import struct, sys
from collections import Counter
from capstone import Cs, CS_ARCH_X86, CS_MODE_64

EXE = "/home/hatch/workspace/localexile2-re/PathOfExile.exe"
data = open(EXE, "rb").read()
IB = 0x140000000
def va2raw(va): return va - 0x140000C00 if va < 0x142e89000 else va - 0x140001200
def u32(va): return struct.unpack_from("<I", data, va2raw(va))[0]
def u64(va): return struct.unpack_from("<Q", data, va2raw(va))[0]

md = Cs(CS_ARCH_X86, CS_MODE_64); md.skipdata = True
def disasm(va, n):
    r = va2raw(va); return list(md.disasm(data[r:r+n], va))

READBYTES = 0x142197e80
JT = 0x1421731dc
cases = {}
for i in range(0x35f):
    cases.setdefault(IB + u32(JT + i*4), []).append(0x0d + i)
ALLOC = 0x142bba600; BASEINIT = 0x140855780

def parse_case(tgt):
    alloc = mid = vt = ctor = None; pending = None
    insns = disasm(tgt, 0x90)
    for j, ins in enumerate(insns):
        s = ins.op_str
        if ins.mnemonic == "mov" and s.startswith("ecx, 0x"):
            try: alloc = int(s.split(",")[1].strip(), 16)
            except Exception: pass
        if ins.mnemonic == "mov" and s.startswith("edx, 0x"):
            try: pending = int(s.split(",")[1].strip(), 16)
            except Exception: pass
        if ins.mnemonic == "call":
            try: callee = int(s, 16)
            except Exception: callee = None
            if callee == BASEINIT and pending is not None: mid = pending
            elif callee not in (ALLOC, BASEINIT) and callee is not None and alloc is not None and ctor is None:
                prev = insns[j-1] if j else None
                if prev and "rcx, rax" in prev.op_str: ctor = callee
        if ins.mnemonic == "lea" and s.startswith("rax, [rip"):
            try:
                if "+" in s: vt = ins.address + ins.size + int(s.split("+")[-1].rstrip("]").strip(), 16)
                elif "-" in s: vt = ins.address + ins.size - int(s.split("-")[-1].rstrip("]").strip(), 16)
            except Exception: pass
        if ins.mnemonic == "jmp": break
    if vt is None and ctor is not None:
        for ins in disasm(ctor, 0x60):
            if ins.mnemonic == "lea" and "rip" in ins.op_str:
                try:
                    if "+" in ins.op_str: vt = ins.address + ins.size + int(ins.op_str.split("+")[-1].rstrip("]").strip(), 16)
                    elif "-" in ins.op_str: vt = ins.address + ins.size - int(ins.op_str.split("-")[-1].rstrip("]").strip(), 16)
                except Exception: pass
            if ins.mnemonic == "mov" and "[rcx + 8]" in ins.op_str:
                try: mid = int(ins.op_str.split(",")[-1].strip(), 16)
                except Exception: pass
            if ins.mnemonic == "ret": break
    return alloc, mid, vt

def fields(rdfn, cap=0x3000):
    per_base = {}
    last_lea = None; last_r8 = None
    for ins in disasm(rdfn, cap):
        s = ins.op_str
        if ins.mnemonic == "lea" and s.startswith("rdx, ["):
            inner = s[len("rdx, ["):-1]
            parts = inner.replace(" - ", "|-").replace(" + ", "|").split("|")
            base = parts[0].strip()
            off = 0
            if len(parts) > 1:
                try: off = int(parts[1].strip(), 0) * (-1 if "|-" in inner else 1)
                except Exception: off = None
            last_lea = (base, off)
        if ins.mnemonic == "mov" and s.startswith("r8d, "):
            try: last_r8 = int(s.split(",")[1].strip(), 0)
            except Exception: last_r8 = None
        if ins.mnemonic == "call":
            try: callee = int(s, 16)
            except Exception: callee = None
            if callee == READBYTES and last_lea and last_lea[1] is not None and last_r8 is not None:
                per_base.setdefault(last_lea[0], []).append((last_r8, last_lea[1]))
                last_lea = None; last_r8 = None
        if ins.mnemonic == "ret": break
    if not per_base: return []
    # dominant base = the one with most reads (object base)
    base = max(per_base, key=lambda b: len(per_base[b]))
    return per_base[base]

want = [int(x, 16) for x in sys.argv[1:]] if len(sys.argv) > 1 else None
for tgt, ids in sorted(cases.items()):
    alloc, mid, vt = parse_case(tgt)
    if mid is None: mid = ids[0]
    if want and mid not in want: continue
    if not vt: continue
    try: rdfn = u64(vt + 0x10)
    except Exception: continue
    fl = fields(rdfn)
    fs = " ".join(f"{sz}@{off:#x}" for sz, off in fl[:24])
    print(f"id={mid:#06x} alloc={alloc and hex(alloc)} fields: {fs}")
