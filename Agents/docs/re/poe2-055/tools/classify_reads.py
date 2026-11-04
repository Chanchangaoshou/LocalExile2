#!/usr/bin/env python3
"""For every S->C instance factory case, walk its read fn and record the
sequence of direct stream reads (call 0x142197e80 preceded by mov r8d, N)
plus notable helper calls, to fingerprint message layouts."""
import struct
from capstone import Cs, CS_ARCH_X86, CS_MODE_64

EXE = "/home/hatch/workspace/localexile2-re/PathOfExile.exe"
data = open(EXE, "rb").read()
IB = 0x140000000

def va2raw(va):
    return va - 0x140000C00 if va < 0x142e89000 else va - 0x140001200

def u32(va): return struct.unpack_from("<I", data, va2raw(va))[0]
def u64(va): return struct.unpack_from("<Q", data, va2raw(va))[0]

md = Cs(CS_ARCH_X86, CS_MODE_64)
md.skipdata = True

READBYTES = 0x142197e80
HELPERS = {
    0x14087cd70: "WSTR",
    0x1408719a0: "H8719a0",
    0x142173ff0: "VEC70?",
    0x1421764b0: "SUB1421764b0",
    0x141cfb540: "SUB141cfb540",
    0x142176540: "SUB142176540",
    0x1421744b0: "VECRESIZE",
    0x142175f90: "VECGROW",
}

JT = 0x1421731dc
cases = {}
for i in range(0x35f):
    mid = 0x0d + i
    cases.setdefault(IB + u32(JT + i*4), []).append(mid)

ALLOC = 0x142bba600
BASEINIT = 0x140855780

def disasm(va, n):
    r = va2raw(va)
    return list(md.disasm(data[r:r+n], va))

def parse_case(tgt):
    alloc = None; mid = None; vt = None; ctor = None
    insns = disasm(tgt, 0x90)
    pending = None
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

def read_profile(rdfn, cap=0x3000):
    seq = []
    last_r8 = None
    for ins in disasm(rdfn, cap):
        s = ins.op_str
        if ins.mnemonic == "mov" and s.startswith("r8d, "):
            try: last_r8 = int(s.split(",")[1].strip(), 0)
            except Exception: last_r8 = None
        elif ins.mnemonic == "mov" and s.startswith("r8, "):
            last_r8 = "r8reg"
        if ins.mnemonic == "call":
            try: callee = int(s, 16)
            except Exception: callee = None
            if callee == READBYTES:
                seq.append(f"R{last_r8}")
                last_r8 = None
            elif callee in HELPERS:
                seq.append(HELPERS[callee])
        if ins.mnemonic == "ret":
            break
    return seq

rows = []
for tgt, ids in cases.items():
    alloc, mid, vt = parse_case(tgt)
    if mid is None: mid = ids[0]
    if not vt: continue
    try: rdfn = u64(vt + 0x10)
    except Exception: continue
    seq = read_profile(rdfn)
    rows.append((mid, alloc, rdfn, seq))

for mid, alloc, rdfn, seq in sorted(rows):
    print(f"id={mid:#06x} alloc={alloc and hex(alloc)} read={rdfn:#x} seq[{len(seq)}]: {' '.join(seq[:40])}")
