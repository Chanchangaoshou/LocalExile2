#!/usr/bin/env python3
"""Decode the 0.5.5 S->C instance factory at 0x142170500:
switch on id (r8w), id-0xd in [0, 0x35e], jump table at 0x1421731dc
(entries are i32 offsets from imagebase 0x140000000).
For each case block extract alloc size, id (mov edx before call 0x140855780,
or word store inside a ctor), vtable (lea rax,[rip+x]; mov [r14],rax or in ctor).
Then read vtable slots: [0]=?, [1]=write fn (+8), [2]=read fn (+0x10).
"""
import struct, sys
from capstone import Cs, CS_ARCH_X86, CS_MODE_64

EXE = "/home/hatch/workspace/localexile2-re/PathOfExile.exe"
data = open(EXE, "rb").read()
IB = 0x140000000

def va2raw(va):
    # .text VA 0x140001000 raw 0x400 ; .rdata VA 0x142e89000 raw 0x2e87e00
    if va < 0x142e89000:
        return va - 0x140000C00
    return va - 0x140001200

def u32(va):
    r = va2raw(va)
    return struct.unpack_from("<I", data, r)[0]

def u64(va):
    r = va2raw(va)
    return struct.unpack_from("<Q", data, r)[0]

md = Cs(CS_ARCH_X86, CS_MODE_64)
md.detail = False

def disasm(va, nbytes):
    r = va2raw(va)
    return list(md.disasm(data[r:r+nbytes], va))

JT = 0x1421731dc
cases = {}  # target -> [ids]
for i in range(0x35f):
    mid = 0x0d + i
    off = u32(JT + i*4)
    tgt = IB + off
    cases.setdefault(tgt, []).append(mid)

ALLOC = 0x142bba600
BASEINIT = 0x140855780

def parse_ctor(va):
    """small ctor: look for lea rax,[rip+x] (vtable) and mov word [rcx+8], imm (id)."""
    vt = None; mid = None
    for ins in disasm(va, 0x60):
        if ins.mnemonic == "lea" and "rip" in ins.op_str:
            try:
                disp = int(ins.op_str.split("+")[-1].rstrip("]").strip(), 16) if "+" in ins.op_str else -int(ins.op_str.split("-")[-1].rstrip("]").strip(), 16)
                vt = ins.address + ins.size + disp
            except Exception:
                pass
        if ins.mnemonic == "mov" and "[rcx + 8]" in ins.op_str and "0x" in ins.op_str:
            try:
                mid = int(ins.op_str.split(",")[-1].strip(), 16)
            except Exception:
                pass
        if ins.mnemonic == "ret":
            break
    return vt, mid

results = {}
for tgt, ids in sorted(cases.items()):
    alloc = None; mid = None; vt = None; ctor = None
    insns = disasm(tgt, 0x90)
    pending_edx = None
    for j, ins in enumerate(insns):
        s = ins.op_str
        if ins.mnemonic == "mov" and s.startswith("ecx, 0x"):
            try: alloc = int(s.split(",")[1].strip(), 16)
            except Exception: pass
        if ins.mnemonic == "mov" and s.startswith("edx, 0x"):
            try: pending_edx = int(s.split(",")[1].strip(), 16)
            except Exception: pass
        if ins.mnemonic == "call":
            try:
                callee = int(s, 16)
            except Exception:
                callee = None
            if callee == BASEINIT and pending_edx is not None:
                mid = pending_edx
            elif callee not in (ALLOC, BASEINIT) and callee is not None and alloc is not None and ctor is None:
                # possible standalone ctor call (rcx=rax object)
                prev = insns[j-1] if j else None
                if prev and "rcx, rax" in prev.op_str:
                    ctor = callee
        if ins.mnemonic == "lea" and s.startswith("rax, [rip"):
            try:
                if "+" in s:
                    disp = int(s.split("+")[-1].rstrip("]").strip(), 16)
                    vt = ins.address + ins.size + disp
                elif "-" in s:
                    disp = int(s.split("-")[-1].rstrip("]").strip(), 16)
                    vt = ins.address + ins.size - disp
            except Exception:
                pass
        if ins.mnemonic == "jmp":
            break
    if vt is None and ctor is not None:
        vt2, mid2 = parse_ctor(ctor)
        vt = vt2
        if mid is None: mid = mid2
    results[tgt] = dict(ids=ids, alloc=alloc, mid=mid, vt=vt, ctor=ctor)

print(f"unique case targets: {len(results)}")
for tgt, r in sorted(results.items(), key=lambda kv: (kv[1]['mid'] is None, kv[1]['mid'] or 0)):
    vt = r['vt']
    rd = wr = None
    if vt:
        try:
            wr = u64(vt + 8); rd = u64(vt + 0x10)
        except Exception:
            pass
    idstr = ",".join(hex(i) for i in r['ids'][:4]) + ("..." if len(r['ids']) > 4 else "")
    print(f"case @{tgt:#x} ids[{len(r['ids'])}]={idstr} mid={r['mid'] and hex(r['mid'])} alloc={r['alloc'] and hex(r['alloc'])} vt={vt and hex(vt)} write={wr and hex(wr)} read={rd and hex(rd)} ctor={r['ctor'] and hex(r['ctor'])}")
