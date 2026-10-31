"""Linear-disassemble the PoE2 client's .text with capstone and collect every
rip-relative memory reference that lands inside the login key neighborhood:
the DSA SPKI blob, the server static public, and the four DH group hex-string
literals. Output tells us exactly which code touches the keys and (by looking
at the neighbors of the referenced addresses) where the client static private
key lives now.

Usage: uv run --with capstone python scripts/re/find_key_refs.py
"""
import os
import struct
import sys
import time

import capstone

EXE = r"C:\Program Files (x86)\Steam\steamapps\common\Path of Exile 2\PathOfExileSteam.exe"
TEXT_OFF, TEXT_VA, TEXT_SZ = 0x400, 0x140001000, 0x2e8791e
RDATA_OFF, RDATA_VA, RDATA_SZ = 0x2e87e00, 0x142e89000, 0xb7c800

SPKI = 0x14310C850           # verified: unique DER-prefix hit
STATIC_PUB = 0x14310C6D0     # verified: y^q == 1 in the static group
GROUP_STRS = {               # hex-string literals (file offsets)
    'staticP_str': 0x350f330, 'ephQ_str': 0x350f640,
    'ephP_str': 0x350f750, 'staticQ_str': 0x350f860,
}
GROUP_VAS = {n: RDATA_VA + (f - RDATA_OFF) for n, f in GROUP_STRS.items()}

# neighborhood windows of interest (inclusive)
WINDOWS = [
    ('SPKI±0x400', SPKI - 0x400, SPKI + 0x400),
    ('staticPub±0x400', STATIC_PUB - 0x400, STATIC_PUB + 0x400),
]
for n, va in GROUP_VAS.items():
    WINDOWS.append((n + '±0x40', va - 0x40, va + 0x40))


def window_of(va):
    for name, lo, hi in WINDOWS:
        if lo <= va < hi:
            return name
    return None


def main():
    data = open(EXE, 'rb').read()
    text = data[TEXT_OFF:TEXT_OFF + TEXT_SZ]
    md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
    md.detail = True

    hits = []
    refs_by_func = {}
    t0 = time.time()
    n_ins = 0
    addr = TEXT_VA
    code = memoryview(text)
    insns = md.disasm(code, TEXT_VA)
    for insn in insns:
        n_ins += 1
        if n_ins % 2_000_000 == 0:
            print(f'... {n_ins} insns, {time.time() - t0:.0f}s', flush=True)
        if insn.mnemonic in ('jmp', 'call') and not insn.op_str.startswith('[rip'):
            # direct control flow: no data reference
            pass
        for op in insn.operands:
            if op.type == capstone.x86.X86_OP_MEM and op.mem.base == capstone.x86.X86_REG_RIP:
                target = insn.address + insn.size + op.mem.disp
                w = window_of(target)
                if w:
                    hits.append((insn.address, target, w, insn.mnemonic, insn.op_str))
                    key = insn.address
                    refs_by_func.setdefault(key, []).append((target, w))
    print(f'disassembled {n_ins} instructions in {time.time() - t0:.0f}s', flush=True)
    print(f'{len(hits)} key-neighborhood references:', flush=True)
    for a, t, w, mn, ops in hits:
        print(f'  0x{a:x}: {mn} {ops}   -> 0x{t:x}  [{w}]', flush=True)
    print('SCAN DONE', flush=True)


if __name__ == '__main__':
    main()
