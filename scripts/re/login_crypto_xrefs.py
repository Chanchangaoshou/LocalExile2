"""Disassemble the PoE2 login-crypto code region and collect every .rdata
reference, to locate the client static private key blob (wave 1).
"""
import capstone

data = open(r"C:\Program Files (x86)\Steam\steamapps\common\Path of Exile 2\PathOfExileSteam.exe", 'rb').read()
TEXT_OFF, TEXT_VA, TEXT_SZ = 0x400, 0x140001000, 0x2e8791e
RDATA_OFF, RDATA_VA, RDATA_SZ = 0x2e87e00, 0x142e89000, 0xb7c800
SPKI = 0x14310C850

lo_off = 0x140ce7000 - TEXT_VA + TEXT_OFF
hi_off = 0x140d36000 - TEXT_VA + TEXT_OFF
md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
md.detail = True

targets = {}
n_ins = 0
i = lo_off
while i < hi_off:
    try:
        got = False
        for insn in md.disasm(data[i:hi_off], TEXT_VA + (i - TEXT_OFF)):
            got = True
            n_ins += 1
            for op in insn.operands:
                if op.type == capstone.x86.X86_OP_MEM and op.mem.base == capstone.x86.X86_REG_RIP:
                    t = insn.address + insn.size + op.mem.disp
                    if RDATA_VA - 0x100 <= t < RDATA_VA + RDATA_SZ + 0x100:
                        targets.setdefault(t, []).append(insn.address)
            i = insn.address - TEXT_VA + TEXT_OFF + insn.size
        if not got:
            i += 1
    except Exception:
        i += 1

print(f'{n_ins} instructions, {len(targets)} distinct .rdata targets', flush=True)
for t in sorted(targets):
    fo = t - RDATA_VA + RDATA_OFF
    if not (RDATA_OFF <= fo < RDATA_OFF + RDATA_SZ):
        continue
    blob = data[fo:fo + 32]
    nz = next((k for k, c in enumerate(blob) if c), -1)
    region = 'SPKI' if SPKI - 0x100 <= t < SPKI + 0x400 else ''
    refs = ' '.join(hex(a) for a in targets[t][:3])
    print(f'  0x{t:x} (file 0x{fo:x}) x{len(refs and targets[t])} {region}: {blob.hex()[:32]} | {refs}', flush=True)
print('DONE', flush=True)
