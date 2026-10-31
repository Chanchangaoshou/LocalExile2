"""Disassemble windows around every known key-referencing instruction and
collect ALL .rdata targets — reveals the client static private blob address.
"""
import capstone

data = open(r"C:\Program Files (x86)\Steam\steamapps\common\Path of Exile 2\PathOfExileSteam.exe", 'rb').read()
TEXT_OFF, TEXT_VA, TEXT_SZ = 0x400, 0x140001000, 0x2e8791e
RDATA_OFF, RDATA_VA, RDATA_SZ = 0x2e87e00, 0x142e89000, 0xb7c800

ref_insns = [0x140ce7dfc,0x140cfdb54,0x140d30830,0x140d30a10,0x140d30bf0,0x140d30dd0,
             0x140d30fb0,0x140d31190,0x140d31370,0x140d333c0,0x14219923c,0x1421992d0,
             0x14219e3fc,0x1421a48a0,0x1421a5f38,0x1421a5f94,0x1421a62d0,0x142afa564,
             0x1404f4221,0x140cf5731,0x140d06059,0x140d087f9,0x14219e105,0x1421a31f9,
             0x142af95a9,0x140ceb26e,0x140cf572a,0x140d209a4,0x140ce7df5,0x140cf572a]

md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
md.detail = True

def disasm_window(center_file_off, span=2048):
    out = {}
    for attempt in range(0, span, 16):
        base = center_file_off - span + attempt
        if base < TEXT_OFF: continue
        try:
            for insn in md.disasm(data[base:base + span], TEXT_VA + (base - TEXT_OFF)):
                for op in insn.operands:
                    if op.type == capstone.x86.X86_OP_MEM and op.mem.base == capstone.x86.X86_REG_RIP:
                        t = insn.address + insn.size + op.mem.disp
                        out.setdefault(t, []).append((insn.address, insn.mnemonic, insn.op_str))
        except Exception:
            pass
    return out

all_targets = {}
for a in sorted(set(ref_insns)):
    off = a - TEXT_VA + TEXT_OFF
    w = disasm_window(off)
    for t, refs in w.items():
        if RDATA_VA - 0x100 <= t < RDATA_VA + RDATA_SZ + 0x100:
            for r in refs:
                all_targets.setdefault(t, []).append((a, r[1], r[2]))

print('distinct .rdata targets across key-referencing code:', len(all_targets))
for t in sorted(all_targets):
    fo = t - RDATA_VA + RDATA_OFF
    blob = data[fo:fo+24]
    n = len(all_targets[t])
    a, mn, ops = all_targets[t][0]
    print(f'  0x{t:x} (file 0x{fo:x}) x{n}: {blob.hex()[:36]} | e.g. 0x{a:x} {mn} {ops}')
print('DONE')
