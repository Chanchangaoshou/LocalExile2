#!/usr/bin/env python3
"""Recon scanner for the PoE2 login-crypto layout inside PathOfExileSteam.exe.

Extracted from the wave-0 session (see PORTING.md). Run:
    python scripts/recon/poe2_login_scan.py [path-to-PathOfExileSteam.exe]

What it does:
  * locates the X.509 DSA SPKI verify-key blob by DER prefix (unique hit),
  * parses p / q / g / y out of it,
  * checks the PoE1-era offsets (client static private +0x350, server static
    public +0x4d0) and searches for the PoE1 DH group constants.

Exit codes: 0 = SPKI found and parsed, 1 = not found.
"""
import re
import sys
from pathlib import Path

DER_PREFIX = bytes.fromhex("308203423082023506072a8648ce380401")
VERIFY_KEY_LEN = 0x346
POE1_OFFSETS = {"clientStaticPrivate": 0x350, "serverStaticPublic": 0x4D0}
POE1_GROUPS = {
    "static_3072": bytes.fromhex("cd8fd4b7415dee60366c437dc8b43cfb01e35540cdd79b22f60b6c6ad4c77571"),
    "ephemeral_1024": bytes.fromhex("c5d1fff6e1e0b5b5a4220a369a4f504d59c7482724053c0d4b05426328031633"),
}


def parse_spki(blob: bytes):
    def tlv(pos):
        tag = blob[pos]; pos += 1
        l = blob[pos]; pos += 1
        if l & 0x80:
            n = l & 0x7F
            l = int.from_bytes(blob[pos:pos + n], "big"); pos += n
        return tag, pos, l, pos + l

    def integer(pos):
        tag, s, l, nxt = tlv(pos)
        assert tag == 0x02, hex(tag)
        raw = blob[s + 1:s + l] if blob[s] == 0 and l else blob[s:s + l]
        return int.from_bytes(raw, "big"), nxt

    _, s, _, _ = tlv(0)                    # outer SEQUENCE
    _, s2, _, nxt2 = tlv(s)                # alg SEQUENCE
    oid = blob[s2:s2 + 9]                  # 06 07 2a8648ce380401
    assert oid == bytes.fromhex("06072a8648ce380401"), oid.hex()
    # params SEQUENCE: 30 82 <2-byte length> directly after the OID TLV
    params = s2 + 9
    assert blob[params] == 0x30 and blob[params + 1] == 0x82, blob[params:params + 4].hex()
    _, s3, _, _ = tlv(params)
    p, nxt = integer(s3)
    q, nxt = integer(nxt)
    g, _ = integer(nxt)
    _, s4, l4, _ = tlv(nxt2)               # BIT STRING carrying the INTEGER y
    y, _ = integer(s4 + 1)
    return p, q, g, y


def main(path: str) -> int:
    data = Path(path).read_bytes()
    hits = [m.start() for m in re.finditer(re.escape(DER_PREFIX), data)]
    print(f"DER prefix hits: {[hex(h) for h in hits]}")
    if not hits:
        print("verify key blob not found")
        return 1
    at = hits[0]
    p, q, g, y = parse_spki(data[at:at + VERIFY_KEY_LEN])
    print(f"p bits {p.bit_length()}  q bits {q.bit_length()}  g {g}  y bits {y.bit_length()}")
    print(f"p hex head {hex(p)[:24]}..")
    for name, off in POE1_OFFSETS.items():
        blob = data[at + off:at + off + 16]
        nz = next((k for k, c in enumerate(blob) if c), -1)
        print(f"  +0x{off:x} {name}: {'zeroed' if nz < 0 else f'first nonzero at {nz}'}")
    for name, pat in POE1_GROUPS.items():
        n = data.count(pat)
        print(f"  PoE1 {name} group present: {n} hit(s)")
    return 0


if __name__ == "__main__":
    default = r"C:\Program Files (x86)\Steam\steamapps\common\Path of Exile 2\PathOfExileSteam.exe"
    raise SystemExit(main(sys.argv[1] if len(sys.argv) > 1 else default))
