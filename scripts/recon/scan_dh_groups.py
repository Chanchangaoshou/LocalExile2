"""Scan PathOfExileSteam.exe .rdata for embedded DH safe-prime groups.

Looks for 3072-bit (384-byte) and 1024-bit (128-byte) big-endian primes P at
16-byte-aligned offsets such that P is a probable prime, Q=(P-1)/2 is a probable
prime, and G (2, 3, 5, 7) generates the order-Q subgroup. Prints candidates as
hex — these are the constants LoginGroups.cs needs for the PoE2 client.
"""
import os
import struct
import sys
from pathlib import Path

EXE = r"C:\Program Files (x86)\Steam\steamapps\common\Path of Exile 2\PathOfExileSteam.exe"
STATE = Path(__file__).resolve().parent.parent / 'data' / 'dh-scan-state.json'


def is_probable_prime(n, rounds=8):
    import random
    if n < 2:
        return False
    for p in (2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37):
        if n % p == 0:
            return n == p
    d = n - 1
    r = 0
    while d % 2 == 0:
        d //= 2; r += 1
    for _ in range(rounds):
        a = random.randrange(2, n - 1)
        x = pow(a, d, n)
        if x in (1, n - 1):
            continue
        for _ in range(r - 1):
            x = pow(x, 2, n)
            if x == n - 1:
                break
        else:
            return False
    return True


def small_primes_composite(n):
    # cheap sieve pre-filter: rejects ~80% of randoms in one pass
    for p in (3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47, 53, 59, 61, 67, 71, 73):
        if n % p == 0:
            return True
    return False


def main():
    data = open(EXE, 'rb').read()
    e_lfanew = struct.unpack_from('<I', data, 0x3C)[0]
    cofh = e_lfanew + 4
    _, nsec, _, _, _, opt_size, _ = struct.unpack_from('<HHIIIHH', data, cofh)
    opt = cofh + 20
    image_base = struct.unpack_from('<Q', data, opt + 24)[0]
    sec_tab = opt + opt_size
    sections = []
    for i in range(nsec):
        e = sec_tab + i * 40
        name = data[e:e + 8].rstrip(b'\x00').decode()
        vsize, vaddr, rsize, roff = struct.unpack_from('<IIII', data, e + 8)
        sections.append((name, roff, rsize))
    print('sections:', [(n, hex(o), hex(s)) for n, o, s in sections])

    for width, label in ((384, '3072-bit static'), (128, '1024-bit ephemeral')):
        found = 0
        for name, roff, rsize in sections:
            if name not in ('.rdata', '.data'):
                continue
            start = roff
            end = roff + rsize - width
            for off in range(start, end, 16):
                w = data[off:off + width]
                if w[0] < 0x80 or w[-1] & 1 == 0:
                    continue
                p = int.from_bytes(w, 'big')
                if small_primes_composite(p):
                    continue
                if not is_probable_prime(p, rounds=4):
                    continue
                q = (p - 1) >> 1
                if not is_probable_prime(q, rounds=6):
                    continue
                va = image_base + (off - roff)
                print(f'CANDIDATE {label}: file 0x{off:x} VA 0x{va:x}')
                print('  P =', hex(p))
                print('  Q =', hex(q))
                for g in (2, 3, 5, 7):
                    if pow(g, q, p) == 1:
                        print('  G =', g)
                        break
                found += 1
                if found >= 8:
                    print(f'stopping {label} scan after 8 candidates')
                    break
            if found >= 8:
                break
        print(f'{label}: {found} candidate(s)')
    print('SCAN DONE')


if __name__ == '__main__':
    main()
