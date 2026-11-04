import hashlib, hmac as hmac_mod, struct

def ROTL(a, b): return ((a << b) | (a >> (32 - b))) & 0xffffffff
def salsa_block(key32, iv8, counter, rounds=20):
    consts = b"expand 32-byte k"
    def w(b, o): return struct.unpack_from("<I", b, o)[0]
    st = [0] * 16
    st[0] = w(consts, 0); st[5] = w(consts, 4); st[10] = w(consts, 8); st[15] = w(consts, 12)
    for i in range(4):
        st[1 + i] = w(key32, 4 * i); st[11 + i] = w(key32, 16 + 4 * i)
    st[6] = w(iv8, 0); st[7] = w(iv8, 4)
    st[8] = counter & 0xffffffff; st[9] = (counter >> 32) & 0xffffffff
    x = st[:]
    def QR(a, b, c, d):
        x[b] ^= ROTL((x[a] + x[d]) & 0xffffffff, 7)
        x[c] ^= ROTL((x[b] + x[a]) & 0xffffffff, 9)
        x[d] ^= ROTL((x[c] + x[b]) & 0xffffffff, 13)
        x[a] ^= ROTL((x[d] + x[c]) & 0xffffffff, 18)
    for _ in range(rounds // 2):
        QR(0, 4, 8, 12); QR(5, 9, 13, 1); QR(10, 14, 2, 6); QR(15, 3, 7, 11)
        QR(0, 1, 2, 3); QR(5, 6, 7, 4); QR(10, 11, 8, 9); QR(15, 12, 13, 14)
    return struct.pack("<16I", *[((x[i] + st[i]) & 0xffffffff) for i in range(16)])
def ks(key32, iv8, n=16, counter=0, rounds=20): return salsa_block(key32, iv8, counter, rounds)[:n]

