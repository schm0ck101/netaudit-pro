"""AES (chiffrement de bloc) en Python pur, pour SNMPv3 (AES-128 en mode CFB,
RFC 3826). Volumes minuscules (quelques Ko par requête) : la lenteur relative
du Python pur est sans importance, et on évite une dépendance compilée."""
from __future__ import annotations


def _xtime(a: int) -> int:
    a <<= 1
    return (a ^ 0x1B) & 0xFF if a & 0x100 else a


def _build_sbox() -> list[int]:
    sbox = [0] * 256
    p = q = 1
    while True:
        p = p ^ ((p << 1) & 0xFF) ^ (0x1B if p & 0x80 else 0)
        q ^= q << 1
        q ^= q << 2
        q ^= q << 4
        q &= 0xFF
        if q & 0x80:
            q ^= 0x09
        x = q ^ ((q << 1) | (q >> 7)) & 0xFF ^ ((q << 2) | (q >> 6)) & 0xFF ^ ((q << 3) | (q >> 5)) & 0xFF \
            ^ ((q << 4) | (q >> 4)) & 0xFF
        sbox[p] = (x ^ 0x63) & 0xFF
        if p == 1:
            break
    sbox[0] = 0x63
    return sbox


SBOX = _build_sbox()


def _expand(key: bytes) -> list[list[int]]:
    nk = len(key) // 4
    nr = nk + 6
    w = [list(key[4 * i:4 * i + 4]) for i in range(nk)]
    rcon = 1
    for i in range(nk, 4 * (nr + 1)):
        t = list(w[i - 1])
        if i % nk == 0:
            t = t[1:] + t[:1]
            t = [SBOX[b] for b in t]
            t[0] ^= rcon
            rcon = _xtime(rcon)
        elif nk > 6 and i % nk == 4:
            t = [SBOX[b] for b in t]
        w.append([w[i - nk][j] ^ t[j] for j in range(4)])
    return [sum(w[4 * r:4 * r + 4], []) for r in range(nr + 1)]


class AES:
    def __init__(self, key: bytes):
        if len(key) not in (16, 24, 32):
            raise ValueError("clé AES de 16, 24 ou 32 octets")
        self.rk = _expand(key)
        self.nr = len(self.rk) - 1

    def encrypt_block(self, block: bytes) -> bytes:
        s = [b ^ k for b, k in zip(block, self.rk[0])]
        for rnd in range(1, self.nr + 1):
            s = [SBOX[b] for b in s]
            # ShiftRows (état en colonnes : s[c*4 + r])
            s = [s[(c * 4 + r * 5) % 16] for c in range(4) for r in range(4)]
            if rnd != self.nr:
                m = []
                for c in range(4):
                    a = s[c * 4:c * 4 + 4]
                    t = a[0] ^ a[1] ^ a[2] ^ a[3]
                    m += [a[i] ^ t ^ _xtime(a[i] ^ a[(i + 1) % 4]) for i in range(4)]
                s = m
            s = [b ^ k for b, k in zip(s, self.rk[rnd])]
        return bytes(s)


def cfb_encrypt(key: bytes, iv: bytes, data: bytes) -> bytes:
    a, out, prev = AES(key), bytearray(), iv
    for i in range(0, len(data), 16):
        ks = a.encrypt_block(prev)
        chunk = bytes(x ^ y for x, y in zip(data[i:i + 16], ks))
        out += chunk
        prev = chunk if len(chunk) == 16 else prev
    return bytes(out)


def cfb_decrypt(key: bytes, iv: bytes, data: bytes) -> bytes:
    a, out, prev = AES(key), bytearray(), iv
    for i in range(0, len(data), 16):
        ks = a.encrypt_block(prev)
        chunk = data[i:i + 16]
        out += bytes(x ^ y for x, y in zip(chunk, ks))
        prev = chunk
    return bytes(out)
