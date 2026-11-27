# SPDX-FileCopyrightText: 2026 Chili.CHIPS
#
# SPDX-License-Identifier: BSD-3-Clause

# Reference for cookie_host.c, written from the specs, not from the C code:
# HChaCha20 from draft-irtf-cfrg-xchacha-03 section 2.2 on Python ints, the
# AEAD from pyca/cryptography, BLAKE2s from hashlib; the cookie messages from
# the WireGuard paper, section 5.4.7. Prints the lines cookie_host prints.
import hashlib
import struct
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305


def rotl(x, n):
    return ((x << n) | (x >> (32 - n))) & 0xffffffff


def qr(s, a, b, c, d):
    s[a] = (s[a] + s[b]) & 0xffffffff; s[d] = rotl(s[d] ^ s[a], 16)
    s[c] = (s[c] + s[d]) & 0xffffffff; s[b] = rotl(s[b] ^ s[c], 12)
    s[a] = (s[a] + s[b]) & 0xffffffff; s[d] = rotl(s[d] ^ s[a], 8)
    s[c] = (s[c] + s[d]) & 0xffffffff; s[b] = rotl(s[b] ^ s[c], 7)


def hchacha20(key, nonce16):
    s = [0x61707865, 0x3320646e, 0x79622d32, 0x6b206574]
    s += list(struct.unpack('<8I', key)) + list(struct.unpack('<4I', nonce16))
    for _ in range(10):
        qr(s, 0, 4, 8, 12); qr(s, 1, 5, 9, 13); qr(s, 2, 6, 10, 14); qr(s, 3, 7, 11, 15)
        qr(s, 0, 5, 10, 15); qr(s, 1, 6, 11, 12); qr(s, 2, 7, 8, 13); qr(s, 3, 4, 9, 14)
    return struct.pack('<8I', *(s[0:4] + s[12:16]))


def xaead(key, nonce24, pt, aad):
    sub = hchacha20(key, nonce24[:16])
    return ChaCha20Poly1305(sub).encrypt(b'\0' * 4 + nonce24[16:], pt, aad)


def fill(n, a, b):
    return bytes((a * i + b) & 0xff for i in range(n))


def h(name, b):
    print(name, b.hex())


def HASH(b):
    return hashlib.blake2s(b).digest()


def MAC(key, b):
    return hashlib.blake2s(b, key=key, digest_size=16).digest()


def msg(n, sender, pub):  # message 1/2 with mac1 to pub, mac2 zero
    m = bytearray(fill(n, 7, 3))
    m[0:4] = bytes([1 if n == 148 else 2, 0, 0, 0])
    m[4:8] = struct.pack('<I', sender)
    m[n - 32:n - 16] = MAC(HASH(b'mac1----' + pub), bytes(m[:n - 32]))
    m[n - 16:] = bytes(16)
    return m


def draw(k):  # the random_32bytes stub of cookie_host.c
    return bytes((0xa0 + 0x11 * k + i) & 0xff for i in range(32))


# HChaCha20 vector, section 2.2.1 (cookie_host.c checks it too)
assert hchacha20(bytes(range(32)), bytes.fromhex('000000090000004a0000000031415927')).hex() == \
    '82413b4227b27bfed30e42508a877d73a0f9e4d58a74a853c12ec41326d3ecdc'
# AEAD vector, appendix A.3.1
assert xaead(fill(32, 1, 0x80), fill(24, 1, 0x40),
             b"Ladies and Gentlemen of the class of '99: If I could offer you only one "
             b"tip for the future, sunscreen would be it.",
             bytes.fromhex('50515253c0c1c2c3c4c5c6c7')).hex().endswith(
    '21f9664c97637da9768812f615c68b13b52e' 'c0875924c1c7987947deafd8780acf49')

for n in (0, 1, 15, 16, 17, 63, 64, 65, 128, 200):
    h('xaead%d' % n, xaead(fill(32, 3, n + 1), fill(24, 5, n + 7), fill(n, 11, n), fill(n % 20, 13, 2)))

ip, port = bytes([192, 168, 1, 7]), 51820
rpub = fill(32, 9, 0x21)
m1 = msg(148, 0x11223344, rpub)
secret = draw(0)                       # the first draw: the cookie secret
nonce = draw(1)[:24]                   # the second: the reply nonce
cookie = MAC(secret, ip + struct.pack('>H', port))
enc = xaead(HASH(b'cookie--' + rpub), nonce, cookie, bytes(m1[116:132]))
h('reply', bytes([3, 0, 0, 0]) + m1[4:8] + nonce + enc)
h('cookie', cookie)
m1b = msg(148, 0x55667788, rpub)
m1b[132:] = MAC(cookie, bytes(m1b[:132]))
h('m1mac2', m1b)
m2 = msg(92, 0x99aabbcc, rpub)
m2[76:] = MAC(cookie, bytes(m2[:76]))
h('m2mac2', m2)

# -----------------------------------------------------------------------------
# Project:     WireGuard-FPGA
# Description: NLnet-funded open-source implementation
# Funding:     https://nlnet.nl/project/KlusterLab-Wireguard (2023-12 to 2025-12)
# -----------------------------------------------------------------------------
