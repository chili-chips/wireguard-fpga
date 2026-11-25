#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Chili.CHIPS
#
# SPDX-License-Identifier: BSD-3-Clause

"""A second Noise_IKpsk2 (WireGuard) implementation, to check noise.c:
written separately from the WireGuard paper (section 5.4), on Python's
hashlib (BLAKE2s, HMAC) and pyca/cryptography (X25519, ChaCha20-Poly1305).

Prints, for fixed keys, message 1, message 2 and both sides' transport keys
as hex lines "name value", the same lines noise_host.c prints.
"""
import hashlib, hmac as _hmac, struct
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.primitives import serialization

RAW = serialization.Encoding.Raw, serialization.PublicFormat.Raw


def HASH(*parts):
    return hashlib.blake2s(b"".join(parts)).digest()


def MAC(key, data):
    return hashlib.blake2s(data, digest_size=16, key=key).digest()


def HMAC(key, data):
    return _hmac.new(key, data, hashlib.blake2s).digest()


def KDF(n, ck, data):
    t0 = HMAC(ck, data)
    out, t = [], b""
    for i in range(1, n + 1):
        t = HMAC(t0, t + bytes([i]))
        out.append(t)
    return out


def pub(priv):
    return X25519PrivateKey.from_private_bytes(priv).public_key().public_bytes(*RAW)


def DH(priv, p):
    return X25519PrivateKey.from_private_bytes(priv).exchange(X25519PublicKey.from_public_bytes(p))


def AEAD(k, pt, ad):
    return ChaCha20Poly1305(k).encrypt(bytes(12), pt, ad)


CONSTRUCTION = b"Noise_IKpsk2_25519_ChaChaPoly_BLAKE2s"
IDENTIFIER = b"WireGuard v1 zx2c4 Jason@zx2c4.com"


def key(b):
    return bytes((b + i) & 0xff for i in range(32))


Si, Sr, Ei, Er = key(0x10), key(0x30), key(0x50), key(0x70)
PSK = key(0x90)
TS = bytes.fromhex("400000006a1b2c3d0badf00d")
I_IDX, R_IDX = 0x11223344, 0xa5a5a5a5
Si_pub, Sr_pub = pub(Si), pub(Sr)

# initiator
C = HASH(CONSTRUCTION)
H = HASH(C, IDENTIFIER)
H = HASH(H, Sr_pub)
e = pub(Ei)
C = KDF(1, C, e)[0]
H = HASH(H, e)
C, k = KDF(2, C, DH(Ei, Sr_pub))
es = AEAD(k, Si_pub, H)
H = HASH(H, es)
C, k = KDF(2, C, DH(Si, Sr_pub))
et = AEAD(k, TS, H)
H = HASH(H, et)
m1 = bytes([1, 0, 0, 0]) + struct.pack("<I", I_IDX) + e + es + et
m1 += MAC(HASH(b"mac1----", Sr_pub), m1) + bytes(16)

# responder
er = pub(Er)
C = KDF(1, C, er)[0]
H = HASH(H, er)
C = KDF(1, C, DH(Er, e))[0]
C = KDF(1, C, DH(Er, Si_pub))[0]
C, tau, k = KDF(3, C, PSK)
H = HASH(H, tau)
en = AEAD(k, b"", H)
H = HASH(H, en)
m2 = bytes([2, 0, 0, 0]) + struct.pack("<II", R_IDX, I_IDX) + er + en
m2 += MAC(HASH(b"mac1----", Si_pub), m2) + bytes(16)
t_i_send, t_i_recv = KDF(2, C, b"")

for name, v in [("msg1", m1), ("msg2", m2), ("i_send", t_i_send), ("i_recv", t_i_recv),
                ("r_send", t_i_recv), ("r_recv", t_i_send), ("h", H)]:
    print(name, v.hex())

# -----------------------------------------------------------------------------
# Project:     WireGuard-FPGA
# Description: NLnet-funded open-source implementation
# Funding:     https://nlnet.nl/project/KlusterLab-Wireguard (2023-12 to 2025-12)
# -----------------------------------------------------------------------------
