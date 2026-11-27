#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Chili.CHIPS
#
# SPDX-License-Identifier: BSD-3-Clause

"""A second implementation of 2.sw/app/random.c, to check it: the seed
(BLAKE2s from hashlib) and the fast-key-erasure DRBG (ChaCha20 from
pyca/cryptography), on the same fixed xorshift32 word stream as rng_host.c.
Prints the lines "rng_host kat" prints, with RANDOM_RESEED_INTERVAL = 4.
"""
import hashlib
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms

INTERVAL = 4  # RANDOM_RESEED_INTERVAL of the test build
SEED_WORDS = 64
TAIL_WORDS = 6  # read after the seed, not hashed
DOMAIN = b"wireguard-fpga random v1"


class Source:
    """rng_host.c's entropy source: xorshift32 from 1"""
    def __init__(self):
        self.x, self.words = 1, 0

    def word(self):
        x = self.x
        x ^= (x << 13) & 0xffffffff
        x ^= x >> 17
        x ^= (x << 5) & 0xffffffff
        self.x = x
        self.words += 1
        return x


def chacha20(key, counter, n):
    """n keystream bytes, nonce 0, from block counter (RFC 8439)"""
    nonce = counter.to_bytes(4, "little") + bytes(12)
    return Cipher(algorithms.ChaCha20(key, nonce), mode=None).encryptor().update(bytes(n))


class Drbg:
    def __init__(self, src):
        self.src, self.key, self.left = src, bytes(32), 0

    def reseed(self):
        h = hashlib.blake2s(digest_size=32)
        h.update(DOMAIN)
        h.update(self.key)
        for _ in range(SEED_WORDS):
            h.update(self.src.word().to_bytes(4, "little"))
        for _ in range(TAIL_WORDS):
            self.src.word()
        self.key, self.left = h.digest(), INTERVAL

    def bytes(self, n):
        if self.left == 0:
            self.reseed()
        ks = chacha20(self.key, 0, 32 + n)
        self.key, self.left = ks[:32], self.left - 1
        return ks[32:]

    def range(self, lo, hi):
        span = (hi - lo + 1) & 0xffffffff
        reject = (2**32 - span) % span
        while True:
            x = int.from_bytes(self.bytes(4), "little")
            if x >= reject:
                return lo + x % span


src = Source()
d = Drbg(src)
for i in range(10):
    print(f"r32.{i} {d.bytes(32).hex()}")
print(f"r200 {d.bytes(200).hex()}")
for _ in range(8):
    print(f"range {d.range(10, 1000)}")
print(f"words {src.words}")

# -----------------------------------------------------------------------------
# Project:     WireGuard-FPGA
# Description: NLnet-funded open-source implementation
# Funding:     https://nlnet.nl/project/KlusterLab-Wireguard (2023-12 to 2025-12)
# -----------------------------------------------------------------------------
