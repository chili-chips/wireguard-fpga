// SPDX-FileCopyrightText: 2026 Chili.CHIPS
//
// SPDX-License-Identifier: BSD-3-Clause

//==========================================================================
// SipHash-2-4, from the paper's description: 2 compression rounds per
// 8-byte word, 4 finalization rounds, 64-bit output. Little-endian words.
//==========================================================================

#include "siphash.h"

static inline uint64_t rotl64(uint64_t x, int b) {
    return (x << b) | (x >> (64 - b));
}

static inline uint64_t load64_le(const uint8_t *p) {
    uint64_t v = 0;
    for (int i = 7; i >= 0; i--) {
        v = (v << 8) | p[i];
    }
    return v;
}

// n SipRounds on the state v[0..3]
static void sip_rounds(uint64_t v[4], int n) {
    for (int r = 0; r < n; r++) {
        v[0] += v[1]; v[1] = rotl64(v[1], 13); v[1] ^= v[0]; v[0] = rotl64(v[0], 32);
        v[2] += v[3]; v[3] = rotl64(v[3], 16); v[3] ^= v[2];
        v[0] += v[3]; v[3] = rotl64(v[3], 21); v[3] ^= v[0];
        v[2] += v[1]; v[1] = rotl64(v[1], 17); v[1] ^= v[2]; v[2] = rotl64(v[2], 32);
    }
}

// absorb one 64-bit message word: 2 compression rounds
static void sip_word(uint64_t v[4], uint64_t w) {
    v[3] ^= w;
    sip_rounds(v, 2);
    v[0] ^= w;
}

uint64_t siphash24(const uint8_t key[SIPHASH_KEY_SIZE], const void *in, size_t inlen) {
    const uint8_t *m = (const uint8_t *)in;
    uint64_t k0 = load64_le(key);
    uint64_t k1 = load64_le(key + 8);
    uint64_t v[4] = {
        k0 ^ 0x736f6d6570736575ULL,  // "somepseudorandomlygeneratedbytes"
        k1 ^ 0x646f72616e646f6dULL,
        k0 ^ 0x6c7967656e657261ULL,
        k1 ^ 0x7465646279746573ULL,
    };

    size_t full = inlen & ~(size_t)7;
    for (size_t i = 0; i < full; i += 8) {
        sip_word(v, load64_le(m + i));
    }

    // last word: the remaining bytes, the length's low byte on top
    uint64_t b = (uint64_t)(inlen & 0xff) << 56;
    for (size_t i = 0; i < (inlen & 7); i++) {
        b |= (uint64_t)m[full + i] << (8 * i);
    }
    sip_word(v, b);

    v[2] ^= 0xff;
    sip_rounds(v, 4);
    return v[0] ^ v[1] ^ v[2] ^ v[3];
}

// -----------------------------------------------------------------------------
// Project:     WireGuard-FPGA
// Description: NLnet-funded open-source implementation
// Funding:     https://nlnet.nl/project/KlusterLab-Wireguard (2023-12 to 2025-12)
// -----------------------------------------------------------------------------
