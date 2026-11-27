// SPDX-FileCopyrightText: 2026 Chili.CHIPS
//
// SPDX-License-Identifier: BSD-3-Clause

//==========================================================================
// XChaCha20-Poly1305 (xchacha20poly1305.h) on top of chacha20.c and
// chacha20poly1305.c. chacha20_block adds the input state to the rounds'
// result; HChaCha20 wants the rounds alone, so it subtracts the input state
// again (mod 2^32, exact).
//==========================================================================

#include "xchacha20poly1305.h"
#include "chacha20.h"
#include "chacha20poly1305.h"
#include "string_bare.h"

static void put32_le(uint8_t *p, uint32_t v) {
    for (int i = 0; i < 4; i++) p[i] = (uint8_t)(v >> (8 * i));
}

static uint32_t get32_le(const uint8_t *p) {
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8) | ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}

void hchacha20(uint8_t out[32], const uint8_t key[32], const uint8_t nonce[HCHACHA20_NONCE_SIZE]) {
    chacha20_state in, x;
    // words 12..15 = the 16 nonce bytes: "counter" = bytes 0..3, "nonce" = 4..15
    chacha20_init(&in, key, nonce + 4, get32_le(nonce));
    chacha20_block(&in, &x);
    for (int i = 0; i < 4; i++) {
        put32_le(out + 4 * i, x.state[i] - in.state[i]);
        put32_le(out + 16 + 4 * i, x.state[12 + i] - in.state[12 + i]);
    }
    bare_wipe(&in, sizeof(in));
    bare_wipe(&x, sizeof(x));
}

// subkey = HChaCha20(key, nonce[0..15]); n12 = 0x00000000 || nonce[16..23]
static void derive(uint8_t subkey[32], uint8_t n12[CHACHA20POLY1305_NONCE_SIZE],
                   const uint8_t *key, const uint8_t *nonce) {
    hchacha20(subkey, key, nonce);
    memset(n12, 0, 4);
    memcpy(n12 + 4, nonce + 16, 8);
}

int xchacha20poly1305_encrypt(uint8_t *ciphertext, uint8_t *auth_tag,
                              const uint8_t *key, const uint8_t *nonce,
                              const uint8_t *plaintext, size_t plaintext_len,
                              const uint8_t *aad, size_t aad_len) {
    uint8_t subkey[32], n12[CHACHA20POLY1305_NONCE_SIZE];
    derive(subkey, n12, key, nonce);
    int rc = chacha20poly1305_encrypt(ciphertext, auth_tag, subkey, n12,
                                      plaintext, plaintext_len, aad, aad_len);
    bare_wipe(subkey, sizeof(subkey));
    return rc;
}

int xchacha20poly1305_decrypt(uint8_t *plaintext,
                              const uint8_t *key, const uint8_t *nonce,
                              const uint8_t *ciphertext, size_t ciphertext_len,
                              const uint8_t *auth_tag,
                              const uint8_t *aad, size_t aad_len) {
    uint8_t subkey[32], n12[CHACHA20POLY1305_NONCE_SIZE];
    derive(subkey, n12, key, nonce);
    int rc = chacha20poly1305_decrypt(plaintext, subkey, n12, ciphertext, ciphertext_len,
                                      auth_tag, aad, aad_len);
    bare_wipe(subkey, sizeof(subkey));
    return rc;
}

// -----------------------------------------------------------------------------
// Project:     WireGuard-FPGA
// Description: NLnet-funded open-source implementation
// Funding:     https://nlnet.nl/project/KlusterLab-Wireguard (2023-12 to 2025-12)
// -----------------------------------------------------------------------------
