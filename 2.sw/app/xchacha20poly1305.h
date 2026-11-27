// SPDX-FileCopyrightText: 2026 Chili.CHIPS
//
// SPDX-License-Identifier: BSD-3-Clause

//==========================================================================
// XChaCha20-Poly1305 AEAD (draft-irtf-cfrg-xchacha-03): ChaCha20-Poly1305
// with a 24-byte nonce, long enough to draw at random. HChaCha20 turns the
// key and the first 16 nonce bytes into a subkey; the AEAD then runs with
// that subkey and the nonce 0x00000000 || the last 8 nonce bytes.
// WireGuard uses it for the cookie reply (message 3, cookie.h).
//==========================================================================

#ifndef XCHACHA20POLY1305_H
#define XCHACHA20POLY1305_H

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

#define XCHACHA20POLY1305_KEY_SIZE   32
#define XCHACHA20POLY1305_NONCE_SIZE 24
#define XCHACHA20POLY1305_TAG_SIZE   16
#define HCHACHA20_NONCE_SIZE         16

// HChaCha20: the 20 ChaCha rounds over (constants, key, nonce), without the
// final addition; out = state words 0..3 and 12..15, little-endian
void hchacha20(uint8_t out[32], const uint8_t key[32], const uint8_t nonce[HCHACHA20_NONCE_SIZE]);

// As chacha20poly1305_encrypt/_decrypt, with a 24-byte nonce. ciphertext may
// equal plaintext. 0 on success; decrypt: -1 on a wrong tag (plaintext
// untouched), both: -1 on a NULL buffer with a non-zero length
int xchacha20poly1305_encrypt(uint8_t *ciphertext, uint8_t *auth_tag,
                              const uint8_t *key, const uint8_t *nonce,
                              const uint8_t *plaintext, size_t plaintext_len,
                              const uint8_t *aad, size_t aad_len);

int xchacha20poly1305_decrypt(uint8_t *plaintext,
                              const uint8_t *key, const uint8_t *nonce,
                              const uint8_t *ciphertext, size_t ciphertext_len,
                              const uint8_t *auth_tag,
                              const uint8_t *aad, size_t aad_len);

#ifdef __cplusplus
}
#endif

#endif  // XCHACHA20POLY1305_H

// -----------------------------------------------------------------------------
// Project:     WireGuard-FPGA
// Description: NLnet-funded open-source implementation
// Funding:     https://nlnet.nl/project/KlusterLab-Wireguard (2023-12 to 2025-12)
// -----------------------------------------------------------------------------
