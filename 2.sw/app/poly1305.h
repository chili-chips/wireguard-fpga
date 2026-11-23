// SPDX-FileCopyrightText: 2026 Chili.CHIPS*ba
//
// SPDX-License-Identifier: BSD-3-Clause

/**
 * @file poly1305.h
 * @brief Poly1305 one-time MAC (RFC 8439), 26-bit limbs for RV32I
 */

#ifndef POLY1305_H
#define POLY1305_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>
#include <stddef.h>

#define POLY1305_KEY_SIZE   32
#define POLY1305_TAG_SIZE   16
#define POLY1305_BLOCK_SIZE 16

/**
 * @brief Incremental Poly1305 state
 */
typedef struct
{
   uint32_t r[5];                       // clamped r, 26-bit limbs
   uint32_t h[5];                       // accumulator, 26-bit limbs
   uint32_t pad[4];                     // s, 32-bit words
   size_t   leftover;                   // bytes waiting in buffer
   uint8_t  buffer[POLY1305_BLOCK_SIZE];
   uint8_t  is_final;                   // last, padded block: no 2^128 bit
} poly1305_ctx;

/**
 * @brief Start a MAC with a 32-byte one-time key (r || s)
 */
void poly1305_init(poly1305_ctx *ctx, const uint8_t *key);

/**
 * @brief Add message bytes; any length, any alignment
 */
void poly1305_update(poly1305_ctx *ctx, const uint8_t *message, size_t message_length);

/**
 * @brief Write the 16-byte tag and wipe the state
 */
void poly1305_finish(poly1305_ctx *ctx, uint8_t *auth_tag);

/**
 * @brief Compute Poly1305 MAC for a message (init + update + finish)
 *
 * @param auth_tag Output buffer for the 16-byte authentication tag
 * @param key 32-byte key (r || s)
 * @param message Input message buffer
 * @param message_length Length of the message in bytes
 */
void poly1305_mac(uint8_t *auth_tag, const uint8_t *key, const uint8_t *message, size_t message_length);

/**
 * @brief Compare two 16-byte tags in constant time
 *
 * @param tag1 First tag (e.g. received)
 * @param tag2 Second tag (e.g. calculated)
 * @return 1 if tags match, 0 otherwise
 */
int poly1305_verify(const uint8_t *tag1, const uint8_t *tag2);

#ifdef __cplusplus
}
#endif

#endif // POLY1305_H

// -----------------------------------------------------------------------------
// Project:     WireGuard-FPGA
// Description: NLnet-funded open-source implementation
// Funding:     https://nlnet.nl/project/KlusterLab-Wireguard (2023-12 to 2025-12)
// -----------------------------------------------------------------------------
