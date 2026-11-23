// SPDX-FileCopyrightText: 2026 Chili.CHIPS*ba
//
// SPDX-License-Identifier: BSD-3-Clause

/**
 * @file chacha20.c
 * @brief Simple implementation of ChaCha20 encription algorithm
 */

#include "chacha20.h"
#include "string_bare.h"

// Little-endian 32-bit load, byte by byte: key and nonce may sit at any address
static inline uint32_t load32_le(const uint8_t *p)
{
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8) | ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}

// Function to rotate left
static inline uint32_t rotate_left(uint32_t x, uint32_t n)
{
    return (x << n) | (x >> (32 - n));
}

// The ChaCha20 quarter round function
static void quarter_round(uint32_t *a, uint32_t *b, uint32_t *c, uint32_t *d)
{
    *a += *b;
    *d = rotate_left(*d ^ *a, 16);
    *c += *d;
    *b = rotate_left(*b ^ *c, 12);
    *a += *b;
    *d = rotate_left(*d ^ *a, 8);
    *c += *d;
    *b = rotate_left(*b ^ *c, 7);
}

// ChaCha20 block function
void chacha20_block(chacha20_state *state, chacha20_state *output)
{
    uint32_t temp_state[16];
    memcpy(temp_state, state->state, sizeof(temp_state));

    // 20 rounds of ChaCha20
    for (int i = 0; i < 10; i++)
    {
        quarter_round(&temp_state[0], &temp_state[4], &temp_state[8], &temp_state[12]);
        quarter_round(&temp_state[1], &temp_state[5], &temp_state[9], &temp_state[13]);
        quarter_round(&temp_state[2], &temp_state[6], &temp_state[10], &temp_state[14]);
        quarter_round(&temp_state[3], &temp_state[7], &temp_state[11], &temp_state[15]);
        quarter_round(&temp_state[0], &temp_state[5], &temp_state[10], &temp_state[15]);
        quarter_round(&temp_state[1], &temp_state[6], &temp_state[11], &temp_state[12]);
        quarter_round(&temp_state[2], &temp_state[7], &temp_state[8], &temp_state[13]);
        quarter_round(&temp_state[3], &temp_state[4], &temp_state[9], &temp_state[14]);
    }

    // Add state to the result and store it in the output
    for (int i = 0; i < 16; i++)
    {
        output->state[i] = temp_state[i] + state->state[i];
    }
}

void chacha20_init(chacha20_state *state, const uint8_t *key, const uint8_t *nonce, uint32_t counter)
{
    // Set the initial state (constants + key + nonce)
    // "expand 32-byte k"
    state->state[0] = 0x61707865; // "apxe"
    state->state[1] = 0x3320646e; // "3 dn"
    state->state[2] = 0x79622d32; // "yb-2"
    state->state[3] = 0x6b206574; // "k et"

    // Key
    for (int i = 0; i < 8; i++)
    {
        state->state[4 + i] = load32_le(key + 4 * i);
    }

    // Counter
    state->state[12] = counter;

    // Nonce
    for (int i = 0; i < 3; i++)
    {
        state->state[13 + i] = load32_le(nonce + 4 * i);
    }
}

// ChaCha20 encryption/decryption function
void chacha20_encrypt(uint8_t *out, const uint8_t *in, size_t length, const uint8_t *key, const uint8_t *nonce, uint32_t counter)
{
    chacha20_state state;
    chacha20_state block;

    while (length > 0)
    {
        chacha20_init(&state, key, nonce, counter);
        chacha20_block(&state, &block);

        // keystream bytes are the state words in little-endian order
        size_t chunk_size = length > 64 ? 64 : length;
        for (size_t i = 0; i < chunk_size; i++)
        {
            out[i] = in[i] ^ (uint8_t)(block.state[i / 4] >> (8 * (i % 4)));
        }

        counter++;
        length -= chunk_size;
        out += chunk_size;
        in += chunk_size;
    }
}

// -----------------------------------------------------------------------------
// Project:     WireGuard-FPGA
// Description: NLnet-funded open-source implementation
// Funding:     https://nlnet.nl/project/KlusterLab-Wireguard (2023-12 to 2025-12)
// -----------------------------------------------------------------------------
