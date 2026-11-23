// SPDX-FileCopyrightText: 2026 Chili.CHIPS*ba
//
// SPDX-License-Identifier: BSD-3-Clause

//==========================================================================
// Wireguard-1GE FPGA * NLnet-sponsored open-source implementation
//--------------------------------------------------------------------------
//                   Copyright (C) 2026 Chili.CHIPS*ba
//
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions
// are met:
//
// 1. Redistributions of source code must retain the above copyright
// notice, this list of conditions and the following disclaimer.
//
// 2. Redistributions in binary form must reproduce the above copyright
// notice, this list of conditions and the following disclaimer in the
// documentation and/or other materials provided with the distribution.
//
// 3. Neither the name of the copyright holder nor the names of its
// contributors may be used to endorse or promote products derived
// from this software without specific prior written permission.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS
// IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED
// TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A
// PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
// HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
// SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
// LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
// DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
// THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
// (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
// OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
//
//              https://opensource.org/license/bsd-3-clause
//--------------------------------------------------------------------------
// Description:
//   ChaCha20-Poly1305 AEAD library (RFC 8439, section 2.8). Poly1305 is
//   fed piece by piece straight from the caller's buffers:
//     AAD || pad16 || ciphertext || pad16 || le64(aad_len) || le64(ct_len)
//   so there is no copy and no limit on the message length.
//==========================================================================

#include "chacha20poly1305.h"
#include "chacha20.h"
#include "poly1305.h"
#include "string_bare.h"

// Helper function to encode a 64-bit value in little-endian format
static void encode_le64(uint8_t *dst, uint64_t value)
{
   for (int i = 0; i < 8; i++)
   {
      dst[i] = (uint8_t)(value >> (8 * i));
   }
}

// Generate Poly1305 one-time key using ChaCha20 (counter 0)
static void poly1305_key_gen(uint8_t *poly1305_key, const uint8_t *key, const uint8_t *nonce)
{
   uint8_t block[CHACHA20_BLOCK_SIZE] = {0};
   chacha20_encrypt(block, block, CHACHA20_BLOCK_SIZE, key, nonce, 0);

   // First 32 bytes of the block become the Poly1305 key
   memcpy(poly1305_key, block, POLY1305_KEY_SIZE);
   memset(block, 0, sizeof(block));
}

// Poly1305 tag over AAD and ciphertext, as the RFC lays them out
static void aead_tag(
   uint8_t *auth_tag,
   const uint8_t *key,
   const uint8_t *nonce,
   const uint8_t *ciphertext,
   size_t ciphertext_len,
   const uint8_t *aad,
   size_t aad_len)
{
   static const uint8_t zeros[POLY1305_BLOCK_SIZE] = {0};

   uint8_t poly1305_key[POLY1305_KEY_SIZE];
   uint8_t lengths[16];
   poly1305_ctx ctx;

   poly1305_key_gen(poly1305_key, key, nonce);
   poly1305_init(&ctx, poly1305_key);
   memset(poly1305_key, 0, sizeof(poly1305_key));

   poly1305_update(&ctx, aad, aad_len);
   poly1305_update(&ctx, zeros, (POLY1305_BLOCK_SIZE - (aad_len % POLY1305_BLOCK_SIZE)) % POLY1305_BLOCK_SIZE);

   poly1305_update(&ctx, ciphertext, ciphertext_len);
   poly1305_update(&ctx, zeros, (POLY1305_BLOCK_SIZE - (ciphertext_len % POLY1305_BLOCK_SIZE)) % POLY1305_BLOCK_SIZE);

   encode_le64(lengths, aad_len);
   encode_le64(lengths + 8, ciphertext_len);
   poly1305_update(&ctx, lengths, sizeof(lengths));

   poly1305_finish(&ctx, auth_tag);
}

int chacha20poly1305_encrypt(
   uint8_t *ciphertext,
   uint8_t *auth_tag,
   const uint8_t *key,
   const uint8_t *nonce,
   const uint8_t *plaintext,
   size_t plaintext_len,
   const uint8_t *aad,
   size_t aad_len)
{
   if ((aad_len && !aad) || (plaintext_len && (!plaintext || !ciphertext)))
      return -1;

   // 1. Encrypt plaintext using ChaCha20 starting with counter 1
   chacha20_encrypt(ciphertext, plaintext, plaintext_len, key, nonce, 1);

   // 2. Poly1305 over AAD and ciphertext, key from counter 0
   aead_tag(auth_tag, key, nonce, ciphertext, plaintext_len, aad, aad_len);

   return 0;
}

int chacha20poly1305_decrypt(
   uint8_t *plaintext,
   const uint8_t *key,
   const uint8_t *nonce,
   const uint8_t *ciphertext,
   size_t ciphertext_len,
   const uint8_t *auth_tag,
   const uint8_t *aad,
   size_t aad_len)
{
   if ((aad_len && !aad) || (ciphertext_len && (!plaintext || !ciphertext)))
      return -1;

   // 1. Compute and verify the Poly1305 tag (constant-time compare)
   uint8_t calculated_tag[CHACHA20POLY1305_TAG_SIZE];
   aead_tag(calculated_tag, key, nonce, ciphertext, ciphertext_len, aad, aad_len);

   int tag_ok = poly1305_verify(auth_tag, calculated_tag);
   // the expected tag must not stay in memory: on a rejected packet it is the
   // valid tag for the attacker's ciphertext
   memset(calculated_tag, 0, sizeof(calculated_tag));
   if (!tag_ok)
      return -1; // Authentication failed: plaintext is not written

   // 2. Decrypt ciphertext using ChaCha20 starting with counter 1
   chacha20_decrypt(plaintext, ciphertext, ciphertext_len, key, nonce, 1);

   return 0;
}

// -----------------------------------------------------------------------------
// Project:     WireGuard-FPGA
// Description: NLnet-funded open-source implementation
// Funding:     https://nlnet.nl/project/KlusterLab-Wireguard (2023-12 to 2025-12)
// -----------------------------------------------------------------------------
