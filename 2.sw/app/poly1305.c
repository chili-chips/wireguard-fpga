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
//   Poly1305 library (RFC 8439). The 130-bit numbers are held in five
//   26-bit limbs ("donna-32" layout), so every product is a 32x32->64
//   multiply with room for the sums: no 128-bit type, no M extension
//   needed (libgcc does the 64-bit multiply on RV32I). Message words are
//   read byte by byte (little-endian), so any buffer alignment works.
//==========================================================================

#include "poly1305.h"
#include "string_bare.h"

#define LIMB_MASK 0x3ffffffu   // 26 bits

//--------------------------------------------------------------------------
// Little-endian 32-bit load / store, byte by byte
//--------------------------------------------------------------------------
static uint32_t load32_le(const uint8_t *p)
{
   return  (uint32_t)p[0]
        | ((uint32_t)p[1] << 8)
        | ((uint32_t)p[2] << 16)
        | ((uint32_t)p[3] << 24);
}

static void store32_le(uint8_t *p, uint32_t v)
{
   p[0] = (uint8_t)(v);
   p[1] = (uint8_t)(v >> 8);
   p[2] = (uint8_t)(v >> 16);
   p[3] = (uint8_t)(v >> 24);
}

//--------------------------------------------------------------------------
// h = (h + m) * r mod 2^130-5, for each 16-byte block of m
//--------------------------------------------------------------------------
static void poly1305_blocks(poly1305_ctx *ctx, const uint8_t *m, size_t bytes)
{
   const uint32_t hibit = ctx->is_final ? 0 : (1u << 24);  // 2^128

   const uint32_t r0 = ctx->r[0], r1 = ctx->r[1], r2 = ctx->r[2];
   const uint32_t r3 = ctx->r[3], r4 = ctx->r[4];

   // 2^130 = 5 mod p: the limbs that wrap past 2^130 come back times 5
   const uint32_t s1 = r1 * 5, s2 = r2 * 5, s3 = r3 * 5, s4 = r4 * 5;

   uint32_t h0 = ctx->h[0], h1 = ctx->h[1], h2 = ctx->h[2];
   uint32_t h3 = ctx->h[3], h4 = ctx->h[4];

   while (bytes >= POLY1305_BLOCK_SIZE)
   {
      // h += m
      h0 += (load32_le(m +  0)     ) & LIMB_MASK;
      h1 += (load32_le(m +  3) >> 2) & LIMB_MASK;
      h2 += (load32_le(m +  6) >> 4) & LIMB_MASK;
      h3 += (load32_le(m +  9) >> 6) & LIMB_MASK;
      h4 += (load32_le(m + 12) >> 8) | hibit;

      // h *= r
      uint64_t d0 = (uint64_t)h0 * r0 + (uint64_t)h1 * s4 + (uint64_t)h2 * s3
                  + (uint64_t)h3 * s2 + (uint64_t)h4 * s1;
      uint64_t d1 = (uint64_t)h0 * r1 + (uint64_t)h1 * r0 + (uint64_t)h2 * s4
                  + (uint64_t)h3 * s3 + (uint64_t)h4 * s2;
      uint64_t d2 = (uint64_t)h0 * r2 + (uint64_t)h1 * r1 + (uint64_t)h2 * r0
                  + (uint64_t)h3 * s4 + (uint64_t)h4 * s3;
      uint64_t d3 = (uint64_t)h0 * r3 + (uint64_t)h1 * r2 + (uint64_t)h2 * r1
                  + (uint64_t)h3 * r0 + (uint64_t)h4 * s4;
      uint64_t d4 = (uint64_t)h0 * r4 + (uint64_t)h1 * r3 + (uint64_t)h2 * r2
                  + (uint64_t)h3 * r1 + (uint64_t)h4 * r0;

      // partial reduction mod 2^130-5
      uint32_t c;
      c = (uint32_t)(d0 >> 26); h0 = (uint32_t)d0 & LIMB_MASK;
      d1 += c; c = (uint32_t)(d1 >> 26); h1 = (uint32_t)d1 & LIMB_MASK;
      d2 += c; c = (uint32_t)(d2 >> 26); h2 = (uint32_t)d2 & LIMB_MASK;
      d3 += c; c = (uint32_t)(d3 >> 26); h3 = (uint32_t)d3 & LIMB_MASK;
      d4 += c; c = (uint32_t)(d4 >> 26); h4 = (uint32_t)d4 & LIMB_MASK;
      h0 += c * 5;  c = h0 >> 26; h0 &= LIMB_MASK;
      h1 += c;

      m     += POLY1305_BLOCK_SIZE;
      bytes -= POLY1305_BLOCK_SIZE;
   }

   ctx->h[0] = h0; ctx->h[1] = h1; ctx->h[2] = h2;
   ctx->h[3] = h3; ctx->h[4] = h4;
}

//--------------------------------------------------------------------------
// Public API
//--------------------------------------------------------------------------
void poly1305_init(poly1305_ctx *ctx, const uint8_t *key)
{
   // r &= 0x0ffffffc0ffffffc0ffffffc0fffffff (the RFC clamp), in 26-bit limbs
   ctx->r[0] = (load32_le(key +  0)     ) & 0x3ffffff;
   ctx->r[1] = (load32_le(key +  3) >> 2) & 0x3ffff03;
   ctx->r[2] = (load32_le(key +  6) >> 4) & 0x3ffc0ff;
   ctx->r[3] = (load32_le(key +  9) >> 6) & 0x3f03fff;
   ctx->r[4] = (load32_le(key + 12) >> 8) & 0x00fffff;

   for (int i = 0; i < 5; i++)
   {
      ctx->h[i] = 0;
   }
   for (int i = 0; i < 4; i++)
   {
      ctx->pad[i] = load32_le(key + 16 + 4 * i);
   }

   ctx->leftover = 0;
   ctx->is_final = 0;
}

void poly1305_update(poly1305_ctx *ctx, const uint8_t *message, size_t message_length)
{
   if (message_length == 0)
   {
      return;
   }

   // top up a partial block first
   if (ctx->leftover)
   {
      size_t want = POLY1305_BLOCK_SIZE - ctx->leftover;
      if (want > message_length)
      {
         want = message_length;
      }
      memcpy(ctx->buffer + ctx->leftover, message, want);
      message        += want;
      message_length -= want;
      ctx->leftover  += want;
      if (ctx->leftover < POLY1305_BLOCK_SIZE)
      {
         return;
      }
      poly1305_blocks(ctx, ctx->buffer, POLY1305_BLOCK_SIZE);
      ctx->leftover = 0;
   }

   // whole blocks straight from the message
   if (message_length >= POLY1305_BLOCK_SIZE)
   {
      size_t want = message_length & ~(size_t)(POLY1305_BLOCK_SIZE - 1);
      poly1305_blocks(ctx, message, want);
      message        += want;
      message_length -= want;
   }

   // keep the tail for later
   if (message_length)
   {
      memcpy(ctx->buffer + ctx->leftover, message, message_length);
      ctx->leftover += message_length;
   }
}

void poly1305_finish(poly1305_ctx *ctx, uint8_t *auth_tag)
{
   // last partial block: append 0x01, pad with zeros, no 2^128 bit
   if (ctx->leftover)
   {
      size_t i = ctx->leftover;
      ctx->buffer[i++] = 1;
      for (; i < POLY1305_BLOCK_SIZE; i++)
      {
         ctx->buffer[i] = 0;
      }
      ctx->is_final = 1;
      poly1305_blocks(ctx, ctx->buffer, POLY1305_BLOCK_SIZE);
   }

   uint32_t h0 = ctx->h[0], h1 = ctx->h[1], h2 = ctx->h[2];
   uint32_t h3 = ctx->h[3], h4 = ctx->h[4];
   uint32_t c;

   // full carry: every limb back under 26 bits
                c = h1 >> 26; h1 &= LIMB_MASK;
   h2 += c;     c = h2 >> 26; h2 &= LIMB_MASK;
   h3 += c;     c = h3 >> 26; h3 &= LIMB_MASK;
   h4 += c;     c = h4 >> 26; h4 &= LIMB_MASK;
   h0 += c * 5; c = h0 >> 26; h0 &= LIMB_MASK;
   h1 += c;

   // g = h - p = h + 5 - 2^130
   uint32_t g0 = h0 + 5; c = g0 >> 26; g0 &= LIMB_MASK;
   uint32_t g1 = h1 + c; c = g1 >> 26; g1 &= LIMB_MASK;
   uint32_t g2 = h2 + c; c = g2 >> 26; g2 &= LIMB_MASK;
   uint32_t g3 = h3 + c; c = g3 >> 26; g3 &= LIMB_MASK;
   uint32_t g4 = h4 + c - (1u << 26);

   // h = (h >= p) ? g : h, without a branch
   uint32_t mask = (g4 >> 31) - 1;   // all ones when g4 did not go negative
   g0 &= mask; g1 &= mask; g2 &= mask; g3 &= mask; g4 &= mask;
   mask = ~mask;
   h0 = (h0 & mask) | g0;
   h1 = (h1 & mask) | g1;
   h2 = (h2 & mask) | g2;
   h3 = (h3 & mask) | g3;
   h4 = (h4 & mask) | g4;

   // h mod 2^128, as four 32-bit words
   h0 = ((h0      ) | (h1 << 26));
   h1 = ((h1 >>  6) | (h2 << 20));
   h2 = ((h2 >> 12) | (h3 << 14));
   h3 = ((h3 >> 18) | (h4 <<  8));

   // tag = (h + s) mod 2^128
   uint64_t f;
   f = (uint64_t)h0 + ctx->pad[0];             h0 = (uint32_t)f;
   f = (uint64_t)h1 + ctx->pad[1] + (f >> 32); h1 = (uint32_t)f;
   f = (uint64_t)h2 + ctx->pad[2] + (f >> 32); h2 = (uint32_t)f;
   f = (uint64_t)h3 + ctx->pad[3] + (f >> 32); h3 = (uint32_t)f;

   store32_le(auth_tag +  0, h0);
   store32_le(auth_tag +  4, h1);
   store32_le(auth_tag +  8, h2);
   store32_le(auth_tag + 12, h3);

   // the one-time key must not outlive the tag
   bare_wipe(ctx, sizeof(*ctx));
}

void poly1305_mac(uint8_t *auth_tag, const uint8_t *key, const uint8_t *message, size_t message_length)
{
   poly1305_ctx ctx;
   poly1305_init(&ctx, key);
   poly1305_update(&ctx, message, message_length);
   poly1305_finish(&ctx, auth_tag);
}

// Constant time: OR of the XORs over all 16 bytes, no early exit
int poly1305_verify(const uint8_t *tag1, const uint8_t *tag2)
{
   uint32_t diff = 0;
   for (int i = 0; i < POLY1305_TAG_SIZE; i++)
   {
      diff |= (uint32_t)(tag1[i] ^ tag2[i]);
   }
   // diff is 0..255: (diff - 1) >> 8 is 1 only for diff == 0
   return (int)(((diff - 1) >> 8) & 1);
}

// -----------------------------------------------------------------------------
// Project:     WireGuard-FPGA
// Description: NLnet-funded open-source implementation
// Funding:     https://nlnet.nl/project/KlusterLab-Wireguard (2023-12 to 2025-12)
// -----------------------------------------------------------------------------
