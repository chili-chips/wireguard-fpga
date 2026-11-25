// SPDX-FileCopyrightText: 2026 Chili.CHIPS
//
// SPDX-License-Identifier: BSD-3-Clause

//==========================================================================
// SipHash-2-4 (Aumasson, Bernstein 2012): a keyed 64-bit hash of short
// inputs. With a secret key, an attacker cannot pick inputs that collide,
// so a hash table built on it cannot be flooded into slow lookups.
//==========================================================================

#ifndef SIPHASH_H
#define SIPHASH_H

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

#define SIPHASH_KEY_SIZE 16

uint64_t siphash24(const uint8_t key[SIPHASH_KEY_SIZE], const void *in, size_t inlen);

#ifdef __cplusplus
}
#endif

#endif

// -----------------------------------------------------------------------------
// Project:     WireGuard-FPGA
// Description: NLnet-funded open-source implementation
// Funding:     https://nlnet.nl/project/KlusterLab-Wireguard (2023-12 to 2025-12)
// -----------------------------------------------------------------------------
