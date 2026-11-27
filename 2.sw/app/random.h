// SPDX-FileCopyrightText: 2026 Chili.CHIPS*ba
//
// SPDX-License-Identifier: BSD-3-Clause

// Random numbers (#2): the hardware entropy source csr.trng (ring
// oscillators with SP 800-90B health tests, 1.hw/ip.infra/trng),
// conditioned with BLAKE2s, seeds a ChaCha20 DRBG (fast key erasure).
// No entropy source, a failed health test or a source that stops: no
// output. 2.sw/README.md, section Random numbers.

#ifndef RANDOM_H
#define RANDOM_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stddef.h>
#include <stdint.h>
#include "blake2s.h"
#include "string_bare.h"

#define RANDOM_OK             0
#define RANDOM_ERR_NO_SOURCE  (-1)  // no entropy source (no csr.trng, impl = 0)
#define RANDOM_ERR_HEALTH     (-2)  // a health test failed (latched in hardware)
#define RANDOM_ERR_TIMEOUT    (-3)  // the source gave no word (or no ready) in time
#define RANDOM_ERR_ARG        (-4)  // a request over RANDOM_MAX_REQUEST bytes

#define RANDOM_MAX_REQUEST    1024  // bytes per random_bytes() call

// Fills out with n random bytes, or returns an error and zeros out.
// The first call starts the entropy source and seeds the DRBG.
int random_bytes(uint8_t *out, size_t n);

// Fills 'out' with 32 random bytes; on an error (a health-test failure after
// 3 tries), halts with a message
void random_32bytes(uint8_t *out);

// Returns a uniform random integer in [min, max] (rejection sampling, no
// modulo bias); min when max <= min. On an error, halts with a message
uint32_t random_range(uint32_t min, uint32_t max);

// The entropy source access layer. random.c has the one for csr.trng; built
// with RANDOM_HW_EXTERNAL (the host test, 2.sw/tests/rng), the caller
// provides these five instead. The source runs only while a seed is taken.
#define RANDOM_HW_READY  (1u << 0)  // startup test passed, no failure since
#define RANDOM_HW_VALID  (1u << 1)  // a data word is waiting
#define RANDOM_HW_FAIL   (1u << 2)  // a health test failed

int      random_hw_start(void);    // enable (from 0: the flags clear, startup test),
                                   // normal mode, rate 0; RANDOM_OK or an error
void     random_hw_stop(void);     // enable = 0: the rings stop
uint32_t random_hw_status(void);   // RANDOM_HW_* bits
uint32_t random_hw_data(void);     // takes one data word (32 raw samples)
void     random_hw_halt(const char *why);  // does not return

#ifdef __cplusplus
}
#endif

#endif // RANDOM_H

// -----------------------------------------------------------------------------
// Project:     WireGuard-FPGA
// Description: NLnet-funded open-source implementation
// Funding:     https://nlnet.nl/project/KlusterLab-Wireguard (2023-12 to 2025-12)
// -----------------------------------------------------------------------------
