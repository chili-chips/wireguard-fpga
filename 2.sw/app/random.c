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
//   Random numbers (#2), 2.sw/README.md section Random numbers:
//
//   entropy  csr.trng (1.hw/ip.infra/trng): two ring-oscillator banks with
//            the SP 800-90B health tests in hardware. A data word holds 16
//            raw samples of each bank; the claim is 0.5 bit of min-entropy
//            per sample (to be confirmed on hardware, trng/README.md)
//   seed     BLAKE2s-256 over a domain string, the old DRBG key and
//            RANDOM_SEED_WORDS = 64 words: 1024 samples of each bank, 512
//            bits of claimed min-entropy from either bank alone, twice the
//            256-bit seed. The source runs only for a seed: enable, the
//            startup test (1024 samples of each bank), 64 words, the status
//            once more, disable. A false alarm of the tests can then only
//            hit a seed, never a long uptime
//   DRBG     ChaCha20 with fast key erasure: each request runs ChaCha20 under
//            the key (nonce 0, counter 0, 1, ...); the first 32 bytes are the
//            next key, the rest the output, and the old key is gone. A new
//            seed every RANDOM_RESEED_INTERVAL requests
//   refusal  no source, a failed health test or no word in time: no seed,
//            the old key is wiped; random_bytes() returns an error and gives
//            zeros. random_32bytes() and random_range() try a new seed up to 3
//            times on a health-test failure (a false alarm), then halt with a
//            message (random_hw_halt)
//==========================================================================

#include "random.h"
#include "chacha20.h"

#ifndef RANDOM_RESEED_INTERVAL
#define RANDOM_RESEED_INTERVAL 256  // requests on one seed
#endif
#define RANDOM_SEED_WORDS  64       // data words per seed
#define RANDOM_TAIL_WORDS  6        // words after a seed: 96 samples, past the RCT cutoff
#define RANDOM_POLLS       1000000  // status reads before RANDOM_ERR_TIMEOUT

//--------------------------------------------------------------------------
// Entropy source access layer: csr.trng (in csr.rdl since #2). A csr.h
// without it (an older build) gets a co-simulation stand-in (VPROC) or no
// source at all, so the firmware refuses
//--------------------------------------------------------------------------
#ifndef RANDOM_HW_EXTERNAL
#include "uart.h"
#include "timer.h"
#include "csr_regs.h"

#if defined(CSR__TRNG__STATUS__READY_bm)
#define TRNG_IMPL_RO   1  // csr.trng.status.impl: ring oscillators
#define TRNG_IMPL_SIM  2  // the SIM_ONLY model of the RTL: not random

int random_hw_start(void)
{
    uint32_t impl = CSR_GET(trng.status, CSR__TRNG__STATUS__IMPL);
    if (impl != TRNG_IMPL_RO && impl != TRNG_IMPL_SIM) return RANDOM_ERR_NO_SOURCE;
    static int warned;
    if (impl == TRNG_IMPL_SIM && !warned)
    {
        uart_send("RNG: csr.trng is the SIM_ONLY model, not random\r\n");
        warned = 1;
    }
    CSR_REG32(trng.ctrl) = 0;  // stopped: the flags and counters clear
    CSR_REG32(trng.ctrl) = CSR_FLD_VAL(CSR__TRNG__CTRL__ENABLE, 1);  // normal mode, rate 0
    return RANDOM_OK;
}

void random_hw_stop(void)
{
    CSR_REG32(trng.ctrl) = 0;
}

uint32_t random_hw_status(void)
{
    uint32_t s = CSR_REG32(trng.status);
    uint32_t r = 0;
    if (RDL_FIELD(s, CSR__TRNG__STATUS__READY)) r |= RANDOM_HW_READY;
    if (RDL_FIELD(s, CSR__TRNG__STATUS__VALID)) r |= RANDOM_HW_VALID;
    if (s & (CSR__TRNG__STATUS__RCT_FAIL_A_bm | CSR__TRNG__STATUS__APT_FAIL_A_bm |
             CSR__TRNG__STATUS__RCT_FAIL_B_bm | CSR__TRNG__STATUS__APT_FAIL_B_bm))
        r |= RANDOM_HW_FAIL;
    return r;
}

uint32_t random_hw_data(void)
{
    return CSR_REG32(trng.data);
}

#elif defined(VPROC)
// co-simulation without csr.trng: a fixed xorshift32, not random
static uint32_t sim_x;

int random_hw_start(void)
{
    if (sim_x == 0)
    {
        VPrint("RNG: no csr.trng in this co-simulation: a stand-in, not random\n");
        sim_x = 0x6d2b79f5u;
    }
    return RANDOM_OK;
}

void random_hw_stop(void)
{
}

uint32_t random_hw_status(void)
{
    return RANDOM_HW_READY | RANDOM_HW_VALID;
}

uint32_t random_hw_data(void)
{
    sim_x ^= sim_x << 13;
    sim_x ^= sim_x >> 17;
    sim_x ^= sim_x << 5;
    return sim_x;
}

#else
// hardware without csr.trng: no entropy source, no random numbers
int random_hw_start(void)
{
    return RANDOM_ERR_NO_SOURCE;
}

void random_hw_stop(void)
{
}

uint32_t random_hw_status(void)
{
    return 0;
}

uint32_t random_hw_data(void)
{
    return 0;
}
#endif

void random_hw_halt(const char *why)
{
    uart_send("RNG: ");
    uart_send(why);
    uart_send(": no random numbers, halted\r\n");
    for (;;)
    {
        (void)cycles();  // a bus access: under VPROC, simulation time goes on
    }
}
#endif  // RANDOM_HW_EXTERNAL

//--------------------------------------------------------------------------
// Conditioning and DRBG
//--------------------------------------------------------------------------
static uint8_t  drbg_key[CHACHA20_KEY_SIZE];
static uint32_t drbg_left;  // requests before the next seed; 0: seed first

static const char domain[] = "wireguard-fpga random v1";

static void forget(void)
{
    bare_wipe(drbg_key, sizeof(drbg_key));
    drbg_left = 0;
}

// wait until the status has all of want; a failure ends the wait
static int wait_for(uint32_t want)
{
    for (uint32_t i = 0; i < RANDOM_POLLS; i++)
    {
        uint32_t s = random_hw_status();
        if (s & RANDOM_HW_FAIL) return RANDOM_ERR_HEALTH;
        if ((s & want) == want) return RANDOM_OK;
    }
    return RANDOM_ERR_TIMEOUT;
}

// new key = BLAKE2s-256(domain || old key || RANDOM_SEED_WORDS raw words,
// each little-endian); the old key is zero at the first seed. The source
// runs from here to the end: a fresh startup test for every seed
static int reseed(void)
{
    blake2s_ctx ctx;
    uint8_t     b[4];
    uint32_t    w   = 0;
    int         err = RANDOM_OK;

    err = random_hw_start();
    if (err != RANDOM_OK)
    {
        forget();
        return err;
    }

    blake2s_init(&ctx, sizeof(drbg_key), NULL, 0);
    blake2s_update(&ctx, domain, sizeof(domain) - 1);
    blake2s_update(&ctx, drbg_key, sizeof(drbg_key));
    for (int i = 0; i < RANDOM_SEED_WORDS && err == RANDOM_OK; i++)
    {
        err = wait_for(RANDOM_HW_READY | RANDOM_HW_VALID);
        if (err == RANDOM_OK)
        {
            w    = random_hw_data();
            b[0] = (uint8_t)w;
            b[1] = (uint8_t)(w >> 8);
            b[2] = (uint8_t)(w >> 16);
            b[3] = (uint8_t)(w >> 24);
            blake2s_update(&ctx, b, sizeof(b));
        }
    }
    // a test fails some samples after the fault (the RCT up to 80): the
    // samples of RANDOM_TAIL_WORDS more words go by, then the status again
    for (int i = 0; i < RANDOM_TAIL_WORDS && err == RANDOM_OK; i++)
    {
        err = wait_for(RANDOM_HW_READY | RANDOM_HW_VALID);
        if (err == RANDOM_OK) (void)random_hw_data();
    }
    if (err == RANDOM_OK && (random_hw_status() & RANDOM_HW_FAIL)) err = RANDOM_ERR_HEALTH;
    random_hw_stop();

    if (err == RANDOM_OK)
    {
        blake2s_final(&ctx, drbg_key);
        drbg_left = RANDOM_RESEED_INTERVAL;
    }
    else
    {
        forget();
    }
    bare_wipe(&ctx, sizeof(ctx));
    bare_wipe(b, sizeof(b));
    bare_wipe(&w, sizeof(w));
    return err;
}

// fast key erasure: block 0 gives the next key and up to 32 bytes, blocks 1,
// 2, ... the rest; the old key is overwritten before the return
static void drbg_generate(uint8_t *out, size_t n)
{
    static const uint8_t nonce[CHACHA20_NONCE_SIZE] = {0};
    uint8_t  blk[CHACHA20_BLOCK_SIZE];
    uint8_t  next[CHACHA20_KEY_SIZE];
    uint32_t ctr  = 0;
    size_t   take;

    memset(blk, 0, sizeof(blk));
    chacha20_encrypt(blk, blk, sizeof(blk), drbg_key, nonce, ctr++);
    memcpy(next, blk, sizeof(next));
    take = n < sizeof(blk) - sizeof(next) ? n : sizeof(blk) - sizeof(next);
    memcpy(out, blk + sizeof(next), take);
    out += take;
    n -= take;
    while (n > 0)
    {
        memset(blk, 0, sizeof(blk));
        chacha20_encrypt(blk, blk, sizeof(blk), drbg_key, nonce, ctr++);
        take = n < sizeof(blk) ? n : sizeof(blk);
        memcpy(out, blk, take);
        out += take;
        n -= take;
    }
    memcpy(drbg_key, next, sizeof(drbg_key));
    bare_wipe(blk, sizeof(blk));
    bare_wipe(next, sizeof(next));
}

int random_bytes(uint8_t *out, size_t n)
{
    int err = RANDOM_OK;

    if (n > RANDOM_MAX_REQUEST) err = RANDOM_ERR_ARG;
    if (err == RANDOM_OK && drbg_left == 0) err = reseed();
    if (err != RANDOM_OK)
    {
        memset(out, 0, n);
        return err;
    }
    drbg_generate(out, n);
    drbg_left--;
    return RANDOM_OK;
}

static const char *why(int err)
{
    switch (err)
    {
    case RANDOM_ERR_NO_SOURCE: return "no entropy source (csr.trng)";
    case RANDOM_ERR_HEALTH:    return "entropy source failed a health test";
    case RANDOM_ERR_TIMEOUT:   return "entropy source gives no data";
    default:                   return "bad request";
    }
}

/*
 * random_bytes(), or halt. A health-test failure may be a false alarm
 * (alpha = 2^-40 per sample): each try takes a new seed, so try
 * RANDOM_HEALTH_TRIES times before halting. A lasting fault fails them all.
 */
#define RANDOM_HEALTH_TRIES 3
static void random_or_halt(uint8_t *out, size_t n)
{
    int err = random_bytes(out, n);
    for (int i = 1; i < RANDOM_HEALTH_TRIES && err == RANDOM_ERR_HEALTH; i++)
        err = random_bytes(out, n);
    if (err != RANDOM_OK) random_hw_halt(why(err));
}

void random_32bytes(uint8_t *out)
{
    random_or_halt(out, 32);
}

static uint32_t random_u32(void)
{
    uint8_t  b[4];
    uint32_t v;
    random_or_halt(b, sizeof(b));
    v = (uint32_t)b[0] | ((uint32_t)b[1] << 8) | ((uint32_t)b[2] << 16) | ((uint32_t)b[3] << 24);
    bare_wipe(b, sizeof(b));
    return v;
}

/*
 * A uniform integer in [min, max]. span = max - min + 1 (0: all 2^32
 * values). The 2^32 mod span lowest values of a draw would make the low
 * results more likely: such draws are thrown away and drawn again (fewer
 * than half of all draws, so on average fewer than 2 draws).
 */
uint32_t random_range(uint32_t min, uint32_t max)
{
    uint32_t span, reject, x;

    if (max <= min) return min;
    span = max - min + 1u;
    if (span == 0) return random_u32();
    reject = (0u - span) % span;  // 2^32 mod span
    do
    {
        x = random_u32();
    } while (x < reject);
    return min + x % span;
}

// -----------------------------------------------------------------------------
// Project:     WireGuard-FPGA
// Description: NLnet-funded open-source implementation
// Funding:     https://nlnet.nl/project/KlusterLab-Wireguard (2023-12 to 2025-12)
// -----------------------------------------------------------------------------
