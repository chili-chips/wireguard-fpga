// SPDX-FileCopyrightText: 2026 Chili.CHIPS
//
// SPDX-License-Identifier: BSD-3-Clause

// Host test of 2.sw/app/random.c, built with RANDOM_HW_EXTERNAL: this file is
// the entropy source (a fixed xorshift32 word stream, as rng_ref.py).
//   rng_host kat        the known-answer lines rng_ref.py prints too
//   rng_host checks     refusals (health failure, failure while seeding, no
//                       data), recovery, random_range uniformity and edges
//   rng_host nosource   no entropy source: errors and a halt, no output
// Exit code = failures.
#include <math.h>
#include <setjmp.h>
#include <stdio.h>
#include <string.h>
#include "random.h"

//--------------------------------------------------------------------------
// the entropy source
//--------------------------------------------------------------------------
static uint32_t src_x     = 1;  // xorshift32 state
static int      src_none  = 0;  // no source
static int      src_stuck = 0;  // a lasting fault: every start fails
static int      src_fail  = 0;  // the latched health-test flag
static int      src_dry   = 0;  // never a word
static long     fail_at   = -1; // words until src_fail goes up (-1: never)
static int      fail_starts = 0; // the next n starts fail (false alarms)
static int      src_on    = 0;  // enable
static long     starts    = 0;
static long     words     = 0;
static long     off_reads = 0;  // data reads with the source off

// enable from 0 clears the flag, as the hardware does
int random_hw_start(void) {
    starts++;
    if (src_none) return RANDOM_ERR_NO_SOURCE;
    src_on   = 1;
    src_fail = src_stuck;
    if (fail_starts > 0) {
        fail_starts--;
        src_fail = 1;
    }
    return RANDOM_OK;
}

void random_hw_stop(void) {
    src_on = 0;
}

uint32_t random_hw_status(void) {
    if (src_none || !src_on) return 0;
    if (src_fail) return RANDOM_HW_FAIL;
    return RANDOM_HW_READY | (src_dry ? 0 : RANDOM_HW_VALID);
}

uint32_t random_hw_data(void) {
    if (!src_on) off_reads++;
    words++;
    if (fail_at >= 0 && --fail_at == 0) src_fail = 1;
    src_x ^= src_x << 13;
    src_x ^= src_x >> 17;
    src_x ^= src_x << 5;
    return src_x;
}

static jmp_buf halted;
static const char *halt_why;
void random_hw_halt(const char *why) {
    halt_why = why;
    longjmp(halted, 1);
}

//--------------------------------------------------------------------------
static int fails = 0, checks = 0;
static void check(const char *what, int ok) {
    checks++;
    if (!ok) { fprintf(stderr, "FAIL %s\n", what); fails++; }
}

static void hex(const char *name, const uint8_t *p, size_t n) {
    printf("%s ", name);
    for (size_t i = 0; i < n; i++) printf("%02x", p[i]);
    printf("\n");
}

static int zeros(const uint8_t *p, size_t n) {
    for (size_t i = 0; i < n; i++) if (p[i]) return 0;
    return 1;
}

// the known answers: rng_ref.py prints the same lines
static void kat(void) {
    uint8_t b[RANDOM_MAX_REQUEST];
    char name[16];
    for (int i = 0; i < 10; i++) {
        random_32bytes(b);
        snprintf(name, sizeof(name), "r32.%d", i);
        hex(name, b, 32);
    }
    check("200 bytes", random_bytes(b, 200) == RANDOM_OK);
    hex("r200", b, 200);
    for (int i = 0; i < 8; i++) printf("range %u\n", random_range(10, 1000));
    printf("words %ld\n", words);
}

// random_32bytes must halt; returns 1 if it did, with out all zeros
static int halts_32(uint8_t out[32]) {
    memset(out, 0x55, 32);
    halt_why = NULL;
    if (setjmp(halted) == 0) {
        random_32bytes(out);
        return 0;
    }
    return halt_why != NULL && zeros(out, 32);
}

static int halts_range(void) {
    halt_why = NULL;
    if (setjmp(halted) == 0) {
        (void)random_range(0, 99);
        return 0;
    }
    return halt_why != NULL;
}

static void checks_all(void) {
    static uint8_t big[RANDOM_MAX_REQUEST + 1];
    uint8_t b[64], c[64];

    // works, and two outputs differ; the source is off between seeds
    check("first request", random_bytes(b, 32) == RANDOM_OK && !zeros(b, 32));
    check("second request", random_bytes(c, 32) == RANDOM_OK && memcmp(b, c, 32) != 0);
    check("source off after a seed", !src_on && starts == 1 && words == 70);
    check("too long a request", random_bytes(big, sizeof(big)) == RANDOM_ERR_ARG);

    // a lasting fault: the next seed fails, then every request (zeros, halt)
    int r;
    src_stuck = 1;
    memset(b, 0x55, sizeof(b));
    do r = random_bytes(b, 64); while (r == RANDOM_OK);
    check("lasting fault refused", r == RANDOM_ERR_HEALTH && zeros(b, 64));
    check("lasting fault: refused again", random_bytes(b, 8) == RANDOM_ERR_HEALTH);
    check("lasting fault halts random_32bytes", halts_32(b));
    check("lasting fault halts random_range", halts_range());

    // false alarms: random_32bytes tries 3 seeds before it halts
    src_stuck = 0;
    long s0 = starts;
    fail_starts = 3;
    check("3 false alarms in a row halt", halts_32(b) && starts - s0 == 3);
    s0 = starts;
    fail_starts = 2;
    halt_why = NULL;
    if (setjmp(halted) == 0) random_32bytes(b);
    check("2 false alarms: no halt, the 3rd seed", halt_why == NULL && !zeros(b, 32) &&
          starts - s0 == 3);
    // back to no key for the recovery check below
    src_stuck = 1;
    do r = random_bytes(b, 64); while (r == RANDOM_OK);
    src_stuck = 0;
    long w = words;
    check("recovers after the fault", random_bytes(b, 32) == RANDOM_OK && !zeros(b, 32));
    check("recovery takes a new seed of 64 + 6 words", words - w == 70);

    // a fault in the middle of a seed, then one in the 6 words after it: each
    // drops its seed; the next request takes a new one
    for (int at = 10; at <= 66; at += 56) {
        w = words;
        fail_at = at;
        do r = random_bytes(b, 32); while (r == RANDOM_OK && words == w);
        check(at == 10 ? "fault while seeding refused" : "fault after the seed refused",
              r == RANDOM_ERR_HEALTH && zeros(b, 32));
        fail_at = -1;
        check("next request seeds again", random_bytes(b, 32) == RANDOM_OK && !zeros(b, 32));
    }

    // a source that gives no word: the next seed times out, no output
    src_dry = 1;
    for (int i = 0; i < 8 && (r = random_bytes(b, 32)) == RANDOM_OK; i++) {}
    check("no data: timeout", r == RANDOM_ERR_TIMEOUT && zeros(b, 32));
    src_dry = 0;

    // random_range: edges
    check("min == max", random_range(7, 7) == 7);
    check("max < min", random_range(9, 3) == 9);
    int hi = 0;
    for (int i = 0; i < 1000; i++) if (random_range(0, 0xffffffffu) >= 0x80000000u) hi++;
    check("full range", hi > 400 && hi < 600);
    for (int i = 0; i < 1000; i++) {
        uint32_t v = random_range(100, 102);
        if (v < 100 || v > 102) { check("range bounds", 0); break; }
    }

    // uniformity: [0, 5], 600000 draws, chi-square with 5 degrees of freedom
    long cnt[6] = {0};
    const long n = 600000;
    for (long i = 0; i < n; i++) cnt[random_range(0, 5)]++;
    double chi = 0;
    for (int i = 0; i < 6; i++) chi += (cnt[i] - n / 6.0) * (cnt[i] - n / 6.0) / (n / 6.0);
    printf("chi2 [0,5] %.2f (df 5, p = 1e-4 at 25.74)\n", chi);
    check("uniform [0,5]", chi < 25.74);

    // span 3 * 2^30: values below 2^30 are 1/3 of the draws; modulo bias
    // (min + x % span) would make them 1/2
    long low = 0;
    const long m = 300000;
    for (long i = 0; i < m; i++) if (random_range(0, 0xbfffffffu) < 0x40000000u) low++;
    double f = (double)low / m;
    printf("P(< 2^30) in [0, 3 * 2^30) %.4f (1/3 = 0.3333)\n", f);
    check("no modulo bias", fabs(f - 1.0 / 3) < 0.005);
    check("no data read with the source off", off_reads == 0 && !src_on);
}

int main(int argc, char **argv) {
    const char *mode = argc > 1 ? argv[1] : "kat";
    if (strcmp(mode, "kat") == 0) {
        kat();
    } else if (strcmp(mode, "checks") == 0) {
        checks_all();
    } else if (strcmp(mode, "nosource") == 0) {
        uint8_t b[32];
        src_none = 1;
        memset(b, 0x55, sizeof(b));
        check("no source refused", random_bytes(b, 32) == RANDOM_ERR_NO_SOURCE && zeros(b, 32));
        check("no source halts random_32bytes", halts_32(b));
        check("no source halts random_range", halts_range());
        if (halt_why) printf("halt: %s\n", halt_why);
    } else {
        fprintf(stderr, "usage: rng_host [kat|checks|nosource]\n");
        return 2;
    }
    fprintf(stderr, "%s: %d of %d checks failed\n", mode, fails, checks);
    return fails;
}

// -----------------------------------------------------------------------------
// Project:     WireGuard-FPGA
// Description: NLnet-funded open-source implementation
// Funding:     https://nlnet.nl/project/KlusterLab-Wireguard (2023-12 to 2025-12)
// -----------------------------------------------------------------------------
