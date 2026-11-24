// SPDX-FileCopyrightText: 2026 Chili.CHIPS
//
// SPDX-License-Identifier: BSD-3-Clause

/*
 * X25519 (RFC 7748) for RV32IM.
 *
 * References:
 *  - RFC 7748, "Elliptic Curves for Security": the X25519 function, the
 *    Montgomery ladder (section 5) and the test vectors (5.2, 6.1).
 *  - ref10, D. J. Bernstein et al., SUPERCOP (public domain), crypto_scalarmult/
 *    curve25519/ref10: the radix 2^25.5 field arithmetic and the inversion
 *    chain.
 *
 * Field elements are 10 signed 32-bit limbs, 26 and 25 bits wide in turn.
 * A limb product is one 32x32->64 multiply (mul + mulh): 100 per field
 * multiply, 55 per square. The inversion takes 254 squares and 11
 * multiplies.
 *
 * Constant time: no branch and no memory index depends on a secret. The
 * ladder swaps with a mask (fe_cswap), and RV32M's mul/mulh take a fixed
 * cycle count on eduBOS5.
 *
 * Limb bounds: fe_mul and fe_sq take inputs with |f[i]| <= 1.65 * 2^26,
 * which covers a reduced element (their own output, |f[i]| <= 2^25) and
 * the sum or difference of two. They never get a sum of three: the ladder
 * below is written so. Then every 32-bit factor (x4 at most on one side,
 * x19 on the other) stays below 2^31 and every 64-bit sum below 2^62.
 */

#include <stdint.h>
#include "x25519.h"

typedef int32_t fe[10];

// Wipe secret working values before returning; volatile so the stores are
// not optimized away. The 64-bit sums inside fe_mul/fe_sq are left to the
// firmware's stack scrub: wiping them on each call costs too much.
static void wipe(void *p, unsigned n)
{
    volatile uint8_t *v = (volatile uint8_t *)p;
    while (n--)
        *v++ = 0;
}

static inline __attribute__((always_inline)) void fe_add(fe h, const fe f, const fe g)
{
    for (int i = 0; i < 10; i++)
        h[i] = f[i] + g[i];
}

static inline __attribute__((always_inline)) void fe_sub(fe h, const fe f, const fe g)
{
    for (int i = 0; i < 10; i++)
        h[i] = f[i] - g[i];
}

// Swap f and g when b is 1, keep them when b is 0, with the same stores.
// The empty asm hides the mask's value from the compiler: knowing it is 0
// or -1, gcc -Os turned the masked swap into branches on b (measured on
// eduBOS5: 10,080 clocks more per call for a key with more bit changes),
// a timing leak of the key bits.
static inline __attribute__((always_inline)) void fe_cswap(fe f, fe g, uint32_t b)
{
    int32_t mask = -(int32_t)b;
    __asm__("" : "+r"(mask));
    for (int i = 0; i < 10; i++) {
        int32_t t = mask & (f[i] ^ g[i]);
        f[i] ^= t;
        g[i] ^= t;
    }
}

// Carry h0..h9 down to 26/25-bit limbs (rounded, so |h[i]| <= 2^25) and
// store them. The top carry wraps around times 19 (2^255 = 19 mod p).
#define C26(a, b) { int64_t c = (a + ((int64_t)1 << 25)) >> 26; b += c; a -= c * ((int64_t)1 << 26); }
#define C25(a, b) { int64_t c = (a + ((int64_t)1 << 24)) >> 25; b += c; a -= c * ((int64_t)1 << 25); }

static inline __attribute__((always_inline)) void fe_carry(fe h, int64_t h0, int64_t h1, int64_t h2,
                                                           int64_t h3, int64_t h4, int64_t h5, int64_t h6,
                                                           int64_t h7, int64_t h8, int64_t h9)
{
    C26(h0, h1);
    C26(h4, h5);
    C25(h1, h2);
    C25(h5, h6);
    C26(h2, h3);
    C26(h6, h7);
    C25(h3, h4);
    C25(h7, h8);
    C26(h4, h5);
    C26(h8, h9);
    {
        int64_t c = (h9 + ((int64_t)1 << 24)) >> 25;
        h0 += c * 19;
        h9 -= c * ((int64_t)1 << 25);
    }
    C26(h0, h1);
    h[0] = (int32_t)h0;
    h[1] = (int32_t)h1;
    h[2] = (int32_t)h2;
    h[3] = (int32_t)h3;
    h[4] = (int32_t)h4;
    h[5] = (int32_t)h5;
    h[6] = (int32_t)h6;
    h[7] = (int32_t)h7;
    h[8] = (int32_t)h8;
    h[9] = (int32_t)h9;
}

// h = f * g. Product f_i * g_j lands in limb (i+j) mod 10, x2 when i and j
// are both odd, x19 when i+j >= 10. Unrolled (generated), no calls.
static void fe_mul(fe h, const fe f, const fe g)
{
    int32_t g1_19 = 19 * g[1], g2_19 = 19 * g[2], g3_19 = 19 * g[3];
    int32_t g4_19 = 19 * g[4], g5_19 = 19 * g[5], g6_19 = 19 * g[6];
    int32_t g7_19 = 19 * g[7], g8_19 = 19 * g[8], g9_19 = 19 * g[9];
    int32_t f1_2 = 2 * f[1], f3_2 = 2 * f[3], f5_2 = 2 * f[5], f7_2 = 2 * f[7], f9_2 = 2 * f[9];

    int64_t h0 = (int64_t)f[0] * g[0] + (int64_t)f1_2 * g9_19 + (int64_t)f[2] * g8_19
               + (int64_t)f3_2 * g7_19 + (int64_t)f[4] * g6_19 + (int64_t)f5_2 * g5_19
               + (int64_t)f[6] * g4_19 + (int64_t)f7_2 * g3_19 + (int64_t)f[8] * g2_19
               + (int64_t)f9_2 * g1_19;
    int64_t h1 = (int64_t)f[0] * g[1] + (int64_t)f[1] * g[0] + (int64_t)f[2] * g9_19
               + (int64_t)f[3] * g8_19 + (int64_t)f[4] * g7_19 + (int64_t)f[5] * g6_19
               + (int64_t)f[6] * g5_19 + (int64_t)f[7] * g4_19 + (int64_t)f[8] * g3_19
               + (int64_t)f[9] * g2_19;
    int64_t h2 = (int64_t)f[0] * g[2] + (int64_t)f1_2 * g[1] + (int64_t)f[2] * g[0]
               + (int64_t)f3_2 * g9_19 + (int64_t)f[4] * g8_19 + (int64_t)f5_2 * g7_19
               + (int64_t)f[6] * g6_19 + (int64_t)f7_2 * g5_19 + (int64_t)f[8] * g4_19
               + (int64_t)f9_2 * g3_19;
    int64_t h3 = (int64_t)f[0] * g[3] + (int64_t)f[1] * g[2] + (int64_t)f[2] * g[1]
               + (int64_t)f[3] * g[0] + (int64_t)f[4] * g9_19 + (int64_t)f[5] * g8_19
               + (int64_t)f[6] * g7_19 + (int64_t)f[7] * g6_19 + (int64_t)f[8] * g5_19
               + (int64_t)f[9] * g4_19;
    int64_t h4 = (int64_t)f[0] * g[4] + (int64_t)f1_2 * g[3] + (int64_t)f[2] * g[2]
               + (int64_t)f3_2 * g[1] + (int64_t)f[4] * g[0] + (int64_t)f5_2 * g9_19
               + (int64_t)f[6] * g8_19 + (int64_t)f7_2 * g7_19 + (int64_t)f[8] * g6_19
               + (int64_t)f9_2 * g5_19;
    int64_t h5 = (int64_t)f[0] * g[5] + (int64_t)f[1] * g[4] + (int64_t)f[2] * g[3]
               + (int64_t)f[3] * g[2] + (int64_t)f[4] * g[1] + (int64_t)f[5] * g[0]
               + (int64_t)f[6] * g9_19 + (int64_t)f[7] * g8_19 + (int64_t)f[8] * g7_19
               + (int64_t)f[9] * g6_19;
    int64_t h6 = (int64_t)f[0] * g[6] + (int64_t)f1_2 * g[5] + (int64_t)f[2] * g[4]
               + (int64_t)f3_2 * g[3] + (int64_t)f[4] * g[2] + (int64_t)f5_2 * g[1]
               + (int64_t)f[6] * g[0] + (int64_t)f7_2 * g9_19 + (int64_t)f[8] * g8_19
               + (int64_t)f9_2 * g7_19;
    int64_t h7 = (int64_t)f[0] * g[7] + (int64_t)f[1] * g[6] + (int64_t)f[2] * g[5]
               + (int64_t)f[3] * g[4] + (int64_t)f[4] * g[3] + (int64_t)f[5] * g[2]
               + (int64_t)f[6] * g[1] + (int64_t)f[7] * g[0] + (int64_t)f[8] * g9_19
               + (int64_t)f[9] * g8_19;
    int64_t h8 = (int64_t)f[0] * g[8] + (int64_t)f1_2 * g[7] + (int64_t)f[2] * g[6]
               + (int64_t)f3_2 * g[5] + (int64_t)f[4] * g[4] + (int64_t)f5_2 * g[3]
               + (int64_t)f[6] * g[2] + (int64_t)f7_2 * g[1] + (int64_t)f[8] * g[0]
               + (int64_t)f9_2 * g9_19;
    int64_t h9 = (int64_t)f[0] * g[9] + (int64_t)f[1] * g[8] + (int64_t)f[2] * g[7]
               + (int64_t)f[3] * g[6] + (int64_t)f[4] * g[5] + (int64_t)f[5] * g[4]
               + (int64_t)f[6] * g[3] + (int64_t)f[7] * g[2] + (int64_t)f[8] * g[1]
               + (int64_t)f[9] * g[0];

    fe_carry(h, h0, h1, h2, h3, h4, h5, h6, h7, h8, h9);
}

// h = f^2: the products f_i * f_j and f_j * f_i taken once, doubled
static void fe_sq(fe h, const fe f)
{
    int32_t f0_2 = 2 * f[0], f1_2 = 2 * f[1], f1_4 = 4 * f[1], f2_2 = 2 * f[2];
    int32_t f3_2 = 2 * f[3], f3_4 = 4 * f[3], f4_2 = 2 * f[4], f5_2 = 2 * f[5];
    int32_t f5_4 = 4 * f[5], f6_2 = 2 * f[6], f7_2 = 2 * f[7], f7_4 = 4 * f[7];
    int32_t f8_2 = 2 * f[8], f9_2 = 2 * f[9];
    int32_t f5_19 = 19 * f[5], f6_19 = 19 * f[6], f7_19 = 19 * f[7];
    int32_t f8_19 = 19 * f[8], f9_19 = 19 * f[9];

    int64_t h0 = (int64_t)f[0] * f[0] + (int64_t)f1_4 * f9_19 + (int64_t)f2_2 * f8_19
               + (int64_t)f3_4 * f7_19 + (int64_t)f4_2 * f6_19 + (int64_t)f5_2 * f5_19;
    int64_t h1 = (int64_t)f0_2 * f[1] + (int64_t)f2_2 * f9_19 + (int64_t)f3_2 * f8_19
               + (int64_t)f4_2 * f7_19 + (int64_t)f5_2 * f6_19;
    int64_t h2 = (int64_t)f0_2 * f[2] + (int64_t)f1_2 * f[1] + (int64_t)f3_4 * f9_19
               + (int64_t)f4_2 * f8_19 + (int64_t)f5_4 * f7_19 + (int64_t)f[6] * f6_19;
    int64_t h3 = (int64_t)f0_2 * f[3] + (int64_t)f1_2 * f[2] + (int64_t)f4_2 * f9_19
               + (int64_t)f5_2 * f8_19 + (int64_t)f6_2 * f7_19;
    int64_t h4 = (int64_t)f0_2 * f[4] + (int64_t)f1_4 * f[3] + (int64_t)f[2] * f[2]
               + (int64_t)f5_4 * f9_19 + (int64_t)f6_2 * f8_19 + (int64_t)f7_2 * f7_19;
    int64_t h5 = (int64_t)f0_2 * f[5] + (int64_t)f1_2 * f[4] + (int64_t)f2_2 * f[3]
               + (int64_t)f6_2 * f9_19 + (int64_t)f7_2 * f8_19;
    int64_t h6 = (int64_t)f0_2 * f[6] + (int64_t)f1_4 * f[5] + (int64_t)f2_2 * f[4]
               + (int64_t)f3_2 * f[3] + (int64_t)f7_4 * f9_19 + (int64_t)f[8] * f8_19;
    int64_t h7 = (int64_t)f0_2 * f[7] + (int64_t)f1_2 * f[6] + (int64_t)f2_2 * f[5]
               + (int64_t)f3_2 * f[4] + (int64_t)f8_2 * f9_19;
    int64_t h8 = (int64_t)f0_2 * f[8] + (int64_t)f1_4 * f[7] + (int64_t)f2_2 * f[6]
               + (int64_t)f3_4 * f[5] + (int64_t)f[4] * f[4] + (int64_t)f9_2 * f9_19;
    int64_t h9 = (int64_t)f0_2 * f[9] + (int64_t)f1_2 * f[8] + (int64_t)f2_2 * f[7]
               + (int64_t)f3_2 * f[6] + (int64_t)f4_2 * f[5];

    fe_carry(h, h0, h1, h2, h3, h4, h5, h6, h7, h8, h9);
}

// h = f^(2^n), n >= 1
static void fe_sqn(fe h, const fe f, int n)
{
    fe_sq(h, f);
    while (--n)
        fe_sq(h, h);
}

// h = f * k, k a small constant (k < 2^17): 121665 (a24 of RFC 7748), or
// 9 (the base point's u). 10 products in place of fe_mul's 100.
static void fe_mul_small(fe h, const fe f, int32_t k)
{
    int64_t h0 = (int64_t)f[0] * k, h1 = (int64_t)f[1] * k;
    int64_t h2 = (int64_t)f[2] * k, h3 = (int64_t)f[3] * k;
    int64_t h4 = (int64_t)f[4] * k, h5 = (int64_t)f[5] * k;
    int64_t h6 = (int64_t)f[6] * k, h7 = (int64_t)f[7] * k;
    int64_t h8 = (int64_t)f[8] * k, h9 = (int64_t)f[9] * k;
    fe_carry(h, h0, h1, h2, h3, h4, h5, h6, h7, h8, h9);
}

// h = z^(p-2) = 1/z: ref10's chain, 254 squares and 11 multiplies
static void fe_invert(fe out, const fe z)
{
    fe t0, t1, t2, t3;
    fe_sq(t0, z);              // z^2
    fe_sqn(t1, t0, 2);         // z^8
    fe_mul(t1, z, t1);         // z^9
    fe_mul(t0, t0, t1);        // z^11
    fe_sq(t2, t0);             // z^22
    fe_mul(t1, t1, t2);        // z^(2^5 - 1)
    fe_sqn(t2, t1, 5);
    fe_mul(t1, t2, t1);        // z^(2^10 - 1)
    fe_sqn(t2, t1, 10);
    fe_mul(t2, t2, t1);        // z^(2^20 - 1)
    fe_sqn(t3, t2, 20);
    fe_mul(t2, t3, t2);        // z^(2^40 - 1)
    fe_sqn(t2, t2, 10);
    fe_mul(t1, t2, t1);        // z^(2^50 - 1)
    fe_sqn(t2, t1, 50);
    fe_mul(t2, t2, t1);        // z^(2^100 - 1)
    fe_sqn(t3, t2, 100);
    fe_mul(t2, t3, t2);        // z^(2^200 - 1)
    fe_sqn(t2, t2, 50);
    fe_mul(t1, t2, t1);        // z^(2^250 - 1)
    fe_sqn(t1, t1, 5);         // z^(2^255 - 2^5)
    fe_mul(out, t1, t0);       // z^(2^255 - 21)
    wipe(t0, sizeof(t0));
    wipe(t1, sizeof(t1));
    wipe(t2, sizeof(t2));
    wipe(t3, sizeof(t3));
}

// Limb i starts at bit OFS[i] of the 255-bit little-endian value
static const uint8_t OFS[11] = {0, 26, 51, 77, 102, 128, 153, 179, 204, 230, 255};

// 32 bytes -> element; bit 255 is ignored (RFC 7748 masks it). 32-bit
// shifts only (no libgcc): a limb starts at most 6 bits into its first byte
// (OFS[i] & 7 <= 6), so 4 bytes hold it (6 + 26 = 32 bits).
static void fe_frombytes(fe h, const uint8_t *s)
{
    for (int i = 0; i < 10; i++) {
        int lo = OFS[i], w = OFS[i + 1] - lo, b = lo >> 3;
        uint32_t v = (uint32_t)s[b] | ((uint32_t)s[b + 1] << 8) | ((uint32_t)s[b + 2] << 16)
                   | ((uint32_t)s[b + 3] << 24);
        h[i] = (int32_t)((v >> (lo & 7)) & ((1u << w) - 1));
    }
}

// Element (reduced, from fe_mul/fe_sq) -> 32 bytes, fully reduced mod p
static void fe_tobytes(uint8_t *s, const fe f)
{
    int32_t h[10];
    for (int i = 0; i < 10; i++)
        h[i] = f[i];

    // q = 1 when h >= p, else 0: carry 19 * h9's overflow through all limbs
    int32_t q = (19 * h[9] + ((int32_t)1 << 24)) >> 25;
    for (int i = 0; i < 10; i++)
        q = (h[i] + q) >> (26 - (i & 1));

    // h - q * p = h + 19 * q - q * 2^255: add 19q, carry, drop bit 255
    h[0] += 19 * q;
    for (int i = 0; i < 9; i++) {
        int sh = 26 - (i & 1);
        int32_t c = h[i] >> sh;
        h[i + 1] += c;
        h[i] -= c * ((int32_t)1 << sh);
    }
    h[9] &= (1 << 25) - 1;

    // pack 10 limbs (26/25 bits) into 8 little-endian words, 32-bit shifts
    // only: a limb that crosses a word boundary sends its top to the next
    uint32_t w[8] = {0};
    for (int i = 0; i < 10; i++) {
        uint32_t v = (uint32_t)h[i];
        int lo = OFS[i], wi = lo >> 5, sh = lo & 31;
        w[wi] |= v << sh;
        if (sh + (OFS[i + 1] - lo) > 32)
            w[wi + 1] |= v >> (32 - sh);
    }
    for (int i = 0; i < 32; i++)
        s[i] = (uint8_t)(w[i >> 2] >> (8 * (i & 3)));
    wipe(h, sizeof(h));
    wipe(w, sizeof(w));
}

// x25519 of scalar n and point p. base = 1 when p is the base point (u = 9):
// then z3 = 9 * (DA - CB)^2 takes fe_mul_small in place of a full fe_mul.
// base is public (which function was called), so the branch on it leaks
// nothing.
static int ladder(uint8_t *q, const uint8_t *n, const uint8_t *p, int base)
{
    uint8_t z[32];
    fe x1, x2, z2, x3, z3, a, aa, b, bb, e, c, d, da, cb;

    for (int i = 0; i < 32; i++)
        z[i] = n[i];
    z[0] &= 248;
    z[31] = (z[31] & 127) | 64;

    fe_frombytes(x1, p);
    for (int i = 0; i < 10; i++) {
        x2[i] = z2[i] = z3[i] = 0;
        x3[i] = x1[i];
    }
    x2[0] = z3[0] = 1;

    // RFC 7748 5: the Montgomery ladder, one swap per bit change
    uint32_t swap = 0;
    for (int t = 254; t >= 0; t--) {
        uint32_t k = (z[t >> 3] >> (t & 7)) & 1;
        swap ^= k;
        fe_cswap(x2, x3, swap);
        fe_cswap(z2, z3, swap);
        swap = k;

        fe_add(a, x2, z2);             // A  = x2 + z2
        fe_sq(aa, a);                  // AA = A^2
        fe_sub(b, x2, z2);             // B  = x2 - z2
        fe_sq(bb, b);                  // BB = B^2
        fe_sub(e, aa, bb);             // E  = AA - BB
        fe_add(c, x3, z3);             // C  = x3 + z3
        fe_sub(d, x3, z3);             // D  = x3 - z3
        fe_mul(da, d, a);              // DA = D * A
        fe_mul(cb, c, b);              // CB = C * B
        fe_add(x3, da, cb);
        fe_sq(x3, x3);                 // x3 = (DA + CB)^2
        fe_sub(z3, da, cb);
        fe_sq(z3, z3);
        if (base)
            fe_mul_small(z3, z3, 9);   // z3 = 9 * (DA - CB)^2
        else
            fe_mul(z3, x1, z3);        // z3 = x1 * (DA - CB)^2
        fe_mul(x2, aa, bb);            // x2 = AA * BB
        fe_mul_small(z2, e, 121665);
        fe_add(z2, aa, z2);
        fe_mul(z2, e, z2);             // z2 = E * (AA + a24 * E)
    }
    fe_cswap(x2, x3, swap);
    fe_cswap(z2, z3, swap);

    fe_invert(z2, z2);
    fe_mul(x2, x2, z2);
    fe_tobytes(q, x2);

    // the clamped scalar is the private key; the ladder state depends on it
    wipe(z, sizeof(z));
    wipe(x1, sizeof(x1));
    wipe(x2, sizeof(x2));
    wipe(z2, sizeof(z2));
    wipe(x3, sizeof(x3));
    wipe(z3, sizeof(z3));
    wipe(a, sizeof(a));
    wipe(aa, sizeof(aa));
    wipe(b, sizeof(b));
    wipe(bb, sizeof(bb));
    wipe(e, sizeof(e));
    wipe(c, sizeof(c));
    wipe(d, sizeof(d));
    wipe(da, sizeof(da));
    wipe(cb, sizeof(cb));
    return 0;
}

static const uint8_t _9[32] = {9};

int x25519_scalarmult(uint8_t *q, const uint8_t *n, const uint8_t *p)
{
    return ladder(q, n, p, 0);
}

int x25519_scalarmult_base(uint8_t *q, const uint8_t *n)
{
    return ladder(q, n, _9, 1);
}
