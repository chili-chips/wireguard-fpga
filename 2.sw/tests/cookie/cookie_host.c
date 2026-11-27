// SPDX-FileCopyrightText: 2026 Chili.CHIPS
//
// SPDX-License-Identifier: BSD-3-Clause

// Host test of 2.sw/app/xchacha20poly1305.c and cookie.c. Checks the
// draft-irtf-cfrg-xchacha vectors, prints the lines cookie_ref.py prints
// (stdout), then runs the negative checks (exit code = failures).
// random_32bytes and wg_now_seconds are stubs here: fixed bytes, a set clock.
#include <stdio.h>
#include <string.h>
#include "xchacha20poly1305.h"
#include "cookie.h"
#include "blake2s.h"

// ---- stubs ----
static int draws;
void random_32bytes(uint8_t *out) {  // draw k: bytes 0xa0 + 0x11 k + i
    for (int i = 0; i < 32; i++) out[i] = (uint8_t)(0xa0 + 0x11 * draws + i);
    draws++;
}
static uint32_t now_s;
uint32_t wg_now_seconds(void) { return now_s; }

// ---- helpers ----
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

static void unhex(uint8_t *out, const char *s) {
    for (size_t i = 0; s[2 * i]; i++) sscanf(s + 2 * i, "%2hhx", &out[i]);
}

static void fill(uint8_t *p, size_t n, int a, int b) {
    for (size_t i = 0; i < n; i++) p[i] = (uint8_t)(a * i + b);
}

// a message 1/2 with a valid mac1 to pub, mac2 zero (cookie_ref.py: msg())
static void msg(uint8_t *m, size_t len, uint32_t sender, const uint8_t pub[32]) {
    uint8_t k[32];
    blake2s_ctx ctx;
    fill(m, len, 7, 3);
    m[0] = len == 148 ? 1 : 2; m[1] = m[2] = m[3] = 0;
    for (int i = 0; i < 4; i++) m[4 + i] = (uint8_t)(sender >> (8 * i));
    blake2s_init(&ctx, 32, NULL, 0);
    blake2s_update(&ctx, "mac1----", 8);
    blake2s_update(&ctx, pub, 32);
    blake2s_final(&ctx, k);
    hash(m + len - 32, 16, k, 32, m, len - 32);
    memset(m + len - 16, 0, 16);
}

static void vectors(void) {
    uint8_t key[32], n[24], out[32], exp[32], pt[114], aad[12], ct[114], tag[16], back[114];
    // section 2.2.1: HChaCha20
    fill(key, 32, 1, 0);
    unhex(n, "000000090000004a0000000031415927");
    unhex(exp, "82413b4227b27bfed30e42508a877d73a0f9e4d58a74a853c12ec41326d3ecdc");
    hchacha20(out, key, n);
    check("HChaCha20 = draft 2.2.1", memcmp(out, exp, 32) == 0);

    // appendix A.3.1: AEAD_XCHACHA20_POLY1305
    const char *s = "Ladies and Gentlemen of the class of '99: If I could offer you only one "
                    "tip for the future, sunscreen would be it.";
    memcpy(pt, s, 114);
    unhex(aad, "50515253c0c1c2c3c4c5c6c7");
    fill(key, 32, 1, 0x80);
    fill(n, 24, 1, 0x40);
    uint8_t ect[114], etag[16];
    unhex(ect, "bd6d179d3e83d43b9576579493c0e939572a1700252bfaccbed2902c21396cbb"
               "731c7f1b0b4aa6440bf3a82f4eda7e39ae64c6708c54c216cb96b72e1213b452"
               "2f8c9ba40db5d945b11b69b982c1bb9e3f3fac2bc369488f76b2383565d3fff9"
               "21f9664c97637da9768812f615c68b13b52e");
    unhex(etag, "c0875924c1c7987947deafd8780acf49");
    xchacha20poly1305_encrypt(ct, tag, key, n, pt, 114, aad, 12);
    check("XChaCha20-Poly1305 ciphertext = draft A.3.1", memcmp(ct, ect, 114) == 0);
    check("XChaCha20-Poly1305 tag = draft A.3.1", memcmp(tag, etag, 16) == 0);
    check("A.3.1 decrypts", xchacha20poly1305_decrypt(back, key, n, ct, 114, tag, aad, 12) == 0 &&
                            memcmp(back, pt, 114) == 0);
    for (int i = 0; i < 114 + 12 + 16 + 24; i++) {  // every byte of ct, aad, tag, nonce
        uint8_t c2[114], a2[12], t2[16], n2[24];
        memcpy(c2, ct, 114); memcpy(a2, aad, 12); memcpy(t2, tag, 16); memcpy(n2, n, 24);
        if (i < 114) c2[i] ^= 0x80;
        else if (i < 126) a2[i - 114] ^= 1;
        else if (i < 142) t2[i - 126] ^= 1;
        else n2[i - 142] ^= 1;
        memset(back, 0x5a, sizeof(back));
        int rc = xchacha20poly1305_decrypt(back, key, n2, c2, 114, t2, a2, 12);
        int untouched = 1;
        for (int j = 0; j < 114; j++) untouched &= back[j] == 0x5a;
        check("tampered A.3.1 refused, plaintext untouched", rc != 0 && untouched);
    }
    // in place
    memcpy(back, pt, 114);
    xchacha20poly1305_encrypt(back, tag, key, n, back, 114, aad, 12);
    check("in-place encrypt", memcmp(back, ect, 114) == 0);

    // lengths around the block sizes, for cookie_ref.py
    static const int lens[] = {0, 1, 15, 16, 17, 63, 64, 65, 128, 200};
    for (size_t t = 0; t < sizeof(lens) / sizeof(lens[0]); t++) {
        int len = lens[t];
        uint8_t p[200], c[200 + 16], a[19], d[200];
        fill(key, 32, 3, len + 1); fill(n, 24, 5, len + 7);
        fill(p, len, 11, len); fill(a, len % 20, 13, 2);
        xchacha20poly1305_encrypt(c, c + len, key, n, p, len, a, len % 20);
        char name[16]; snprintf(name, sizeof(name), "xaead%d", len);
        hex(name, c, len + 16);
        check("round trip", xchacha20poly1305_decrypt(d, key, n, c, len, c + len, a, len % 20) == 0 &&
                            memcmp(d, p, len) == 0);
    }
}

static void cookies(void) {
    static const uint8_t ip[4] = {192, 168, 1, 7};
    const uint16_t port = 51820;
    uint8_t rpub[32], m1[148], m1b[148], m2[92], r[64], bad[64];
    wg_cookie_checker_t chk;
    wg_cookie_t ini, keep;

    fill(rpub, 32, 9, 0x21);
    now_s = 1000;
    wg_cookie_checker_init(&chk, rpub);
    wg_cookie_init(&ini, rpub);
    msg(m1, 148, 0x11223344, rpub);

    check("consume with nothing sent refused", wg_cookie_consume_reply(&ini, m1, 64) != 0);
    check("no cookie: mac2 zeros", wg_cookie_add_mac2(&ini, m1, 148) == 0);
    check("mac1 valid", wg_cookie_check_mac1(&chk, m1, 148));
    check("not under load: OK", wg_cookie_validate(&chk, m1, 148, ip, port, 0) == WG_COOKIE_OK);
    check("under load, no mac2: SEND_REPLY",
          wg_cookie_validate(&chk, m1, 148, ip, port, 1) == WG_COOKIE_SEND_REPLY);
    check("reply created", wg_cookie_create_reply(&chk, r, m1, 148, ip, port) == 0);
    hex("reply", r, 64);
    check("receiver = sender of m1", wg_cookie_reply_receiver(r) == 0x11223344);

    // tampered replies: refused, ini unchanged
    for (int i = 0; i < 64; i++) {
        memcpy(bad, r, 64);
        bad[i] ^= (i < 8) ? 0x80 : 1;
        keep = ini;
        int rc = wg_cookie_consume_reply(&ini, bad, 64);
        // bytes 4..7 (receiver) are not authenticated: the caller's peer lookup checks them
        if (i >= 4 && i < 8) { ini = keep; continue; }
        check("tampered reply refused, state unchanged",
              rc != 0 && memcmp(&ini, &keep, sizeof(ini)) == 0);
    }
    check("short reply refused", wg_cookie_consume_reply(&ini, r, 63) != 0);
    check("reply consumed", wg_cookie_consume_reply(&ini, r, 64) == 0);
    hex("cookie", ini.cookie, 16);
    check("the same reply again refused", wg_cookie_consume_reply(&ini, r, 64) != 0);

    now_s = 1010;
    msg(m1b, 148, 0x55667788, rpub);
    check("cookie held: mac2 set", wg_cookie_add_mac2(&ini, m1b, 148) == 1);
    hex("m1mac2", m1b, 148);
    check("under load, valid mac2: OK", wg_cookie_validate(&chk, m1b, 148, ip, port, 1) == WG_COOKIE_OK);
    static const uint8_t ip2[4] = {192, 168, 1, 8};
    check("other port: mac2 wrong", !wg_cookie_check_mac2(&chk, m1b, 148, ip, port + 1));
    check("other ip: mac2 wrong", !wg_cookie_check_mac2(&chk, m1b, 148, ip2, port));
    check("the old reply answers an older mac1: refused", wg_cookie_consume_reply(&ini, r, 64) != 0);

    msg(m2, 92, 0x99aabbcc, rpub);
    check("message 2: mac2 set", wg_cookie_add_mac2(&ini, m2, 92) == 1);
    hex("m2mac2", m2, 92);
    check("message 2 under load: OK", wg_cookie_validate(&chk, m2, 92, ip, port, 1) == WG_COOKIE_OK);
    m2[50] ^= 1;
    check("message 2 changed: mac1 BAD", wg_cookie_validate(&chk, m2, 92, ip, port, 0) == WG_COOKIE_BAD);
    m2[50] ^= 1;
    check("wrong length: BAD", wg_cookie_validate(&chk, m2, 91, ip, port, 0) == WG_COOKIE_BAD);
    check("reply to a bad message refused", wg_cookie_create_reply(&chk, r, m2, 148, ip, port) != 0);
    uint8_t m3[148]; memcpy(m3, m1b, 148);
    check("add_mac2 on a bad message: -1", wg_cookie_add_mac2(&ini, m3, 147) == -1 &&
                                            memcmp(m3, m1b, 148) == 0);
    m1b[147] ^= 1;
    check("mac2 bit flipped: SEND_REPLY",
          wg_cookie_validate(&chk, m1b, 148, ip, port, 1) == WG_COOKIE_SEND_REPLY);
    m1b[147] ^= 1;

    // responder secret: same for 119 s, new at 120 s
    now_s = 1000 + 119;
    check("secret 119 s old: mac2 still valid", wg_cookie_check_mac2(&chk, m1b, 148, ip, port));
    int d = draws;
    now_s = 1000 + 120;
    check("secret 120 s old: redrawn, old mac2 wrong",
          !wg_cookie_check_mac2(&chk, m1b, 148, ip, port) && draws == d + 1);

    // initiator cookie: kept 114 s, dropped at 115 s (consumed at 1000)
    now_s = 1000 + 114;
    check("cookie 114 s old: mac2 set", wg_cookie_add_mac2(&ini, m1b, 148) == 1);
    now_s = 1000 + 115;
    check("cookie 115 s old: mac2 zeros", wg_cookie_add_mac2(&ini, m1b, 148) == 0 &&
                                          !ini.cookie_valid);
    int z = 1;
    for (int i = 132; i < 148; i++) z &= m1b[i] == 0;
    check("expired: mac2 bytes zero", z);

    // the clock wraps
    now_s = 0xfffffff0u;
    wg_cookie_create_reply(&chk, r, m1b, 148, ip, port);
    check("reply consumed before the wrap", wg_cookie_consume_reply(&ini, r, 64) == 0);
    now_s = 0x40;
    check("after the wrap (0x50 s): mac2 set", wg_cookie_add_mac2(&ini, m1b, 148) == 1);
    check("after the wrap: mac2 valid", wg_cookie_check_mac2(&chk, m1b, 148, ip, port));
}

int main(void) {
    vectors();
    cookies();
    fprintf(stderr, "%s %d checks\n", fails ? "FAIL" : "PASS", checks);
    return fails;
}

// -----------------------------------------------------------------------------
// Project:     WireGuard-FPGA
// Description: NLnet-funded open-source implementation
// Funding:     https://nlnet.nl/project/KlusterLab-Wireguard (2023-12 to 2025-12)
// -----------------------------------------------------------------------------
