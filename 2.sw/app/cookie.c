// SPDX-FileCopyrightText: 2026 Chili.CHIPS
//
// SPDX-License-Identifier: BSD-3-Clause

//==========================================================================
// WireGuard cookies (cookie.h), WireGuard paper section 5.4.7.
//   message 3: type 3, 3 zero bytes | receiver index (LE) | nonce (24) |
//              encrypted cookie (16) | tag (16)              = 64 bytes
//   message 1/2: mac1 at len - 32, mac2 at len - 16
//==========================================================================

#include "cookie.h"
#include "blake2s.h"
#include "xchacha20poly1305.h"
#include "random.h"
#include "string_bare.h"

#define MAC_LEN   16
#define KEY_LEN   32

// message 3 field offsets
#define C_RECEIVER 4
#define C_NONCE    8
#define C_COOKIE   32
#define C_TAG      48

static const char LABEL_MAC1[]   = "mac1----";
static const char LABEL_COOKIE[] = "cookie--";

// 1 when equal; the time does not depend on where they differ
static int ct_equal(const uint8_t *a, const uint8_t *b, size_t n) {
    uint8_t d = 0;
    for (size_t i = 0; i < n; i++) d |= a[i] ^ b[i];
    return d == 0;
}

// The one RNG call (random.c, #2)
static void draw32(uint8_t out[32]) {
    random_32bytes(out);
}

// out = HASH(label || key)
static void label_key(uint8_t out[KEY_LEN], const char *label, const uint8_t pub[KEY_LEN]) {
    blake2s_ctx ctx;
    blake2s_init(&ctx, BLAKE2S_HASH_SIZE, NULL, 0);
    blake2s_update(&ctx, label, 8);
    blake2s_update(&ctx, pub, KEY_LEN);
    blake2s_final(&ctx, out);
}

// message 1 (148 B) or 2 (92 B), reserved bytes zero
static int handshake_msg(const uint8_t *msg, size_t len) {
    if (!msg || (len != 148 && len != 92) || (msg[1] | msg[2] | msg[3])) return 0;
    return msg[0] == (len == 148 ? 1 : 2);
}

// cookie = MAC(secret, ip || port); the secret is redrawn when 2 minutes old
static void make_cookie(wg_cookie_checker_t *c, uint8_t cookie[MAC_LEN],
                        const uint8_t ip[4], uint16_t port) {
    uint32_t now = wg_now_seconds();
    uint8_t a[6];
    if (!c->secret_set || (uint32_t)(now - c->secret_time) >= WG_COOKIE_SECRET_AGE_S) {
        draw32(c->secret);
        c->secret_time = now;
        c->secret_set = 1;
    }
    memcpy(a, ip, 4);
    a[4] = (uint8_t)(port >> 8);
    a[5] = (uint8_t)port;
    hash(cookie, MAC_LEN, c->secret, KEY_LEN, a, sizeof(a));
}

void wg_cookie_checker_init(wg_cookie_checker_t *c, const uint8_t our_pub[32]) {
    bare_wipe(c, sizeof(*c));
    label_key(c->mac1_key, LABEL_MAC1, our_pub);
    label_key(c->cookie_key, LABEL_COOKIE, our_pub);
}

int wg_cookie_check_mac1(const wg_cookie_checker_t *c, const uint8_t *msg, size_t len) {
    uint8_t m[MAC_LEN];
    if (!handshake_msg(msg, len)) return 0;
    hash(m, MAC_LEN, c->mac1_key, KEY_LEN, msg, len - 2 * MAC_LEN);
    return ct_equal(m, msg + len - 2 * MAC_LEN, MAC_LEN);
}

int wg_cookie_check_mac2(wg_cookie_checker_t *c, const uint8_t *msg, size_t len,
                         const uint8_t ip[4], uint16_t port) {
    uint8_t cookie[MAC_LEN], m[MAC_LEN];
    if (!handshake_msg(msg, len)) return 0;
    make_cookie(c, cookie, ip, port);
    hash(m, MAC_LEN, cookie, MAC_LEN, msg, len - MAC_LEN);
    bare_wipe(cookie, sizeof(cookie));
    int ok = ct_equal(m, msg + len - MAC_LEN, MAC_LEN);
    bare_wipe(m, sizeof(m));
    return ok;
}

int wg_cookie_validate(wg_cookie_checker_t *c, const uint8_t *msg, size_t len,
                       const uint8_t ip[4], uint16_t port, int under_load) {
    if (!wg_cookie_check_mac1(c, msg, len)) return WG_COOKIE_BAD;
    if (under_load && !wg_cookie_check_mac2(c, msg, len, ip, port)) return WG_COOKIE_SEND_REPLY;
    return WG_COOKIE_OK;
}

int wg_cookie_create_reply(wg_cookie_checker_t *c, uint8_t out[WG_MSG_COOKIE_LEN],
                           const uint8_t *msg, size_t len,
                           const uint8_t ip[4], uint16_t port) {
    uint8_t cookie[MAC_LEN], r[32];
    if (!handshake_msg(msg, len)) return -1;
    memset(out, 0, WG_MSG_COOKIE_LEN);
    out[0] = WG_MSG_COOKIE;
    memcpy(out + C_RECEIVER, msg + 4, 4);  // the sender index of msg
    draw32(r);
    memcpy(out + C_NONCE, r, XCHACHA20POLY1305_NONCE_SIZE);
    bare_wipe(r, sizeof(r));
    make_cookie(c, cookie, ip, port);
    xchacha20poly1305_encrypt(out + C_COOKIE, out + C_TAG, c->cookie_key, out + C_NONCE,
                              cookie, MAC_LEN, msg + len - 2 * MAC_LEN, MAC_LEN);
    bare_wipe(cookie, sizeof(cookie));
    return 0;
}

void wg_cookie_init(wg_cookie_t *c, const uint8_t peer_pub[32]) {
    bare_wipe(c, sizeof(*c));
    label_key(c->cookie_key, LABEL_COOKIE, peer_pub);
}

uint32_t wg_cookie_reply_receiver(const uint8_t msg[WG_MSG_COOKIE_LEN]) {
    const uint8_t *p = msg + C_RECEIVER;
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8) | ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}

int wg_cookie_consume_reply(wg_cookie_t *c, const uint8_t *msg, size_t len) {
    uint8_t cookie[MAC_LEN];
    if (!msg || len != WG_MSG_COOKIE_LEN || msg[0] != WG_MSG_COOKIE || (msg[1] | msg[2] | msg[3]))
        return -1;
    if (!c->mac1_sent) return -1;  // nothing sent, or that message already answered
    if (xchacha20poly1305_decrypt(cookie, c->cookie_key, msg + C_NONCE, msg + C_COOKIE, MAC_LEN,
                                  msg + C_TAG, c->last_mac1, MAC_LEN) != 0)
        return -1;
    memcpy(c->cookie, cookie, MAC_LEN);
    bare_wipe(cookie, sizeof(cookie));
    c->cookie_time = wg_now_seconds();
    c->cookie_valid = 1;
    c->mac1_sent = 0;
    return 0;
}

int wg_cookie_add_mac2(wg_cookie_t *c, uint8_t *msg, size_t len) {
    if (!handshake_msg(msg, len)) return -1;
    uint8_t *mac2 = msg + len - MAC_LEN;
    memcpy(c->last_mac1, msg + len - 2 * MAC_LEN, MAC_LEN);
    c->mac1_sent = 1;
    if (c->cookie_valid && (uint32_t)(wg_now_seconds() - c->cookie_time) >= WG_COOKIE_VALID_S) {
        bare_wipe(c->cookie, MAC_LEN);  // expired
        c->cookie_valid = 0;
    }
    if (!c->cookie_valid) {
        memset(mac2, 0, MAC_LEN);
        return 0;
    }
    hash(mac2, MAC_LEN, c->cookie, MAC_LEN, msg, len - MAC_LEN);
    return 1;
}

// -----------------------------------------------------------------------------
// Project:     WireGuard-FPGA
// Description: NLnet-funded open-source implementation
// Funding:     https://nlnet.nl/project/KlusterLab-Wireguard (2023-12 to 2025-12)
// -----------------------------------------------------------------------------
