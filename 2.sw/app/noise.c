// SPDX-FileCopyrightText: 2026 Chili.CHIPS
//
// SPDX-License-Identifier: BSD-3-Clause

//==========================================================================
// The WireGuard handshake (noise.h), step by step as in the WireGuard paper,
// section 5.4.2 (initiation) and 5.4.3 (response); transport keys 5.4.5.
//   HASH: BLAKE2s-256, MAC: keyed BLAKE2s-128, KDFn: HKDF over HMAC-BLAKE2s
//   (hkdf.c), AEAD: ChaCha20-Poly1305 with nonce 0 (each key is used once)
//==========================================================================

#include "noise.h"
#include "blake2s.h"
#include "hkdf.h"
#include "curve25519.h"
#include "chacha20poly1305.h"
#include "string_bare.h"

#define TAG_LEN 16
#define MAC_LEN 16

// message 1 field offsets
#define I_SENDER    4
#define I_EPHEMERAL 8
#define I_STATIC    40   // 32 + tag
#define I_TIMESTAMP 88   // 12 + tag
#define I_MAC1      116
#define I_MAC2      132

// message 2 field offsets
#define R_SENDER    4
#define R_RECEIVER  8
#define R_EPHEMERAL 12
#define R_EMPTY     44   // tag only
#define R_MAC1      60
#define R_MAC2      76

static const char CONSTRUCTION[] = "Noise_IKpsk2_25519_ChaChaPoly_BLAKE2s";
static const char IDENTIFIER[]   = "WireGuard v1 zx2c4 Jason@zx2c4.com";
static const char LABEL_MAC1[]   = "mac1----";

static const uint8_t ZERO_NONCE[CHACHA20POLY1305_NONCE_SIZE] = {0};

// volatile stores (string_bare.c), kept even when the memory dies
#define wipe bare_wipe

// 1 when equal; the time does not depend on where they differ
static int ct_equal(const uint8_t *a, const uint8_t *b, size_t n) {
    uint8_t d = 0;
    for (size_t i = 0; i < n; i++) d |= a[i] ^ b[i];
    return d == 0;
}

static void put32_le(uint8_t *p, uint32_t v) {
    for (int i = 0; i < 4; i++) p[i] = (uint8_t)(v >> (8 * i));
}

static uint32_t get32_le(const uint8_t *p) {
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8) | ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}

// h = HASH(h || data)
static void mix_hash(uint8_t h[WG_KEY_LEN], const void *data, size_t len) {
    blake2s_ctx ctx;
    blake2s_init(&ctx, BLAKE2S_HASH_SIZE, NULL, 0);
    blake2s_update(&ctx, h, WG_KEY_LEN);
    blake2s_update(&ctx, data, len);
    blake2s_final(&ctx, h);
}

// out = HASH(label || key): the mac1 key of the side whose static key it is
static void mac1_key(uint8_t out[WG_KEY_LEN], const uint8_t key[WG_KEY_LEN]) {
    blake2s_ctx ctx;
    blake2s_init(&ctx, BLAKE2S_HASH_SIZE, NULL, 0);
    blake2s_update(&ctx, LABEL_MAC1, sizeof(LABEL_MAC1) - 1);
    blake2s_update(&ctx, key, WG_KEY_LEN);
    blake2s_final(&ctx, out);
}

// mac1 over the message up to mac1
static void mac1(uint8_t out[MAC_LEN], const uint8_t key[WG_KEY_LEN], const uint8_t *msg, size_t len) {
    hash(out, MAC_LEN, key, WG_KEY_LEN, msg, len);
}

// ck, h at the start of every handshake, after the responder's static key
static void handshake_start(uint8_t ck[WG_KEY_LEN], uint8_t h[WG_KEY_LEN],
                            const uint8_t responder_static[WG_KEY_LEN]) {
    hash(ck, WG_KEY_LEN, NULL, 0, CONSTRUCTION, sizeof(CONSTRUCTION) - 1);
    memcpy(h, ck, WG_KEY_LEN);
    mix_hash(h, IDENTIFIER, sizeof(IDENTIFIER) - 1);
    mix_hash(h, responder_static, WG_KEY_LEN);
}

// ck = KDF1(ck, data)
static void kdf1(uint8_t ck[WG_KEY_LEN], const uint8_t *data, size_t len) {
    kdf(ck, WG_KEY_LEN, NULL, 0, NULL, 0, data, len, ck);
}

// ck, k = KDF2(ck, data)
static void kdf2(uint8_t ck[WG_KEY_LEN], uint8_t k[WG_KEY_LEN], const uint8_t *data, size_t len) {
    kdf(ck, WG_KEY_LEN, k, WG_KEY_LEN, NULL, 0, data, len, ck);
}

// X25519; -1 on an all-zero result (a low-order public key)
static int dh(uint8_t out[WG_KEY_LEN], const uint8_t priv[WG_KEY_LEN], const uint8_t pub[WG_KEY_LEN]) {
    static const uint8_t zero[WG_KEY_LEN] = {0};
    if (curve25519_compute_shared_secret(out, priv, pub) != 0) return -1;
    return ct_equal(out, zero, WG_KEY_LEN) ? -1 : 0;
}

// ck, k = KDF2(ck, DH(priv, pub)); -1 on a bad key
static int mix_dh2(uint8_t ck[WG_KEY_LEN], uint8_t k[WG_KEY_LEN],
                   const uint8_t priv[WG_KEY_LEN], const uint8_t pub[WG_KEY_LEN]) {
    uint8_t s[WG_KEY_LEN];
    int rc = dh(s, priv, pub);
    if (rc == 0) kdf2(ck, k, s, WG_KEY_LEN);
    wipe(s, sizeof(s));
    return rc;
}

// ck = KDF1(ck, DH(priv, pub)); -1 on a bad key
static int mix_dh1(uint8_t ck[WG_KEY_LEN], const uint8_t priv[WG_KEY_LEN], const uint8_t pub[WG_KEY_LEN]) {
    uint8_t s[WG_KEY_LEN];
    int rc = dh(s, priv, pub);
    if (rc == 0) kdf1(ck, s, WG_KEY_LEN);
    wipe(s, sizeof(s));
    return rc;
}

// ck, tau, k = KDF3(ck, psk); h = HASH(h || tau)
static void mix_psk(uint8_t ck[WG_KEY_LEN], uint8_t h[WG_KEY_LEN], uint8_t k[WG_KEY_LEN],
                    const uint8_t psk[WG_KEY_LEN]) {
    uint8_t tau[WG_KEY_LEN];
    kdf(ck, WG_KEY_LEN, tau, WG_KEY_LEN, k, WG_KEY_LEN, psk, WG_KEY_LEN, ck);
    mix_hash(h, tau, WG_KEY_LEN);
    wipe(tau, sizeof(tau));
}

// out = AEAD(k, 0, pt, h) (ciphertext then tag); h = HASH(h || out)
static void encrypt_and_hash(uint8_t *out, const uint8_t k[WG_KEY_LEN], const uint8_t *pt, size_t len,
                             uint8_t h[WG_KEY_LEN]) {
    chacha20poly1305_encrypt(out, out + len, k, ZERO_NONCE, pt, len, h, WG_KEY_LEN);
    mix_hash(h, out, len + TAG_LEN);
}

// pt = AEAD-open(k, 0, in, h); h = HASH(h || in). -1 when the tag is wrong
static int decrypt_and_hash(uint8_t *pt, const uint8_t k[WG_KEY_LEN], const uint8_t *in, size_t len,
                            uint8_t h[WG_KEY_LEN]) {
    if (chacha20poly1305_decrypt(pt, k, ZERO_NONCE, in, len, in + len, h, WG_KEY_LEN) != 0) return -1;
    mix_hash(h, in, len + TAG_LEN);
    return 0;
}

// first, second = KDF2(ck, empty)
static void transport_keys(uint8_t first[WG_KEY_LEN], uint8_t second[WG_KEY_LEN], const uint8_t ck[WG_KEY_LEN]) {
    uint8_t none = 0;
    kdf(first, WG_KEY_LEN, second, WG_KEY_LEN, NULL, 0, &none, 0, ck);
}

void wg_identity_init(wg_identity_t *id, const uint8_t priv[WG_KEY_LEN]) {
    memcpy(id->priv, priv, WG_KEY_LEN);
    curve25519_generate_public_key(id->pub, id->priv);
    mac1_key(id->mac1_key, id->pub);
}

int wg_create_initiation(const wg_identity_t *id, wg_handshake_t *hs, uint32_t local_index,
                         const uint8_t e_priv[WG_KEY_LEN], const uint8_t timestamp[WG_TAI64N_LEN],
                         uint8_t msg[WG_MSG_INIT_LEN]) {
    uint8_t k[WG_KEY_LEN], key[WG_KEY_LEN];
    int rc = -1;

    hs->state = WG_HS_NONE;
    memset(msg, 0, WG_MSG_INIT_LEN);
    msg[0] = WG_MSG_INIT;
    put32_le(msg + I_SENDER, local_index);
    hs->local_index = local_index;
    memcpy(hs->e_priv, e_priv, WG_KEY_LEN);

    handshake_start(hs->ck, hs->h, hs->remote_static);
    curve25519_generate_public_key(msg + I_EPHEMERAL, hs->e_priv);
    kdf1(hs->ck, msg + I_EPHEMERAL, WG_KEY_LEN);
    mix_hash(hs->h, msg + I_EPHEMERAL, WG_KEY_LEN);

    if (mix_dh2(hs->ck, k, hs->e_priv, hs->remote_static) != 0) goto out;
    encrypt_and_hash(msg + I_STATIC, k, id->pub, WG_KEY_LEN, hs->h);

    if (mix_dh2(hs->ck, k, id->priv, hs->remote_static) != 0) goto out;
    encrypt_and_hash(msg + I_TIMESTAMP, k, timestamp, WG_TAI64N_LEN, hs->h);

    mac1_key(key, hs->remote_static);
    mac1(msg + I_MAC1, key, msg, I_MAC1);
    hs->state = WG_HS_INITIATED;
    rc = 0;
out:
    wipe(k, sizeof(k));
    if (rc != 0) {  // no half-built initiation: a response cannot match it
        wipe(hs->e_priv, WG_KEY_LEN);
        wipe(hs->ck, WG_KEY_LEN);
        wipe(hs->h, WG_KEY_LEN);
        hs->state = WG_HS_NONE;
    }
    return rc;
}

int wg_consume_initiation(const wg_identity_t *id, wg_handshake_t *hs,
                          const uint8_t msg[WG_MSG_INIT_LEN],
                          uint8_t initiator_static[WG_KEY_LEN],
                          uint8_t timestamp[WG_TAI64N_LEN]) {
    uint8_t m[MAC_LEN], k[WG_KEY_LEN], ck[WG_KEY_LEN], h[WG_KEY_LEN];
    const uint8_t *e = msg + I_EPHEMERAL;
    int rc = -1;

    memset(initiator_static, 0, WG_KEY_LEN);
    memset(timestamp, 0, WG_TAI64N_LEN);
    if (msg[0] != WG_MSG_INIT || msg[1] | msg[2] | msg[3]) return -1;
    mac1(m, id->mac1_key, msg, I_MAC1);
    if (!ct_equal(m, msg + I_MAC1, MAC_LEN)) return -1;

    // on copies: anyone can compute mac1, so hs changes only once both
    // AEADs open
    handshake_start(ck, h, id->pub);
    kdf1(ck, e, WG_KEY_LEN);
    mix_hash(h, e, WG_KEY_LEN);

    if (mix_dh2(ck, k, id->priv, e) != 0) goto out;
    if (decrypt_and_hash(initiator_static, k, msg + I_STATIC, WG_KEY_LEN, h) != 0) goto out;

    if (mix_dh2(ck, k, id->priv, initiator_static) != 0) goto out;
    if (decrypt_and_hash(timestamp, k, msg + I_TIMESTAMP, WG_TAI64N_LEN, h) != 0) goto out;

    memcpy(hs->ck, ck, WG_KEY_LEN);
    memcpy(hs->h, h, WG_KEY_LEN);
    memcpy(hs->remote_ephemeral, e, WG_KEY_LEN);
    memcpy(hs->remote_static, initiator_static, WG_KEY_LEN);
    hs->remote_index = get32_le(msg + I_SENDER);
    hs->state = WG_HS_CONSUMED;
    rc = 0;
out:
    wipe(k, sizeof(k));
    wipe(ck, sizeof(ck));
    if (rc != 0) {  // nothing from a rejected message leaves the call
        wipe(initiator_static, WG_KEY_LEN);
        wipe(timestamp, WG_TAI64N_LEN);
    }
    return rc;
}

int wg_create_response(wg_handshake_t *hs, uint32_t local_index,
                       const uint8_t e_priv[WG_KEY_LEN], uint8_t msg[WG_MSG_RESP_LEN]) {
    uint8_t k[WG_KEY_LEN], key[WG_KEY_LEN];
    int rc = -1;

    memset(msg, 0, WG_MSG_RESP_LEN);
    if (hs->state != WG_HS_CONSUMED) return -1;
    hs->state = WG_HS_NONE;  // one response per consumed initiation
    msg[0] = WG_MSG_RESP;
    put32_le(msg + R_SENDER, local_index);
    put32_le(msg + R_RECEIVER, hs->remote_index);
    hs->local_index = local_index;
    memcpy(hs->e_priv, e_priv, WG_KEY_LEN);

    curve25519_generate_public_key(msg + R_EPHEMERAL, hs->e_priv);
    kdf1(hs->ck, msg + R_EPHEMERAL, WG_KEY_LEN);
    mix_hash(hs->h, msg + R_EPHEMERAL, WG_KEY_LEN);
    if (mix_dh1(hs->ck, hs->e_priv, hs->remote_ephemeral) != 0) goto out;
    if (mix_dh1(hs->ck, hs->e_priv, hs->remote_static) != 0) goto out;
    mix_psk(hs->ck, hs->h, k, hs->psk);
    encrypt_and_hash(msg + R_EMPTY, k, NULL, 0, hs->h);

    mac1_key(key, hs->remote_static);
    mac1(msg + R_MAC1, key, msg, R_MAC1);

    transport_keys(hs->recv_key, hs->send_key, hs->ck);  // the responder's order
    hs->state = WG_HS_DONE;
    rc = 0;
out:
    wipe(k, sizeof(k));
    wipe(hs->e_priv, WG_KEY_LEN);
    wipe(hs->ck, WG_KEY_LEN);
    return rc;
}

int wg_consume_response(const wg_identity_t *id, wg_handshake_t *hs,
                        const uint8_t msg[WG_MSG_RESP_LEN]) {
    uint8_t m[MAC_LEN], k[WG_KEY_LEN], ck[WG_KEY_LEN], h[WG_KEY_LEN];
    const uint8_t *e = msg + R_EPHEMERAL;
    int rc = -1;

    if (msg[0] != WG_MSG_RESP || msg[1] | msg[2] | msg[3]) return -1;
    if (hs->state != WG_HS_INITIATED) return -1;  // also a replay after success
    if (get32_le(msg + R_RECEIVER) != hs->local_index) return -1;
    mac1(m, id->mac1_key, msg, R_MAC1);
    if (!ct_equal(m, msg + R_MAC1, MAC_LEN)) return -1;

    // on copies: a bad response leaves the initiation in hs usable
    memcpy(ck, hs->ck, WG_KEY_LEN);
    memcpy(h, hs->h, WG_KEY_LEN);
    kdf1(ck, e, WG_KEY_LEN);
    mix_hash(h, e, WG_KEY_LEN);
    if (mix_dh1(ck, hs->e_priv, e) != 0) goto out;
    if (mix_dh1(ck, id->priv, e) != 0) goto out;
    mix_psk(ck, h, k, hs->psk);
    if (decrypt_and_hash(NULL, k, msg + R_EMPTY, 0, h) != 0) goto out;

    memcpy(hs->remote_ephemeral, e, WG_KEY_LEN);
    hs->remote_index = get32_le(msg + R_SENDER);
    memcpy(hs->h, h, WG_KEY_LEN);
    transport_keys(hs->send_key, hs->recv_key, ck);  // the initiator's order
    wipe(hs->e_priv, WG_KEY_LEN);
    wipe(hs->ck, WG_KEY_LEN);
    hs->state = WG_HS_DONE;
    rc = 0;
out:
    wipe(k, sizeof(k));
    wipe(ck, sizeof(ck));
    return rc;
}

void wg_tai64n(uint8_t out[WG_TAI64N_LEN], uint64_t unix_seconds, uint32_t nanoseconds) {
    uint64_t s = 0x400000000000000aULL + unix_seconds;
    for (int i = 0; i < 8; i++) out[i] = (uint8_t)(s >> (56 - 8 * i));
    for (int i = 0; i < 4; i++) out[8 + i] = (uint8_t)(nanoseconds >> (24 - 8 * i));
}

void wg_handshake_wipe(wg_handshake_t *hs) {
    wipe(hs, sizeof(*hs));
}

// -----------------------------------------------------------------------------
// Project:     WireGuard-FPGA
// Description: NLnet-funded open-source implementation
// Funding:     https://nlnet.nl/project/KlusterLab-Wireguard (2023-12 to 2025-12)
// -----------------------------------------------------------------------------
