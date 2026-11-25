// SPDX-FileCopyrightText: 2026 Chili.CHIPS
//
// SPDX-License-Identifier: BSD-3-Clause

// Host test of 2.sw/app/noise.c: the same fixed keys as noise_ref.py; prints
// the same lines, then runs the negative checks (exit code = failures)
#include <stdio.h>
#include <string.h>
#include "noise.h"
#include "blake2s.h"

static void key(uint8_t k[32], int b) {
    for (int i = 0; i < 32; i++) k[i] = (uint8_t)(b + i);
}

static void hex(const char *name, const uint8_t *p, size_t n) {
    printf("%s ", name);
    for (size_t i = 0; i < n; i++) printf("%02x", p[i]);
    printf("\n");
}

static int fails = 0, checks = 0;
static void check(const char *what, int ok) {
    checks++;
    if (!ok) { fprintf(stderr, "FAIL %s\n", what); fails++; }
}

// mac1 again after a change, so the message gets past mac1 to the DH/AEAD
static void remac1(uint8_t *msg, size_t mac1_at, const wg_identity_t *to) {
    hash(msg + mac1_at, 16, to->mac1_key, 32, msg, mac1_at);
}

static int all(const uint8_t *p, size_t n, uint8_t v) {
    for (size_t i = 0; i < n; i++) if (p[i] != v) return 0;
    return 1;
}

// the rejection paths: after mac1 passes, a low-order key, calls out of order
static void negative(const wg_identity_t *idi, const wg_identity_t *idr,
                     const uint8_t m1[WG_MSG_INIT_LEN], const uint8_t m2[WG_MSG_RESP_LEN],
                     const wg_handshake_t *hi, const wg_handshake_t *hi0, const wg_handshake_t *hr,
                     const uint8_t ei[32], const uint8_t er[32], const uint8_t ts[12]) {
    uint8_t bad1[WG_MSG_INIT_LEN], bad2[WG_MSG_RESP_LEN], st[32], tm[12], r2[WG_MSG_RESP_LEN];
    wg_handshake_t t, keep;

    // a rejected initiation leaves hs and the outputs as zeros/untouched
    memcpy(bad1, m1, sizeof(bad1));
    bad1[60] ^= 1;  // the encrypted static key, mac1 made valid again
    remac1(bad1, 116, idr);
    memset(&t, 0xaa, sizeof(t)); keep = t;
    check("valid mac1, bad static AEAD refused", wg_consume_initiation(idr, &t, bad1, st, tm) != 0);
    check("rejected initiation: hs untouched", memcmp(&t, &keep, sizeof(t)) == 0);
    check("rejected initiation: outputs zero", all(st, 32, 0) && all(tm, 12, 0));

    memcpy(bad1, m1, sizeof(bad1));
    bad1[100] ^= 1;  // the encrypted timestamp: the static key decrypted first
    remac1(bad1, 116, idr);
    check("valid mac1, bad timestamp AEAD refused", wg_consume_initiation(idr, &t, bad1, st, tm) != 0);
    check("rejected timestamp: static key not left", all(st, 32, 0) && all(tm, 12, 0));
    check("rejected timestamp: hs untouched", memcmp(&t, &keep, sizeof(t)) == 0);

    // low-order points: all-zero ephemeral (initiation, response), static
    memcpy(bad1, m1, sizeof(bad1));
    memset(bad1 + 8, 0, 32);
    remac1(bad1, 116, idr);
    check("zero initiator ephemeral refused", wg_consume_initiation(idr, &t, bad1, st, tm) != 0);

    memset(&t, 0, sizeof(t));
    uint8_t m[WG_MSG_INIT_LEN];
    check("zero responder static refused", wg_create_initiation(idi, &t, 1, ei, ts, m) != 0);
    check("refused initiation: secrets wiped",
          t.state == WG_HS_NONE && all(t.e_priv, 32, 0) && all(t.ck, 32, 0) && all(t.h, 32, 0));

    // the responder side: replay, out of order, low-order ephemeral
    t = *hr;
    check("second response from one initiation refused", wg_create_response(&t, 2, er, r2) != 0);
    memset(&t, 0, sizeof(t));
    check("response without an initiation refused", wg_create_response(&t, 2, er, r2) != 0);

    // the initiator side: a replayed message 2, and one with a zero ephemeral
    t = *hi;
    check("replayed response refused", wg_consume_response(idi, &t, m2) != 0);
    check("replay leaves the keys", memcmp(t.send_key, hi->send_key, 32) == 0);
    memset(&t, 0, sizeof(t));
    t.local_index = 0x11223344;
    check("response with no initiation refused", wg_consume_response(idi, &t, m2) != 0);

    t = *hi0;  // the initiation before message 2
    memcpy(bad2, m2, sizeof(bad2));
    memset(bad2 + 12, 0, 32);
    remac1(bad2, 60, idi);
    check("zero responder ephemeral refused", wg_consume_response(idi, &t, bad2) != 0);
    check("refused response leaves the initiation", t.state == WG_HS_INITIATED);
}

// a full handshake with no psk (zeros): allowed, keys must still match
static void zero_psk(const wg_identity_t *idi, const wg_identity_t *idr,
                     const uint8_t ei[32], const uint8_t er[32], const uint8_t ts[12]) {
    wg_handshake_t a, b;
    uint8_t m1[WG_MSG_INIT_LEN], m2[WG_MSG_RESP_LEN], st[32], tm[12];
    memset(&a, 0, sizeof(a)); memset(&b, 0, sizeof(b));
    memcpy(a.remote_static, idr->pub, 32);
    int ok = wg_create_initiation(idi, &a, 7, ei, ts, m1) == 0
          && wg_consume_initiation(idr, &b, m1, st, tm) == 0
          && wg_create_response(&b, 9, er, m2) == 0
          && wg_consume_response(idi, &a, m2) == 0;
    check("zero psk handshake", ok && a.state == WG_HS_DONE && b.state == WG_HS_DONE
          && memcmp(a.send_key, b.recv_key, 32) == 0 && memcmp(a.recv_key, b.send_key, 32) == 0);
}

int main(void) {
    uint8_t si[32], sr[32], ei[32], er[32], psk[32];
    uint8_t ts[12] = {0x40, 0, 0, 0, 0x6a, 0x1b, 0x2c, 0x3d, 0x0b, 0xad, 0xf0, 0x0d};
    key(si, 0x10); key(sr, 0x30); key(ei, 0x50); key(er, 0x70); key(psk, 0x90);

    wg_identity_t idi, idr;
    wg_identity_init(&idi, si);
    wg_identity_init(&idr, sr);

    wg_handshake_t hi, hr;
    memset(&hi, 0, sizeof(hi)); memset(&hr, 0, sizeof(hr));
    memcpy(hi.remote_static, idr.pub, 32);
    memcpy(hi.psk, psk, 32);

    uint8_t m1[WG_MSG_INIT_LEN], m2[WG_MSG_RESP_LEN], got_static[32], got_ts[12];
    check("create initiation", wg_create_initiation(&idi, &hi, 0x11223344, ei, ts, m1) == 0);

    // negative: a flipped bit anywhere before mac2 is refused
    for (int i = 0; i < 132; i++) {
        uint8_t bad[WG_MSG_INIT_LEN];
        wg_handshake_t t;
        memcpy(bad, m1, sizeof(bad));
        bad[i] ^= 0x01;
        check("tampered initiation refused", wg_consume_initiation(&idr, &t, bad, got_static, got_ts) != 0);
    }
    // negative: sent to another responder
    {
        wg_identity_t other; uint8_t ok[32]; wg_handshake_t t;
        key(ok, 0xb0); wg_identity_init(&other, ok);
        check("wrong responder refused", wg_consume_initiation(&other, &t, m1, got_static, got_ts) != 0);
    }

    check("consume initiation", wg_consume_initiation(&idr, &hr, m1, got_static, got_ts) == 0);
    check("initiator static", memcmp(got_static, idi.pub, 32) == 0);
    check("timestamp", memcmp(got_ts, ts, 12) == 0);
    check("remote index", hr.remote_index == 0x11223344);
    memcpy(hr.psk, psk, 32);
    check("create response", wg_create_response(&hr, 0xa5a5a5a5, er, m2) == 0);

    // negative: a tampered response, a wrong psk; hi stays usable after them
    for (int i = 0; i < 76; i++) {
        uint8_t bad[WG_MSG_RESP_LEN];
        memcpy(bad, m2, sizeof(bad));
        bad[i] ^= 0x80;
        check("tampered response refused", wg_consume_response(&idi, &hi, bad) != 0);
    }
    {
        wg_handshake_t t = hi;
        t.psk[0] ^= 1;
        check("wrong psk refused", wg_consume_response(&idi, &t, m2) != 0);
    }

    wg_handshake_t hi0 = hi;
    check("consume response", wg_consume_response(&idi, &hi, m2) == 0);
    check("keys match", memcmp(hi.send_key, hr.recv_key, 32) == 0 && memcmp(hi.recv_key, hr.send_key, 32) == 0);
    check("indices", hi.remote_index == 0xa5a5a5a5);

    negative(&idi, &idr, m1, m2, &hi, &hi0, &hr, ei, er, ts);
    zero_psk(&idi, &idr, ei, er, ts);

    hex("msg1", m1, sizeof(m1));
    hex("msg2", m2, sizeof(m2));
    hex("i_send", hi.send_key, 32);
    hex("i_recv", hi.recv_key, 32);
    hex("r_send", hr.send_key, 32);
    hex("r_recv", hr.recv_key, 32);
    hex("h", hi.h, 32);

    uint8_t t64[12];
    wg_tai64n(t64, 1764000000ULL, 123456789);
    hex("tai64n", t64, 12);
    fprintf(stderr, "%s %d checks, %d failed\n", fails ? "FAIL" : "PASS", checks, fails);
    return fails;
}

// -----------------------------------------------------------------------------
// Project:     WireGuard-FPGA
// Description: NLnet-funded open-source implementation
// Funding:     https://nlnet.nl/project/KlusterLab-Wireguard (2023-12 to 2025-12)
// -----------------------------------------------------------------------------
