// SPDX-FileCopyrightText: 2026 Chili.CHIPS
//
// SPDX-License-Identifier: BSD-3-Clause

// Host test of 2.sw/app/wg_session.c (the device), against a peer driven
// directly with noise.c. The platform (wg_hw_*) is faked: the cryptokey
// table entries it would write are kept here and checked.
#include <stdio.h>
#include <string.h>
#include <time.h>
#include "wg_session.h"
#include "peer_map.h"
#include "rtc.h"

static int fails, checks;
static void check(const char *what, int ok) {
    checks++;
    if (!ok) { fprintf(stderr, "FAIL %s\n", what); fails++; }
}

static void key(uint8_t k[32], int b) { for (int i = 0; i < 32; i++) k[i] = (uint8_t)(b + i); }

// ---- the fake platform ----
static uint32_t     rng_ctr;
static wg_install_t table[WG_PEERS];
static int          table_set[WG_PEERS], installs, hw_busy;

void wg_hw_random(uint8_t out[32]) {
    for (int i = 0; i < 32; i++) out[i] = (uint8_t)(rng_ctr * 37 + i * 11 + 1);
    rng_ctr++;
}
void random_32bytes(uint8_t *out) { wg_hw_random(out); }  // peer_map's SipHash key
int wg_hw_install(int n, const wg_install_t *in) {
    if (hw_busy) return -1;
    installs++;
    if (in) {
        table[n]     = *in;
        table_set[n] = 1;
    } else {
        memset(&table[n], 0, sizeof(table[n]));
        table_set[n] = 0;
    }
    return 0;
}

static uint32_t le32(const uint8_t *p) {
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8) | ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}

int main(void) {
    uint8_t dev_priv[32], peer_priv[32], other_priv[32], psk[32], e[32];
    key(dev_priv, 0x10); key(peer_priv, 0x30); key(other_priv, 0x70); key(psk, 0x90); key(e, 0x50);
    wg_identity_t peer, other;
    wg_identity_init(&peer, peer_priv);
    wg_identity_init(&other, other_priv);

    const wg_endpoint_t src = {{0x02, 0, 0, 0, 0, 0x22}, {10, 0, 0, 1}, 51820, 2};
    uint8_t out[WG_MSG_INIT_LEN], m1[WG_MSG_INIT_LEN], m2[WG_MSG_RESP_LEN], is[32], ts[12];
    size_t out_len;
    wg_endpoint_t dst;

    // set-up
    peer_map_init();
    wg_session_init();
    uint8_t ts1[12] = {0x40, 0, 0, 0, 0x6a, 0, 0, 1, 0, 0, 0, 0};
    memset(m1, 0, sizeof(m1)); m1[0] = WG_MSG_INIT;
    check("no key: message 1 dropped", wg_session_rx(m1, sizeof(m1), &src, out, &out_len, &dst) == -1);
    wg_set_private(dev_priv);
    const uint8_t *dev_pub = wg_identity()->pub;
    check("our own key is no peer", wg_peer_add(dev_pub, NULL, NULL) == -1);
    int n = wg_peer_add(peer.pub, psk, NULL);
    check("peer added as entry 1", n == 1);
    check("added twice refused", wg_peer_add(peer.pub, NULL, NULL) == -1);
    check("no endpoint yet: no initiation", wg_session_initiate(n, m1, &dst) == -1);

    // 1. the peer initiates; we respond and install the keys
    wg_handshake_t ph; memset(&ph, 0, sizeof(ph));
    memcpy(ph.remote_static, dev_pub, 32); memcpy(ph.psk, psk, 32);
    check("peer builds message 1", wg_create_initiation(&peer, &ph, 0x1111, e, ts1, m1) == 0);
    check("we answer message 1", wg_session_rx(m1, sizeof(m1), &src, out, &out_len, &dst) == 0);
    check("answer: 92 bytes to the source", out_len == WG_MSG_RESP_LEN && memcmp(&dst, &src, sizeof(src)) == 0);
    check("peer accepts our answer", wg_consume_response(&peer, &ph, out) == 0);
    check("entry 1 written", table_set[1] && installs == 1);
    check("encrypt key = peer's receive key", memcmp(table[1].send_key, ph.recv_key, 32) == 0);
    check("decrypt key = peer's send key", memcmp(table[1].recv_key, ph.send_key, 32) == 0);
    check("remote_id = the peer's index", table[1].remote_id == 0x1111);
    check("local_id: entry in the low 6 bits, = message 2 sender",
          (table[1].local_id & 63) == 1 && table[1].local_id == le32(out + 4));
    check("remote address = the source", memcmp(&table[1].remote, &src, sizeof(src)) == 0);
    check("peer live, endpoint learnt", wg_peer(1)->live && wg_peer(1)->has_ep);

    // 2. replay and an older timestamp
    check("replayed message 1 dropped", wg_session_rx(m1, sizeof(m1), &src, out, &out_len, &dst) == -1);
    check("... counted as replay, nothing written", wg_stats()->drop_replay == 1 && installs == 1 && out_len == 0);
    {
        uint8_t old[12]; memcpy(old, ts1, 12); old[7] = 0;
        wg_handshake_t t; memset(&t, 0, sizeof(t));
        memcpy(t.remote_static, dev_pub, 32); memcpy(t.psk, psk, 32);
        wg_create_initiation(&peer, &t, 0x3333, e, old, m1);
        check("older timestamp dropped", wg_session_rx(m1, sizeof(m1), &src, out, &out_len, &dst) == -1
              && wg_stats()->drop_replay == 2);
    }

    // 3. an unknown peer, a busy data plane
    {
        wg_handshake_t t; memset(&t, 0, sizeof(t));
        memcpy(t.remote_static, dev_pub, 32);
        wg_create_initiation(&other, &t, 0x4444, e, ts1, m1);
        check("unknown peer dropped", wg_session_rx(m1, sizeof(m1), &src, out, &out_len, &dst) == -1
              && wg_stats()->drop_unknown == 1);
    }
    uint8_t ts2[12]; memcpy(ts2, ts1, 12); ts2[7] = 2;
    memset(&ph, 0, sizeof(ph));
    memcpy(ph.remote_static, dev_pub, 32); memcpy(ph.psk, psk, 32);
    wg_create_initiation(&peer, &ph, 0x5555, e, ts2, m1);
    hw_busy = 1;
    check("data plane busy: no answer", wg_session_rx(m1, sizeof(m1), &src, out, &out_len, &dst) == -1
          && out_len == 0 && wg_stats()->drop_hw == 1);
    hw_busy = 0;
    check("... the retry (same timestamp) is answered",
          wg_session_rx(m1, sizeof(m1), &src, out, &out_len, &dst) == 0 && table[1].remote_id == 0x5555);

    // 4. we initiate; the peer answers
    check("we build message 1", wg_session_initiate(1, m1, &dst) == 0 && memcmp(&dst, &src, sizeof(src)) == 0);
    {
        wg_handshake_t r; memset(&r, 0, sizeof(r));
        uint8_t e2[32]; key(e2, 0x60);
        check("peer accepts our message 1", wg_consume_initiation(&peer, &r, m1, is, ts) == 0
              && memcmp(is, dev_pub, 32) == 0);
        uint8_t t0[12]; wg_now_tai64n(t0);
        check("our timestamp is now-ish (TAI64N label)", ts[0] == 0x40 && memcmp(ts, t0, 12) <= 0);
        memcpy(r.psk, psk, 32);
        check("peer builds message 2", wg_create_response(&r, 0x6666, e2, m2) == 0);
        uint8_t bad[WG_MSG_RESP_LEN]; memcpy(bad, m2, sizeof(bad)); bad[8] ^= 0x40;  // receiver index
        check("message 2 to another index dropped", wg_session_rx(bad, sizeof(bad), &src, out, &out_len, &dst) == -1);
        int before = installs;
        check("we accept message 2", wg_session_rx(m2, sizeof(m2), &src, out, &out_len, &dst) == 0 && out_len == 0);
        check("entry 1 rewritten with the new keys", installs == before + 1 && table[1].remote_id == 0x6666
              && memcmp(table[1].send_key, r.recv_key, 32) == 0 && memcmp(table[1].recv_key, r.send_key, 32) == 0);
        check("pending handshake wiped", wg_peer(1)->hs.state == WG_HS_NONE);
        check("replayed message 2 dropped", wg_session_rx(m2, sizeof(m2), &src, out, &out_len, &dst) == -1);
    }

    // 4b. cookies (cookie.c): we are under load, then the peer is
    {
        wg_cookie_t pc;  // the peer's cookie state for us
        wg_cookie_init(&pc, dev_pub);
        uint8_t ts3[12]; memcpy(ts3, ts1, 12); ts3[7] = 3;
        wg_handshake_t t; memset(&t, 0, sizeof(t));
        memcpy(t.remote_static, dev_pub, 32); memcpy(t.psk, psk, 32);
        wg_create_initiation(&peer, &t, 0x7777, e, ts3, m1);
        check("peer has no cookie: mac2 zeros", wg_cookie_add_mac2(&pc, m1, sizeof(m1)) == 0);
        wg_set_under_load(1);
        int before = installs;
        check("under load, no mac2: a cookie reply instead",
              wg_session_rx(m1, sizeof(m1), &src, out, &out_len, &dst) == 0 && out_len == WG_MSG_COOKIE_LEN
              && out[0] == WG_MSG_COOKIE && wg_stats()->cookie_tx == 1 && installs == before);
        check("peer takes the cookie", wg_cookie_consume_reply(&pc, out, WG_MSG_COOKIE_LEN) == 0);
        check("peer's retransmit carries mac2", wg_cookie_add_mac2(&pc, m1, sizeof(m1)) == 1);
        check("under load, valid mac2: answered", wg_session_rx(m1, sizeof(m1), &src, out, &out_len, &dst) == 0
              && out_len == WG_MSG_RESP_LEN && installs == before + 1 && table[1].remote_id == 0x7777);
        wg_endpoint_t other_src = src; other_src.port = 40000;
        wg_create_initiation(&peer, &t, 0x7778, e, ts3, m1);
        wg_cookie_add_mac2(&pc, m1, sizeof(m1));
        check("mac2 from another port: a cookie reply again",
              wg_session_rx(m1, sizeof(m1), &other_src, out, &out_len, &dst) == 0 && out_len == WG_MSG_COOKIE_LEN);
        wg_set_under_load(0);

        // the peer is under load: our initiation gets its cookie reply
        wg_cookie_checker_t pchk;
        wg_cookie_checker_init(&pchk, peer.pub);
        const uint8_t dev_ip[4] = {10, 0, 0, 2};
        check("we initiate", wg_session_initiate(1, m1, &dst) == 0);
        check("peer under load wants a cookie",
              wg_cookie_validate(&pchk, m1, sizeof(m1), dev_ip, 51820, 1) == WG_COOKIE_SEND_REPLY);
        uint8_t c3[WG_MSG_COOKIE_LEN];
        wg_cookie_create_reply(&pchk, c3, m1, sizeof(m1), dev_ip, 51820);
        check("we take the peer's cookie reply, send nothing",
              wg_session_rx(c3, sizeof(c3), &src, out, &out_len, &dst) == 0 && out_len == 0
              && wg_stats()->cookie_rx == 1);
        check("a second copy of it is refused", wg_session_rx(c3, sizeof(c3), &src, out, &out_len, &dst) == -1);
        check("our next initiation carries a mac2 the peer accepts", wg_session_initiate(1, m1, &dst) == 0
              && wg_cookie_validate(&pchk, m1, sizeof(m1), dev_ip, 51820, 1) == WG_COOKIE_OK);
    }

    // 5. the peer map survives a rebuild (test siphash), a peer is removed
    int n2 = wg_peer_add(other.pub, NULL, NULL);
    wg_peer_map_rebuild();
    check("rebuild keeps both peers", peer_map_find(peer.pub) == 1 && peer_map_find(other.pub) == n2);
    hw_busy = 1;
    check("remove refused while the data plane is busy", wg_peer_remove(1) == -1 && wg_peer(1));
    hw_busy = 0;
    check("removed: entry cleared, map forgets it",
          wg_peer_remove(1) == 0 && !wg_peer(1) && !table_set[1] && peer_map_find(peer.pub) == -1);

    // 6. junk
    check("short message dropped", wg_session_rx(m1, 3, &src, out, &out_len, &dst) == -1);
    check("message 1 of the wrong length dropped", wg_session_rx(m1, 147, &src, out, &out_len, &dst) == -1);
    m1[0] = WG_MSG_DATA;
    check("a data message is not ours", wg_session_rx(m1, sizeof(m1), &src, out, &out_len, &dst) == -1);

    // 7. the clock (rtc_host.c: starts at RTC_EPOCH_DEFAULT, 2026-01-01)
    const uint64_t t_set = RTC_EPOCH_DEFAULT + 400ULL * 86400;
    check("set time forward", wg_set_time(t_set) == 0);
    uint8_t a[12], b[12], want[12];
    wg_now_tai64n(a); wg_now_tai64n(b);
    wg_tai64n(want, t_set, 0);
    check("set time: seconds as set", memcmp(a, want, 8) == 0 || a[7] == (uint8_t)(want[7] + 1));
    check("the clock strictly grows", memcmp(a, b, 12) < 0);
    check("set time back refused", wg_set_time(t_set - 10) != 0);
    wg_now_tai64n(b);
    check("... the clock did not go back", memcmp(a, b, 12) < 0);

    fprintf(stderr, "%s %d checks, %d failed\n", fails ? "FAIL" : "PASS", checks, fails);
    return fails;
}

// -----------------------------------------------------------------------------
// Project:     WireGuard-FPGA
// Description: NLnet-funded open-source implementation
// Funding:     https://nlnet.nl/project/KlusterLab-Wireguard (2023-12 to 2025-12)
// -----------------------------------------------------------------------------
