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
#include "rtc.h"
#include "chacha20poly1305.h"

static int fails, checks;
static void check(const char *what, int ok) {
    checks++;
    if (!ok) { fprintf(stderr, "FAIL %s\n", what); fails++; }
}

static void key(uint8_t k[32], int b) { for (int i = 0; i < 32; i++) k[i] = (uint8_t)(b + i); }

// ---- the fake platform ----
static uint32_t     rng_ctr;
static wg_install_t table[WG_ENTRIES];
static int          table_set[WG_ENTRIES], installs, hw_busy;
// the peer tags (local_port.tag): written at install, moved with the routes
static int          hw_tag[WG_ENTRIES], tag_bad;

void wg_hw_random(uint8_t out[32]) {
    for (int i = 0; i < 32; i++) out[i] = (uint8_t)(rng_ctr * 37 + i * 11 + 1);
    rng_ctr++;
}
void random_32bytes(uint8_t *out) { wg_hw_random(out); }  // cookie.c's secrets
// the entries' counters (the timers, #80), as the data plane would move them
static uint64_t hw_send_cnt[WG_ENTRIES], hw_recv_cnt[WG_ENTRIES], hw_recv_win[WG_ENTRIES];
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
    hw_tag[n] = in ? in->tag : 0;
    hw_send_cnt[n] = hw_recv_cnt[n] = hw_recv_win[n] = 0;
    return 0;
}
void wg_hw_counters(int n, uint64_t *s, uint64_t *r, uint64_t *w) {
    *s = hw_send_cnt[n]; *r = hw_recv_cnt[n]; *w = hw_recv_win[n];
}
static int take_busy;  // only wg_hw_take_send_cnt does not drain
int wg_hw_take_send_cnt(int n, uint64_t *c) {
    if (hw_busy || take_busy) return -1;
    *c = hw_send_cnt[n]++;
    return 0;
}
// the routes' peer_idx (the session pool, #85), the entries' tags with them,
// and the pauses that moved them
static int hw_route[WG_ROUTES], route_moves;
int wg_hw_routes(uint64_t routes, uint64_t entries, int e) {
    if (hw_busy) return -1;
    route_moves++;
    for (int r = 0; r < WG_ROUTES; r++) {
        if ((routes >> r) & 1) hw_route[r] = e;
    }
    for (int x = 0; x < WG_ENTRIES; x++) {
        if ((entries >> x) & 1) hw_tag[x] = e;
    }
    return 0;
}
// the messages the timers send: the last few, with their times
#define TX_MAX 64
static uint8_t       tx_msg[TX_MAX][WG_MSG_INIT_LEN];
static size_t        tx_len[TX_MAX];
static uint32_t      tx_at[TX_MAX];
static wg_endpoint_t tx_dst;
static int           tx_n;
void wg_hw_send(const wg_endpoint_t *dst, const uint8_t *msg, size_t len) {
    if (tx_n < TX_MAX && len <= WG_MSG_INIT_LEN) {
        memcpy(tx_msg[tx_n], msg, len);
        tx_len[tx_n] = len;
        tx_at[tx_n]  = wg_timer_ms();
    }
    tx_dst = *dst;
    tx_n++;
}
void rtc_host_advance_ms(uint64_t ms);  // rtc_host.c

// the X25519 calls, counted (the Makefile links them with --wrap)
#include "curve25519.h"
static int x_dh, x_pub;
int __real_curve25519_compute_shared_secret(uint8_t s[32], const uint8_t priv[32], const uint8_t pub[32]);
int __real_curve25519_generate_public_key(uint8_t pub[32], const uint8_t priv[32]);
int __wrap_curve25519_compute_shared_secret(uint8_t s[32], const uint8_t priv[32], const uint8_t pub[32]) {
    x_dh++;
    return __real_curve25519_compute_shared_secret(s, priv, pub);
}
int __wrap_curve25519_generate_public_key(uint8_t pub[32], const uint8_t priv[32]) {
    x_pub++;
    return __real_curve25519_generate_public_key(pub, priv);
}

static uint32_t le32(const uint8_t *p) {
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8) | ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}

// the timer tests (#80): ms pass in polls of 250 ms; each poll the data
// plane sends to and receives from peer tm_peer, when asked to, on the
// entry its routes point at (its current one)
// the peer tags follow the routes (lkup_egress's AllowedIPs check compares
// them): an entry with keys has its peer's current entry as its tag, also
// as that peer's next or old entry; a cleared one 0
static int tags_ok(void) {
    for (int x = 1; x < WG_ENTRIES; x++) {
        int want = 0;
        for (int n = 1; n < WG_PEERS && table_set[x]; n++) {
            const wg_peer_t *p = wg_peer(n);
            if (p && (p->cur.entry == x || p->next.entry == x || p->prev.entry == x)) want = p->cur.entry;
        }
        if (hw_tag[x] != want) return 0;
    }
    return 1;
}

static int tm_peer;
static void run_ms(uint32_t ms, int send, int recv) {
    for (uint32_t t = 0; t < ms; t += 250) {
        int e = wg_peer(tm_peer)->cur.entry;
        if (send) hw_send_cnt[e]++;
        if (recv) hw_recv_cnt[e]++;
        rtc_host_advance_ms(250);
        wg_session_timers();
        tag_bad += !tags_ok();
    }
}
static uint32_t age_ms(void) { return wg_timer_ms() - wg_peer(tm_peer)->cur.t_start; }
// one poll of the timers, a poll interval later
static void poll(void) {
    rtc_host_advance_ms(WG_TIMER_POLL_MS);
    wg_session_timers();
    tag_bad += !tags_ok();
}
static int cur_of(int n) { return wg_peer(n)->cur.entry; }
static int next_of(int n) { return wg_peer(n)->next.entry; }
static int is_init(int i) { return i < tx_n && tx_len[i] == WG_MSG_INIT_LEN && tx_msg[i][0] == WG_MSG_INIT; }
// the last message 1 the timers sent from entry e (its index), from tx_msg[from]: or -1
static int last_init(int e, int from) {
    int last = -1;
    for (int i = from; i < tx_n && i < TX_MAX; i++) {
        if (is_init(i) && (le32(tx_msg[i] + 4) & 63) == (uint32_t)e) last = i;
    }
    return last;
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
    wg_session_init();
    uint8_t ts1[12] = {0x40, 0, 0, 0, 0x6a, 0, 0, 1, 0, 0, 0, 0};
    memset(m1, 0, sizeof(m1)); m1[0] = WG_MSG_INIT;
    check("no key: message 1 dropped", wg_session_rx(m1, sizeof(m1), &src, out, &out_len, &dst) == -1);
    wg_set_private(dev_priv);
    const uint8_t *dev_pub = wg_identity()->pub;
    check("our own key is no peer", wg_peer_add(dev_pub, NULL, NULL) == -1);
    int n = wg_peer_add(peer.pub, psk, NULL);
    check("peer 1 added, its current entry 1 from the pool (no keys)",
          n == 1 && cur_of(1) == 1 && !wg_peer(1)->live && wg_pool_free() == 62 && installs == 0);
    check("a route to peer 1 names its current entry", wg_route_set(0, 1) == 1 && wg_route_peer(0) == 1);
    hw_route[0] = 1;  // as config routes writes it
    check("a route to no peer is not ours", wg_route_set(1, 5) == -1 && wg_route_peer(1) == 0);
    check("added twice refused", wg_peer_add(peer.pub, NULL, NULL) == -1);
    check("no endpoint yet: no initiation", wg_session_initiate(n, m1, &dst) == -1);
    check("load detection on by default", wg_load_mode() == WG_LOAD_AUTO && !wg_under_load());
    wg_set_load_mode(WG_LOAD_OFF);  // 1 .. 4b send faster than WG_LOAD_MAX a second: 4c tests it

    // 1. the peer initiates; we respond and install the keys
    wg_handshake_t ph; memset(&ph, 0, sizeof(ph));
    memcpy(ph.remote_static, dev_pub, 32); memcpy(ph.psk, psk, 32);
    check("peer builds message 1", wg_create_initiation(&peer, &ph, 0x1111, e, ts1, m1) == 0);
    check("we answer message 1", wg_session_rx(m1, sizeof(m1), &src, out, &out_len, &dst) == 0);
    check("answer: 92 bytes to the source", out_len == WG_MSG_RESP_LEN && memcmp(&dst, &src, sizeof(src)) == 0);
    check("peer accepts our answer", wg_consume_response(&peer, &ph, out) == 0);
    int ne = next_of(1);
    check("the session in a new entry (2), the next one, waiting for confirmation",
          ne == 2 && table_set[2] && installs == 1 && wg_peer(1)->next.state == WG_KP_PENDING
          && wg_pool_free() == 61);
    check("encrypt key = peer's receive key", memcmp(table[ne].send_key, ph.recv_key, 32) == 0);
    check("decrypt key = peer's send key", memcmp(table[ne].recv_key, ph.send_key, 32) == 0);
    check("remote_id = the peer's index", table[ne].remote_id == 0x1111);
    check("local_id: entry in the low 6 bits, = message 2 sender",
          (table[ne].local_id & 63) == (uint32_t)ne && table[ne].local_id == le32(out + 4));
    check("remote address = the source", memcmp(&table[ne].remote, &src, sizeof(src)) == 0);
    check("its peer tag: the current entry (1), where the routes still point", hw_tag[ne] == 1);
    check("endpoint learnt; not live: nothing sent before confirmation",
          !wg_peer(1)->live && wg_peer(1)->has_ep && !table_set[1]);

    // 1b. the responder's first session (#85): the routes stay on the
    // current entry (no keys: the data plane drops and counts) until the
    // first data on the new one; data to the peer starts no handshake
    {
        int tx0 = tx_n;
        hw_send_cnt[1] += 3;  // the routes send to entry 1: dropped, counted
        poll();
        poll();
        check("responder, unconfirmed: route on the keyless entry, nothing sent",
              hw_route[0] == 1 && tx_n == tx0 && !wg_peer(1)->live && route_moves == 0);
        hw_recv_cnt[ne] = 0; hw_recv_win[ne] = 1;  // the initiator's first data (counter 0)
        poll();
        check("first data on the new entry: confirmed, the route moves to it",
              hw_route[0] == ne && cur_of(1) == ne && wg_peer(1)->live && next_of(1) == 0
              && route_moves == 1 && wg_stats()->switches == 1);
        check("... the keyless entry 1 back in the pool (no old session to keep)",
              wg_peer(1)->prev.entry == 0 && wg_pool_free() == 62 && installs == 1);
        check("... its tag moved with the route", hw_tag[ne] == ne && tags_ok());
        check("... our keepalive key = the entry's", memcmp(wg_peer(1)->cur.send_key, table[ne].send_key, 32) == 0
              && !(wg_peer(1)->tm & WG_TM_INITIATOR));
    }

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
    check("... the entry it took back in the pool", wg_pool_free() == 62 && next_of(1) == 0);
    hw_busy = 0;
    check("... the retry (same timestamp) is answered",
          wg_session_rx(m1, sizeof(m1), &src, out, &out_len, &dst) == 0 && next_of(1) == 1
          && table[1].remote_id == 0x5555);

    // 3b. a responder rekey (#85): we keep sending on the old entry until
    // the first data on the new one, then the routes switch; the old entry
    // still decrypts until the next switch (4) or its REJECT_AFTER_TIME (9)
    {
        int old = cur_of(1), nw = next_of(1);
        poll();
        check("rekey as responder: still sending on the old entry", hw_route[0] == old && cur_of(1) == old
              && wg_peer(1)->live && wg_peer(1)->next.state == WG_KP_PENDING);
        hw_recv_cnt[nw] = 1;
        poll();
        check("first data on the new entry: the route switches to it",
              hw_route[0] == nw && cur_of(1) == nw && wg_peer(1)->prev.entry == old && wg_stats()->switches == 2);
        check("... the old entry keeps its keys (still decrypts)", table_set[old] && table[old].remote_id == 0x1111);
        check("... both entries tagged with the new one: data on the old passes AllowedIPs",
              hw_tag[nw] == nw && hw_tag[old] == nw);
        hw_recv_cnt[old] = 5;  // a late packet on the old keys
        poll();
        rtc_host_advance_ms(2 * REKEY_TIMEOUT_MS);  // then 10 s without data on it
        wg_session_timers();
        check("the old entry kept 10 s without data (Linux's previous keypair), its keys there",
              wg_peer(1)->prev.entry == old && table_set[old] && table[old].remote_id == 0x1111
              && wg_stats()->retired == 0 && wg_pool_free() == 61);
        hw_recv_cnt[old] = 6;  // the peer still on the old keys
        poll();
        check("... data on it still decrypts: seen as received", wg_peer(1)->t_recv == wg_timer_ms()
              && wg_peer(1)->prev.entry == old && tags_ok());
        // F4: two late packets in one poll, recv_cnt unchanged, one window bit
        // in each half (the same position): still a receive event
        hw_recv_cnt[nw] = 40; hw_recv_win[nw] = 1;
        poll();
        uint32_t t_in = wg_peer(1)->t_recv;
        poll();
        hw_recv_win[nw] |= (1ull << 3) | (1ull << 35);  // counters 37 and 5
        poll();
        check("two late packets, one bit in each window half: a receive event",
              t_in != wg_timer_ms() && wg_peer(1)->t_recv == wg_timer_ms());
    }

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
        int before = installs, old = cur_of(1), nw = next_of(1), tx0 = tx_n, older = wg_peer(1)->prev.entry;
        check("our initiation holds a next entry (3: 2 is still the old one), named in its index",
              nw == 3 && older == 2 && wg_peer(1)->next.state == WG_KP_RESERVED
              && (le32(m1 + 4) & 63) == (uint32_t)nw);
        check("we accept message 2", wg_session_rx(m2, sizeof(m2), &src, out, &out_len, &dst) == 0 && out_len == 0);
        check("initiator rekey: the new keys in the next entry (and 3b's old one cleared)",
              installs == before + 2 && table[nw].remote_id == 0x6666
              && memcmp(table[nw].send_key, r.recv_key, 32) == 0 && memcmp(table[nw].recv_key, r.send_key, 32) == 0);
        check("... message 2 confirms: the route switches at once",
              hw_route[0] == nw && cur_of(1) == nw && wg_peer(1)->prev.entry == old
              && (wg_peer(1)->tm & WG_TM_INITIATOR));
        check("... the old entry keeps its keys (still decrypts)", table_set[old] && table[old].remote_id == 0x5555);
        check("... the one before it (3b's) retired at this switch, back in the pool",
              !table_set[older] && hw_tag[older] == 0 && wg_stats()->retired == 1 && wg_pool_free() == 61);
        check("... installed tagged with the old entry, both on the new one after the switch",
              hw_tag[nw] == nw && hw_tag[old] == nw && tags_ok());
        {
            uint8_t nn[12] = {0}, pt[1];
            check("... a keepalive confirms the session to the responder (counter 0, new keys)",
                  tx_n == tx0 + 1 && tx_len[tx0] == WG_MSG_KEEPALIVE_LEN && le32(tx_msg[tx0] + 4) == 0x6666
                  && le32(tx_msg[tx0] + 8) == 0 && hw_send_cnt[nw] == 1
                  && chacha20poly1305_decrypt(pt, r.recv_key, nn, tx_msg[tx0] + 16, 0, tx_msg[tx0] + 16, NULL, 0) == 0);
        }
        check("pending handshake: its slot wiped and free",
              !wg_peer(1)->hs && !wg_peer_hs(1) && wg_hs_free() == WG_HS_SLOTS);
        // F1: the keepalive lost. The responder still sends on the old keys:
        // the keepalive again (REKEY_TIMEOUT after the first), until data
        // comes on the new entry
        rtc_host_advance_ms(2 * REKEY_TIMEOUT_MS);
        wg_session_timers();
        check("idle 10 s after the switch: the old entry kept, no keepalive again (nothing on the old keys)",
              wg_peer(1)->prev.entry == old && table_set[old] && tx_n == tx0 + 1
              && (wg_peer(1)->tm & WG_TM_CONFIRM));
        hw_recv_cnt[old]++;  // the responder sends on the old keys: our keepalive was lost
        poll();
        {
            uint8_t nn[12] = {0}, pt[1];
            nn[4] = 1;
            check("... data on the old keys: the confirmation keepalive again (counter 1, new keys)",
                  tx_n == tx0 + 2 && tx_len[tx0 + 1] == WG_MSG_KEEPALIVE_LEN
                  && le32(tx_msg[tx0 + 1] + 4) == 0x6666 && le32(tx_msg[tx0 + 1] + 8) == 1
                  && chacha20poly1305_decrypt(pt, r.recv_key, nn, tx_msg[tx0 + 1] + 16, 0,
                                              tx_msg[tx0 + 1] + 16, NULL, 0) == 0);
        }
        hw_recv_cnt[old]++;
        poll();
        check("... not again before REKEY_TIMEOUT", tx_n == tx0 + 2);
        rtc_host_advance_ms(REKEY_TIMEOUT_MS);
        hw_recv_cnt[old]++;
        wg_session_timers();
        check("... lost again, the responder still on the old keys: again after REKEY_TIMEOUT",
              tx_n == tx0 + 3 && le32(tx_msg[tx0 + 2] + 8) == 2);
        hw_recv_cnt[nw] = 0; hw_recv_win[nw] = 1;  // it got that one: its data on the new entry
        poll();
        check("... data on the new entry: confirmed, no more retries", !(wg_peer(1)->tm & WG_TM_CONFIRM));
        hw_recv_cnt[old]++;  // late on the old keys
        rtc_host_advance_ms(REKEY_TIMEOUT_MS);
        wg_session_timers();
        check("... late data on the old keys then sends nothing", tx_n == tx0 + 3 && wg_peer(1)->prev.entry == old);
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
              && out_len == WG_MSG_RESP_LEN && installs == before + 1 && table[next_of(1)].remote_id == 0x7777);
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
        check("an unconfirmed responder session blocks our initiation for REKEY_TIMEOUT",
              wg_session_initiate(1, m1, &dst) == -1 && wg_peer(1)->next.state == WG_KP_PENDING);
        rtc_host_advance_ms(REKEY_TIMEOUT_MS);
        check("... then we initiate, in its entry (reserved for ours now)", wg_session_initiate(1, m1, &dst) == 0
              && wg_peer(1)->next.state == WG_KP_RESERVED && (le32(m1 + 4) & 63) == (uint32_t)next_of(1));
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

        // F2: the responder session our initiation took over still has its
        // keys; the peer's data on it confirms it (and ends our attempt)
        int cv = next_of(1), old = cur_of(1);
        check("the taken-over entry keeps the peer's session", wg_peer(1)->next.state == WG_KP_RESERVED
              && table_set[cv] && table[cv].remote_id == 0x7777 && wg_peer(1)->hs);
        hw_recv_cnt[cv] = 0; hw_recv_win[cv] = 1;  // the peer's first data on it
        poll();
        check("... data on it: confirmed, not cleared; the routes switch to it",
              cur_of(1) == cv && hw_route[0] == cv && table_set[cv] && table[cv].remote_id == 0x7777
              && wg_peer(1)->prev.entry == old && wg_peer(1)->next.entry == 0 && wg_peer(1)->live
              && !(wg_peer(1)->tm & WG_TM_INITIATOR) && tags_ok());
        check("... our attempt over, its slot free", !wg_peer(1)->hs && !(wg_peer(1)->tm & WG_TM_ATTEMPT)
              && wg_hs_free() == WG_HS_SLOTS);
    }

    // 4c. load detection (#81): more than WG_LOAD_MAX messages with a valid
    // mac1 in a second put us under load, for 1 s after the last such one
    {
        uint8_t tsn[12]; memcpy(tsn, ts1, 12); tsn[7] = 10;  // newer than any above
        wg_handshake_t t;
        wg_cookie_t pc;  // the peer's cookie state for us, none yet
        wg_cookie_init(&pc, dev_pub);
#define PEER_INIT(index)                                                         \
        do {                                                                     \
            memset(&t, 0, sizeof(t));                                            \
            memcpy(t.remote_static, dev_pub, 32); memcpy(t.psk, psk, 32);        \
            tsn[7]++;                                                            \
            wg_create_initiation(&peer, &t, (index), e, tsn, m1);                \
        } while (0)
#define RX(m) wg_session_rx((m), sizeof(m), &src, out, &out_len, &dst)
        check("WG_LOAD_MAX from the handshake cost: 2 a second", WG_LOAD_MAX == 2);
        wg_set_time((uint64_t)wg_now_seconds() + 2);  // 1 .. 4b long ago
        wg_set_load_mode(WG_LOAD_AUTO);
        check("auto, idle: not under load", !wg_under_load());
        uint32_t hits = wg_stats()->load_hits;
        PEER_INIT(0x8001);
        check("1st initiation answered", RX(m1) == 0 && out_len == WG_MSG_RESP_LEN);
        PEER_INIT(0x8002);
        check("2nd initiation answered, not under load",
              RX(m1) == 0 && out_len == WG_MSG_RESP_LEN && !wg_under_load());
        PEER_INIT(0x8003);
        wg_cookie_add_mac2(&pc, m1, sizeof(m1));  // no cookie: mac2 zeros, mac1 kept
        check("3rd in a second: under load, a cookie reply",
              RX(m1) == 0 && out_len == WG_MSG_COOKIE_LEN && wg_under_load()
              && wg_stats()->load_hits == hits + 1);
        check("peer takes the cookie", wg_cookie_consume_reply(&pc, out, WG_MSG_COOKIE_LEN) == 0);
        PEER_INIT(0x8004);
        check("under load, no mac2: a cookie reply", RX(m1) == 0 && out_len == WG_MSG_COOKIE_LEN);
        PEER_INIT(0x8005);
        check("... with a valid mac2", wg_cookie_add_mac2(&pc, m1, sizeof(m1)) == 1);
        check("under load, valid mac2: answered", RX(m1) == 0 && out_len == WG_MSG_RESP_LEN
              && table[next_of(1)].remote_id == 0x8005);
        check("still under load", wg_under_load());
        wg_set_time((uint64_t)wg_now_seconds() + 1);  // the flood stops: 1 s later
        check("1 s after the flood: not under load", !wg_under_load());
        PEER_INIT(0x8006);
        check("... no mac2 answered again", RX(m1) == 0 && out_len == WG_MSG_RESP_LEN);

        // wg load off: the rate is still counted, but no cookies
        wg_set_load_mode(WG_LOAD_OFF);
        hits = wg_stats()->load_hits;
        int answered = 0;
        for (int i = 0; i < 4; i++) {
            PEER_INIT(0x8010 + i);
            answered += RX(m1) == 0 && out_len == WG_MSG_RESP_LEN;
        }
        check("wg load off: a flood without mac2 is answered, no cookie replies",
              answered == 4 && !wg_under_load() && wg_stats()->load_hits > hits);
        wg_set_load_mode(WG_LOAD_AUTO);
        check("... back to auto: under load (the flood)", wg_under_load());
        wg_set_load_mode(WG_LOAD_ON);
        wg_set_time((uint64_t)wg_now_seconds() + 2);
        PEER_INIT(0x8020);
        check("wg load on, idle: a cookie reply", wg_under_load() && RX(m1) == 0
              && out_len == WG_MSG_COOKIE_LEN);
        wg_set_load_mode(WG_LOAD_OFF);

        // the X25519 calls: an unknown static key costs one, not two
        memset(&t, 0, sizeof(t));
        memcpy(t.remote_static, dev_pub, 32);
        tsn[7]++;
        wg_create_initiation(&other, &t, 0x8030, e, tsn, m1);
        int dh0 = x_dh, pub0 = x_pub;
        uint32_t unk = wg_stats()->drop_unknown;
        check("unknown static key refused", RX(m1) == -1 && wg_stats()->drop_unknown == unk + 1);
        check("... after one X25519 (no DH(s_i, s_r))", x_dh - dh0 == 1 && x_pub - pub0 == 0);
        PEER_INIT(0x8031);
        dh0 = x_dh; pub0 = x_pub;
        check("a peer's initiation answered", RX(m1) == 0 && out_len == WG_MSG_RESP_LEN);
        check("... with 4 X25519, not 5 (static-static cached)", x_dh - dh0 == 3 && x_pub - pub0 == 1);
        rtc_host_advance_ms(REKEY_TIMEOUT_MS);  // the last answer unconfirmed: ours replaces it
        dh0 = x_dh; pub0 = x_pub;
        check("our initiation: 2 X25519, not 3", wg_session_initiate(1, m1, &dst) == 0
              && x_dh - dh0 == 1 && x_pub - pub0 == 1);
        {
            wg_handshake_t r; memset(&r, 0, sizeof(r));
            check("... the peer accepts it (the cached DH is the right one)",
                  wg_consume_initiation(&peer, &r, m1, is, ts) == 0 && memcmp(is, dev_pub, 32) == 0);
            wg_handshake_wipe(&r);
        }
        uint8_t ss[32];
        check("static-static = the peer's DH", wg_static_static(&peer, dev_pub, ss) == 0
              && memcmp(ss, wg_peer(1)->ss, 32) == 0);
        uint8_t zero_pub[32] = {0};
        check("a low-order key: static-static refused, zeros",
              wg_static_static(&peer, zero_pub, ss) == -1 && ss[0] == 0 && ss[31] == 0);
#undef PEER_INIT
#undef RX
    }

    // 5. the peer lookup (a search of the public keys), a peer is removed
    int n2 = wg_peer_add(other.pub, NULL, NULL);
    check("a second peer; both found by their keys (added again: refused)", n2 > 1
          && wg_peer_add(peer.pub, NULL, NULL) == -1 && wg_peer_add(other.pub, NULL, NULL) == -1);
    hw_busy = 1;
    check("remove refused while the data plane is busy", wg_peer_remove(1) == -1 && wg_peer(1));
    hw_busy = 0;
    check("removed: its entries cleared and back in the pool, its route to entry 0",
          wg_peer_remove(1) == 0 && !wg_peer(1) && !table_set[1] && !table_set[2] && hw_route[0] == 0
          && wg_route_peer(0) == 0 && wg_pool_free() == 62);  // 8 adds its key again
    check("... its tags 0", hw_tag[1] == 0 && hw_tag[2] == 0 && tags_ok());

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

    // 8. the timers (#80), on the fake clock and the fake counters
    {
        tm_peer = wg_peer_add(peer.pub, psk, &src);
        int tn  = tm_peer;
        check("timers: the peer again, with its endpoint", tn > 0);
        const wg_peer_t *p = wg_peer(tn);
        wg_handshake_t r; memset(&r, 0, sizeof(r));
        uint8_t e2[32]; key(e2, 0x61);
        check("we initiate", wg_session_initiate(tn, m1, &dst) == 0 && (p->tm & WG_TM_ATTEMPT));
        check("... the peer answers", wg_consume_initiation(&peer, &r, m1, is, ts) == 0
              && (memcpy(r.psk, psk, 32), wg_create_response(&r, 0x9001, e2, m2) == 0));
        check("... we take it: live, we initiated, no attempt",
              wg_session_rx(m2, sizeof(m2), &src, out, &out_len, &dst) == 0 && p->live
              && (p->tm & WG_TM_INITIATOR) && !(p->tm & WG_TM_ATTEMPT));
        check("... our copy of the send key = the entry's", memcmp(p->cur.send_key, table[cur_of(tn)].send_key, 32) == 0
              && cur_of(tn) == 1 && next_of(tn) == 0 && tx_len[tx_n - 1] == WG_MSG_KEEPALIVE_LEN);

        int tx0 = tx_n;
        run_ms(30000, 0, 0);
        check("idle both ways 30 s: nothing sent, no keepalive due", tx_n == tx0 && !(p->tm & WG_TM_KA));

        // keepalive: data received, nothing sent for KEEPALIVE_TIMEOUT
        hw_send_cnt[cur_of(tn)] = 7;  // 7 packets out earlier
        run_ms(250, 0, 0);
        hw_recv_cnt[cur_of(tn)] = 3; hw_recv_win[cur_of(tn)] = 0xF;
        run_ms(250, 0, 0);
        check("data in: keepalive timer armed", (p->tm & WG_TM_KA) && (p->tm & WG_TM_RECV));
        tx0 = tx_n;
        uint32_t ka0 = wg_stats()->keepalive_tx;
        run_ms(9500, 0, 0);
        check("no keepalive before 10 s", tx_n == tx0);
        run_ms(750, 0, 0);
        check("keepalive after 10 s of receive-only", tx_n == tx0 + 1 && tx_len[tx0] == WG_MSG_KEEPALIVE_LEN
              && tx_msg[tx0][0] == WG_MSG_DATA && le32(tx_msg[tx0] + 4) == 0x9001
              && memcmp(&tx_dst, &src, sizeof(src)) == 0);
        {
            uint64_t c = 0;
            for (int i = 0; i < 8; i++) c |= (uint64_t)tx_msg[tx0][8 + i] << (8 * i);
            check("... its counter from send_cnt (7), send_cnt now 8", c == 7 && hw_send_cnt[cur_of(tn)] == 8);
            uint8_t nn[12] = {0}, pt[1];
            for (int i = 0; i < 8; i++) nn[4 + i] = (uint8_t)(c >> (8 * i));
            check("... the peer's receive key opens it (empty payload)",
                  chacha20poly1305_decrypt(pt, r.recv_key, nn, tx_msg[tx0] + 16, 0, tx_msg[tx0] + 16, NULL, 0) == 0);
        }
        run_ms(15000, 0, 0);
        check("one keepalive only, and no handshake after it", tx_n == tx0 + 1 && wg_stats()->keepalive_tx == ka0 + 1);
        run_ms(250, 1, 1);
        run_ms(11000, 0, 0);
        check("in and out in one poll: no keepalive", tx_n == tx0 + 1);

        // rekey: the initiator sends and the session is REKEY_AFTER_TIME old
        run_ms(REKEY_AFTER_TIME_MS - 1000 - age_ms(), 1, 1);
        check("traffic both ways to 119 s: no rekey", tx_n == tx0 + 1 && wg_stats()->rekeys == 0);
        run_ms(1500, 1, 1);
        int i0 = tx0 + 1;
        check("sending at 120 s: a rekey, message 1", tx_n == i0 + 1 && is_init(i0) && wg_stats()->rekeys == 1
              && (p->tm & WG_TM_ATTEMPT) && p->live);
        uint32_t t_att = p->t_attempt;

        // no answer: retransmits after REKEY_TIMEOUT + jitter; reject at 180 s
        run_ms(REJECT_AFTER_TIME_MS - 500 - age_ms(), 0, 0);
        check("179.5 s: the keys still in the data plane", table_set[cur_of(tn)] && p->live);
        run_ms(1000, 0, 0);
        check("180 s: keys rejected, the entry cleared in place", !table_set[cur_of(tn)] && !p->live && cur_of(tn) == 1
              && (p->tm & WG_TM_REJECTED) && wg_stats()->rejected == 1);
        {
            uint8_t z[32] = {0};
            check("... our copy of the send key wiped", memcmp(p->cur.send_key, z, 32) == 0);
        }
        run_ms(REKEY_ATTEMPT_TIME_MS - 500 - (wg_timer_ms() - t_att), 0, 0);
        check("89.5 s into the attempt: still trying", (p->tm & WG_TM_ATTEMPT) != 0);
        int ok = 1, retx = tx_n - i0 - 1;
        for (int i = i0 + 1; i < tx_n; i++) {
            uint32_t d = tx_at[i] - tx_at[i - 1];
            ok &= is_init(i) && d >= REKEY_TIMEOUT_MS && d <= REKEY_TIMEOUT_MS + REKEY_JITTER_MS + 300;
            ok &= memcmp(tx_msg[i] + 4, tx_msg[i - 1] + 4, 4) != 0;  // a new initiation each time
        }
        check("retransmits every 5 s + 0 .. 333 ms, each a new message 1", ok && retx >= 15 && retx <= 18
              && wg_stats()->retransmits == (uint32_t)retx && p->retries == retx);
        run_ms(1000, 0, 0);
        check("90 s: gave up", !(p->tm & WG_TM_ATTEMPT) && (p->tm & WG_TM_GAVE_UP)
              && wg_stats()->gave_up == 1 && !p->hs && wg_hs_free() == WG_HS_SLOTS);
        tx0 = tx_n;
        run_ms(20000, 0, 0);
        check("... then nothing sent; the entry reserved for the attempt back in the pool",
              tx_n == tx0 && next_of(tn) == 0 && wg_pool_free() == 61);

        // data to it with no keys: a handshake; the peer, under load, sends
        // a cookie reply; the retransmit carries mac2
        uint32_t ip0 = wg_stats()->in_place;
        hw_send_cnt[cur_of(tn)] = 1;
        run_ms(250, 0, 0);
        check("data with no keys: a new attempt", tx_n == tx0 + 1 && is_init(tx0)
              && (p->tm & WG_TM_ATTEMPT) && !(p->tm & WG_TM_GAVE_UP));
        wg_cookie_checker_t pchk;
        wg_cookie_checker_init(&pchk, peer.pub);
        const uint8_t dev_ip[4] = {10, 0, 0, 2};
        check("peer under load wants a cookie",
              wg_cookie_validate(&pchk, tx_msg[tx0], WG_MSG_INIT_LEN, dev_ip, 51820, 1) == WG_COOKIE_SEND_REPLY);
        uint8_t c3[WG_MSG_COOKIE_LEN];
        wg_cookie_create_reply(&pchk, c3, tx_msg[tx0], WG_MSG_INIT_LEN, dev_ip, 51820);
        check("we take its cookie reply, send nothing now",
              wg_session_rx(c3, sizeof(c3), &src, out, &out_len, &dst) == 0 && out_len == 0 && tx_n == tx0 + 1);
        run_ms(REKEY_TIMEOUT_MS + REKEY_JITTER_MS + 250, 0, 0);
        check("the retransmit after 5 s + jitter carries a mac2 the peer accepts", tx_n == tx0 + 2
              && is_init(tx0 + 1) && tx_at[tx0 + 1] - tx_at[tx0] >= REKEY_TIMEOUT_MS
              && wg_cookie_validate(&pchk, tx_msg[tx0 + 1], WG_MSG_INIT_LEN, dev_ip, 51820, 1) == WG_COOKIE_OK);
        memset(&r, 0, sizeof(r));
        take_busy = 1;  // F1: the confirmation keepalive's counter does not drain
        check("... the peer answers it",
              wg_consume_initiation(&peer, &r, tx_msg[tx0 + 1], is, ts) == 0
              && (memcpy(r.psk, psk, 32), wg_create_response(&r, 0x9002, e2, m2) == 0)
              && wg_session_rx(m2, sizeof(m2), &src, out, &out_len, &dst) == 0);
        take_busy = 0;
        check("... the confirmation keepalive did not go out (no drain)", tx_n == tx0 + 2
              && (p->tm & WG_TM_CONF_DUE));
        run_ms(1500, 0, 0);
        check("... sent at the poll after WG_HW_RETRY_MS", tx_n == tx0 + 3
              && tx_len[tx0 + 2] == WG_MSG_KEEPALIVE_LEN && le32(tx_msg[tx0 + 2] + 4) == 0x9002
              && !(p->tm & WG_TM_CONF_DUE));
        check("... live again in place (no keys to keep: no switch), the attempt over", p->live && table_set[cur_of(tn)]
              && table[cur_of(tn)].remote_id == 0x9002 && !(p->tm & (WG_TM_ATTEMPT | WG_TM_REJECTED))
              && wg_stats()->in_place == ip0);
        tx0 = tx_n;
        run_ms(REJECT_AFTER_TIME_MS - 17000 - age_ms(), 0, 0);
        check("a new session idle to 163 s: nothing sent, keys kept", tx_n == tx0 && table_set[cur_of(tn)]);

        // F3: the receive rekey at 165 s, refused (the peer's initiation
        // just answered waits for confirmation): retried, not lost
        {
            wg_handshake_t q; memset(&q, 0, sizeof(q));
            uint8_t tsq[12]; memcpy(tsq, ts1, 12); tsq[7] = 0x70;
            memcpy(q.remote_static, dev_pub, 32); memcpy(q.psk, psk, 32);
            wg_create_initiation(&peer, &q, 0x9004, e, tsq, m1);
            run_ms(REJECT_AFTER_TIME_MS - 15000 - 250 - age_ms(), 0, 0);
            check("at 164.75 s the peer initiates: answered, pending",
                  wg_session_rx(m1, sizeof(m1), &src, out, &out_len, &dst) == 0
                  && p->next.state == WG_KP_PENDING && p->live);
            wg_handshake_wipe(&q);
            uint32_t rk = wg_stats()->rekeys;
            tx0 = tx_n;
            run_ms(500, 0, 1);  // data in at 165 s
            check("data in at 165 s: the receive rekey refused (a session under 5 s pending)",
                  age_ms() >= REJECT_AFTER_TIME_MS - 15000 && last_init(p->next.entry, tx0) < 0
                  && !(p->tm & WG_TM_RXREKEY) && wg_stats()->rekeys == rk);
            run_ms(REKEY_TIMEOUT_MS + 500, 0, 1);
            check("... retried on data in after it: message 1, the event done",
                  last_init(p->next.entry, tx0) >= 0 && (p->tm & WG_TM_RXREKEY) && (p->tm & WG_TM_ATTEMPT)
                  && wg_stats()->rekeys == rk + 1);
            check("... in the pending session's entry, its keys kept (F2)",
                  p->next.state == WG_KP_RESERVED && table_set[p->next.entry]
                  && table[p->next.entry].remote_id == 0x9004);
        }

        // the responder never rekeys on time; a persistent keepalive
        wg_peer_set_keepalive(tn, 25);
        run_ms(REJECT_AFTER_TIME_MS + 1000 - age_ms(), 0, 0);  // 180 s: rejected
        memset(&r, 0, sizeof(r));
        uint8_t tsr[12]; memcpy(tsr, ts1, 12); tsr[7] = 0x7F;  // newer than any above
        memcpy(r.remote_static, dev_pub, 32); memcpy(r.psk, psk, 32);
        wg_create_initiation(&peer, &r, 0x9003, e, tsr, m1);
        tx0 = tx_n;
        check("the peer initiates: we answer, the session waits for confirmation",
              wg_session_rx(m1, sizeof(m1), &src, out, &out_len, &dst) == 0
              && out_len == WG_MSG_RESP_LEN && !p->live && p->next.state == WG_KP_PENDING);
        int rej = cur_of(tn);
        hw_recv_win[next_of(tn)] = 1;
        run_ms(250, 0, 0);
        check("... its first data confirms it: live, we did not initiate, the rejected entry freed",
              p->live && !(p->tm & WG_TM_INITIATOR) && cur_of(tn) != rej && wg_pool_free() == 61);
        run_ms(REKEY_AFTER_TIME_MS + 5000, 1, 1);
        check("responder sending at 125 s: no rekey", wg_stats()->rekeys == 2 && tx_n == tx0);
        uint32_t ka = wg_stats()->keepalive_tx;
        run_ms(24000, 0, 0);
        check("persistent keepalive: none before 25 s", wg_stats()->keepalive_tx == ka);
        run_ms(1500, 0, 0);
        check("... one at 25 s without a packet", wg_stats()->keepalive_tx == ka + 1
              && tx_len[tx_n - 1] == WG_MSG_KEEPALIVE_LEN);
        wg_handshake_wipe(&r);
    }

    // 9. the session pool full (#85): 63 peers, all with sessions; a rekey
    // then goes in place (counted); a free entry makes it overlap again
    {
        static wg_identity_t pi[WG_PEERS];
        uint8_t k[32], e2[32];
        key(e2, 0x62);
        wg_session_init();
        wg_set_private(dev_priv);
        wg_set_load_mode(WG_LOAD_OFF);  // 63 handshakes at once
        memset(table_set, 0, sizeof(table_set));
        memset(hw_tag, 0, sizeof(hw_tag));
        memset(hw_route, 0, sizeof(hw_route));
        int ok = 1;
        for (int i = 1; i < WG_PEERS; i++) {
            key(k, 0x40 + i);
            wg_identity_init(&pi[i], k);
            ok &= wg_peer_add(pi[i].pub, NULL, &src) == i && cur_of(i) == i;
            ok &= wg_route_set(i - 1, i) == i;
            hw_route[i - 1] = i;
        }
        key(k, 0x20);
        wg_identity_t x;
        wg_identity_init(&x, k);
        check("63 peers, each with its current entry; the pool empty, a 64th refused",
              ok && wg_pool_free() == 0 && wg_peer_add(x.pub, NULL, NULL) == -1);
        // we initiate to 1 .. 62 (no keys yet: into the current entry, not
        // a fallback); 63 initiates to us (the pool empty: in place, counted)
        int live = 0;
        for (int i = 1; i < WG_PEERS - 1; i++) {
            wg_handshake_t r; memset(&r, 0, sizeof(r));
            live += wg_session_initiate(i, m1, &dst) == 0 && (le32(m1 + 4) & 63) == (uint32_t)i
                    && wg_consume_initiation(&pi[i], &r, m1, is, ts) == 0
                    && wg_create_response(&r, 0xA000 + i, e2, m2) == 0
                    && wg_session_rx(m2, sizeof(m2), &src, out, &out_len, &dst) == 0
                    && wg_peer(i)->live && table[i].remote_id == 0xA000u + i;
            wg_handshake_wipe(&r);
        }
        {
            wg_handshake_t r; memset(&r, 0, sizeof(r));
            memcpy(r.remote_static, dev_pub, 32);
            wg_create_initiation(&pi[63], &r, 0xA03F, e, ts1, m1);
            live += wg_session_rx(m1, sizeof(m1), &src, out, &out_len, &dst) == 0 && wg_peer(63)->live
                    && cur_of(63) == 63 && (le32(out + 4) & 63) == 63;
            wg_handshake_wipe(&r);
        }
        ok = 1;
        for (int i = 1; i < WG_PEERS; i++) ok &= hw_route[i - 1] == i && table_set[i];
        check("all 63 peers live, each in its own entry, its route on it", live == 63 && ok);
        check("... 63 as responder with the pool empty: in place, counted", wg_stats()->in_place == 1);

        // a rekey with the pool full: in place over the live entry
        wg_handshake_t r; memset(&r, 0, sizeof(r));
        uint32_t sw = wg_stats()->switches;
        check("rekey of peer 1, pool full: message 1 names its current entry",
              wg_session_initiate(1, m1, &dst) == 0 && (le32(m1 + 4) & 63) == 1 && next_of(1) == 0);
        check("... message 2: the keys over entry 1, counted, no switch",
              wg_consume_initiation(&pi[1], &r, m1, is, ts) == 0 && wg_create_response(&r, 0xB001, e2, m2) == 0
              && wg_session_rx(m2, sizeof(m2), &src, out, &out_len, &dst) == 0 && table[1].remote_id == 0xB001
              && hw_route[0] == 1 && wg_stats()->in_place == 2 && wg_stats()->switches == sw);
        check("... its tag stays 1", hw_tag[1] == 1 && tags_ok());
        wg_handshake_wipe(&r);

        // one peer removed: the next rekey overlaps again
        check("peer 63 removed: its entry free", wg_peer_remove(63) == 0 && wg_pool_free() == 1
              && hw_route[62] == 0 && !table_set[63]);
        memset(&r, 0, sizeof(r));
        check("rekey of peer 1: a next entry (63), the switch on message 2",
              wg_session_initiate(1, m1, &dst) == 0 && next_of(1) == 63
              && wg_consume_initiation(&pi[1], &r, m1, is, ts) == 0 && wg_create_response(&r, 0xB002, e2, m2) == 0
              && wg_session_rx(m2, sizeof(m2), &src, out, &out_len, &dst) == 0
              && hw_route[0] == 63 && cur_of(1) == 63 && wg_peer(1)->prev.entry == 1 && table_set[1]
              && wg_pool_free() == 0 && wg_stats()->in_place == 2);
        check("... both entries tagged 63 (the routes' entry)", hw_tag[63] == 63 && hw_tag[1] == 63 && tags_ok());
        wg_handshake_wipe(&r);
        rtc_host_advance_ms(2 * REKEY_TIMEOUT_MS);
        wg_session_timers();
        check("... the old entry kept 10 s without data: the pool still empty",
              wg_peer(1)->prev.entry == 1 && table_set[1] && wg_pool_free() == 0);
        memset(&r, 0, sizeof(r));
        uint32_t rt = wg_stats()->retired;
        check("rekey of peer 2, the pool empty: peer 1's old entry (1) reclaimed, an overlap, not in place",
              wg_session_initiate(2, m1, &dst) == 0 && next_of(2) == 1 && (le32(m1 + 4) & 63) == 1
              && wg_peer(1)->prev.entry == 0 && wg_stats()->retired == rt + 1
              && wg_consume_initiation(&pi[2], &r, m1, is, ts) == 0 && wg_create_response(&r, 0xB003, e2, m2) == 0
              && wg_session_rx(m2, sizeof(m2), &src, out, &out_len, &dst) == 0
              && cur_of(2) == 1 && wg_peer(2)->prev.entry == 2 && hw_route[1] == 1
              && wg_stats()->in_place == 2 && tags_ok());
        wg_handshake_wipe(&r);
        // the old entry at its REJECT_AFTER_TIME (the session of 9's start)
        tm_peer = 2;
        run_ms(REJECT_AFTER_TIME_MS + 500 - (wg_timer_ms() - wg_peer(2)->prev.t_start), 0, 0);
        check("peer 2's old entry retired at its REJECT_AFTER_TIME, its new session still live",
              wg_peer(2)->prev.entry == 0 && !table_set[2] && wg_peer(2)->live && table_set[1]);
        check("... after 65 handshakes all handshake slots free again", wg_hs_free() == WG_HS_SLOTS);
    }

    // 10. the handshake pool (WG_HS_SLOTS): each initiation of ours in
    // flight holds a slot. All busy: a new one waits for its retransmit
    // timer (counted); one to us is still answered (the responder needs no
    // slot). Every way out of an attempt frees its slot, wiped
    {
        enum { NP = WG_HS_SLOTS + 2 };  // 1 .. 8 take the slots, 9 waits, 10 initiates to us
        static wg_identity_t hp[NP + 1];
        uint8_t k[32], e2[32];
        key(e2, 0x63);
        wg_session_init();
        wg_set_private(dev_priv);
        wg_set_load_mode(WG_LOAD_OFF);
        memset(table_set, 0, sizeof(table_set));
        memset(hw_tag, 0, sizeof(hw_tag));
        memset(hw_route, 0, sizeof(hw_route));
        memset(hw_send_cnt, 0, sizeof(hw_send_cnt));
        memset(hw_recv_cnt, 0, sizeof(hw_recv_cnt));
        memset(hw_recv_win, 0, sizeof(hw_recv_win));
        tx_n = 0;
        int ok = 1;
        for (int i = 1; i <= NP; i++) {
            key(k, 0xA0 + i);
            wg_identity_init(&hp[i], k);
            ok &= wg_peer_add(hp[i].pub, NULL, &src) == i;
        }
        check("pool: 10 peers, all 8 handshake slots free", ok && wg_hs_free() == WG_HS_SLOTS);
        ok = 1;
        for (int i = 1; i <= WG_HS_SLOTS; i++) {
            ok &= wg_session_initiate(i, m1, &dst) == 0 && wg_peer_hs(i)
                  && wg_peer_hs(i)->state == WG_HS_INITIATED;
        }
        check("pool: 8 initiations in flight, one slot each, none free", ok && wg_hs_free() == 0);
        const int        w  = WG_HS_SLOTS + 1;
        const wg_peer_t *pw = wg_peer(w);
        uint32_t ti = wg_stats()->tx_init, busy = wg_stats()->hs_busy;
        check("pool full: a 9th initiation deferred (no message 1, counted), its attempt started",
              wg_session_initiate(w, m1, &dst) == -1 && !pw->hs && !wg_peer_hs(w)
              && wg_stats()->tx_init == ti && wg_stats()->hs_busy == busy + 1
              && (pw->tm & WG_TM_ATTEMPT) && next_of(w) == 0);
        {
            wg_handshake_t r; memset(&r, 0, sizeof(r));
            memcpy(r.remote_static, dev_pub, 32);
            wg_create_initiation(&hp[NP], &r, 0xC00A, e, ts1, m1);
            check("pool full: an initiation to us still answered (no slot needed)",
                  wg_session_rx(m1, sizeof(m1), &src, out, &out_len, &dst) == 0
                  && out_len == WG_MSG_RESP_LEN && wg_consume_response(&hp[NP], &r, out) == 0
                  && wg_peer(NP)->next.state == WG_KP_PENDING && !wg_peer(NP)->hs && wg_hs_free() == 0);
            wg_handshake_wipe(&r);
        }
        tm_peer = 1;
        run_ms(REKEY_TIMEOUT_MS + REKEY_JITTER_MS + 250, 0, 0);
        check("pool full at the retransmit: 8 resend, 9 waits again (counted), nothing to it",
              last_init(1, 0) >= 0 && last_init(8, 0) >= 0 && last_init(w, 0) < 0 && !pw->hs
              && wg_stats()->hs_busy == busy + 2 && (pw->tm & WG_TM_ATTEMPT));
        {
            wg_handshake_t r; memset(&r, 0, sizeof(r));
            int i1 = last_init(1, 0);
            check("peer 1 answers its retransmit: live, its slot freed",
                  i1 >= 0 && wg_consume_initiation(&hp[1], &r, tx_msg[i1], is, ts) == 0
                  && wg_create_response(&r, 0xC001, e2, m2) == 0
                  && wg_session_rx(m2, sizeof(m2), &src, out, &out_len, &dst) == 0
                  && wg_peer(1)->live && !wg_peer(1)->hs && wg_hs_free() == 1);
            wg_handshake_wipe(&r);
            memset(&r, 0, sizeof(r));
            memcpy(r.remote_static, dev_pub, 32);
            wg_create_initiation(&hp[2], &r, 0xC002, e, ts1, m1);
            check("peer 2 initiates to us mid-attempt: answered, our slot for it freed",
                  wg_session_rx(m1, sizeof(m1), &src, out, &out_len, &dst) == 0
                  && !wg_peer(2)->hs && !(wg_peer(2)->tm & WG_TM_ATTEMPT) && wg_hs_free() == 2);
            wg_handshake_wipe(&r);
        }
        {
            const uint8_t *s3 = (const uint8_t *)wg_peer_hs(3);
            ok = s3 && wg_peer_remove(3) == 0 && wg_hs_free() == 3;
            for (size_t i = 0; s3 && i < sizeof(wg_handshake_t); i++) ok &= s3[i] == 0;
            check("peer 3 removed mid-attempt: its slot freed and wiped", ok);
        }
        {
            wg_handshake_t r; memset(&r, 0, sizeof(r));
            int i4 = last_init(4, 0);
            ok = i4 >= 0 && wg_consume_initiation(&hp[4], &r, tx_msg[i4], is, ts) == 0
                 && wg_create_response(&r, 0xC004, e2, m2) == 0;
            uint8_t bad[WG_MSG_RESP_LEN]; memcpy(bad, m2, sizeof(bad)); bad[50] ^= 1;
            check("a corrupted message 2 to peer 4: dropped, its slot kept",
                  ok && wg_session_rx(bad, sizeof(bad), &src, out, &out_len, &dst) == -1
                  && wg_peer_hs(4) && wg_hs_free() == 3);
            wg_handshake_wipe(&r);
        }
        int tx0 = tx_n;
        run_ms(REKEY_TIMEOUT_MS + REKEY_JITTER_MS + 250, 0, 0);
        check("a slot free at its next retransmit: 9 takes it and sends message 1",
              last_init(w, tx0) >= 0 && wg_peer_hs(w) && wg_hs_free() == 2);
        uint32_t gu = wg_stats()->gave_up;
        run_ms(REKEY_ATTEMPT_TIME_MS, 0, 0);
        ok = 1;
        for (int i = 1; i <= NP; i++) ok &= !wg_peer(i) || (!wg_peer(i)->hs && !(wg_peer(i)->tm & WG_TM_ATTEMPT));
        check("REKEY_ATTEMPT_TIME: 4 .. 9 gave up, every slot free again",
              ok && wg_stats()->gave_up == gu + 6 && wg_hs_free() == WG_HS_SLOTS);
        uint32_t du = wg_stats()->drop_unknown;
        check("... a late message 2 to peer 4 finds no slot (dropped: unknown)",
              wg_session_rx(m2, sizeof(m2), &src, out, &out_len, &dst) == -1
              && wg_stats()->drop_unknown == du + 1);
    }

    check("the tags followed every install and route switch (each poll)", tag_bad == 0 && tags_ok());

    fprintf(stderr, "%s %d checks, %d failed\n", fails ? "FAIL" : "PASS", checks, fails);
    return fails;
}

// -----------------------------------------------------------------------------
// Project:     WireGuard-FPGA
// Description: NLnet-funded open-source implementation
// Funding:     https://nlnet.nl/project/KlusterLab-Wireguard (2023-12 to 2025-12)
// -----------------------------------------------------------------------------
