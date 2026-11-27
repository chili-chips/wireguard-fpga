// SPDX-FileCopyrightText: 2026 Chili.CHIPS
//
// SPDX-License-Identifier: BSD-3-Clause

//==========================================================================
// WireGuard sessions (wg_session.h): the responder and initiator around
// noise.c, the replay check on the initiation's timestamp, and the hand-over
// of the transport keys to the data plane (wg_hw_install).
//==========================================================================

#include "wg_session.h"
#include "peer_map.h"
#include "rtc.h"
#include "string_bare.h"

static wg_identity_t       id;
static wg_cookie_checker_t chk;   // our cookie keys and secret (responder side)
static int                 have_key, under_load;
static wg_peer_t     peers[WG_PEERS];
static wg_stats_t    st;

static uint32_t get32_le(const uint8_t *p) {
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8) | ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}

static int drop(uint32_t *counter) {
    (*counter)++;
    return -1;
}

// ---- set-up -----------------------------------------------------------------

void wg_session_init(void) {
    bare_wipe(&id, sizeof(id));
    bare_wipe(&chk, sizeof(chk));
    bare_wipe(peers, sizeof(peers));
    memset(&st, 0, sizeof(st));
    have_key   = 0;
    under_load = 0;
}

void wg_set_private(const uint8_t priv[WG_KEY_LEN]) {
    wg_identity_init(&id, priv);
    wg_cookie_checker_init(&chk, id.pub);  // also a new cookie secret
    have_key = 1;
}

int wg_has_private(void) { return have_key; }

const wg_identity_t *wg_identity(void) { return &id; }

int wg_peer_add(const uint8_t pub[WG_KEY_LEN], const uint8_t *psk, const wg_endpoint_t *ep) {
    if (have_key && memcmp(pub, id.pub, WG_KEY_LEN) == 0) return -1;  // ourselves
    if (peer_map_find(pub) >= 0) return -1;
    for (int n = 1; n < WG_PEERS; n++) {
        wg_peer_t *p = &peers[n];
        if (p->used) continue;
        if (peer_map_set(pub, (uint8_t)n) != 0) return -1;
        bare_wipe(p, sizeof(*p));
        p->used = 1;
        memcpy(p->pub, pub, WG_KEY_LEN);
        wg_cookie_init(&p->cookie, pub);
        if (psk) memcpy(p->psk, psk, WG_KEY_LEN);
        if (ep) {
            p->ep     = *ep;
            p->has_ep = 1;
        }
        return n;
    }
    return -1;
}

int wg_peer_remove(int n) {
    if (n < 1 || n >= WG_PEERS || !peers[n].used) return -1;
    if (wg_hw_install(n, NULL) != 0) return -1;  // its keys stay in the data plane
    peer_map_remove(peers[n].pub);
    bare_wipe(&peers[n], sizeof(peers[n]));
    return 0;
}

const wg_peer_t *wg_peer(int n) {
    return (n >= 1 && n < WG_PEERS && peers[n].used) ? &peers[n] : NULL;
}

void wg_peer_map_rebuild(void) {
    peer_map_init();
    for (int n = 1; n < WG_PEERS; n++) {
        if (peers[n].used) peer_map_set(peers[n].pub, (uint8_t)n);
    }
}

const wg_stats_t *wg_stats(void) { return &st; }

// ---- the clock ----------------------------------------------------------------
// The real-time clock (rtc.c, #30): it starts at boot from a high-water mark
// in the configuration flash, and is only set forward, so our timestamps grow
// also across a reboot and a peer's replay check never refuses them. The
// cookie ages (cookie.h) take its seconds too: a clock that is never set back
// cannot make a cookie or the cookie secret look new.

int  wg_set_time(uint64_t unix_seconds) { return rtc_set_time(unix_seconds); }
void wg_now_tai64n(uint8_t ts[WG_TAI64N_LEN]) { rtc_now_tai64n(ts); }
uint32_t wg_now_seconds(void) { return rtc_now_seconds(); }

// ---- messages -------------------------------------------------------------------

// Under load, a handshake message must carry a valid mac2 (a cookie from our
// cookie reply), else it gets a cookie reply instead of an answer. Detecting
// load (the handshakes per second, #4) is not done: wg_set_under_load only
int  wg_under_load(void) { return under_load; }
void wg_set_under_load(int on) { under_load = on != 0; }

// a new receiver index for peer n: random upper bits, n in the low 6, and
// not one of the peer's indices still in use
static uint32_t new_index(int n, uint32_t avoid1, uint32_t avoid2) {
    uint8_t  r[WG_KEY_LEN];
    uint32_t idx;
    do {
        wg_hw_random(r);
        idx = (get32_le(r) & ~(uint32_t)(WG_PEERS - 1)) | (uint32_t)n;
    } while (idx == avoid1 || idx == avoid2);
    bare_wipe(r, sizeof(r));
    return idx;
}

static void install_fill(wg_install_t *in, const wg_handshake_t *hs, const wg_endpoint_t *ep) {
    in->local_id  = hs->local_index;
    in->remote_id = hs->remote_index;
    memcpy(in->send_key, hs->send_key, WG_KEY_LEN);
    memcpy(in->recv_key, hs->recv_key, WG_KEY_LEN);
    in->remote = *ep;
}

static void went_live(wg_peer_t *p, const wg_install_t *in) {
    p->ep        = in->remote;  // roaming: the address the handshake came from
    p->has_ep    = 1;
    p->live      = 1;
    p->local_id  = in->local_id;
    p->remote_id = in->remote_id;
    st.sessions++;
}

// message 1: answer with message 2 and hand the keys to the data plane
static int rx_init(const uint8_t *msg, const wg_endpoint_t *src,
                   uint8_t *out, size_t *out_len, wg_endpoint_t *dst) {
    wg_handshake_t s;            // scratch: a peer's state changes only below
    wg_install_t   in;
    uint8_t        is[WG_KEY_LEN], ts[WG_TAI64N_LEN], e[WG_KEY_LEN];
    int            rc = -1, n;
    uint32_t       idx;
    wg_peer_t     *p;

    memset(&s, 0, sizeof(s));
    memset(&in, 0, sizeof(in));
    memset(e, 0, sizeof(e));
    if (wg_consume_initiation(&id, &s, msg, is, ts) != 0) return drop(&st.drop_bad);

    n = peer_map_find(is);
    p = (n >= 1 && n < WG_PEERS && peers[n].used) ? &peers[n] : NULL;
    if (!p) {
        drop(&st.drop_unknown);
        goto out;
    }
    // replay: TAI64N is big-endian, so a byte compare orders it
    if (memcmp(ts, p->last_ts, WG_TAI64N_LEN) <= 0) {
        drop(&st.drop_replay);
        goto out;
    }
    memcpy(s.psk, p->psk, WG_KEY_LEN);
    wg_hw_random(e);
    idx = new_index(n, p->local_id, p->hs.local_index);
    if (wg_create_response(&s, idx, e, out) != 0) {
        drop(&st.drop_bad);
        goto out;
    }
    wg_cookie_add_mac2(&p->cookie, out, WG_MSG_RESP_LEN);
    install_fill(&in, &s, src);
    if (wg_hw_install(n, &in) != 0) {  // no answer: the initiator retries
        drop(&st.drop_hw);
        goto out;
    }
    memcpy(p->last_ts, ts, WG_TAI64N_LEN);
    went_live(p, &in);
    st.rx_init++;
    st.tx_resp++;
    *out_len = WG_MSG_RESP_LEN;
    *dst     = *src;
    rc       = 0;
out:
    wg_handshake_wipe(&s);
    bare_wipe(&in, sizeof(in));
    bare_wipe(e, sizeof(e));
    return rc;
}

// message 2, the answer to our initiation: hand the keys to the data plane
static int rx_resp(const uint8_t *msg, const wg_endpoint_t *src) {
    wg_install_t in;
    uint32_t     r = get32_le(msg + 8);
    int          n = (int)(r & (WG_PEERS - 1));
    wg_peer_t   *p = &peers[n];

    if (n == 0 || !p->used || p->hs.state != WG_HS_INITIATED || p->hs.local_index != r) {
        return drop(&st.drop_unknown);
    }
    if (wg_consume_response(&id, &p->hs, msg) != 0) return drop(&st.drop_bad);  // hs kept

    install_fill(&in, &p->hs, src);
    int rc = wg_hw_install(n, &in);
    if (rc == 0) {
        went_live(p, &in);
        st.rx_resp++;
    } else {
        drop(&st.drop_hw);  // the handshake is used up: initiate again
    }
    wg_handshake_wipe(&p->hs);
    bare_wipe(&in, sizeof(in));
    return rc;
}

int wg_session_rx(const uint8_t *msg, size_t len, const wg_endpoint_t *src,
                  uint8_t *out, size_t *out_len, wg_endpoint_t *dst) {
    *out_len = 0;
    if (!have_key || len < 4 || (msg[1] | msg[2] | msg[3]) != 0) return drop(&st.drop_bad);
    if (msg[0] == WG_MSG_COOKIE) {
        // a cookie reply to our last message 1/2 to that peer: keep the
        // cookie for the next one (the retransmit), send nothing now
        if (len != WG_MSG_COOKIE_LEN) return drop(&st.drop_bad);
        int n = (int)(wg_cookie_reply_receiver(msg) & (WG_PEERS - 1));
        if (n == 0 || !peers[n].used) return drop(&st.drop_unknown);
        if (wg_cookie_consume_reply(&peers[n].cookie, msg, len) != 0) return drop(&st.drop_bad);
        st.cookie_rx++;
        return 0;
    }
    if (msg[0] != WG_MSG_INIT && msg[0] != WG_MSG_RESP) {
        return drop(&st.drop_bad);  // WG_MSG_DATA is the data plane's: never here
    }
    // mac1 always, and under load mac2 before any DH work (cookie.c)
    switch (wg_cookie_validate(&chk, msg, len, src->ip, src->port, wg_under_load())) {
        case WG_COOKIE_OK:
            break;
        case WG_COOKIE_SEND_REPLY:
            if (wg_cookie_create_reply(&chk, out, msg, len, src->ip, src->port) != 0) {
                return drop(&st.drop_bad);
            }
            *out_len = WG_MSG_COOKIE_LEN;
            *dst     = *src;
            st.cookie_tx++;
            return 0;
        default:
            return drop(&st.drop_bad);  // not message 1/2, or mac1 wrong
    }
    return msg[0] == WG_MSG_INIT ? rx_init(msg, src, out, out_len, dst) : rx_resp(msg, src);
}

int wg_session_initiate(int n, uint8_t msg[WG_MSG_INIT_LEN], wg_endpoint_t *dst) {
    uint8_t e[WG_KEY_LEN], ts[WG_TAI64N_LEN];

    if (!have_key || n < 1 || n >= WG_PEERS || !peers[n].used || !peers[n].has_ep) return -1;
    wg_peer_t *p = &peers[n];
    wg_handshake_wipe(&p->hs);
    memcpy(p->hs.remote_static, p->pub, WG_KEY_LEN);
    memcpy(p->hs.psk, p->psk, WG_KEY_LEN);
    uint32_t idx = new_index(n, p->local_id, 0);
    wg_hw_random(e);
    wg_now_tai64n(ts);
    int rc = wg_create_initiation(&id, &p->hs, idx, e, ts, msg);
    bare_wipe(e, sizeof(e));
    if (rc != 0) {
        wg_handshake_wipe(&p->hs);
        return -1;
    }
    wg_cookie_add_mac2(&p->cookie, msg, WG_MSG_INIT_LEN);  // a cookie under 115 s old
    *dst = p->ep;
    st.tx_init++;
    return 0;
}

// -----------------------------------------------------------------------------
// Project:     WireGuard-FPGA
// Description: NLnet-funded open-source implementation
// Funding:     https://nlnet.nl/project/KlusterLab-Wireguard (2023-12 to 2025-12)
// -----------------------------------------------------------------------------
