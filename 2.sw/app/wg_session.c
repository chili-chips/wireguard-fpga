// SPDX-FileCopyrightText: 2026 Chili.CHIPS
//
// SPDX-License-Identifier: BSD-3-Clause

//==========================================================================
// WireGuard sessions (wg_session.h): the responder and initiator around
// noise.c, the replay check on the initiation's timestamp, the hand-over
// of the transport keys to the data plane (wg_hw_install), and the session
// pool: which cryptokey table entry holds which session, where the routes
// point (#85).
//==========================================================================

#include "wg_session.h"
#include "rtc.h"
#include "string_bare.h"
#include "chacha20poly1305.h"

static wg_identity_t       id;
static wg_cookie_checker_t chk;   // our cookie keys and secret (responder side)
static int                 have_key;
static wg_peer_t     peers[WG_PEERS];
static wg_stats_t    st;

// the handshake pool (WG_HS_SLOTS, wg_session.h): slot i is peer
// hs_owner[i]'s initiation in flight (0: free, its state wiped)
static wg_handshake_t hs_slot[WG_HS_SLOTS];
static uint8_t        hs_owner[WG_HS_SLOTS];

// the session pool (#85): the free entries (bit e: entry e), whose peer
// each other entry is, and the peer each route leads to (0: not ours)
static uint64_t pool;
static uint8_t  owner[WG_ENTRIES];
static uint8_t  route_peer[WG_ROUTES];

// the load detector (wg_under_load): the arrival times, ms, of the last
// WG_LOAD_MAX handshake messages with a valid mac1 (a ring), and when the
// rate was last exceeded
static int      load_mode;           // WG_LOAD_*
static uint64_t load_t[WG_LOAD_MAX];
static uint32_t load_n, load_i;      // messages in the ring, the oldest's slot
static uint64_t load_hit;
static int      load_hit_set;

// the timers (#80): the clock jumps of wg_set_time (the timers do not see
// them), the last poll
static uint64_t clock_jump_ms;
static uint32_t tm_last;
static int      tm_started;

static uint32_t get32_le(const uint8_t *p) {
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8) | ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}

static void put64_le(uint8_t *p, uint64_t v) {
    for (int i = 0; i < 8; i++) p[i] = (uint8_t)(v >> (8 * i));
}

static uint64_t now_ms(void);
static int send_keepalive(wg_peer_t *p, uint32_t now);
static int retire_prev(wg_peer_t *p);
static void hw_failed(wg_peer_t *p, uint32_t now);

static int drop(uint32_t *counter) {
    (*counter)++;
    return -1;
}

// ---- the handshake pool -------------------------------------------------------

// peer n's slot (its own when it holds one, else a free one, wiped), or
// NULL when all are busy
static wg_handshake_t *hs_alloc(int n) {
    wg_peer_t *p = &peers[n];
    if (p->hs) return &hs_slot[p->hs - 1];
    for (int i = 0; i < WG_HS_SLOTS; i++) {
        if (!hs_owner[i]) {
            hs_owner[i] = (uint8_t)n;
            p->hs       = (uint8_t)(i + 1);
            return &hs_slot[i];
        }
    }
    return NULL;
}

// peer p's slot, if any, wiped and back to the pool
static void hs_free(wg_peer_t *p) {
    if (!p->hs) return;
    bare_wipe(&hs_slot[p->hs - 1], sizeof(wg_handshake_t));
    hs_owner[p->hs - 1] = 0;
    p->hs               = 0;
}

int wg_hs_free(void) {
    int f = 0;
    for (int i = 0; i < WG_HS_SLOTS; i++) f += !hs_owner[i];
    return f;
}

const wg_handshake_t *wg_peer_hs(int n) {
    return (n >= 1 && n < WG_PEERS && peers[n].used && peers[n].hs) ? &hs_slot[peers[n].hs - 1]
                                                                   : NULL;
}

// peer of public key pub, or 0. A plain search: 63 compares of 32 bytes,
// ~25 us, next to the 295 ms of a handshake (the keys are public: memcmp)
static int peer_find(const uint8_t pub[WG_KEY_LEN]) {
    for (int n = 1; n < WG_PEERS; n++) {
        if (peers[n].used && memcmp(peers[n].pub, pub, WG_KEY_LEN) == 0) return n;
    }
    return 0;
}

// ---- the session pool (#85) ---------------------------------------------------
// An entry is in the pool (its keys zero), or owned by one peer as its cur,
// next or prev. Entry 0 is never handed out: receiver index 0 never
// matches, its keys stay zero, so a route to it drops (a removed peer's)

// a free entry for peer n, the lowest first; 0 when the pool is empty
static int entry_alloc(int n) {
    for (int e = 1; e < WG_ENTRIES; e++) {
        if ((pool >> e) & 1) {
            pool &= ~(1ull << e);
            owner[e] = (uint8_t)n;
            return e;
        }
    }
    return 0;
}

// entry e back to the pool, its keys cleared first (zero: they are): 0, or
// -1 when the data plane did not drain (still owned)
static int entry_free(int e, int zero) {
    if (zero && wg_hw_install(e, NULL) != 0) return -1;
    pool |= 1ull << e;
    owner[e] = 0;
    return 0;
}

// a free entry for a new session of peer n. With the pool empty, an old
// entry (prev) is reclaimed first: peer n's own (its next switch would
// retire it anyway), else the one whose session is oldest; what is still in
// flight on it drops. 0 when there is none, or its pause did not drain
static int entry_get(int n) {
    int e = entry_alloc(n);
    if (e) return e;
    uint32_t now = wg_timer_ms();
    int      m   = peers[n].prev.entry ? n : 0;
    for (int k = 1; !peers[n].prev.entry && k < WG_PEERS; k++) {
        if (peers[k].used && peers[k].prev.entry &&
            (!m || now - peers[k].prev.t_start > now - peers[m].prev.t_start)) {
            m = k;
        }
    }
    if (!m) return 0;
    if (retire_prev(&peers[m]) != 0) {
        hw_failed(&peers[m], now);
        return 0;
    }
    return entry_alloc(n);
}

int wg_pool_free(void) {
    int f = 0;
    for (int e = 1; e < WG_ENTRIES; e++) f += (int)((pool >> e) & 1);
    return f;
}

// peer n's routes to entry e, and the peer tag of the entries in tags with
// them, all under one pause: 0, or -1 (none moved). The tag is what the
// AllowedIPs check after decryption compares with the source route's
// entry, so data on the peer's next or old entry passes too
static int routes_to(int n, int e, uint64_t t) {
    uint64_t m = 0;
    for (int r = 0; r < WG_ROUTES; r++) {
        if (route_peer[r] == n) m |= 1ull << r;
    }
    return (m | t) ? wg_hw_routes(m, t, e) : 0;
}

int wg_route_set(int r, int n) {
    if (r < 0 || r >= WG_ROUTES) return -1;
    if (n < 1 || n >= WG_PEERS || !peers[n].used) {
        route_peer[r] = 0;
        return -1;
    }
    route_peer[r] = (uint8_t)n;
    return peers[n].cur.entry;
}

int wg_route_peer(int r) { return (r >= 0 && r < WG_ROUTES) ? route_peer[r] : 0; }

// ---- set-up -----------------------------------------------------------------

void wg_session_init(void) {
    bare_wipe(&id, sizeof(id));
    bare_wipe(&chk, sizeof(chk));
    bare_wipe(peers, sizeof(peers));
    bare_wipe(hs_slot, sizeof(hs_slot));
    memset(hs_owner, 0, sizeof(hs_owner));
    memset(&st, 0, sizeof(st));
    memset(owner, 0, sizeof(owner));
    memset(route_peer, 0, sizeof(route_peer));
    pool         = ~1ull;  // 1 .. 63
    have_key     = 0;
    load_mode    = WG_LOAD_AUTO;
    load_n       = 0;
    load_i       = 0;
    load_hit_set = 0;
    tm_started   = 0;
}

void wg_set_private(const uint8_t priv[WG_KEY_LEN]) {
    wg_identity_init(&id, priv);
    wg_cookie_checker_init(&chk, id.pub);  // also a new cookie secret
    have_key = 1;
    // the static-static DH of each peer with the new key: one X25519 each
    // now, one less in every handshake later
    for (int n = 1; n < WG_PEERS; n++) {
        if (peers[n].used) wg_static_static(&id, peers[n].pub, peers[n].ss);
    }
}

int wg_has_private(void) { return have_key; }

const wg_identity_t *wg_identity(void) { return &id; }

int wg_peer_add(const uint8_t pub[WG_KEY_LEN], const uint8_t *psk, const wg_endpoint_t *ep) {
    if (have_key && memcmp(pub, id.pub, WG_KEY_LEN) == 0) return -1;  // ourselves
    if (peer_find(pub)) return -1;
    for (int n = 1; n < WG_PEERS; n++) {
        wg_peer_t *p = &peers[n];
        if (p->used) continue;
        int e = entry_alloc(n);  // its current entry: no keys yet
        if (!e) return -1;
        bare_wipe(p, sizeof(*p));
        p->used      = 1;
        p->cur.entry = (uint8_t)e;
        memcpy(p->pub, pub, WG_KEY_LEN);
        if (have_key) wg_static_static(&id, pub, p->ss);  // else at wg_set_private
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

// Its routes first, to entry 0: an entry of its back in the pool may be
// another peer's next. A step that does not drain leaves the rest for a retry
int wg_peer_remove(int n) {
    if (n < 1 || n >= WG_PEERS || !peers[n].used) return -1;
    wg_peer_t *p = &peers[n];
    if (routes_to(n, 0, 0) != 0) return -1;  // its keys stay (and their tags: never 0)
    for (int r = 0; r < WG_ROUTES; r++) {
        if (route_peer[r] == n) route_peer[r] = 0;
    }
    if (p->next.entry) {
        if (entry_free(p->next.entry, 1) != 0) return -1;
        p->next.entry = 0;
    }
    if (p->prev.entry) {
        if (entry_free(p->prev.entry, 1) != 0) return -1;
        p->prev.entry = 0;
    }
    if (entry_free(p->cur.entry, 1) != 0) return -1;
    hs_free(p);
    bare_wipe(p, sizeof(*p));
    return 0;
}

const wg_peer_t *wg_peer(int n) {
    return (n >= 1 && n < WG_PEERS && peers[n].used) ? &peers[n] : NULL;
}

const wg_stats_t *wg_stats(void) { return &st; }

// ---- the clock ----------------------------------------------------------------
// The real-time clock (rtc.c, #30): it starts at boot from a high-water mark
// in the configuration flash, and is only set forward, so our timestamps grow
// also across a reboot and a peer's replay check never refuses them. The
// cookie ages (cookie.h) take its seconds too: a clock that is never set back
// cannot make a cookie or the cookie secret look new.

// The timers (#80) run on wg_timer_ms(): the same clock less these jumps,
// so setting the clock does not age a session or fire a timer

int wg_set_time(uint64_t unix_seconds) {
    uint64_t t0 = now_ms();
    int      rc = rtc_set_time(unix_seconds);
    if (rc == 0) clock_jump_ms += now_ms() - t0;
    return rc;
}

// WG_TIME_SCALE: the co-simulation's end-to-end test (4.sim, WG_E2E=1) runs
// the timers and the load detection that many times faster (proto_ms), so
// REKEY_AFTER_TIME and the rest fit in simulated time; the timestamps and
// the cookie ages keep the real clock. Hardware builds: 1
#ifndef WG_TIME_SCALE
#define WG_TIME_SCALE 1
#endif
static uint64_t proto_ms(void) {
#if WG_TIME_SCALE == 1
    return now_ms();
#else
    uint64_t sec;
    uint32_t nsec;
    rtc_get(&sec, &nsec);
    return sec * 1000u * WG_TIME_SCALE + (uint64_t)nsec * WG_TIME_SCALE / 1000000u;
#endif
}
uint32_t wg_timer_ms(void) { return (uint32_t)(proto_ms() - clock_jump_ms * WG_TIME_SCALE); }
void wg_now_tai64n(uint8_t ts[WG_TAI64N_LEN]) { rtc_now_tai64n(ts); }
uint32_t wg_now_seconds(void) { return rtc_now_seconds(); }

// ---- messages -------------------------------------------------------------------

// Under load, a handshake message must carry a valid mac2 (a cookie from our
// cookie reply), else it gets a cookie reply instead of an answer. Load
// (#81, wg_session.h): more than WG_LOAD_MAX messages with a valid mac1 in
// WG_LOAD_WINDOW_MS, and WG_LOAD_AFTER_MS after the last time that was so.
// The cookie replies count too: a flood that gets them is still a flood. The
// clock is rtc.c's (ms, 64 bits: no wrap; proto_ms); setting it forward ends a
// load early

static uint64_t now_ms(void) {
    uint64_t sec;
    uint32_t nsec;
    rtc_get(&sec, &nsec);
    return sec * 1000u + nsec / 1000000u;
}

// one more handshake message with a valid mac1
static void load_count(void) {
    uint64_t now = proto_ms();
    // the ring full: its oldest entry and now are WG_LOAD_MAX + 1 messages
    if (load_n == WG_LOAD_MAX && now - load_t[load_i] < WG_LOAD_WINDOW_MS) {
        load_hit     = now;
        load_hit_set = 1;
        st.load_hits++;
    }
    load_t[load_i] = now;
    load_i         = (load_i + 1) % WG_LOAD_MAX;
    if (load_n < WG_LOAD_MAX) load_n++;
}

int wg_under_load(void) {
    if (load_mode != WG_LOAD_AUTO) return load_mode == WG_LOAD_ON;
    return load_hit_set && proto_ms() - load_hit < WG_LOAD_AFTER_MS;
}

void wg_set_load_mode(int mode) {
    load_mode = (mode == WG_LOAD_ON || mode == WG_LOAD_OFF) ? mode : WG_LOAD_AUTO;
}

int  wg_load_mode(void) { return load_mode; }
void wg_set_under_load(int on) { wg_set_load_mode(on ? WG_LOAD_ON : WG_LOAD_OFF); }

// a new receiver index for a session in entry e: random upper bits, e in
// the low 6, and not one of the indices still in use there
static uint32_t new_index(int e, uint32_t avoid1, uint32_t avoid2) {
    uint8_t  r[WG_KEY_LEN];
    uint32_t idx;
    do {
        wg_hw_random(r);
        idx = (get32_le(r) & ~(uint32_t)(WG_ENTRIES - 1)) | (uint32_t)e;
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

// a handshake finished: the peer's address (roaming), and no attempt of
// ours waits any more
static void handshake_done(wg_peer_t *p, const wg_endpoint_t *ep) {
    p->ep      = *ep;
    p->has_ep  = 1;
    p->t_hs    = wg_timer_ms();
    p->tm      = (uint16_t)((p->tm & ~(WG_TM_ATTEMPT | WG_TM_GAVE_UP)) | WG_TM_HS);
    p->retries = 0;
    st.sessions++;
}

// the session just installed in entry e (its counters are 0)
static void keypair_set(wg_keypair_t *k, int e, const wg_install_t *in, int state, int initiator) {
    bare_wipe(k, sizeof(*k));
    k->entry     = (uint8_t)e;
    k->state     = (uint8_t)state;
    k->initiator = (uint8_t)initiator;
    k->local_id  = in->local_id;
    k->remote_id = in->remote_id;
    memcpy(k->send_key, in->send_key, WG_KEY_LEN);  // the keepalives'
    k->t_start   = wg_timer_ms();
}

// cur is a new session: the routes send through it, its timers start
static void make_current(wg_peer_t *p, int initiator) {
    p->live = 1;
    p->tm   = (uint16_t)((p->tm & ~(WG_TM_KA | WG_TM_NH | WG_TM_REJECTED | WG_TM_RXREKEY |
                                    WG_TM_INITIATOR | WG_TM_CONFIRM | WG_TM_CONF_DUE)) |
                       (initiator ? WG_TM_INITIATOR : 0));
}

// a pause that did not drain: no table write for this peer for WG_HW_RETRY_MS
static int hw_waiting(const wg_peer_t *p, uint32_t now) {
    return (p->tm & WG_TM_HWFAIL) && now - p->t_hwfail < WG_HW_RETRY_MS;
}

static void hw_failed(wg_peer_t *p, uint32_t now) {
    p->t_hwfail = now;
    p->tm       = (uint16_t)(p->tm | WG_TM_HWFAIL);
}

// we initiated cur: a keepalive confirms it to the responder. Retried
// (WG_TM_CONF_DUE, peer_timers) while no data came on cur: when this one
// does not go out, or when the responder still sends on the old keys
static int confirm_start(wg_peer_t *p, uint32_t now) {
    p->tm     = (uint16_t)(p->tm | WG_TM_CONFIRM | WG_TM_CONF_DUE);
    p->t_conf = now - REKEY_TIMEOUT_MS;  // due at once
    return send_keepalive(p, now);       // it clears WG_TM_CONF_DUE
}

// the old entry: keys zero, local_id 0, back to the pool
static int retire_prev(wg_peer_t *p) {
    if (entry_free(p->prev.entry, 1) != 0) return -1;
    memset(&p->prev, 0, sizeof(p->prev));
    st.retired++;
    return 0;
}

// the next entry dropped (an attempt over, a session never confirmed)
static int drop_next(wg_peer_t *p) {
    if (entry_free(p->next.entry, 1) != 0) return -1;
    bare_wipe(&p->next, sizeof(p->next));
    return 0;
}

// The switch: peer n's routes move to the confirmed next entry, which
// becomes cur; the old cur, if it had keys, becomes prev (a prev still there
// goes first: three sessions are one too many), else goes back to the pool.
// 0, or -1 when the data plane did not drain (the timers retry)
static int switch_next(int n, wg_peer_t *p, uint32_t now) {
    if (hw_waiting(p, now)) return -1;
    // the tags of its entries with keys: next, and cur if live (prev goes first)
    uint64_t tags = (1ull << p->next.entry) | (p->live ? 1ull << p->cur.entry : 0);
    if ((p->prev.entry && retire_prev(p) != 0) || routes_to(n, p->next.entry, tags) != 0) {
        hw_failed(p, now);
        return -1;
    }
    if (p->live) {
        p->prev.entry   = p->cur.entry;
        p->prev.t_start = p->cur.t_start;
        p->prev.snap    = p->cur.snap;
    } else {
        entry_free(p->cur.entry, 0);  // no keys: cleared at reject, or never had any
    }
    bare_wipe(&p->cur, sizeof(p->cur));
    p->cur       = p->next;
    p->cur.state = WG_KP_NONE;
    bare_wipe(&p->next, sizeof(p->next));
    make_current(p, p->cur.initiator);
    st.switches++;
    if (p->cur.initiator) confirm_start(p, now);  // key confirmation for the responder
    return 0;
}

// the responder's peer lookup (wg_consume_initiation_peer): *ctx = its number
static const uint8_t *find_peer(void *ctx, const uint8_t is[WG_KEY_LEN]) {
    int n = peer_find(is);
    if (!n) return NULL;
    *(int *)ctx = n;
    return peers[n].ss;
}

// Message 1: answer with message 2 and hand the keys to the data plane. The
// new session goes to the next entry (a free one, or the one our own
// initiation holds): it decrypts at once, so the initiator's first data
// confirms it, but the routes stay on cur until then (#85): we send nothing
// under keys the initiator may not have. No free entry (entry_get): over cur
// (in place: what is in flight under the old keys drops, and we send before
// confirmation). No handshake slot: message 1 to message 2 is this one call,
// on the scratch state s, so a full handshake pool never refuses an answer
static int rx_init(const uint8_t *msg, const wg_endpoint_t *src,
                   uint8_t *out, size_t *out_len, wg_endpoint_t *dst) {
    wg_handshake_t s;            // scratch: a peer's state changes only below
    wg_install_t   in;
    uint8_t        is[WG_KEY_LEN], ts[WG_TAI64N_LEN], e[WG_KEY_LEN];
    int            rc = -1, n = 0, ent, fresh = 0;
    uint32_t       idx;
    wg_peer_t     *p;

    memset(&s, 0, sizeof(s));
    memset(&in, 0, sizeof(in));
    memset(e, 0, sizeof(e));
    // the peer is found after the first X25519, before the second (its
    // cached static-static): an unknown static key costs one
    switch (wg_consume_initiation_peer(&id, &s, msg, find_peer, &n, is, ts)) {
        case 0:
            break;
        case -2:
            return drop(&st.drop_unknown);  // s not written
        default:
            return drop(&st.drop_bad);
    }
    p = &peers[n];
    // replay: TAI64N is big-endian, so a byte compare orders it
    if (memcmp(ts, p->last_ts, WG_TAI64N_LEN) <= 0) {
        drop(&st.drop_replay);
        goto out;
    }
    ent = p->next.entry;
    if (!ent && (ent = entry_get(n)) != 0) fresh = 1;
    if (!ent) ent = p->cur.entry;
    memcpy(s.psk, p->psk, WG_KEY_LEN);
    wg_hw_random(e);
    idx = new_index(ent, ent == p->cur.entry ? p->cur.local_id : p->next.local_id,
                    p->hs ? hs_slot[p->hs - 1].local_index : 0);
    if (wg_create_response(&s, idx, e, out) != 0) {
        drop(&st.drop_bad);
        goto out;
    }
    wg_cookie_add_mac2(&p->cookie, out, WG_MSG_RESP_LEN);
    install_fill(&in, &s, src);
    in.tag = p->cur.entry;  // the routes stay on cur until the switch
    if (wg_hw_install(ent, &in) != 0) {  // no answer: the initiator retries
        drop(&st.drop_hw);
        goto out;
    }
    fresh = 0;
    memcpy(p->last_ts, ts, WG_TAI64N_LEN);
    handshake_done(p, src);
    hs_free(p);  // our own initiation, if any: answered by this one
    if (ent == p->cur.entry) {
        keypair_set(&p->cur, ent, &in, WG_KP_NONE, 0);
        make_current(p, 0);
        st.in_place++;
    } else {
        keypair_set(&p->next, ent, &in, WG_KP_PENDING, 0);
    }
    st.rx_init++;
    st.tx_resp++;
    *out_len = WG_MSG_RESP_LEN;
    *dst     = *src;
    rc       = 0;
out:
    if (fresh) entry_free(ent, 0);  // nothing written to it
    wg_handshake_wipe(&s);
    bare_wipe(&in, sizeof(in));
    bare_wipe(e, sizeof(e));
    return rc;
}

// Message 2, the answer to our initiation: it confirms the keys, so the
// routes move to the new entry at once (the old one still decrypts), and a
// keepalive confirms them to the responder
static int rx_resp(const uint8_t *msg, const wg_endpoint_t *src) {
    wg_install_t in;
    uint32_t     r = get32_le(msg + 8);
    int          e = (int)(r & (WG_ENTRIES - 1)), n = owner[e];
    wg_peer_t   *p = &peers[n];

    wg_handshake_t *hs = (n != 0 && p->used && p->hs) ? &hs_slot[p->hs - 1] : NULL;

    if (!hs || hs->state != WG_HS_INITIATED || hs->local_index != r) {
        return drop(&st.drop_unknown);
    }
    if (wg_consume_response(&id, hs, msg) != 0) return drop(&st.drop_bad);  // slot kept

    install_fill(&in, hs, src);
    in.tag = p->cur.entry;  // switch_next moves the routes and the tags
    int rc = wg_hw_install(e, &in);
    if (rc == 0) {
        uint32_t now = wg_timer_ms();
        handshake_done(p, src);
        if (e == p->cur.entry) {  // no next entry: cur had no keys, or the pool was empty
            if (p->live) st.in_place++;
            keypair_set(&p->cur, e, &in, WG_KP_NONE, 1);
            make_current(p, 1);
            confirm_start(p, now);
        } else {
            keypair_set(&p->next, e, &in, WG_KP_CONFIRMED, 1);
            switch_next(n, p, now);  // with the keepalive; else the timers retry
        }
        st.rx_resp++;
    } else {
        drop(&st.drop_hw);  // the handshake is used up: the retransmit timer initiates again
    }
    hs_free(p);
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
        int n = owner[wg_cookie_reply_receiver(msg) & (WG_ENTRIES - 1)];
        if (n == 0 || !peers[n].used) return drop(&st.drop_unknown);
        if (wg_cookie_consume_reply(&peers[n].cookie, msg, len) != 0) return drop(&st.drop_bad);
        st.cookie_rx++;
        return 0;
    }
    if (msg[0] != WG_MSG_INIT && msg[0] != WG_MSG_RESP) {
        return drop(&st.drop_bad);  // WG_MSG_DATA is the data plane's: never here
    }
    // mac1 always, and under load mac2 before any DH work (cookie.c, as
    // wg_cookie_validate); a valid mac1 counts towards the load
    if (!wg_cookie_check_mac1(&chk, msg, len)) {
        return drop(&st.drop_bad);  // not message 1/2, or mac1 wrong
    }
    load_count();
    if (wg_under_load() && !wg_cookie_check_mac2(&chk, msg, len, src->ip, src->port)) {
        if (wg_cookie_create_reply(&chk, out, msg, len, src->ip, src->port) != 0) {
            return drop(&st.drop_bad);
        }
        *out_len = WG_MSG_COOKIE_LEN;
        *dst     = *src;
        st.cookie_tx++;
        return 0;
    }
    return msg[0] == WG_MSG_INIT ? rx_init(msg, src, out, out_len, dst) : rx_resp(msg, src);
}

// Message 1 to peer n; retry: a retransmit of the attempt in flight, else a
// new attempt (REKEY_ATTEMPT_TIME from now). The new session's entry, which
// its index names: the next one (a free entry); cur while it has no keys
// and there is no next one, or when no entry is free (entry_get: in place).
// A responder session waiting for confirmation is kept for REKEY_TIMEOUT
// (its initiator confirms at once); after that our initiation takes its
// entry (RESERVED), but its keys stay until message 2: data on it still
// confirms it (peer_timers), and it is never cleared for our attempt
static int initiate(int n, uint8_t msg[WG_MSG_INIT_LEN], wg_endpoint_t *dst, int retry) {
    uint8_t e[WG_KEY_LEN], ts[WG_TAI64N_LEN];

    if (!have_key || n < 1 || n >= WG_PEERS || !peers[n].used || !peers[n].has_ep) return -1;
    wg_peer_t *p   = &peers[n];
    uint32_t   now = wg_timer_ms();
    if (p->next.state == WG_KP_CONFIRMED ||
        (p->next.state == WG_KP_PENDING && now - p->next.t_start < REKEY_TIMEOUT_MS)) {
        return -1;
    }
    // its handshake slot; all busy: the attempt goes on without message 1,
    // and its retransmit timer tries again (1)
    wg_handshake_t *hs = hs_alloc(n);
    if (!hs) st.hs_busy++;
    if (hs) {
        if (p->next.state == WG_KP_PENDING) p->next.state = WG_KP_RESERVED;
        int ent = (p->live || p->next.entry) ? p->next.entry : p->cur.entry;
        if (!ent && (ent = entry_get(n)) != 0) {
            p->next.entry = (uint8_t)ent;
            p->next.state = WG_KP_RESERVED;
        }
        if (!ent) ent = p->cur.entry;
        bare_wipe(hs, sizeof(*hs));
        memcpy(hs->remote_static, p->pub, WG_KEY_LEN);
        memcpy(hs->psk, p->psk, WG_KEY_LEN);
        uint32_t idx = new_index(ent, ent == p->cur.entry ? p->cur.local_id : p->next.local_id, 0);
        wg_hw_random(e);
        wg_now_tai64n(ts);
        int rc = wg_create_initiation_ss(&id, hs, idx, e, ts, p->ss, msg);  // cached DH(s_i, S_r)
        bare_wipe(e, sizeof(e));
        if (rc != 0) {
            hs_free(p);
            return -1;  // a reserved next entry goes back at the next poll (no attempt)
        }
        wg_cookie_add_mac2(&p->cookie, msg, WG_MSG_INIT_LEN);  // a cookie under 115 s old
        *dst = p->ep;
        st.tx_init++;
        p->t_any = now;  // a packet sent: no keepalive needed
        p->tm    = (uint16_t)(p->tm & ~WG_TM_KA);
    }
    // the retransmit timer: REKEY_TIMEOUT + a new jitter from now
    wg_hw_random(e);
    p->jitter = (uint16_t)(get32_le(e) % REKEY_JITTER_MS);
    bare_wipe(e, sizeof(e));
    p->t_init = now;
    p->tm     = (uint16_t)(p->tm | WG_TM_INIT | WG_TM_ATTEMPT);
    if (!retry) {
        p->t_attempt = now;
        p->retries   = 0;
        p->tm        = (uint16_t)(p->tm & ~WG_TM_GAVE_UP);
    }
    return hs ? 0 : 1;
}

int wg_session_initiate(int n, uint8_t msg[WG_MSG_INIT_LEN], wg_endpoint_t *dst) {
    return initiate(n, msg, dst, 0) == 0 ? 0 : -1;
}

// ---- timers (#80, wg_session.h) -------------------------------------------------

int wg_peer_set_keepalive(int n, uint16_t seconds) {
    if (n < 1 || n >= WG_PEERS || !peers[n].used) return -1;
    peers[n].keepalive = seconds;
    return 0;
}

// a handshake the timers want: a new attempt, unless one is in flight or
// the last initiation is under REKEY_TIMEOUT old (the protocol's rate
// limit). 1: message 1 sent; 0: a handshake is under way without one (an
// attempt in flight, or one started with no handshake slot free); -1:
// refused (the rate limit, an unconfirmed responder session under
// REKEY_TIMEOUT old): the caller keeps its event for a later poll
static int want_handshake(int n, wg_peer_t *p, uint32_t now, int rekey) {
    uint8_t       msg[WG_MSG_INIT_LEN];
    wg_endpoint_t dst;
    if (p->tm & WG_TM_ATTEMPT) return 0;
    if ((p->tm & WG_TM_INIT) && now - p->t_init < REKEY_TIMEOUT_MS) return -1;
    int rc = initiate(n, msg, &dst, 0);
    if (rc != 0) return rc > 0 ? 0 : -1;
    wg_hw_send(&dst, msg, sizeof(msg));
    if (rekey) st.rekeys++;
    return 1;
}

// the retransmit of the attempt in flight, or the end of it
static int retransmit(int n, wg_peer_t *p, uint32_t now) {
    uint8_t       msg[WG_MSG_INIT_LEN];
    wg_endpoint_t dst;
    if (!(p->tm & WG_TM_ATTEMPT)) return 0;
    if (now - p->t_attempt >= REKEY_ATTEMPT_TIME_MS) {
        hs_free(p);  // a late answer finds nothing
        p->tm = (uint16_t)((p->tm & ~WG_TM_ATTEMPT) | WG_TM_GAVE_UP);
        st.gave_up++;
        return 0;
    }
    if (now - p->t_init < REKEY_TIMEOUT_MS + p->jitter) return 0;
    if (initiate(n, msg, &dst, 1) != 0) return 0;  // with mac2 after a cookie reply
    wg_hw_send(&dst, msg, sizeof(msg));
    if (p->retries < 0xFF) p->retries++;
    st.retransmits++;
    return 1;
}

// A keepalive: a transport data message with an empty payload, built here,
// since the data plane only encrypts what it forwards. Its counter comes
// from the current entry (wg_hw_take_send_cnt: the encryptor never reuses
// it), the key is our copy of the session's send key, the nonce 4 zero
// bytes and the counter, no AAD: the tag over nothing
static int send_keepalive(wg_peer_t *p, uint32_t now) {
    uint8_t  msg[WG_MSG_KEEPALIVE_LEN], nonce[CHACHA20POLY1305_NONCE_SIZE];
    uint64_t c;
    if (hw_waiting(p, now)) return 0;
    if (wg_hw_take_send_cnt(p->cur.entry, &c) != 0) {
        hw_failed(p, now);
        return 0;
    }
    memset(msg, 0, 16);
    msg[0] = WG_MSG_DATA;
    for (int i = 0; i < 4; i++) msg[4 + i] = (uint8_t)(p->cur.remote_id >> (8 * i));
    put64_le(msg + 8, c);
    memset(nonce, 0, 4);
    put64_le(nonce + 4, c);
    chacha20poly1305_encrypt(msg + 16, msg + 16, p->cur.send_key, nonce, NULL, 0, NULL, 0);
    wg_hw_send(&p->ep, msg, sizeof(msg));
    p->cur.snap.send = (uint32_t)(c + 1);  // ours: not data sent
    p->t_any         = now;
    p->t_conf        = now;  // also a key confirmation (WG_TM_CONFIRM)
    p->tm            = (uint16_t)(p->tm & ~(WG_TM_KA | WG_TM_CONF_DUE));
    st.keepalive_tx++;
    return 1;
}

// REJECT_AFTER_*: the keys leave the data plane: cur cleared in place
// (keys zero, local_id 0, so no receiver index matches), with the DPE
// paused. The routes stay on it: what they send is dropped and counted,
// which starts a handshake. Our copy of the send key goes too
static void reject(wg_peer_t *p, uint32_t now) {
    if (hw_waiting(p, now)) return;
    if (wg_hw_install(p->cur.entry, NULL) != 0) {
        hw_failed(p, now);  // the keys stay: again after WG_HW_RETRY_MS
        return;
    }
    uint8_t e = p->cur.entry;
    bare_wipe(&p->cur, sizeof(p->cur));
    p->cur.entry = e;
    p->live      = 0;
    p->tm        = (uint16_t)((p->tm & ~(WG_TM_KA | WG_TM_NH | WG_TM_CONFIRM | WG_TM_CONF_DUE)) |
                              WG_TM_REJECTED);
    st.rejected++;
}

// entry e's counters against its snapshot (then updated): EV_SENT when
// send_cnt moved, EV_RECV when recv_cnt or recv_win did
#define EV_SENT 1
#define EV_RECV 2
static int poll_entry(int e, wg_snap_t *s, uint64_t *sc, uint64_t *rc) {
    uint64_t rw;
    wg_hw_counters(e, sc, rc, &rw);
    int ev = ((uint32_t)*sc != s->send ? EV_SENT : 0) |
             ((uint32_t)*rc != s->recv || rw != s->win ? EV_RECV : 0);
    s->send = (uint32_t)*sc;
    s->recv = (uint32_t)*rc;
    s->win  = rw;
    return ev;
}

// one peer's poll: its old and next entries (the session pool, #85), then
// the events from its current entry's counters and its timers
static int peer_timers(int n, wg_peer_t *p, uint32_t now) {
    uint64_t sc, rc;
    int      ev, sent, recv = 0, tx = 0;
    // the old session: what is still in flight to it decrypts, as Linux's
    // previous keypair, until the next switch or its REJECT_AFTER_TIME (or a
    // new session that finds the pool empty: entry_get). Data on it while
    // we wait for key confirmation: the responder did not get our keepalive
    if (p->prev.entry) {
        if (poll_entry(p->prev.entry, &p->prev.snap, &sc, &rc) & EV_RECV) {
            recv = 1;
            if (p->tm & WG_TM_CONFIRM) p->tm = (uint16_t)(p->tm | WG_TM_CONF_DUE);
        }
        if (now - p->prev.t_start >= REJECT_AFTER_TIME_MS && !hw_waiting(p, now)) {
            if (retire_prev(p) != 0) hw_failed(p, now);
        }
    }
    // a next session with keys, the responder's (PENDING, or RESERVED with
    // a local_id: taken over by our initiation, its keys still there):
    // confirmed by the first data on it (#85), which also ends our attempt
    // (the peer uses its session); a PENDING one never confirmed goes at its
    // REJECT_AFTER_TIME. An entry reserved for an initiation goes when the
    // attempt is over; one with keys goes back to PENDING instead
    if (p->next.state == WG_KP_PENDING || (p->next.state == WG_KP_RESERVED && p->next.local_id)) {
        if (poll_entry(p->next.entry, &p->next.snap, &sc, &rc) & EV_RECV) {
            recv = 1;
            if (p->next.state == WG_KP_RESERVED) {
                hs_free(p);  // a late message 2 finds nothing
                p->tm = (uint16_t)(p->tm & ~WG_TM_ATTEMPT);
            }
            p->next.state = WG_KP_CONFIRMED;
        } else if (p->next.state == WG_KP_PENDING &&
                   now - p->next.t_start >= REJECT_AFTER_TIME_MS && !hw_waiting(p, now)) {
            if (drop_next(p) != 0) hw_failed(p, now);
        }
    }
    if (p->next.state == WG_KP_CONFIRMED) {
        switch_next(n, p, now);
    } else if (p->next.state == WG_KP_RESERVED && !(p->tm & WG_TM_ATTEMPT)) {
        if (p->next.local_id) {
            p->next.state = WG_KP_PENDING;  // the peer's session: kept, never cleared for ours
        } else if (!hw_waiting(p, now) && drop_next(p) != 0) {
            hw_failed(p, now);
        }
    }

    ev   = poll_entry(p->cur.entry, &p->cur.snap, &sc, &rc);
    sent = ev & EV_SENT;
    recv |= (ev & EV_RECV) != 0;
    if (ev & EV_RECV) {  // the responder sends on cur: it has confirmed
        p->tm = (uint16_t)(p->tm & ~(WG_TM_CONFIRM | WG_TM_CONF_DUE));
    }
    if (sent) {  // data out: no keepalive (nor confirmation) due; a handshake if nothing comes back
        p->t_sent = now;
        p->t_any  = now;
        p->t_conf = now;
        if (!(p->tm & WG_TM_NH)) p->t_nh = now;
        p->tm = (uint16_t)((p->tm | WG_TM_SENT | WG_TM_NH) & ~(WG_TM_KA | WG_TM_CONF_DUE));
    }
    if (recv) {  // data in: a keepalive unless we send (both in one poll: we did)
        p->t_recv = now;
        p->t_any  = now;
        if (!sent && !(p->tm & WG_TM_KA)) {
            p->t_ka = now;
            p->tm   = (uint16_t)(p->tm | WG_TM_KA);
        }
        p->tm = (uint16_t)((p->tm | WG_TM_RECV) & ~WG_TM_NH);
    }
    tx += retransmit(n, p, now);

    int pk = p->keepalive && now - p->t_any >= (uint32_t)p->keepalive * 1000u;
    if (!p->live) {
        // no keys: data to it (dropped, but counted in send_cnt), or the
        // persistent keepalive, wants a handshake
        if (sent || pk) tx += want_handshake(n, p, now, 0) > 0;
        return tx;
    }
    uint32_t age = now - p->cur.t_start;
    if (age >= REJECT_AFTER_TIME_MS || sc >= REJECT_AFTER_MESSAGES || rc >= REJECT_AFTER_MESSAGES) {
        reject(p, now);
        return tx;
    }
    if (sent && (sc >= REKEY_AFTER_MESSAGES ||
                 ((p->tm & WG_TM_INITIATOR) && age >= REKEY_AFTER_TIME_MS))) {
        tx += want_handshake(n, p, now, 1) > 0;
    }
    // the one-shot events end only when a handshake is under way; refused
    // (the rate limit, an unconfirmed responder session), they stay for a
    // later poll: the receive rekey for the next data in, the new-handshake
    // timer for the next poll
    if (recv && (p->tm & WG_TM_INITIATOR) && !(p->tm & WG_TM_RXREKEY) &&
        age >= REJECT_AFTER_TIME_MS - KEEPALIVE_TIMEOUT_MS - REKEY_TIMEOUT_MS) {
        int hs = want_handshake(n, p, now, 1);
        if (hs >= 0) p->tm = (uint16_t)(p->tm | WG_TM_RXREKEY);
        tx += hs > 0;
    }
    if ((p->tm & WG_TM_NH) && now - p->t_nh >= KEEPALIVE_TIMEOUT_MS + REKEY_TIMEOUT_MS) {
        int hs = want_handshake(n, p, now, 1);  // sent, nothing back: a new handshake
        if (hs >= 0) p->tm = (uint16_t)(p->tm & ~WG_TM_NH);
        tx += hs > 0;
    }
    // the key confirmation again (confirm_start), at most every REKEY_TIMEOUT;
    // else the keepalive timer, the persistent keepalive
    int ka = (p->tm & WG_TM_CONF_DUE) && now - p->t_conf >= REKEY_TIMEOUT_MS &&
             send_keepalive(p, now);
    if (!ka && (((p->tm & WG_TM_KA) && now - p->t_ka >= KEEPALIVE_TIMEOUT_MS) || pk)) {
        ka = send_keepalive(p, now);
    }
    tx += ka;
    return tx;
}

int wg_session_timers(void) {
    uint32_t now = wg_timer_ms();
    int      tx  = 0;
    if (tm_started && now - tm_last < WG_TIMER_POLL_MS) return 0;
    tm_started = 1;
    tm_last    = now;
    if (!have_key) return 0;
    for (int n = 1; n < WG_PEERS; n++) {
        if (peers[n].used) tx += peer_timers(n, &peers[n], now);
    }
    return tx;
}

// -----------------------------------------------------------------------------
// Project:     WireGuard-FPGA
// Description: NLnet-funded open-source implementation
// Funding:     https://nlnet.nl/project/KlusterLab-Wireguard (2023-12 to 2025-12)
// -----------------------------------------------------------------------------
