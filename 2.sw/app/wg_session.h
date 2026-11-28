// SPDX-FileCopyrightText: 2026 Chili.CHIPS
//
// SPDX-License-Identifier: BSD-3-Clause

//==========================================================================
// WireGuard sessions: the peers, their handshakes (noise.c) and what a
// finished handshake hands the data plane (the cryptokey table entry).
//
// No I/O here. wg_session_rx() takes the UDP payload of a handshake message
// and where it came from, and gives back the reply to send. The platform
// (main.cpp on the CPU, the tests on the host) provides the wg_hw_*
// functions below: the clock, the RNG and the cryptokey table write.
//
// The session pool (#85): a cryptokey table entry (1 .. 63; 0 is not used)
// holds one session, not one peer. Each peer has a current entry (the one
// its routes point at; zero keys while it has no session) and at most one
// next and one old (retiring) entry; the free entries are the pool. The low
// 6 bits of each receiver index we hand out are the session's entry: the
// disassembler finds the entry from them and checks the whole index against
// local_id.
//==========================================================================

#ifndef WG_SESSION_H
#define WG_SESSION_H

#include <stdint.h>
#include <stddef.h>
#include "noise.h"
#include "cookie.h"

#ifdef __cplusplus
extern "C" {
#endif

#define WG_PEERS        64      // peers 1 .. 63; 0 is not used
#define WG_ENTRIES      64      // cryptokey table entries 1 .. 63; 0 is not used
#define WG_ROUTES       64      // routing table entries
// The handshake pool: the Noise state of our initiations in flight, shared
// by all peers. A peer holds a slot from message 1 to message 2, the end
// of its attempt (REKEY_ATTEMPT_TIME), an initiation of theirs, or its
// removal. The responder needs none: message 1 to message 2 is one call
// (a scratch state). The CPU answers about 3 handshakes a second, so 8 are
// plenty; with all 8 busy, a new attempt of ours starts without a message
// and its retransmit timer tries again (counted: hs_busy)
#define WG_HS_SLOTS     8
#define WG_MSG_DATA     4       // WG_MSG_COOKIE, WG_MSG_COOKIE_LEN: cookie.h

// where a message came from or goes to: the outer Ethernet/IPv4/UDP addresses
typedef struct {
    uint8_t  mac[6];
    uint8_t  ip[4];
    uint16_t port;
    uint8_t  ifc;               // the Ethernet port, DPE_ADDR_ETH_1 .. 4
} wg_endpoint_t;

// an entry's counters at the last poll (the timers, #80): send_cnt and
// recv_cnt, the low 32 bits, and the whole recv_win (two late packets in one
// poll may move only the window, by one bit in each half)
typedef struct {
    uint32_t send, recv;
    uint64_t win;
} wg_snap_t;

// One session in one cryptokey table entry (wg_peer_t.cur, .next). Times
// are wg_timer_ms(), compared as differences (the 32 bits wrap after 49 days)
typedef struct {
    uint8_t   entry;            // 1 .. 63 (0: none)
    uint8_t   state;            // WG_KP_* (next only)
    uint8_t   initiator;        // we initiated it
    uint32_t  local_id, remote_id;
    uint8_t   send_key[WG_KEY_LEN];  // for keepalives (wiped with the session)
    uint32_t  t_start;          // its handshake
    wg_snap_t snap;
} wg_keypair_t;

// wg_keypair_t.state of the next entry
enum {
    WG_KP_NONE      = 0,        // no next entry
    WG_KP_RESERVED  = 1,        // held for our initiation in flight (its index names it); with
                                // a local_id, a responder session it took over: still decrypts,
                                // confirmed by data on it like WG_KP_PENDING
    WG_KP_PENDING   = 2,        // the responder's new session: decrypts, sends nothing yet
    WG_KP_CONFIRMED = 3         // confirmed: the routes move to it (retried if busy)
};

// the old session after a switch: decrypts what is still in flight
typedef struct {
    uint8_t   entry;            // 0: none
    uint32_t  t_start;          // its handshake (REJECT_AFTER_TIME)
    wg_snap_t snap;
} wg_old_t;

typedef struct {
    uint8_t        used;
    uint8_t        pub[WG_KEY_LEN];
    uint8_t        psk[WG_KEY_LEN];
    uint8_t        ss[WG_KEY_LEN];          // wg_static_static with our key (zeros: none yet)
    uint8_t        last_ts[WG_TAI64N_LEN];  // newest initiation accepted from it
    wg_endpoint_t  ep;          // the last authenticated source, or as configured
    uint8_t        has_ep;
    uint8_t        live;        // cur has keys: its routes send through it
    wg_keypair_t   cur;         // the routes point at cur.entry (zero keys: no session)
    wg_keypair_t   next;        // the new session before the switch
    wg_old_t       prev;        // the old one after it
    uint8_t        hs;          // its handshake pool slot + 1 (0: none), our initiation
    wg_cookie_t    cookie;      // its cookie for our mac2, our last mac1 to it
    // the timers (#80, wg_session_timers), on the current session
    uint16_t       tm;          // WG_TM_* flags
    uint16_t       keepalive;   // persistent keepalive interval, s (0: off)
    uint8_t        retries;     // retransmits of the initiation in flight
    uint16_t       jitter;      // its retransmit jitter, ms
    uint32_t       t_hs;        // the last handshake
    uint32_t       t_sent, t_recv;    // the last data the data plane sent to it, got from it
    uint32_t       t_any;       // the last packet either way (persistent keepalive)
    uint32_t       t_init, t_attempt; // our last initiation, the first of its attempt
    uint32_t       t_ka, t_nh;  // when the keepalive / new-handshake timer was armed
    uint32_t       t_hwfail;    // the last pause that did not drain
    uint32_t       t_conf;      // our last keepalive on cur (WG_TM_CONFIRM)
} wg_peer_t;

// wg_peer_t.tm
#define WG_TM_HS       0x0001   // a handshake completed (t_hs valid)
#define WG_TM_SENT     0x0002   // t_sent valid
#define WG_TM_RECV     0x0004   // t_recv valid
#define WG_TM_INIT     0x0008   // an initiation sent (t_init valid)
#define WG_TM_ATTEMPT  0x0010   // an initiation waits for its answer (retransmits)
#define WG_TM_GAVE_UP  0x0020   // the last attempt got no answer in REKEY_ATTEMPT_TIME
#define WG_TM_REJECTED 0x0040   // REJECT_AFTER_*: the keys left the data plane
#define WG_TM_KA       0x0080   // keepalive timer armed (data in, nothing out)
#define WG_TM_NH       0x0100   // new-handshake timer armed (data out, nothing in)
#define WG_TM_RXREKEY  0x0200   // the receive-side rekey of this session done
#define WG_TM_INITIATOR 0x0400  // we initiated the live session
#define WG_TM_HWFAIL   0x0800   // t_hwfail valid
#define WG_TM_CONFIRM  0x1000   // we initiated cur: no data on it yet from the responder
#define WG_TM_CONF_DUE 0x2000   // ... and a confirmation keepalive is due (WG_TM_CONFIRM)

typedef struct {
    uint32_t rx_init, rx_resp, tx_init, tx_resp, sessions;
    uint32_t cookie_tx, cookie_rx;  // message 3 sent (under load), taken
    uint32_t drop_bad, drop_unknown, drop_replay, drop_hw;
    uint32_t load_hits;             // handshake messages that found the rate exceeded
    uint32_t keepalive_tx, rekeys, retransmits, gave_up, rejected;  // the timers (#80)
    uint32_t switches, retired;     // the session pool (#85): routes moved, old entries freed
    uint32_t in_place;              // new sessions over the current entry (pool empty)
    uint32_t hs_busy;               // our initiations deferred: no free handshake slot
} wg_stats_t;

// The keys and addresses one cryptokey table entry gets
typedef struct {
    uint32_t      local_id, remote_id;
    uint8_t       send_key[WG_KEY_LEN];  // -> encrypt_key
    uint8_t       recv_key[WG_KEY_LEN];  // -> decrypt_key
    wg_endpoint_t remote;
    uint8_t       tag;  // the peer tag: the entry its routes point at (its cur)
} wg_install_t;

// ---- the platform (main.cpp, or a test) ----
void     wg_hw_random(uint8_t out[WG_KEY_LEN]);  // random_32bytes (#2)
// write cryptokey table entry e (send/recv counters to 0): 0, or -1 when
// the data plane did not drain (nothing written); in = NULL clears the entry
int      wg_hw_install(int e, const wg_install_t *in);
// the timers (#80): entry e's counters as the data plane left them, read
// without a pause (send_cnt; recv_cnt and recv_win, the replay window)
void     wg_hw_counters(int e, uint64_t *send_cnt, uint64_t *recv_cnt, uint64_t *recv_win);
// a counter for a message the CPU encrypts (a keepalive): with the data
// plane paused, send_cnt into *cnt and send_cnt + 1 written back, so the
// encryptor never uses it. 0, or -1 when it did not drain (nothing taken)
int      wg_hw_take_send_cnt(int e, uint64_t *cnt);
// the session pool (#85): peer_idx of every route r with bit r set in
// routes := e (encrypt and the rest kept), and the peer tag of every entry
// x with bit x set in entries := e, under one pause: 0, or -1 when the data
// plane did not drain (nothing written)
int      wg_hw_routes(uint64_t routes, uint64_t entries, int e);
// send a WireGuard message (the UDP payload) to dst, past the data plane
void     wg_hw_send(const wg_endpoint_t *dst, const uint8_t *msg, size_t len);

// ---- set-up ----
void wg_session_init(void);                      // no key, no peers
void wg_set_private(const uint8_t priv[WG_KEY_LEN]);
int  wg_has_private(void);
const wg_identity_t *wg_identity(void);
// add a peer (psk NULL: none, ep NULL: learn it from its first handshake):
// its number 1 .. 63, or -1 (ourselves, already there, no free peer or
// entry). It takes its current entry from the pool
int  wg_peer_add(const uint8_t pub[WG_KEY_LEN], const uint8_t *psk, const wg_endpoint_t *ep);
// 0 or -1: its routes to entry 0 (no keys: dropped), its entries cleared
int  wg_peer_remove(int n);
const wg_peer_t *wg_peer(int n);                 // NULL when not used
const wg_stats_t *wg_stats(void);
int  wg_pool_free(void);                         // free entries, of 63
int  wg_hs_free(void);                           // free handshake slots, of WG_HS_SLOTS
// peer n's initiation in flight (its slot), or NULL
const wg_handshake_t *wg_peer_hs(int n);

// ---- routes (#85): what the user configured, per peer ----
// Route r leads through the tunnel to peer n (0: not to a peer of ours):
// the entry its peer_idx must name now (n's current), or -1 (n no peer;
// the route is then not ours). Its peer_idx follows the peer's sessions
int  wg_route_set(int r, int n);
int  wg_route_peer(int r);                       // the peer route r leads to, 0: none

// ---- the clock: rtc.c (#30), or the test's stand-in ----
int  wg_set_time(uint64_t unix_seconds);         // only forward: 0, or -1
void wg_now_tai64n(uint8_t ts[WG_TAI64N_LEN]);   // strictly increasing
// wg_now_seconds() (cookie.h): the clock's seconds, for the cookie ages

// ---- messages ----
// A WireGuard message from src: 0 and the reply in out (len in *out_len, 0
// for none) and its destination in *dst; -1 when it is dropped (counted)
int  wg_session_rx(const uint8_t *msg, size_t len, const wg_endpoint_t *src,
                   uint8_t *out, size_t *out_len, wg_endpoint_t *dst);
// Start a handshake with peer n: 0 and message 1 for its endpoint, or -1
// (also when no handshake slot is free: the attempt then starts, and its
// retransmit timer sends message 1 once a slot is)
int  wg_session_initiate(int n, uint8_t msg[WG_MSG_INIT_LEN], wg_endpoint_t *dst);

// ---- timers (#80): WireGuard paper section 6, times in ms ----
// The data plane encrypts and decrypts; the CPU sees the traffic only in
// the counters of each entry (wg_hw_counters): send_cnt moved = data sent,
// recv_cnt or recv_win moved = data received. wg_session_timers() polls
// them every WG_TIMER_POLL_MS and runs the protocol's timers per peer:
// - rekey: the initiator of the session starts a new handshake when it
//   sends and the session is REKEY_AFTER_TIME old, or on receive at
//   REJECT_AFTER_TIME - KEEPALIVE_TIMEOUT - REKEY_TIMEOUT (once); either
//   side after REKEY_AFTER_MESSAGES sent, and when it sent data and got
//   nothing back for KEEPALIVE_TIMEOUT + REKEY_TIMEOUT
// - retransmit: an unanswered initiation again after REKEY_TIMEOUT + a
//   jitter of 0 .. REKEY_JITTER_MS - 1, a new one each time (with mac2
//   when a cookie reply came), until REKEY_ATTEMPT_TIME: then give up
// - reject: at REJECT_AFTER_TIME or REJECT_AFTER_MESSAGES (either counter)
//   the keys leave the data plane (wg_hw_install(e, NULL)): its data stops
//   until a new handshake, which data to it then starts
// - keepalive: data received and nothing sent for KEEPALIVE_TIMEOUT: an
//   empty transport message, encrypted by the CPU with a counter from
//   wg_hw_take_send_cnt; also every keepalive s without a packet either way
//   when the peer has a persistent keepalive, and by the initiator right
//   after message 2 (key confirmation for the responder): again, at most
//   every REKEY_TIMEOUT, while no data came on the new session and the
//   first did not go out (the pause did not drain) or the responder still
//   sends on the old keys (data on the old entry: the keepalive was lost)
// The session pool (#85), as Linux's previous, current and next keypair:
// a new session goes to a free entry. The initiator moves the peer's routes
// to it on message 2; the responder at key confirmation, the first data on
// the new entry (its recv_cnt or recv_win moved). The old entry still
// decrypts until the next switch or its REJECT_AFTER_TIME, as Linux keeps
// the previous keypair, then goes back to the pool. A new session that finds
// the pool empty reclaims an old entry first (the peer's own, else the
// oldest); with none, it goes over the current entry, as before the pool
// (counted: in_place).
#define REKEY_AFTER_MESSAGES  (1ull << 60)
#define REJECT_AFTER_MESSAGES (~0ull - (1ull << 13))  // 2^64 - 2^13 - 1
#define REKEY_AFTER_TIME_MS   120000u
#define REJECT_AFTER_TIME_MS  180000u
#define REKEY_ATTEMPT_TIME_MS 90000u
#define REKEY_TIMEOUT_MS      5000u
#define REKEY_JITTER_MS       334u    // the retransmit jitter: 0 .. 333 ms
#define KEEPALIVE_TIMEOUT_MS  10000u
#define WG_TIMER_POLL_MS      200u    // how often wg_session_timers polls
#define WG_HW_RETRY_MS        1000u   // after a pause that did not drain
#define WG_MSG_KEEPALIVE_LEN  32      // type, receiver, counter, tag

// Call often (the main loop): every WG_TIMER_POLL_MS it polls the peers and
// sends what the timers want (wg_hw_send). The messages sent (0: none)
int      wg_session_timers(void);
// the timers' clock, ms: the RTC less the jumps of wg_set_time
uint32_t wg_timer_ms(void);
// persistent keepalive interval of peer n, s (0: off): 0, or -1
int      wg_peer_set_keepalive(int n, uint16_t seconds);

// ---- cookies (cookie.c, #29) ----
// Under load, message 1/2 needs a valid mac2, else it gets a cookie reply
// (message 3) instead of an answer. Load (#81), as the Linux driver: under
// load while handshake messages come faster than the CPU answers them, and
// for WG_LOAD_AFTER_MS after. Linux measures its queue; we have none, so a
// rate: more than WG_LOAD_MAX messages with a valid mac1 in WG_LOAD_WINDOW_MS.
// One answered initiation costs 23.6 M cycles, 295 ms at 80 MHz (rv32 ISS
// with eduBOS5's measured timing, 2.sw/tests/iss_timing, mul 8 cycles: 4
// X25519 at 5.63 M each, the KDFs), so the CPU answers 3 a second at most;
// WG_LOAD_MAX = 2 keeps the handshakes under two thirds of the CPU
#define WG_LOAD_HS_MS      295   // one answered initiation, measured as above
#define WG_LOAD_WINDOW_MS  1000
#define WG_LOAD_MAX        (WG_LOAD_WINDOW_MS * 2 / 3 / WG_LOAD_HS_MS)  // 2 a second
#define WG_LOAD_AFTER_MS   1000  // Linux UNDER_LOAD_AFTER_TIME

enum { WG_LOAD_AUTO = 0, WG_LOAD_ON = 1, WG_LOAD_OFF = 2 };  // wg_set_load_mode

int  wg_under_load(void);           // now, by the mode
void wg_set_load_mode(int mode);    // WG_LOAD_*: auto (the rate, default), forced on/off
int  wg_load_mode(void);
void wg_set_under_load(int on);     // = wg_set_load_mode(on ? WG_LOAD_ON : WG_LOAD_OFF)

#ifdef __cplusplus
}
#endif

#endif  // WG_SESSION_H

// -----------------------------------------------------------------------------
// Project:     WireGuard-FPGA
// Description: NLnet-funded open-source implementation
// Funding:     https://nlnet.nl/project/KlusterLab-Wireguard (2023-12 to 2025-12)
// -----------------------------------------------------------------------------
