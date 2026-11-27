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
// Peer n is cryptokey table entry n (1 .. 63; 0 is not used), and the low 6
// bits of each receiver index we hand out are n: the disassembler finds the
// entry from them and checks the whole index against local_id.
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

#define WG_PEERS        64      // cryptokey table entries; 0 is not used
#define WG_MSG_DATA     4       // WG_MSG_COOKIE, WG_MSG_COOKIE_LEN: cookie.h

// where a message came from or goes to: the outer Ethernet/IPv4/UDP addresses
typedef struct {
    uint8_t  mac[6];
    uint8_t  ip[4];
    uint16_t port;
    uint8_t  ifc;               // the Ethernet port, DPE_ADDR_ETH_1 .. 4
} wg_endpoint_t;

typedef struct {
    uint8_t        used;
    uint8_t        pub[WG_KEY_LEN];
    uint8_t        psk[WG_KEY_LEN];
    uint8_t        last_ts[WG_TAI64N_LEN];  // newest initiation accepted from it
    wg_endpoint_t  ep;          // the last authenticated source, or as configured
    uint8_t        has_ep;
    uint8_t        live;        // the data plane has keys for it
    uint32_t       local_id;    // of the live session
    uint32_t       remote_id;
    wg_handshake_t hs;          // our initiation to it, while WG_HS_INITIATED
    wg_cookie_t    cookie;      // its cookie for our mac2, our last mac1 to it
} wg_peer_t;

typedef struct {
    uint32_t rx_init, rx_resp, tx_init, tx_resp, sessions;
    uint32_t cookie_tx, cookie_rx;  // message 3 sent (under load), taken
    uint32_t drop_bad, drop_unknown, drop_replay, drop_hw;
} wg_stats_t;

// The keys and addresses one cryptokey table entry gets
typedef struct {
    uint32_t      local_id, remote_id;
    uint8_t       send_key[WG_KEY_LEN];  // -> encrypt_key
    uint8_t       recv_key[WG_KEY_LEN];  // -> decrypt_key
    wg_endpoint_t remote;
} wg_install_t;

// ---- the platform (main.cpp, or a test) ----
void     wg_hw_random(uint8_t out[WG_KEY_LEN]);  // random_32bytes (#2)
// write entry n (send/recv counters to 0): 0, or -1 when the data plane did
// not drain (nothing written); in = NULL clears the entry
int      wg_hw_install(int n, const wg_install_t *in);

// ---- set-up ----
void wg_session_init(void);                      // no key, no peers
void wg_set_private(const uint8_t priv[WG_KEY_LEN]);
int  wg_has_private(void);
const wg_identity_t *wg_identity(void);
// add a peer (psk NULL: none, ep NULL: learn it from its first handshake):
// its entry 1 .. 63, or -1 (no key, full, already there)
int  wg_peer_add(const uint8_t pub[WG_KEY_LEN], const uint8_t *psk, const wg_endpoint_t *ep);
int  wg_peer_remove(int n);                      // 0 or -1; clears its table entry
const wg_peer_t *wg_peer(int n);                 // NULL when not used
void wg_peer_map_rebuild(void);                  // peer_map from the peers (a new SipHash key)
const wg_stats_t *wg_stats(void);

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
int  wg_session_initiate(int n, uint8_t msg[WG_MSG_INIT_LEN], wg_endpoint_t *dst);

// ---- cookies (cookie.c, #29) ----
// Under load, message 1/2 needs a valid mac2, else it gets a cookie reply
// (message 3) instead of an answer. Load detection is #4: until then only
// wg_set_under_load (the CLI, the tests) turns it on
int  wg_under_load(void);
void wg_set_under_load(int on);

#ifdef __cplusplus
}
#endif

#endif  // WG_SESSION_H

// -----------------------------------------------------------------------------
// Project:     WireGuard-FPGA
// Description: NLnet-funded open-source implementation
// Funding:     https://nlnet.nl/project/KlusterLab-Wireguard (2023-12 to 2025-12)
// -----------------------------------------------------------------------------
