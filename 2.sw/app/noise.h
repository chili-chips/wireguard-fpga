// SPDX-FileCopyrightText: 2026 Chili.CHIPS
//
// SPDX-License-Identifier: BSD-3-Clause

//==========================================================================
// The WireGuard handshake, Noise_IKpsk2_25519_ChaChaPoly_BLAKE2s
// (WireGuard paper, section 5.4): handshake initiation (message 1),
// response (message 2) and the transport keys both sides derive.
//
// No I/O and no RNG here: the caller passes the ephemeral private key
// (random_32bytes on the CPU, fixed values in the tests), finds the peer
// from the decrypted static key (peer_map) and checks the timestamp.
// Cookies (mac2, message 3) are not handled yet: mac2 is sent as zeros.
//==========================================================================

#ifndef NOISE_H
#define NOISE_H

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

#define WG_KEY_LEN        32
#define WG_TAI64N_LEN     12
#define WG_MSG_INIT_LEN   148
#define WG_MSG_RESP_LEN   92
#define WG_MSG_INIT       1
#define WG_MSG_RESP       2

// This device's static key pair, and the mac1 key that incoming handshake
// messages use: HASH("mac1----" || our public key)
typedef struct {
    uint8_t priv[WG_KEY_LEN];
    uint8_t pub[WG_KEY_LEN];
    uint8_t mac1_key[WG_KEY_LEN];
} wg_identity_t;

// Where a handshake is: each call checks it, so a call out of order (a
// response without an initiation, a replayed response) fails before any DH
enum {
    WG_HS_NONE      = 0,  // nothing, or the last call failed
    WG_HS_INITIATED = 1,  // wg_create_initiation done: waiting for message 2
    WG_HS_CONSUMED  = 2,  // wg_consume_initiation done: wg_create_response next
    WG_HS_DONE      = 3   // transport keys set
};

// One handshake with one peer. Set remote_static and psk (zeros: none)
// before the first call; the rest is the Noise state between the messages,
// then the transport keys. A zeroed struct is WG_HS_NONE
typedef struct {
    uint8_t  state;                     // WG_HS_*
    uint8_t  remote_static[WG_KEY_LEN];
    uint8_t  psk[WG_KEY_LEN];
    uint8_t  ck[WG_KEY_LEN];            // chaining key
    uint8_t  h[WG_KEY_LEN];             // handshake hash
    uint8_t  e_priv[WG_KEY_LEN];        // our ephemeral private key
    uint8_t  remote_ephemeral[WG_KEY_LEN];
    uint32_t local_index;               // our sender index
    uint32_t remote_index;              // the peer's sender index
    uint8_t  send_key[WG_KEY_LEN];      // transport keys, once WG_HS_DONE
    uint8_t  recv_key[WG_KEY_LEN];
} wg_handshake_t;

// Set our static key pair from the private key (clamped by X25519)
void wg_identity_init(wg_identity_t *id, const uint8_t priv[WG_KEY_LEN]);

// Initiator: build message 1 to hs->remote_static, with our sender index,
// an ephemeral private key and a TAI64N timestamp. 0, or -1 on a bad key
int wg_create_initiation(const wg_identity_t *id, wg_handshake_t *hs, uint32_t local_index,
                         const uint8_t e_priv[WG_KEY_LEN], const uint8_t timestamp[WG_TAI64N_LEN],
                         uint8_t msg[WG_MSG_INIT_LEN]);

// Responder: check message 1 (mac1, both AEADs). 0 and the initiator's
// static key and timestamp, for the caller to find the peer and check that
// the timestamp is newer than its last; -1 when the message is not valid
// (both outputs then zeros). hs is written only when the message is valid,
// with the state for wg_create_response (set hs->psk before that). A replayed
// initiation is valid here: pass a scratch hs, and copy it into the peer's
// only after the timestamp check, so a replay cannot replace a live session
int wg_consume_initiation(const wg_identity_t *id, wg_handshake_t *hs,
                          const uint8_t msg[WG_MSG_INIT_LEN],
                          uint8_t initiator_static[WG_KEY_LEN],
                          uint8_t timestamp[WG_TAI64N_LEN]);

// Responder: build message 2 after a successful wg_consume_initiation, then
// derive the transport keys. 0 or -1
int wg_create_response(wg_handshake_t *hs, uint32_t local_index,
                       const uint8_t e_priv[WG_KEY_LEN], uint8_t msg[WG_MSG_RESP_LEN]);

// Initiator: check message 2 against the initiation in hs, then derive the
// transport keys. 0, or -1 (hs is left as it was)
int wg_consume_response(const wg_identity_t *id, wg_handshake_t *hs,
                        const uint8_t msg[WG_MSG_RESP_LEN]);

// TAI64N (12 bytes, big-endian): 2^62 + 10 + seconds, then nanoseconds
void wg_tai64n(uint8_t out[WG_TAI64N_LEN], uint64_t unix_seconds, uint32_t nanoseconds);

// Wipe the handshake's secrets (all of hs)
void wg_handshake_wipe(wg_handshake_t *hs);

#ifdef __cplusplus
}
#endif

#endif  // NOISE_H

// -----------------------------------------------------------------------------
// Project:     WireGuard-FPGA
// Description: NLnet-funded open-source implementation
// Funding:     https://nlnet.nl/project/KlusterLab-Wireguard (2023-12 to 2025-12)
// -----------------------------------------------------------------------------
