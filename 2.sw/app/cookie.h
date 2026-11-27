// SPDX-FileCopyrightText: 2026 Chili.CHIPS
//
// SPDX-License-Identifier: BSD-3-Clause

//==========================================================================
// WireGuard cookies (WireGuard paper, section 5.4.7; wireguard.com/protocol):
// the DoS defence of the handshake. A responder under load answers a message
// 1 or 2 that has a valid mac1 but no valid mac2 with a cookie reply
// (message 3) instead of doing the DH work. The cookie is bound to the
// sender's IP address and port, so only a sender that receives at that
// address can put it in mac2 of its next message.
//
//   responder: cookie = MAC(secret, ip || port), the secret redrawn every
//              2 minutes; message 3 = XAEAD(HASH("cookie--" || our static
//              public key), random nonce, cookie, AAD = mac1 of the message)
//   initiator: keeps the cookie 115 s (120 s less latency) and then sends
//              mac2 = MAC(cookie, message up to mac2)
//   MAC = keyed BLAKE2s-128, HASH = BLAKE2s-256, XAEAD = XChaCha20-Poly1305
//
// Both sides apply to message 1 and 2 alike: a peer that sends message 2 can
// get a cookie reply too. Under-load detection is the caller's (a bool here).
// The address: ip = the 4 IPv4 source address bytes as in the IP header,
// port = the UDP source port as a number (sent big-endian, as on the wire).
//==========================================================================

#ifndef COOKIE_H
#define COOKIE_H

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

#define WG_COOKIE_LEN          16
#define WG_MSG_COOKIE          3
#define WG_MSG_COOKIE_LEN      64
#define WG_COOKIE_SECRET_AGE_S 120  // responder: a new secret after this
#define WG_COOKIE_VALID_S      115  // initiator: 120 s less 5 s latency, as Linux

// Seconds from any start, counting up; only differences are used, so it may
// wrap. Not defined here: wg_session.c (the real-time clock, #30), or a test
uint32_t wg_now_seconds(void);

// ---- responder: one per device -------------------------------------------

typedef struct {
    uint8_t  mac1_key[32];    // HASH("mac1----" || our static public key)
    uint8_t  cookie_key[32];  // HASH("cookie--" || our static public key)
    uint8_t  secret[32];      // the cookie secret, redrawn every 2 minutes
    uint32_t secret_time;     // wg_now_seconds() when it was drawn
    uint8_t  secret_set;
} wg_cookie_checker_t;

// wg_cookie_validate results
enum {
    WG_COOKIE_BAD        = -1,  // not message 1/2, or mac1 wrong: drop it
    WG_COOKIE_OK         = 0,   // go on with the handshake
    WG_COOKIE_SEND_REPLY = 1    // under load, no valid mac2: send message 3
};

// Set the keys from our static public key. The secret is drawn on first use
void wg_cookie_checker_init(wg_cookie_checker_t *c, const uint8_t our_pub[32]);

// 1 when msg is message 1 (148 B) or 2 (92 B) with a valid mac1, else 0
int wg_cookie_check_mac1(const wg_cookie_checker_t *c, const uint8_t *msg, size_t len);

// 1 when mac2 of message 1/2 is MAC(cookie of ip/port, msg up to mac2), else 0
int wg_cookie_check_mac2(wg_cookie_checker_t *c, const uint8_t *msg, size_t len,
                         const uint8_t ip[4], uint16_t port);

// Both checks in the right order: mac1 always, mac2 only when under_load
int wg_cookie_validate(wg_cookie_checker_t *c, const uint8_t *msg, size_t len,
                       const uint8_t ip[4], uint16_t port, int under_load);

// Message 3 that answers msg (message 1/2 from ip/port, mac1 already
// checked): receiver = msg's sender index, a random nonce. 0, or -1 when msg
// is not message 1/2
int wg_cookie_create_reply(wg_cookie_checker_t *c, uint8_t out[WG_MSG_COOKIE_LEN],
                           const uint8_t *msg, size_t len,
                           const uint8_t ip[4], uint16_t port);

// ---- initiator: one per peer ---------------------------------------------

typedef struct {
    uint8_t  cookie_key[32];             // HASH("cookie--" || peer's public key)
    uint8_t  cookie[WG_COOKIE_LEN];      // the last cookie the peer sent
    uint32_t cookie_time;                // when it came
    uint8_t  cookie_valid;
    uint8_t  last_mac1[WG_COOKIE_LEN];   // mac1 of our last message 1/2 to it
    uint8_t  mac1_sent;                  // a message 3 may answer last_mac1
} wg_cookie_t;

// Set the key from the peer's static public key; no cookie yet
void wg_cookie_init(wg_cookie_t *c, const uint8_t peer_pub[32]);

// The receiver index of message 3: our sender index of the message it answers
// (find the peer with it). Check the length first
uint32_t wg_cookie_reply_receiver(const uint8_t msg[WG_MSG_COOKIE_LEN]);

// Take the cookie from message 3, which must answer our last message 1/2 to
// this peer (once). 0, or -1 (c unchanged). Do not resend at once: the next
// message 1/2 (the retransmit timer) carries mac2
int wg_cookie_consume_reply(wg_cookie_t *c, const uint8_t *msg, size_t len);

// Call on every message 1/2 to this peer after mac1, before sending: keeps
// mac1 for a cookie reply and sets mac2 (cookie under 115 s old) or zeros.
// 1 mac2 set, 0 mac2 zeros, -1 not message 1/2 (msg unchanged)
int wg_cookie_add_mac2(wg_cookie_t *c, uint8_t *msg, size_t len);

#ifdef __cplusplus
}
#endif

#endif  // COOKIE_H

// -----------------------------------------------------------------------------
// Project:     WireGuard-FPGA
// Description: NLnet-funded open-source implementation
// Funding:     https://nlnet.nl/project/KlusterLab-Wireguard (2023-12 to 2025-12)
// -----------------------------------------------------------------------------
