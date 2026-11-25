// SPDX-FileCopyrightText: 2026 Chili.CHIPS
//
// SPDX-License-Identifier: BSD-3-Clause

//==========================================================================
// Peer map: a peer's static public key (32 bytes) to its peer-table index.
// The handshake responder decrypts the initiator's static key and looks the
// peer up here. A hash table keyed with SipHash-2-4 under a random secret
// key: lookups stay short whatever keys an attacker sends (no hash flooding).
// Open addressing, linear probing, twice as many slots as peers.
//==========================================================================

#ifndef PEER_MAP_H
#define PEER_MAP_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define PEER_MAP_PEERS 64                    // the peer table's entries
#define PEER_MAP_SLOTS (2 * PEER_MAP_PEERS)  // a power of two
#define PEER_KEY_SIZE  32

// Empty the map and draw a new secret SipHash key (random_32bytes)
void peer_map_init(void);

// Map pub to peer (adds it, or moves it to a new peer). 0, or -1 when full
int peer_map_set(const uint8_t pub[PEER_KEY_SIZE], uint8_t peer);

// The peer of pub, or -1
int peer_map_find(const uint8_t pub[PEER_KEY_SIZE]);

// Forget pub (nothing when it is not in the map)
void peer_map_remove(const uint8_t pub[PEER_KEY_SIZE]);

// Entries in the map
int peer_map_count(void);

#ifdef __cplusplus
}
#endif

#endif

// -----------------------------------------------------------------------------
// Project:     WireGuard-FPGA
// Description: NLnet-funded open-source implementation
// Funding:     https://nlnet.nl/project/KlusterLab-Wireguard (2023-12 to 2025-12)
// -----------------------------------------------------------------------------
