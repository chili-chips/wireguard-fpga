// SPDX-FileCopyrightText: 2026 Chili.CHIPS
//
// SPDX-License-Identifier: BSD-3-Clause

//==========================================================================
// Peer map (see peer_map.h). A key's home slot is its SipHash, modulo the
// slot count; a lookup probes from there to the first empty slot. Removal
// shifts later entries of the same run back (no tombstones), so a run
// never holds a gap.
//==========================================================================

#include "peer_map.h"
#include "siphash.h"
#include "random.h"
#include "string_bare.h"

typedef struct {
    uint8_t pub[PEER_KEY_SIZE];
    uint8_t peer;
    uint8_t used;
} peer_slot_t;

static peer_slot_t slots[PEER_MAP_SLOTS];
static uint8_t     sip_key[SIPHASH_KEY_SIZE];
static int         count;

static unsigned home(const uint8_t pub[PEER_KEY_SIZE]) {
    return (unsigned)siphash24(sip_key, pub, PEER_KEY_SIZE) & (PEER_MAP_SLOTS - 1);
}

// Equal keys, in a time that does not depend on where they differ
static int key_equal(const uint8_t a[PEER_KEY_SIZE], const uint8_t b[PEER_KEY_SIZE]) {
    uint8_t diff = 0;
    for (int i = 0; i < PEER_KEY_SIZE; i++) {
        diff |= a[i] ^ b[i];
    }
    return diff == 0;
}

// The slot that holds pub, or -1; *free_slot: the empty slot ending its run
static int locate(const uint8_t pub[PEER_KEY_SIZE], unsigned *free_slot) {
    unsigned i = home(pub);
    for (int n = 0; n < PEER_MAP_SLOTS; n++, i = (i + 1) & (PEER_MAP_SLOTS - 1)) {
        if (!slots[i].used) {
            if (free_slot) *free_slot = i;
            return -1;
        }
        if (key_equal(slots[i].pub, pub)) return (int)i;
    }
    return -1;  // full table, not in it (cannot happen: at most half full)
}

void peer_map_init(void) {
    uint8_t seed[32];
    memset(slots, 0, sizeof(slots));
    count = 0;
    random_32bytes(seed);
    memcpy(sip_key, seed, SIPHASH_KEY_SIZE);
    memset(seed, 0, sizeof(seed));
}

int peer_map_set(const uint8_t pub[PEER_KEY_SIZE], uint8_t peer) {
    unsigned free_slot = 0;
    int i = locate(pub, &free_slot);
    if (i >= 0) {
        slots[i].peer = peer;
        return 0;
    }
    if (count >= PEER_MAP_PEERS) return -1;
    memcpy(slots[free_slot].pub, pub, PEER_KEY_SIZE);
    slots[free_slot].peer = peer;
    slots[free_slot].used = 1;
    count++;
    return 0;
}

int peer_map_find(const uint8_t pub[PEER_KEY_SIZE]) {
    int i = locate(pub, 0);
    return (i < 0) ? -1 : slots[i].peer;
}

void peer_map_remove(const uint8_t pub[PEER_KEY_SIZE]) {
    int found = locate(pub, 0);
    if (found < 0) return;
    unsigned gap = (unsigned)found;
    unsigned j = gap;
    memset(&slots[gap], 0, sizeof(slots[gap]));
    count--;
    // move back each later entry of the run whose home is not between the
    // gap and its own slot (cyclically): it would be unreachable otherwise
    for (;;) {
        j = (j + 1) & (PEER_MAP_SLOTS - 1);
        if (!slots[j].used) break;
        unsigned h = home(slots[j].pub);
        unsigned dist_j = (j - h) & (PEER_MAP_SLOTS - 1);    // how far j is from home
        unsigned dist_gap = (j - gap) & (PEER_MAP_SLOTS - 1);  // how far j is from the gap
        if (dist_j >= dist_gap) {
            slots[gap] = slots[j];
            memset(&slots[j], 0, sizeof(slots[j]));
            gap = j;
        }
    }
}

int peer_map_count(void) {
    return count;
}

// -----------------------------------------------------------------------------
// Project:     WireGuard-FPGA
// Description: NLnet-funded open-source implementation
// Funding:     https://nlnet.nl/project/KlusterLab-Wireguard (2023-12 to 2025-12)
// -----------------------------------------------------------------------------
