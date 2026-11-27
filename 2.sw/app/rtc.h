// SPDX-FileCopyrightText: 2026 Chili.CHIPS
//
// SPDX-License-Identifier: BSD-3-Clause

//==========================================================================
// The real-time clock (#30): csr.rtc (1.hw/ip.infra/rtc.sv), and a clock
// that only goes forward, also across a reboot, for the TAI64N timestamps
// of handshake initiations. There is no battery-backed clock: a high-water
// mark in the configuration flash, kept an hour ahead of the clock, is
// where the clock starts after a reboot. The scheme: 2.sw/README.md,
// "Timestamps across a reboot".
//==========================================================================

#ifndef RTC_H
#define RTC_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>

// the two flash sectors of the records: the top 8 KiB of the 16 MiB, far
// above the bitstream (xc7a200t: 9,730,652 bytes at most, to 0x947A5C)
#define RTC_FLASH_A       0xFFE000u
#define RTC_FLASH_B       0xFFF000u
#define RTC_EPOCH_DEFAULT 1767225600ull  // 2026-01-01 00:00:00 UTC: an empty flash
#define RTC_AHEAD_S       3600u          // the mark this far ahead of the clock
#define RTC_GUARD_S       60u            // a new mark when the clock is this close

// the hardware clock: seconds and nanoseconds, one atomic read
void rtc_get(uint64_t *sec, uint32_t *nsec);
void rtc_set(uint64_t sec, uint32_t nsec);

typedef struct {
    uint32_t flash_id;  // 0: no flash, the clock does not survive a reboot
    int      flash_ok;  // the last record write worked
    uint32_t boots;     // boots counted in the flash (1 on the first)
    uint32_t seq;       // records written, ever
    uint64_t mark;      // the high-water mark, seconds
} rtc_state_t;

// At boot, before the first timestamp: read the last record, start the
// clock at its mark, write the next record (boots + 1, mark + an hour).
// 0, or -1 without a flash (the clock then starts at RTC_EPOCH_DEFAULT)
int  rtc_boot(void);
// Call often (the main loop): a new mark before the clock reaches it
void rtc_poll(void);
// Set the time (the operator's): only forward. 0, or -1 (behind the clock)
int  rtc_set_time(uint64_t unix_seconds);
const rtc_state_t *rtc_state(void);

// TAI64N of now, strictly increasing, also across a reboot (with a flash)
void     rtc_now_tai64n(uint8_t ts[12]);
uint32_t rtc_now_seconds(void);  // the clock's seconds (low 32 bits): only forward

#ifdef __cplusplus
}
#endif

#endif  // RTC_H

// -----------------------------------------------------------------------------
// Project:     WireGuard-FPGA
// Description: NLnet-funded open-source implementation
// Funding:     https://nlnet.nl/project/KlusterLab-Wireguard (2023-12 to 2025-12)
// -----------------------------------------------------------------------------
