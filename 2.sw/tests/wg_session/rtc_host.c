// SPDX-FileCopyrightText: 2026 Chili.CHIPS
//
// SPDX-License-Identifier: BSD-3-Clause

// Host stand-in for 2.sw/app/rtc.c (no csr.rtc, no flash): the clock starts
// at RTC_EPOCH_DEFAULT (an empty flash) when the test starts and runs on
// CLOCK_MONOTONIC; rtc_set_time only moves it forward; the timestamps
// strictly increase, as on the device. rtc_host_advance_ms() lets time pass.
#include <time.h>
#include "rtc.h"
#include "noise.h"

static uint64_t base_ns;     // CLOCK_MONOTONIC at the first call
static uint64_t offset_s = RTC_EPOCH_DEFAULT;
static uint64_t skip_ns;     // rtc_host_advance_ms: time passing, faster
static uint64_t last_sec;
static uint32_t last_nsec;

static uint64_t mono_ns(void) {
    struct timespec t;
    clock_gettime(CLOCK_MONOTONIC, &t);
    return (uint64_t)t.tv_sec * 1000000000ull + (uint64_t)t.tv_nsec;
}

void rtc_get(uint64_t *sec, uint32_t *nsec) {
    if (base_ns == 0) base_ns = mono_ns();
    uint64_t ns = mono_ns() - base_ns + skip_ns;
    *sec        = offset_s + ns / 1000000000ull;
    *nsec       = (uint32_t)(ns % 1000000000ull);
}

// the timer tests (#80): let ms pass at once, as the hardware clock would
// (not a clock set: the timers see it)
void rtc_host_advance_ms(uint64_t ms) { skip_ns += ms * 1000000ull; }

int rtc_set_time(uint64_t unix_seconds) {
    uint64_t sec;
    uint32_t nsec;
    rtc_get(&sec, &nsec);
    if (unix_seconds <= sec) return -1;
    offset_s += unix_seconds - sec;
    return 0;
}

void rtc_now_tai64n(uint8_t ts[12]) {
    uint64_t sec;
    uint32_t nsec;
    rtc_get(&sec, &nsec);
    if (sec < last_sec || (sec == last_sec && nsec <= last_nsec)) {
        sec  = last_sec;
        nsec = last_nsec + 1;
        if (nsec >= 1000000000u) {
            sec++;
            nsec = 0;
        }
    }
    last_sec  = sec;
    last_nsec = nsec;
    wg_tai64n(ts, sec, nsec);
}

uint32_t rtc_now_seconds(void) {
    uint64_t sec;
    uint32_t nsec;
    rtc_get(&sec, &nsec);
    return (uint32_t)sec;
}

// -----------------------------------------------------------------------------
// Project:     WireGuard-FPGA
// Description: NLnet-funded open-source implementation
// Funding:     https://nlnet.nl/project/KlusterLab-Wireguard (2023-12 to 2025-12)
// -----------------------------------------------------------------------------
