// SPDX-FileCopyrightText: 2026 Chili.CHIPS
//
// SPDX-License-Identifier: BSD-3-Clause

//==========================================================================
// The real-time clock and its high-water mark in the flash (rtc.h).
//
// A record (32 bytes, little-endian): magic, seq, boots, 0, mark (64-bit
// seconds), 0, FNV-1a of the 28 bytes before it. The records are appended
// to sector A or B, 128 per sector; a full sector continues at the start of
// the other one, erased first, so the newest record of the old one stays
// until then. At boot the valid record with the highest seq wins; a slot
// that is neither erased nor valid (power lost while programming) is
// skipped.
//==========================================================================

#include "rtc.h"
#include "flash.h"
#include "noise.h"
#include "csr_regs.h"

#define REC_MAGIC 0x53544757u  // "WGTS"
#define REC_LEN   32u
#define REC_SLOTS (FLASH_SECTOR / REC_LEN)

static rtc_state_t st;
static uint32_t    sector;  // where the newest record is
static uint32_t    slot;    // the next free slot in it (REC_SLOTS: full)
static uint64_t    last_sec;
static uint32_t    last_nsec;

// ---- the hardware clock ----------------------------------------------------

static void rtc_read(uint64_t *sec, uint32_t *nsec) {
    uint32_t ns = CSR_GET(rtc.nsec, CSR__RTC__NSEC__NSEC);  // first: latches the seconds
    uint32_t lo = CSR_REG32(rtc.sec_lo);
    uint32_t hi = CSR_REG32(rtc.sec_hi);
    *sec        = ((uint64_t)hi << 32) | lo;
    *nsec       = ns;
}

// Read twice: another reader of csr.rtc.nsec (the UART bus master) between
// our nsec and seconds reads latches the seconds anew, maybe past a carry.
// Two reads in the same second, the second one later, are not torn
void rtc_get(uint64_t *sec, uint32_t *nsec) {
    uint64_t s1, s2;
    uint32_t n1, n2;
    rtc_read(&s1, &n1);
    for (int i = 0; i < 4; i++) {
        rtc_read(&s2, &n2);
        if (s2 == s1 && n2 >= n1) break;
        s1 = s2;
        n1 = n2;
    }
    *sec  = s1;
    *nsec = n1;
}

void rtc_set(uint64_t sec, uint32_t nsec) {
    CSR_REG32(rtc.set_nsec)   = nsec % 1000000000u;
    CSR_REG32(rtc.set_sec_lo) = (uint32_t)sec;
    CSR_REG32(rtc.set_sec_hi) = (uint32_t)(sec >> 32);
    CSR_REG32(rtc.ctrl)       = CSR__RTC__CTRL__LOAD_bm;
}

// ---- the records -------------------------------------------------------------

static uint32_t get32(const uint8_t *p) {
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8) | ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}

static void put32(uint8_t *p, uint32_t v) {
    for (int i = 0; i < 4; i++) p[i] = (uint8_t)(v >> (8 * i));
}

static uint32_t fnv1a(const uint8_t *p, uint32_t n) {
    uint32_t h = 2166136261u;
    for (uint32_t i = 0; i < n; i++) h = (h ^ p[i]) * 16777619u;
    return h;
}

static int erased(const uint8_t *r) {
    for (uint32_t i = 0; i < REC_LEN; i++) {
        if (r[i] != 0xFF) return 0;
    }
    return 1;
}

static int valid(const uint8_t *r) {
    return get32(r) == REC_MAGIC && get32(r + 28) == fnv1a(r, 28);
}

// the newest record: 1 and st filled, or 0 (none); sector and slot set
static int scan(void) {
    static const uint32_t sec_addr[2] = {RTC_FLASH_A, RTC_FLASH_B};
    uint8_t r[REC_LEN];
    int     found = 0;
    for (int s = 0; s < 2; s++) {
        uint32_t used = 0;  // slots up to the last one not erased
        int      best = 0;  // this sector holds the newest record
        for (uint32_t i = 0; i < REC_SLOTS; i++) {
            flash_read(sec_addr[s] + i * REC_LEN, r, REC_LEN);
            if (!erased(r)) used = i + 1;
            if (valid(r) && (!found || (int32_t)(get32(r + 4) - st.seq) > 0)) {
                found    = 1;
                best     = 1;
                st.seq   = get32(r + 4);
                st.boots = get32(r + 8);
                st.mark  = ((uint64_t)get32(r + 20) << 32) | get32(r + 16);
            }
        }
        if (best) {
            sector = sec_addr[s];
            slot   = used;
        }
    }
    if (!found) {  // the first record goes to A, erased first
        sector = RTC_FLASH_B;
        slot   = REC_SLOTS;
    }
    return found;
}

// append a record with st's seq, boots and mark: 0, or -1
static int put_record(void) {
    uint8_t r[REC_LEN];
    put32(r + 0, REC_MAGIC);
    put32(r + 4, st.seq);
    put32(r + 8, st.boots);
    put32(r + 12, 0);
    put32(r + 16, (uint32_t)st.mark);
    put32(r + 20, (uint32_t)(st.mark >> 32));
    put32(r + 24, 0);
    put32(r + 28, fnv1a(r, 28));
    if (slot >= REC_SLOTS) {  // full: on to the other sector
        sector = (sector == RTC_FLASH_A) ? RTC_FLASH_B : RTC_FLASH_A;
        slot   = 0;
        if (flash_erase_sector(sector) != 0) return -1;
    }
    uint32_t a = sector + slot * REC_LEN;
    slot++;  // a failed slot is not used again
    if (flash_program(a, r, REC_LEN) != 0) return -1;
    uint8_t back[REC_LEN];
    flash_read(a, back, REC_LEN);
    return valid(back) ? 0 : -1;
}

static void new_mark(uint64_t now) {
    st.mark = now + RTC_AHEAD_S;
    st.seq++;
    if (st.flash_id) st.flash_ok = (put_record() == 0);
}

// ---- the persistent clock -------------------------------------------------------

int rtc_boot(void) {
    uint64_t start = RTC_EPOCH_DEFAULT;
    st.flash_ok    = 0;
    st.boots       = 0;
    st.seq         = 0;
    st.flash_id    = (flash_init() == 0) ? flash_id() : 0;
    if (st.flash_id && scan()) start = st.mark;  // every older timestamp is below it
    st.boots++;
    new_mark(start);  // written before the clock starts
    rtc_set(start, 0);
    last_sec  = start;
    last_nsec = 0;
    return st.flash_id ? 0 : -1;
}

void rtc_poll(void) {
    uint64_t sec;
    uint32_t nsec;
    rtc_get(&sec, &nsec);
    if (sec + RTC_GUARD_S >= st.mark) new_mark(sec);
}

int rtc_set_time(uint64_t unix_seconds) {
    uint64_t sec;
    uint32_t nsec;
    rtc_get(&sec, &nsec);
    if (unix_seconds <= sec) return -1;  // a peer keeps our newest timestamp
    new_mark(unix_seconds);
    rtc_set(unix_seconds, 0);
    return 0;
}

const rtc_state_t *rtc_state(void) { return &st; }

void rtc_now_tai64n(uint8_t ts[12]) {
    uint64_t sec;
    uint32_t nsec;
    rtc_poll();
    rtc_get(&sec, &nsec);
    // strictly increasing, whatever the clock does
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
