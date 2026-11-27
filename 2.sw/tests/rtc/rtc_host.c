// SPDX-FileCopyrightText: 2026 Chili.CHIPS
//
// SPDX-License-Identifier: BSD-3-Clause

//==========================================================================
// Host test of 2.sw/app/rtc.c: the clock's high-water mark in the flash.
// The flash is an in-memory NOR array (erase sets 0xFF, program only clears
// bits), with a torn and a failing program on request; csr.rtc is plain
// variables (csr_regs.h here). A "reboot" is rtc_boot() again: it forgets
// everything but the flash.
//==========================================================================

#include <stdio.h>
#include <string.h>
#include "rtc.h"
#include "flash.h"
#include "csr_regs.h"

static int fails, checks;
static void check(const char *what, int ok) {
    checks++;
    if (!ok) {
        fails++;
        printf("FAIL %s\n", what);
    }
}

// ---- the flash ---------------------------------------------------------------
static uint8_t  mem[2][FLASH_SECTOR];  // sectors A and B: all rtc.c uses
static int      present  = 1;
static int      torn     = 0;  // the next program writes only half
static int      prog_err = 0;  // the next program fails
static int      erases, progs;
static uint8_t *at(uint32_t a) {
    if (a >= RTC_FLASH_A && a < RTC_FLASH_A + FLASH_SECTOR) return &mem[0][a - RTC_FLASH_A];
    if (a >= RTC_FLASH_B && a < RTC_FLASH_B + FLASH_SECTOR) return &mem[1][a - RTC_FLASH_B];
    printf("FAIL access outside the record sectors: 0x%06x\n", a);
    fails++;
    return NULL;
}
int      flash_init(void) { return present ? 0 : -1; }
uint32_t flash_id(void) { return present ? 0x20BA18u : 0; }
void     flash_read(uint32_t a, uint8_t *buf, uint32_t n) {
    for (uint32_t i = 0; i < n; i++) buf[i] = *at(a + i);
}
int flash_erase_sector(uint32_t a) {
    erases++;
    memset(at(a), 0xFF, FLASH_SECTOR);
    return 0;
}
int flash_program(uint32_t a, const uint8_t *buf, uint32_t n) {
    progs++;
    if (prog_err) {
        prog_err = 0;
        return -1;
    }
    if (torn) {  // power lost halfway
        torn = 0;
        n /= 2;
    }
    for (uint32_t i = 0; i < n; i++) *at(a + i) &= buf[i];
    return 0;
}

// ---- noise.c's wg_tai64n, not needed here -------------------------------------
void wg_tai64n(uint8_t out[12], uint64_t sec, uint32_t nsec) {
    memset(out, 0, 12);
    (void)sec;
    (void)nsec;
}

// ---- csr.rtc ---------------------------------------------------------------------
fake_csr_t fake_csr;
// a scripted sequence of reads: {nsec, latched seconds}, else the clock as set
static struct { uint32_t ns; uint64_t sec; } script[8];
static int script_n, script_i;
uint32_t fake_nsec_read(void) {
    if (script_i < script_n) {
        fake_csr.rtc.sec_lo = (uint32_t)script[script_i].sec;
        fake_csr.rtc.sec_hi = (uint32_t)(script[script_i].sec >> 32);
        return script[script_i++].ns;
    }
    return fake_csr.rtc.nsec;
}
static void clock_at(uint64_t sec) {
    fake_csr.rtc.sec_lo = (uint32_t)sec;
    fake_csr.rtc.sec_hi = (uint32_t)(sec >> 32);
    fake_csr.rtc.nsec   = 0;
}
// the hardware's load: the clock takes the set_* registers
static uint64_t loaded(void) {
    uint64_t s = ((uint64_t)fake_csr.rtc.set_sec_hi << 32) | fake_csr.rtc.set_sec_lo;
    if (fake_csr.rtc.ctrl & CSR__RTC__CTRL__LOAD_bm) clock_at(s);
    fake_csr.rtc.ctrl = 0;
    return s;
}

// ---- records, as rtc.c writes them ------------------------------------------------
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
static void make_rec(int s, int slot, uint32_t seq, uint64_t mark) {
    uint8_t *r = &mem[s][slot * 32];
    memset(r, 0, 32);
    put32(r, 0x53544757u);
    put32(r + 4, seq);
    put32(r + 8, 1);
    put32(r + 16, (uint32_t)mark);
    put32(r + 20, (uint32_t)(mark >> 32));
    put32(r + 28, fnv1a(r, 28));
}
static int rec_valid(int s, int slot) {
    const uint8_t *r = &mem[s][slot * 32];
    return get32(r) == 0x53544757u && get32(r + 28) == fnv1a(r, 28);
}
static uint64_t rec_mark(int s, int slot) {
    const uint8_t *r = &mem[s][slot * 32];
    return ((uint64_t)get32(r + 20) << 32) | get32(r + 16);
}
static int slot_erased(int s, int slot) {
    for (int i = 0; i < 32; i++)
        if (mem[s][slot * 32 + i] != 0xFF) return 0;
    return 1;
}

static uint64_t boot(void) {
    rtc_boot();
    return loaded();
}

int main(void) {
    const rtc_state_t *st = rtc_state();
    memset(mem, 0xFF, sizeof(mem));

    // 1. first boot, an empty flash: A erased, the first record there
    uint64_t t = boot();
    check("first boot: the default epoch", t == RTC_EPOCH_DEFAULT);
    check("first boot: one erase, of A", erases == 1 && rec_valid(0, 0) && slot_erased(1, 0));
    check("first boot: seq 1, boot 1, the mark an hour ahead",
          st->seq == 1 && st->boots == 1 && st->mark == RTC_EPOCH_DEFAULT + RTC_AHEAD_S && st->flash_ok);

    // 2. a reboot starts at the mark, its record in the next slot
    uint64_t m = st->mark;
    t = boot();
    check("reboot: starts at the mark", t == m);
    check("reboot: boot 2, slot 1", st->boots == 2 && rec_valid(0, 1) && rec_mark(0, 1) == m + RTC_AHEAD_S);

    // 3. an hour of uptime per record, until both sectors have filled once
    //    (records 1 to 128 in A, 129 to 256 in B, 257 on in A again)
    int ok = 1, a_kept = 1;
    for (int n = 3; n <= 300; n++) {
        clock_at(st->mark - RTC_GUARD_S);  // just inside the guard
        rtc_poll();
        if (st->seq != (uint32_t)n || !st->flash_ok) ok = 0;
        // when B takes its first record, A still holds all 128 of its own
        if (n == 129) {
            for (int i = 0; i < 128; i++) a_kept &= rec_valid(0, i);
            a_kept &= rec_valid(1, 0);
        }
    }
    check("300 records written", ok);
    check("A kept until B had its first record", a_kept);
    check("erases: A, B, A again", erases == 3);
    check("record 300 in A slot 43", rec_valid(0, 43) && slot_erased(0, 44) && rec_valid(1, 127));
    m = st->mark;
    uint32_t boots = st->boots;
    t = boot();
    check("reboot after 300: the newest mark, the next slot",
          t == m && st->boots == boots + 1 && rec_valid(0, 44));

    // 4. a torn record (power lost while programming): skipped at boot
    m = st->mark;
    torn = 1;
    clock_at(st->mark - RTC_GUARD_S);
    rtc_poll();
    check("torn record: refused", !st->flash_ok && !rec_valid(0, 45) && !slot_erased(0, 45));
    t = boot();
    check("torn record: boot from the one before, the slot after it", t == m && rec_valid(0, 46));

    // 5. a program that fails: reported, the boot after uses the last good one
    m = st->mark;
    prog_err = 1;
    clock_at(st->mark - RTC_GUARD_S);
    rtc_poll();
    check("failed program: refused", !st->flash_ok);
    t = boot();
    check("failed program: boot from the last good mark", t == m);

    // 6. the seq wraps: 0 and 1 in B are newer than 0xFFFFFFFE, 0xFFFFFFFF in A
    memset(mem, 0xFF, sizeof(mem));
    make_rec(0, 0, 0xFFFFFFFEu, 1000);
    make_rec(0, 1, 0xFFFFFFFFu, 2000);
    make_rec(1, 0, 0u, 3000);
    make_rec(1, 1, 1u, 4000);
    t = boot();
    check("seq wrap: the newest is seq 1", t == 4000 && st->seq == 2 && rec_valid(1, 2));

    // 7. no flash: the default epoch on every boot, no flash access
    present   = 0;
    int p0    = progs, e0 = erases;
    t         = boot();
    check("no flash: the default epoch", t == RTC_EPOCH_DEFAULT && !st->flash_ok && st->flash_id == 0);
    check("no flash: no program, no erase", progs == p0 && erases == e0);
    present = 1;

    // 8. setting the time: only forward, the mark written first
    boot();
    clock_at(5000);
    check("set back: refused", rtc_set_time(4999) == -1);
    check("set forward", rtc_set_time(1800000000ull) == 0 && st->mark == 1800000000ull + RTC_AHEAD_S &&
          loaded() == 1800000000ull);

    // 9. a torn read: another reader's nsec read between ours and the seconds
    //    latched them past the carry; the second read shows it, the third agrees
    uint64_t sec;
    uint32_t ns;
    script[0].ns = 999999990u, script[0].sec = 7;  // torn: 7.999999990 for 6.999999990
    script[1].ns = 5u, script[1].sec = 7;
    script[2].ns = 10u, script[2].sec = 7;
    script_n = 3, script_i = 0;
    rtc_get(&sec, &ns);
    check("torn read: not taken", sec == 7 && ns == 5);
    script_n = 0;

    printf("%s %d checks (%d failed)\n", fails ? "FAIL" : "PASS", checks, fails);
    return fails ? 1 : 0;
}

// -----------------------------------------------------------------------------
// Project:     WireGuard-FPGA
// Description: NLnet-funded open-source implementation
// Funding:     https://nlnet.nl/project/KlusterLab-Wireguard (2023-12 to 2025-12)
// -----------------------------------------------------------------------------
