// SPDX-FileCopyrightText: 2026 Chili.CHIPS
//
// SPDX-License-Identifier: BSD-3-Clause

//==========================================================================
// Host stand-in for 3.build/csr_build/csr_regs.h, csr.rtc only: plain
// variables the test sets and reads. A read of nsec goes through
// fake_nsec_read(), so a test can change the seconds between the reads
//==========================================================================

#ifndef CSR_REGS_H
#define CSR_REGS_H
#include <stdint.h>

typedef struct {
    uint32_t nsec, sec_lo, sec_hi, set_nsec, set_sec_lo, set_sec_hi, ctrl;
} fake_rtc_t;
typedef struct {
    fake_rtc_t rtc;
} fake_csr_t;
extern fake_csr_t fake_csr;
uint32_t fake_nsec_read(void);

#define CSR_REG32(member)  (fake_csr.member)
#define CSR_GET(member, f) fake_nsec_read()
#define CSR__RTC__CTRL__LOAD_bm 1u

#endif

// -----------------------------------------------------------------------------
// Project:     WireGuard-FPGA
// Description: NLnet-funded open-source implementation
// Funding:     https://nlnet.nl/project/KlusterLab-Wireguard (2023-12 to 2025-12)
// -----------------------------------------------------------------------------
