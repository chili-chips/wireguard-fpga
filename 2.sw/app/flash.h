// SPDX-FileCopyrightText: 2026 Chili.CHIPS
//
// SPDX-License-Identifier: BSD-3-Clause

//==========================================================================
// The configuration flash (#30): N25Q128 on the AX7201's core board,
// 16 MiB, x1 SPI through csr.flash (1.hw/ip.infra/flash_spi.sv), 3-byte
// addresses, so the first 16 MiB of a larger part too. The bitstream sits
// at 0; see 2.sw/README.md for the sectors the firmware keeps for itself.
//==========================================================================

#ifndef FLASH_H
#define FLASH_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>

#define FLASH_SIZE   0x1000000u  // 16 MiB
#define FLASH_SECTOR 4096u       // the smallest erase
#define FLASH_PAGE   256u        // the most one program takes

// Wait for the controller (its start-up clocks), read the JEDEC ID: 0, or
// -1 when no flash answers (ID 00 00 00 or FF FF FF)
int      flash_init(void);
uint32_t flash_id(void);  // the JEDEC ID flash_init read, e.g. 0x20BA18

void flash_read(uint32_t addr, uint8_t *buf, uint32_t n);
// Erase the 4 KiB sector addr is in / program n bytes (one page at most,
// not across a page boundary; bits only go 1 -> 0). 0, or -1 on a timeout
// or a bad argument
int  flash_erase_sector(uint32_t addr);
int  flash_program(uint32_t addr, const uint8_t *buf, uint32_t n);

#ifdef __cplusplus
}
#endif

#endif  // FLASH_H

// -----------------------------------------------------------------------------
// Project:     WireGuard-FPGA
// Description: NLnet-funded open-source implementation
// Funding:     https://nlnet.nl/project/KlusterLab-Wireguard (2023-12 to 2025-12)
// -----------------------------------------------------------------------------
