// SPDX-FileCopyrightText: 2026 Chili.CHIPS
//
// SPDX-License-Identifier: BSD-3-Clause

//==========================================================================
// Configuration flash driver (flash.h): the SPI commands over csr.flash,
// one byte per transfer. 03 READ, 06 WRITE ENABLE, 05 READ STATUS,
// 02 PAGE PROGRAM, 20 4 KiB ERASE, 9F READ ID: common to the N25Q128 and
// the W25Q parts.
//==========================================================================

#include "flash.h"
#include "timer.h"
#include "csr_regs.h"

#define CMD_READ   0x03
#define CMD_WREN   0x06
#define CMD_RDSR   0x05
#define CMD_PP     0x02
#define CMD_SE4K   0x20
#define CMD_RDID   0x9F
#define SR_WIP     0x01

#define READY_MS   10    // the start-up clocks take 2 us
#define PROG_MS    10    // page program: 5 ms at most
#define ERASE_MS   2000  // 4 KiB erase: 0.8 s at most

static uint32_t id;

static uint8_t xfer(uint8_t b) {
    CSR_REG32(flash.tx) = b;
    uint32_t s;
    do {
        s = CSR_REG32(flash.status);
    } while (s & CSR__FLASH__STATUS__BUSY_bm);
    return (uint8_t)RDL_FIELD(s, CSR__FLASH__STATUS__DATA);
}

static void sel(int on) { CSR_REG32(flash.ctrl) = on ? CSR__FLASH__CTRL__CS_bm : 0; }

static void cmd_addr(uint8_t cmd, uint32_t addr) {
    xfer(cmd);
    xfer((uint8_t)(addr >> 16));
    xfer((uint8_t)(addr >> 8));
    xfer((uint8_t)addr);
}

static void wren(void) {
    sel(1);
    xfer(CMD_WREN);
    sel(0);
}

static int wait_idle(uint32_t ms) {
    uint32_t t0 = cycles();
    for (;;) {
        sel(1);
        xfer(CMD_RDSR);
        uint8_t sr = xfer(0);
        sel(0);
        if (!(sr & SR_WIP)) return 0;
        if (cycles() - t0 > ms * CYCLES_PER_MS) return -1;
    }
}

int flash_init(void) {
    uint32_t t0 = cycles();
    id          = 0;
    while (!(CSR_REG32(flash.status) & CSR__FLASH__STATUS__READY_bm)) {
        if (cycles() - t0 > READY_MS * CYCLES_PER_MS) return -1;
    }
    sel(1);
    xfer(CMD_RDID);
    for (int i = 0; i < 3; i++) id = (id << 8) | xfer(0);
    sel(0);
    if (id == 0 || id == 0xFFFFFFu) {
        id = 0;
        return -1;
    }
    return 0;
}

uint32_t flash_id(void) { return id; }

void flash_read(uint32_t addr, uint8_t *buf, uint32_t n) {
    sel(1);
    cmd_addr(CMD_READ, addr);
    for (uint32_t i = 0; i < n; i++) buf[i] = xfer(0);
    sel(0);
}

int flash_erase_sector(uint32_t addr) {
    if (!id || addr >= FLASH_SIZE) return -1;
    wren();
    sel(1);
    cmd_addr(CMD_SE4K, addr);
    sel(0);
    return wait_idle(ERASE_MS);
}

int flash_program(uint32_t addr, const uint8_t *buf, uint32_t n) {
    if (!id || n == 0 || n > FLASH_PAGE || addr >= FLASH_SIZE) return -1;
    if ((addr % FLASH_PAGE) + n > FLASH_PAGE) return -1;  // it would wrap in the page
    wren();
    sel(1);
    cmd_addr(CMD_PP, addr);
    for (uint32_t i = 0; i < n; i++) xfer(buf[i]);
    sel(0);
    return wait_idle(PROG_MS);
}

// -----------------------------------------------------------------------------
// Project:     WireGuard-FPGA
// Description: NLnet-funded open-source implementation
// Funding:     https://nlnet.nl/project/KlusterLab-Wireguard (2023-12 to 2025-12)
// -----------------------------------------------------------------------------
