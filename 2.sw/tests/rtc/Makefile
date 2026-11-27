# SPDX-FileCopyrightText: 2026 Chili.CHIPS
#
# SPDX-License-Identifier: BSD-3-Clause

# Host test of the clock's high-water mark in the flash (2.sw/app/rtc.c), on
# Linux/WSL, against an in-memory NOR flash (rtc_host.c):
#   make test      first boot, reboots, both sector switches, a torn slot,
#                  a failed program, seq wrap, no flash, a torn clock read
APP    = ../../app
OUT    = build
CC     = gcc
CFLAGS = -O1 -g -Wall -Wextra -fsanitize=address,undefined -I. -I$(APP)

.PHONY: all test clean
all: test

$(OUT)/rtc_host: rtc_host.c csr_regs.h $(APP)/rtc.c $(APP)/rtc.h $(APP)/flash.h
	@mkdir -p $(OUT)
	$(CC) $(CFLAGS) rtc_host.c $(APP)/rtc.c -o $@

test: $(OUT)/rtc_host
	$(OUT)/rtc_host

clean:
	rm -rf $(OUT)

# -----------------------------------------------------------------------------
# Project:     WireGuard-FPGA
# Description: NLnet-funded open-source implementation
# Funding:     https://nlnet.nl/project/KlusterLab-Wireguard (2023-12 to 2025-12)
# -----------------------------------------------------------------------------
