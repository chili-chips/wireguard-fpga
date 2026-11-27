# SPDX-FileCopyrightText: 2026 Chili.CHIPS
#
# SPDX-License-Identifier: BSD-3-Clause

# TRNG unit bench (1.hw/ip.infra/trng): make [SIM=verilator|icarus|janushdl],
# see ../sim.mk

VFLAGS = -Wno-UNUSEDPARAM -Wno-GENUNNAMED -Wno-DECLFILENAME --no-sched-zero-delay
SRC_F  = tb.filelist
SRC    = tb.sv
# the ring model (PLUSARGS=+trng_rings=1) has ps stage delays
TIMESCALE = 1ns/1ps

include ../sim.mk

# -----------------------------------------------------------------------------
# Project:     WireGuard-FPGA
# Description: NLnet-funded open-source implementation
# Funding:     https://nlnet.nl/project/KlusterLab-Wireguard (2023-12 to 2025-12)
# -----------------------------------------------------------------------------
