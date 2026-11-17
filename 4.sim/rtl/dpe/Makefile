# SPDX-FileCopyrightText: 2026 Chili.CHIPS*ba
#
# SPDX-License-Identifier: BSD-3-Clause

# dpe block-level bench: make [SIM=verilator|icarus|janushdl], see ../sim.mk

VFLAGS = -Wall -Wno-PINCONNECTEMPTY -Wno-UNUSEDPARAM -Wno-GENUNNAMED
SRC_F  = ${HW_SRC}/top.filelist
SRC    = ../dpe_tb_pkg.sv ../dpe_tb_src.sv ../dpe_tb_sink.sv tb.sv

include ../sim.mk

# -----------------------------------------------------------------------------
# Project:     WireGuard-FPGA
# Description: NLnet-funded open-source implementation
# Funding:     https://nlnet.nl/project/KlusterLab-Wireguard (2023-12 to 2025-12)
# -----------------------------------------------------------------------------
