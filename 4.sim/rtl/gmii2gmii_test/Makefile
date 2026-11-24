# SPDX-FileCopyrightText: 2026 Chili.CHIPS*ba
#
# SPDX-License-Identifier: BSD-3-Clause

# gmii2gmii_test block-level bench: make [SIM=verilator|icarus|janushdl], see ../sim.mk

VFLAGS = -Wall -Wno-SPECIFYIGN -Wno-PINCONNECTEMPTY -Wno-UNUSEDPARAM -Wno-GENUNNAMED
SRC_F  = ${HW_SRC}/top.filelist
# the Xilinx primitives the MAC instantiates, and glbl
SRC    = $(addprefix ${SIM_SRC}/models/no-change/,BUFG.v BUFGMUX.v ODDR.v glbl.v) tb.sv

include ../sim.mk

# -----------------------------------------------------------------------------
# Project:     WireGuard-FPGA
# Description: NLnet-funded open-source implementation
# Funding:     https://nlnet.nl/project/KlusterLab-Wireguard (2023-12 to 2025-12)
# -----------------------------------------------------------------------------
