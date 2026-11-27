# SPDX-FileCopyrightText: 2026 Chili.CHIPS
#
# SPDX-License-Identifier: BSD-3-Clause

# flash_spi + rtc unit bench (#30): make [SIM=verilator|icarus|janushdl], see ../sim.mk

VFLAGS = -Wno-PINCONNECTEMPTY -Wno-UNUSEDPARAM -Wno-UNUSEDSIGNAL -Wno-GENUNNAMED -Wno-DECLFILENAME \
         -Wno-UNDRIVEN -Wno-WIDTHEXPAND -Wno-WIDTHTRUNC -Wno-MULTIDRIVEN -Wno-BLKSEQ -Wno-CMPCONST
SRC_F  = tb.filelist
SRC    = tb.sv

include ../sim.mk

# -----------------------------------------------------------------------------
# Project:     WireGuard-FPGA
# Description: NLnet-funded open-source implementation
# Funding:     https://nlnet.nl/project/KlusterLab-Wireguard (2023-12 to 2025-12)
# -----------------------------------------------------------------------------
