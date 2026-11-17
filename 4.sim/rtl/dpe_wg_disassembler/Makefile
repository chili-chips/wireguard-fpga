# SPDX-FileCopyrightText: 2026 Chili.CHIPS*ba
#
# SPDX-License-Identifier: BSD-3-Clause

# dpe_wg_disassembler block-level bench: make [SIM=verilator|icarus|janushdl], see ../sim.mk

VFLAGS = -Wall -Wno-PINCONNECTEMPTY -Wno-UNUSEDPARAM -Wno-GENUNNAMED
SRC_F  = ${HW_SRC}/top.filelist
SRC    = ${HW_SRC}/ip.dpe/dpe_wg_disassembler.sv tb.sv

include ../sim.mk
