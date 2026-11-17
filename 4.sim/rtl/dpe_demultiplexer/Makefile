# SPDX-FileCopyrightText: 2026 Chili.CHIPS*ba
#
# SPDX-License-Identifier: BSD-3-Clause

# dpe_demultiplexer block-level bench: make [SIM=verilator|icarus|janushdl], see ../sim.mk

VFLAGS = -Wall -Wno-PINCONNECTEMPTY -Wno-UNUSEDPARAM -Wno-GENUNNAMED
SRC_F  = tb.filelist
SRC    = ../dpe_tb_pkg.sv ../dpe_tb_src.sv ../dpe_tb_sink.sv tb.sv

include ../sim.mk
