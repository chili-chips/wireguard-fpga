# SPDX-FileCopyrightText: 2026 Chili.CHIPS*ba
#
# SPDX-License-Identifier: BSD-3-Clause

# pcap_reader_writer block-level bench: make [SIM=verilator|icarus|janushdl], see ../sim.mk

VFLAGS = -Wall -Wno-PINCONNECTEMPTY -Wno-UNUSEDPARAM -Wno-UNUSEDSIGNAL -Wno-GENUNNAMED
SRC_F  = tb.filelist
SRC    = tb.sv

include ../sim.mk

# Self-checking: the frames read from test1.pcap must come back out of the
# writer the same (timestamps aside; a packet captured short at its wire length)
CHECK = @python3 ../pcap_same.py --replay test1.pcap output/test2.pcap \
	&& echo "RESULT: PASS (test1.pcap through reader and writer)" \
	|| { echo "RESULT: FAIL (output/test2.pcap differs from test1.pcap)"; exit 1; }
