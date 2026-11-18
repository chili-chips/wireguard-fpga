# SPDX-FileCopyrightText: 2026 Chili.CHIPS
#
# SPDX-License-Identifier: BSD-3-Clause

# dpe_switch system bench: make [SIM=verilator], see ../sim.mk and tb.sv

VFLAGS = -Wno-MODDUP -Wno-PINCONNECTEMPTY -Wno-UNUSEDPARAM -Wno-UNUSEDSIGNAL -Wno-GENUNNAMED -Wno-DECLFILENAME -Wno-UNOPTFLAT
SRC_F  = tb.filelist
SRC    = tb.sv
PLAIN  = ../dpe_wg_encryptor/plaintext_mix.pcap

include ../sim.mk

# the input, built from the plaintext before the run (JanusHDL's sim does
# not go through compile)
compile sim: output/sys_in.pcap
output/sys_in.pcap: sys_check.py ../wg_check.py $(PLAIN)
	@mkdir -p output
	python3 sys_check.py gen $(PLAIN) $@

CHECK = @grep -q "RESULT: FAIL" output/sim.log && exit 1; \
	python3 sys_check.py check $(PLAIN) output/sys_out.pcap output/sys_meta.txt \
	&& echo "RESULT: PASS (dpe_switch: encrypted, decrypted, routed, dropped)" \
	|| { echo "RESULT: FAIL (output/sys_out.pcap, sys_meta.txt, see above)"; exit 1; }

# -----------------------------------------------------------------------------
# Project:     WireGuard-FPGA
# Description: NLnet-funded open-source implementation
# Funding:     https://nlnet.nl/project/KlusterLab-Wireguard (2023-12 to 2025-12)
# -----------------------------------------------------------------------------
