# SPDX-FileCopyrightText: 2026 Chili.CHIPS
#
# SPDX-License-Identifier: BSD-3-Clause

# dpe_switch system bench: make [SIM=verilator], see ../sim.mk and tb.sv

VFLAGS = -Wno-PINCONNECTEMPTY -Wno-UNUSEDPARAM -Wno-UNUSEDSIGNAL -Wno-GENUNNAMED -Wno-DECLFILENAME -Wno-UNOPTFLAT
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

# Throughput: N frames of CASE back to back, no stalls (tb.sv PERF); prints
# the clocks per frame, in and out, and checks the output byte for byte.
#   make perf CASE=dec1420      CASE: enc|dec|mix and the inner IPv4 bytes
# It leaves a PERF build in output/; make sim builds the normal bench again.
CASE ?= enc1420
N    ?= 24
.PHONY: perf
perf: unpack
	@mkdir -p output
	python3 sys_check.py perf $(PLAIN) $(CASE) $(N) output/perf_in.pcap output/perf_want.pcap
	$(MAKE) compile VFLAGS="$(VFLAGS) -GPASS_PCT=100 -GPERF=1"
	cp output/perf_in.pcap output/sys_in.pcap
	cd output && make -f V$(TB_NAME).mk V$(TB_NAME) && ./V$(TB_NAME) | tee sim.log
	@rm -f output/sys_in.pcap  # make sim makes its own again
	@grep -q "RESULT: FAIL" output/sim.log && exit 1; \
	python3 sys_check.py same output/sys_out.pcap output/perf_want.pcap
	@grep "^PERF" output/sim.log

CHECK = @grep -q "RESULT: FAIL" output/sim.log && exit 1; \
	python3 sys_check.py check $(PLAIN) output/sys_out.pcap output/sys_meta.txt \
	&& echo "RESULT: PASS (dpe_switch: encrypted, decrypted, routed, dropped)" \
	|| { echo "RESULT: FAIL (output/sys_out.pcap, sys_meta.txt, see above)"; exit 1; }

# -----------------------------------------------------------------------------
# Project:     WireGuard-FPGA
# Description: NLnet-funded open-source implementation
# Funding:     https://nlnet.nl/project/KlusterLab-Wireguard (2023-12 to 2025-12)
# -----------------------------------------------------------------------------
