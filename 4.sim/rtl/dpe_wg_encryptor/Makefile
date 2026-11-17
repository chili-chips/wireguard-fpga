# SPDX-FileCopyrightText: 2026 Chili.CHIPS*ba
#
# SPDX-License-Identifier: BSD-3-Clause

# dpe_wg_encryptor block-level bench: make [SIM=verilator|icarus|janushdl], see ../sim.mk

VFLAGS = -Wno-PINCONNECTEMPTY -Wno-UNUSEDPARAM -Wno-UNUSEDSIGNAL -Wno-GENUNNAMED -Wno-DECLFILENAME -Wno-UNOPTFLAT
SRC_F  = tb.filelist
SRC    = tb.sv

include ../sim.mk

# Self-checking by its output: under stalls on both sides, each frame of
# plaintext_mix.pcap must come out as the WireGuard frame ../wg_check.py builds
CHECK = @python3 ../wg_check.py enc plaintext_mix.pcap output/ciphertext_mix.pcap \
	&& echo "RESULT: PASS (WireGuard frames of plaintext_mix.pcap)" \
	|| { echo "RESULT: FAIL (output/ciphertext_mix.pcap, see above)"; exit 1; }

# -----------------------------------------------------------------------------
# Project:     WireGuard-FPGA
# Description: NLnet-funded open-source implementation
# Funding:     https://nlnet.nl/project/KlusterLab-Wireguard (2023-12 to 2025-12)
# -----------------------------------------------------------------------------
