# SPDX-FileCopyrightText: 2026 Chili.CHIPS
#
# SPDX-License-Identifier: BSD-3-Clause

# dpe_wg_decryptor loopback bench (encryptor -> decryptor): make [SIM=verilator|icarus|janushdl], see ../sim.mk

# LOOPBACK=0: wg_mix.pcap instead of the encryptor: RFC 8439 frames, then a keepalive,
# an authentic packet whose IPv4 length is over its plaintext, one too long for
# the core, one longer than its IPv4 length says (7 KB more; all four dropped,
# the core must not overfill) and one more good frame. Remake it with
#   python3 ../wg_check.py wgx wg_mix.pcap ../dpe_wg_encryptor/plaintext_mix.pcap
LOOPBACK ?= 1
VFLAGS = -GLOOPBACK=$(LOOPBACK) -Wno-PINCONNECTEMPTY -Wno-UNUSEDPARAM -Wno-UNUSEDSIGNAL -Wno-GENUNNAMED -Wno-DECLFILENAME -Wno-UNOPTFLAT
SRC_F  = tb.filelist
SRC    = tb.sv

include ../sim.mk

# Self-checking by its output: under stalls on every link, each frame of the
# encryptor bench's plaintext_mix.pcap must come back, except frame 3, whose
# ciphertext the bench corrupts (tb.sv: CORRUPT_FRAME)
CHECK = @python3 ../wg_check.py $(if $(filter 0,$(LOOPBACK)),decx,dec) ../dpe_wg_encryptor/plaintext_mix.pcap output/decrypted_mix.pcap 3 \
	&& echo "RESULT: PASS (plaintext_mix.pcap back, corrupted frame 3 dropped)" \
	|| { echo "RESULT: FAIL (output/decrypted_mix.pcap, see above)"; exit 1; }

# -----------------------------------------------------------------------------
# Project:     WireGuard-FPGA
# Description: NLnet-funded open-source implementation
# Funding:     https://nlnet.nl/project/KlusterLab-Wireguard (2023-12 to 2025-12)
# -----------------------------------------------------------------------------
