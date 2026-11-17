# SPDX-FileCopyrightText: 2026 Chili.CHIPS
#
# SPDX-License-Identifier: BSD-3-Clause

# dpe_wg_decryptor loopback bench (encryptor -> decryptor): make [SIM=verilator|icarus|janushdl], see ../sim.mk

# MODDUP: the two PipelineC netlists share helper modules (same hashed name, same body)
VFLAGS = -Wno-MODDUP -Wno-PINCONNECTEMPTY -Wno-UNUSEDPARAM -Wno-UNUSEDSIGNAL -Wno-GENUNNAMED -Wno-DECLFILENAME -Wno-UNOPTFLAT
SRC_F  = tb.filelist
SRC    = tb.sv

include ../sim.mk

# Self-checking by its output: under stalls on every link, each frame of the
# encryptor bench's plaintext_mix.pcap must come back, except frame 3, whose
# ciphertext the bench corrupts (tb.sv: CORRUPT_FRAME)
CHECK = @python3 ../wg_check.py dec ../dpe_wg_encryptor/plaintext_mix.pcap output/decrypted_mix.pcap 3 \
	&& echo "RESULT: PASS (plaintext_mix.pcap back, corrupted frame 3 dropped)" \
	|| { echo "RESULT: FAIL (output/decrypted_mix.pcap, see above)"; exit 1; }

# -----------------------------------------------------------------------------
# Project:     WireGuard-FPGA
# Description: NLnet-funded open-source implementation
# Funding:     https://nlnet.nl/project/KlusterLab-Wireguard (2023-12 to 2025-12)
# -----------------------------------------------------------------------------
