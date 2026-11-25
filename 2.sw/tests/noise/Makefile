# SPDX-FileCopyrightText: 2026 Chili.CHIPS
#
# SPDX-License-Identifier: BSD-3-Clause

# Host tests of the WireGuard handshake (2.sw/app/noise.c), on Linux/WSL:
#   make test      noise_host against noise_ref.py, byte for byte, plus the
#                  negative checks
#   make interop   against the Linux kernel's WireGuard (wireguard-tools,
#                  the wireguard module loaded), in a user+net namespace
APP    = ../../app
OUT    = build
CC     = gcc
CFLAGS = -O1 -g -Wall -Wextra -DVPROC -fsanitize=address,undefined -I$(APP)
LIB    = $(addprefix $(APP)/,noise.c blake2s.c hkdf.c curve25519.c x25519.c \
           chacha20poly1305.c chacha20.c poly1305.c string_bare.c)

.PHONY: all test interop clean
all: test interop

$(OUT)/%: %.c $(LIB) $(APP)/noise.h
	@mkdir -p $(OUT)
	$(CC) $(CFLAGS) $< $(LIB) -o $@

test: $(OUT)/noise_host
	$(OUT)/noise_host > $(OUT)/all.txt
	grep -v tai64n $(OUT)/all.txt > $(OUT)/c.txt
	python3 -I -B noise_ref.py > $(OUT)/py.txt
	diff $(OUT)/c.txt $(OUT)/py.txt && echo "PASS noise.c = noise_ref.py"

interop: $(OUT)/wg_interop
	unshare -rn bash run_interop.sh $(OUT)

clean:
	rm -rf $(OUT)

# -----------------------------------------------------------------------------
# Project:     WireGuard-FPGA
# Description: NLnet-funded open-source implementation
# Funding:     https://nlnet.nl/project/KlusterLab-Wireguard (2023-12 to 2025-12)
# -----------------------------------------------------------------------------
