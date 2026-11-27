# SPDX-FileCopyrightText: 2026 Chili.CHIPS
#
# SPDX-License-Identifier: BSD-3-Clause

# Host tests of the WireGuard cookies (2.sw/app/cookie.c) and
# XChaCha20-Poly1305 (xchacha20poly1305.c), on Linux/WSL:
#   make test      the draft-irtf-cfrg-xchacha vectors, cookie_host against
#                  cookie_ref.py byte for byte, plus the negative checks
#   make interop   against the Linux kernel's WireGuard (wireguard-tools,
#                  the wireguard module loaded), in a user+net namespace
APP    = ../../app
OUT    = build
CC     = gcc
CFLAGS = -O1 -g -Wall -Wextra -DVPROC -fsanitize=address,undefined -I$(APP)
LIB    = $(addprefix $(APP)/,cookie.c xchacha20poly1305.c blake2s.c chacha20poly1305.c \
           chacha20.c poly1305.c string_bare.c)
NOISE  = $(addprefix $(APP)/,noise.c hkdf.c curve25519.c x25519.c)

.PHONY: all test interop clean
all: test interop

$(OUT)/cookie_host: cookie_host.c $(LIB) $(APP)/cookie.h $(APP)/xchacha20poly1305.h
	@mkdir -p $(OUT)
	$(CC) $(CFLAGS) $< $(LIB) -o $@

$(OUT)/cookie_interop: cookie_interop.c $(LIB) $(NOISE) $(APP)/cookie.h $(APP)/noise.h
	@mkdir -p $(OUT)
	$(CC) $(CFLAGS) $< $(LIB) $(NOISE) -o $@

test: $(OUT)/cookie_host
	$(OUT)/cookie_host > $(OUT)/c.txt
	python3 -I -B cookie_ref.py > $(OUT)/py.txt
	diff $(OUT)/c.txt $(OUT)/py.txt && echo "PASS cookie.c = cookie_ref.py"

interop: $(OUT)/cookie_interop
	unshare -rn bash run_interop.sh $(OUT)

clean:
	rm -rf $(OUT)

# -----------------------------------------------------------------------------
# Project:     WireGuard-FPGA
# Description: NLnet-funded open-source implementation
# Funding:     https://nlnet.nl/project/KlusterLab-Wireguard (2023-12 to 2025-12)
# -----------------------------------------------------------------------------
