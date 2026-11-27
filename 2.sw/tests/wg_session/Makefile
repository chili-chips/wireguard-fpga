# SPDX-FileCopyrightText: 2026 Chili.CHIPS
#
# SPDX-License-Identifier: BSD-3-Clause

# Host tests of the WireGuard session layer (2.sw/app/wg_session.c), on Linux/WSL:
#   make test      wg_session against a peer driven with noise.c: answers,
#                  replay, unknown peers, a busy data plane, our initiation,
#                  the table entry it writes
#   make interop   against the Linux kernel's WireGuard (wireguard-tools, the
#                  wireguard module loaded), in a user+net namespace: the keys
#                  it hands the data plane decrypt the kernel's packets
APP    = ../../app
OUT    = build
CC     = gcc
CFLAGS = -O1 -g -Wall -Wextra -DVPROC -fsanitize=address,undefined -I$(APP)
LIB    = $(addprefix $(APP)/,wg_session.c noise.c cookie.c xchacha20poly1305.c peer_map.c \
           siphash.c blake2s.c hkdf.c curve25519.c x25519.c chacha20poly1305.c chacha20.c \
           poly1305.c string_bare.c) rtc_host.c

.PHONY: all test interop clean
all: test interop

$(OUT)/%: %.c $(LIB) $(APP)/wg_session.h $(APP)/noise.h $(APP)/cookie.h $(APP)/rtc.h
	@mkdir -p $(OUT)
	$(CC) $(CFLAGS) $< $(LIB) -o $@

test: $(OUT)/wg_session_host
	$(OUT)/wg_session_host

interop: $(OUT)/wg_session_interop
	unshare -rn bash run_interop.sh $(OUT)

clean:
	rm -rf $(OUT)

# -----------------------------------------------------------------------------
# Project:     WireGuard-FPGA
# Description: NLnet-funded open-source implementation
# Funding:     https://nlnet.nl/project/KlusterLab-Wireguard (2023-12 to 2025-12)
# -----------------------------------------------------------------------------
