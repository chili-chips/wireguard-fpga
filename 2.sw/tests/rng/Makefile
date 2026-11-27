# SPDX-FileCopyrightText: 2026 Chili.CHIPS
#
# SPDX-License-Identifier: BSD-3-Clause

# Host test of the random numbers (2.sw/app/random.c), on Linux/WSL:
#   make test   rng_host kat against rng_ref.py, byte for byte (seed and
#               DRBG), then the refusals and random_range's uniformity
# random.c is built with RANDOM_HW_EXTERNAL: rng_host.c is the entropy source
APP    = ../../app
OUT    = build
CC     = gcc
CFLAGS = -O1 -g -Wall -Wextra -DVPROC -DRANDOM_HW_EXTERNAL -DRANDOM_RESEED_INTERVAL=4 \
         -fsanitize=address,undefined -I$(APP)
LIB    = $(addprefix $(APP)/,random.c blake2s.c chacha20.c string_bare.c)

.PHONY: all test clean
all: test

$(OUT)/rng_host: rng_host.c $(LIB) $(APP)/random.h
	@mkdir -p $(OUT)
	$(CC) $(CFLAGS) $< $(LIB) -lm -o $@

test: $(OUT)/rng_host
	$(OUT)/rng_host kat > $(OUT)/c.txt
	python3 -I -B rng_ref.py > $(OUT)/py.txt
	diff $(OUT)/c.txt $(OUT)/py.txt && echo "PASS random.c = rng_ref.py"
	$(OUT)/rng_host checks
	$(OUT)/rng_host nosource
	@echo "PASS rng_host checks"

clean:
	rm -rf $(OUT)

# -----------------------------------------------------------------------------
# Project:     WireGuard-FPGA
# Description: NLnet-funded open-source implementation
# Funding:     https://nlnet.nl/project/KlusterLab-Wireguard (2023-12 to 2025-12)
# -----------------------------------------------------------------------------
