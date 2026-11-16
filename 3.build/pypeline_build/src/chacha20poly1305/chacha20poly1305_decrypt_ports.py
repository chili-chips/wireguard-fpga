# SPDX-FileCopyrightText: 2026 Julian Kemmerer
# SPDX-FileCopyrightText: 2026 Chili.CHIPS
#
# SPDX-License-Identifier: BSD-3-Clause

# pyright: reportInvalidTypeForm=none
"""Structured decrypt ports connecting the dataflow to hardware I/O or a testbench.

Hardware I/O is defined in chacha20poly1305_decrypt_hw_io.py.

Pypeline port of the wire declarations in
../pipelinec_build/src/chacha20poly1305/chacha20poly1305_decrypt.h.
"""
import wireguard_env  # noqa: F401

from pypeline import Wire, uint1_t, uint8_t

from aead_types import (
    CHACHA20_KEY_SIZE,
    CHACHA20_NONCE_SIZE,
    AAD_MAX_LEN,
    aead_axis_if_t,
)

axis_in_if: Wire[aead_axis_if_t]  # .stream is input, .ready is output
key: Wire[uint8_t[CHACHA20_KEY_SIZE]]  # input
nonce: Wire[uint8_t[CHACHA20_NONCE_SIZE]]  # input
aad: Wire[uint8_t[AAD_MAX_LEN]]  # input
aad_len: Wire[uint8_t]  # input
axis_out_if: Wire[aead_axis_if_t]  # .stream is output, .ready is input

# Authentication verdict for each valid plaintext output beat
is_verified_out: Wire[uint1_t]  # output
