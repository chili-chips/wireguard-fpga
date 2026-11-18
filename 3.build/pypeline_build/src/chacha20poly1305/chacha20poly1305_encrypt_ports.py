# SPDX-FileCopyrightText: 2026 Julian Kemmerer
# SPDX-FileCopyrightText: 2026 Chili.CHIPS
#
# SPDX-License-Identifier: BSD-3-Clause

# pyright: reportInvalidTypeForm=none
"""Structured encrypt ports connecting the dataflow to hardware I/O or a testbench.

Hardware I/O is defined in chacha20poly1305_encrypt_hw_io.py.

Pypeline port of the wire declarations in
../pipelinec_build/src/chacha20poly1305/chacha20poly1305_encrypt.h.
"""
import wireguard_env  # noqa: F401

from pypeline import Wire, array_to_uint_le, sim_output, sim_wave, sim_wave_enabled, uint8_t
from axi.axis import axis_wave

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


@sim_output
def encrypt_port_waves():
    """Record the converged wires under their flat hardware port names."""
    if sim_wave_enabled():
        axis_wave("/encrypt_s_axis", axis_in_if)
        axis_wave("/encrypt_m_axis", axis_out_if)
        # Testbenches can write plain ints. Pack each lane at its hardware width.
        sim_wave("/encrypt_key", array_to_uint_le([uint8_t(b) for b in key]))
        sim_wave("/encrypt_nonce", array_to_uint_le([uint8_t(b) for b in nonce]))
        sim_wave("/encrypt_aad", array_to_uint_le([uint8_t(b) for b in aad]))
        sim_wave("/encrypt_aad_len", uint8_t(aad_len))
