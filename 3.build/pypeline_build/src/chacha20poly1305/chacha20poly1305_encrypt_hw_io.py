# pyright: reportInvalidTypeForm=none
"""Flattened AXI-stream ports and wiring for the encrypt hardware boundary.

Simulation connects directly to chacha20poly1305_encrypt_ports.py instead.

Pypeline port of the DECL_INPUT/DECL_OUTPUT + io_wires MAIN in
../pipelinec_build/src/chacha20poly1305/chacha20poly1305_encrypt.h.
"""
import wireguard_env  # noqa: F401

from pypeline import (
    MAIN,
    wires,
    Input,
    Output,
    uint1_t,
    uint8_t,
    uint_to_array_le,
    array_to_uint_le,
)

import chacha20poly1305_encrypt_ports

from aead_types import (
    key_uint_t,
    nonce_uint_t,
    aad_uint_t,
    aead_data_uint_t,
    aead_keep_uint_t,
    aead_axis_intrf,
)

# Key, nonce, and associated data
encrypt_key: Input[key_uint_t]
encrypt_nonce: Input[nonce_uint_t]
encrypt_aad: Input[aad_uint_t]
encrypt_aad_len: Input[uint8_t]

# Plaintext input
encrypt_s_axis_tdata: Input[aead_data_uint_t]
encrypt_s_axis_tkeep: Input[aead_keep_uint_t]
encrypt_s_axis_tlast: Input[uint1_t]
encrypt_s_axis_tvalid: Input[uint1_t]
encrypt_s_axis_tready: Output[uint1_t]

# Ciphertext and authentication tag output
encrypt_m_axis_tdata: Output[aead_data_uint_t]
encrypt_m_axis_tkeep: Output[aead_keep_uint_t]
encrypt_m_axis_tlast: Output[uint1_t]
encrypt_m_axis_tvalid: Output[uint1_t]
encrypt_m_axis_tready: Input[uint1_t]


@MAIN(wireguard_env.TARGET_MHZ)
@wires
def chacha20poly1305_encrypt_io_wires():
    # Unpack the input stream; lane 0 is the least significant byte/keep bit.
    axis_in_s: aead_axis_intrf.stream_t
    axis_in_s.data.frag.data = uint_to_array_le(encrypt_s_axis_tdata, 8)
    axis_in_s.data.frag.keep = uint_to_array_le(encrypt_s_axis_tkeep, 1)
    axis_in_s.data.eod[0] = encrypt_s_axis_tlast
    axis_in_s.valid = encrypt_s_axis_tvalid
    chacha20poly1305_encrypt_ports.axis_in_if.stream = axis_in_s
    encrypt_s_axis_tready = chacha20poly1305_encrypt_ports.axis_in_if.ready

    chacha20poly1305_encrypt_ports.key = uint_to_array_le(encrypt_key, 8)
    chacha20poly1305_encrypt_ports.nonce = uint_to_array_le(encrypt_nonce, 8)
    chacha20poly1305_encrypt_ports.aad = uint_to_array_le(encrypt_aad, 8)
    chacha20poly1305_encrypt_ports.aad_len = encrypt_aad_len

    # Pack the output stream and return the receiver's ready signal.
    encrypt_m_axis_tdata = array_to_uint_le(
        chacha20poly1305_encrypt_ports.axis_out_if.stream.data.frag.data
    )
    encrypt_m_axis_tkeep = array_to_uint_le(
        chacha20poly1305_encrypt_ports.axis_out_if.stream.data.frag.keep
    )
    encrypt_m_axis_tlast = chacha20poly1305_encrypt_ports.axis_out_if.stream.data.eod[0]
    encrypt_m_axis_tvalid = chacha20poly1305_encrypt_ports.axis_out_if.stream.valid
    chacha20poly1305_encrypt_ports.axis_out_if.ready = encrypt_m_axis_tready
