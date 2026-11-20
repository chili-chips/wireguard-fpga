# SPDX-FileCopyrightText: 2026 Julian Kemmerer
# SPDX-FileCopyrightText: 2026 Chili.CHIPS
#
# SPDX-License-Identifier: BSD-3-Clause

# pyright: reportInvalidTypeForm=none
"""Hardware top for the selected ChaCha20-Poly1305 direction(s).

The flat AXI-stream pins connect to the structured dataflow wires here. See
../README.md#setup-and-options for design and sharing choices.
"""
import wireguard_env

from pypeline import (
    MAIN,
    PART,
    NamedTuple,
    Input,
    Output,
    hw_func,
    struct,
    uint1_t,
    uint8_t,
    uint_to_array_le,
    array_to_uint_le,
    wires,
)

from aead_types import (
    key_uint_t,
    nonce_uint_t,
    aad_uint_t,
    aead_data_uint_t,
    aead_keep_uint_t,
    aead_axis_if_t,
)


PART("xc7a200tffg1156-2")  # Artix 7 200T


@struct
class flat_axis_t(NamedTuple):
    data: aead_data_uint_t
    keep: aead_keep_uint_t
    last: uint1_t
    valid: uint1_t


@hw_func
def axis_stream_from_flat(
    data: aead_data_uint_t,
    keep: aead_keep_uint_t,
    last: uint1_t,
    valid: uint1_t,
) -> aead_axis_if_t.stream_t:
    result: aead_axis_if_t.stream_t
    result.data.frag.data = uint_to_array_le(data, 8)
    result.data.frag.keep = uint_to_array_le(keep, 1)
    result.data.eod[0] = last
    result.valid = valid
    return result


@hw_func
def axis_stream_to_flat(stream: aead_axis_if_t.stream_t) -> flat_axis_t:
    result: flat_axis_t
    result.data = array_to_uint_le(stream.data.frag.data)
    result.keep = array_to_uint_le(stream.data.frag.keep)
    result.last = stream.data.eod[0]
    result.valid = stream.valid
    return result


# Pypeline discovers only module-scope declarations. The inactive direction's
# annotations evaluate to ordinary Python types and are therefore not hardware I/O.
encrypt_key: Input[key_uint_t] if wireguard_env.ENCRYPT else int
encrypt_nonce: Input[nonce_uint_t] if wireguard_env.ENCRYPT else int
encrypt_aad: Input[aad_uint_t] if wireguard_env.ENCRYPT else int
encrypt_aad_len: Input[uint8_t] if wireguard_env.ENCRYPT else int

# Plaintext input and ciphertext/tag output
encrypt_s_axis_tdata: Input[aead_data_uint_t] if wireguard_env.ENCRYPT else int
encrypt_s_axis_tkeep: Input[aead_keep_uint_t] if wireguard_env.ENCRYPT else int
encrypt_s_axis_tlast: Input[uint1_t] if wireguard_env.ENCRYPT else int
encrypt_s_axis_tvalid: Input[uint1_t] if wireguard_env.ENCRYPT else int
encrypt_s_axis_tready: Output[uint1_t] if wireguard_env.ENCRYPT else int
encrypt_m_axis_tdata: Output[aead_data_uint_t] if wireguard_env.ENCRYPT else int
encrypt_m_axis_tkeep: Output[aead_keep_uint_t] if wireguard_env.ENCRYPT else int
encrypt_m_axis_tlast: Output[uint1_t] if wireguard_env.ENCRYPT else int
encrypt_m_axis_tvalid: Output[uint1_t] if wireguard_env.ENCRYPT else int
encrypt_m_axis_tready: Input[uint1_t] if wireguard_env.ENCRYPT else int

# Decrypt key, nonce, and associated data
decrypt_key: Input[key_uint_t] if wireguard_env.DECRYPT else int
decrypt_nonce: Input[nonce_uint_t] if wireguard_env.DECRYPT else int
decrypt_aad: Input[aad_uint_t] if wireguard_env.DECRYPT else int
decrypt_aad_len: Input[uint8_t] if wireguard_env.DECRYPT else int

# Ciphertext/tag input, plaintext output, and authentication verdict
decrypt_s_axis_tdata: Input[aead_data_uint_t] if wireguard_env.DECRYPT else int
decrypt_s_axis_tkeep: Input[aead_keep_uint_t] if wireguard_env.DECRYPT else int
decrypt_s_axis_tlast: Input[uint1_t] if wireguard_env.DECRYPT else int
decrypt_s_axis_tvalid: Input[uint1_t] if wireguard_env.DECRYPT else int
decrypt_s_axis_tready: Output[uint1_t] if wireguard_env.DECRYPT else int
decrypt_m_axis_tdata: Output[aead_data_uint_t] if wireguard_env.DECRYPT else int
decrypt_m_axis_tkeep: Output[aead_keep_uint_t] if wireguard_env.DECRYPT else int
decrypt_m_axis_tlast: Output[uint1_t] if wireguard_env.DECRYPT else int
decrypt_m_axis_tvalid: Output[uint1_t] if wireguard_env.DECRYPT else int
decrypt_m_axis_tready: Input[uint1_t] if wireguard_env.DECRYPT else int
decrypt_m_verified: Output[uint1_t] if wireguard_env.DECRYPT else int


if wireguard_env.ENCRYPT:
    import encrypt_dataflow

    @MAIN(wireguard_env.TARGET_MHZ)
    @wires
    def chacha20poly1305_encrypt_io_wires():
        encrypt_dataflow.port_axis_in_if.stream = axis_stream_from_flat(
            encrypt_s_axis_tdata,
            encrypt_s_axis_tkeep,
            encrypt_s_axis_tlast,
            encrypt_s_axis_tvalid,
        )
        encrypt_s_axis_tready = encrypt_dataflow.port_axis_in_if.ready

        encrypt_dataflow.port_key = uint_to_array_le(encrypt_key, 8)
        encrypt_dataflow.port_nonce = uint_to_array_le(encrypt_nonce, 8)
        encrypt_dataflow.port_aad = uint_to_array_le(encrypt_aad, 8)
        encrypt_dataflow.port_aad_len = encrypt_aad_len

        output = axis_stream_to_flat(encrypt_dataflow.port_axis_out_if.stream)
        encrypt_m_axis_tdata = output.data
        encrypt_m_axis_tkeep = output.keep
        encrypt_m_axis_tlast = output.last
        encrypt_m_axis_tvalid = output.valid
        encrypt_dataflow.port_axis_out_if.ready = encrypt_m_axis_tready


if wireguard_env.DECRYPT:
    import decrypt_dataflow

    @MAIN(wireguard_env.TARGET_MHZ)
    @wires
    def chacha20poly1305_decrypt_io_wires():
        decrypt_dataflow.port_axis_in_if.stream = axis_stream_from_flat(
            decrypt_s_axis_tdata,
            decrypt_s_axis_tkeep,
            decrypt_s_axis_tlast,
            decrypt_s_axis_tvalid,
        )
        decrypt_s_axis_tready = decrypt_dataflow.port_axis_in_if.ready

        decrypt_dataflow.port_key = uint_to_array_le(decrypt_key, 8)
        decrypt_dataflow.port_nonce = uint_to_array_le(decrypt_nonce, 8)
        decrypt_dataflow.port_aad = uint_to_array_le(decrypt_aad, 8)
        decrypt_dataflow.port_aad_len = decrypt_aad_len

        output = axis_stream_to_flat(decrypt_dataflow.port_axis_out_if.stream)
        decrypt_m_axis_tdata = output.data
        decrypt_m_axis_tkeep = output.keep
        decrypt_m_axis_tlast = output.last
        decrypt_m_axis_tvalid = output.valid
        decrypt_dataflow.port_axis_out_if.ready = decrypt_m_axis_tready
        decrypt_m_verified = decrypt_dataflow.port_is_verified_out
