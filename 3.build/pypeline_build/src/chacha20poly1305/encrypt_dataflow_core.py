# SPDX-FileCopyrightText: 2026 Julian Kemmerer
# SPDX-FileCopyrightText: 2026 Chili.CHIPS
#
# SPDX-License-Identifier: BSD-3-Clause

# pyright: reportInvalidTypeForm=none
"""Encrypt dataflow wiring and buffering around the selected crypto functions.

See ../../README.md#data-flow for the default graph. Interface functions
connect the streams below and generate their reverse ready wiring.
"""
import wireguard_env  # noqa: F401

from pypeline import NamedTuple, uint8_t

from interface import interface
from interface_func import make_hw_func_from_interface_func

import prep_auth_data
import prep_auth_data_wide
import auth_tag_wide
from poly1305_select import IMPLEMENTATION, make_poly1305_mac
import auth_tag

from aead_types import (
    CHACHA20_KEY_SIZE,
    CHACHA20_NONCE_SIZE,
    AAD_MAX_LEN,
    aead_axis_if_t,
    aead_axis_frag_t,
    aead_2broadcast,
    make_aead_output_slice,
    make_aead_fifo,
    overlap_fifo_sizing,
)


@interface
class encrypt_dataflow_core_ports(NamedTuple):
    axis_out_if: aead_axis_if_t


def make_encrypt_dataflow_core(chacha_func, mac_func=None):
    """Define the encrypt graph with the selected ChaCha20 and Poly1305 functions.

    chacha_func follows chacha20.chacha20_if_func's interface; omitting mac_func
    selects a private MAC. Widths and buffers are chosen during elaboration.
    """

    if mac_func is None:
        mac_func = make_poly1305_mac("encrypt")

    # Match authentication framing and tag packing to the selected packet width.
    append_func = auth_tag.append_auth_tag
    prep_func = prep_auth_data.prep_auth_data_fsm
    if wireguard_env.POLY1305_BLOCKS_PER_CYCLE == 2:
        prep_func = prep_auth_data_wide.prep_auth_data_wide
        append_func = auth_tag_wide.append_auth_tag_wide
    # Retain the unbuffered functions for the wrappers below.
    framing_func = prep_func
    packing_func = append_func

    # Pipelined MACs buffer both ciphertext forks; legacy connects them directly.
    if IMPLEMENTATION == "pipelined":
        # Let ChaCha output advance while authentication framing/MAC initialization waits.
        auth_sizing = overlap_fifo_sizing("encrypt/auth_fifo", chacha_func, mac_func)
        auth_fifo = make_aead_fifo(
            aead_axis_frag_t, auth_sizing["memory_depth_beats"],
            "auth_fifo", "encrypt", sizing=auth_sizing,
        )
        # Keep the output fork moving while append waits for a tag. Account for
        # the auth FIFO's actual capacity as well as MAC initialization/completion time.
        append_sizing = overlap_fifo_sizing(
            "encrypt/append_fifo", chacha_func, mac_func,
            auth_capacity_beats=auth_fifo.capacity_beats,
        )
        append_fifo = make_aead_fifo(
            aead_axis_frag_t, append_sizing["memory_depth_beats"],
            "append_fifo", "encrypt", sizing=append_sizing,
        )
        output_slice = make_aead_output_slice(aead_axis_if_t, "output_slice", "encrypt")

        @interface
        class buffered_prep_ports(NamedTuple):
            axis_if: aead_axis_if_t

        def buffered_prep_interface(
            aad: uint8_t[AAD_MAX_LEN],
            aad_len: uint8_t,
            axis_in_if: aead_axis_if_t,
        ) -> buffered_prep_ports:
            queued = auth_fifo(in_stream_if=axis_in_if)
            framed = framing_func(
                aad=aad, aad_len=aad_len, axis_in_if=queued.out_stream_if
            )
            return buffered_prep_ports(axis_if=framed.axis_if)

        prep_func = make_hw_func_from_interface_func(buffered_prep_interface)

        def buffered_append(
            axis_in_if: aead_axis_if_t,
            auth_tag_in_if: auth_tag.poly1305_auth_tag_stream_if_t,
        ) -> encrypt_dataflow_core_ports:
            queued = append_fifo(in_stream_if=axis_in_if)
            packed = packing_func(
                axis_in_if=queued.out_stream_if, auth_tag_in_if=auth_tag_in_if
            )
            # Hold the complete output beat (data, keep, last, valid) stable
            # while the external receiver is stalled.
            sliced = output_slice(stream_in_if=packed.axis_out_if)
            return encrypt_dataflow_core_ports(axis_out_if=sliced.stream_out_if)

        append_func = make_hw_func_from_interface_func(buffered_append)

    def encrypt_dataflow_core(
        axis_in_if: aead_axis_if_t,
        key: uint8_t[CHACHA20_KEY_SIZE],
        nonce: uint8_t[CHACHA20_NONCE_SIZE],
        aad: uint8_t[AAD_MAX_LEN],
        aad_len: uint8_t,
    ) -> encrypt_dataflow_core_ports:
        # ChaCha supplies ciphertext and a separate per-packet Poly1305 key.
        chacha = chacha_func(key=key, nonce=nonce, axis_in_if=axis_in_if)
        bcast = aead_2broadcast(axis_in_if=chacha.axis_out_if)

        # Authenticate AAD, padded ciphertext, and lengths on the first fork.
        prep = prep_func(
            aad=aad, aad_len=aad_len, axis_in_if=bcast.axis_out_if[0]
        )
        mac = mac_func(key_if=chacha.key_if, data_in_if=prep.axis_if)

        # The other fork keeps ciphertext unpadded and packs the tag after it.
        # With pipelined MACs, this also includes the append FIFO and output slice.
        append = append_func(
            axis_in_if=bcast.axis_out_if[1], auth_tag_in_if=mac.auth_tag_if
        )
        return encrypt_dataflow_core_ports(axis_out_if=append.axis_out_if)

    return make_hw_func_from_interface_func(encrypt_dataflow_core)
