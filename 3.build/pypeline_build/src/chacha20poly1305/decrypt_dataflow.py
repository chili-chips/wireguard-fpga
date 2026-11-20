# SPDX-FileCopyrightText: 2026 Julian Kemmerer
# SPDX-FileCopyrightText: 2026 Chili.CHIPS
#
# SPDX-License-Identifier: BSD-3-Clause

# pyright: reportInvalidTypeForm=none
"""Decrypt dataflow, structured ports, buffering, and resource selection."""
import wireguard_env

from pypeline import (
    MAIN, NamedTuple, Wire, array_to_uint_le, sim_output, sim_wave,
    sim_wave_enabled, uint1_t, uint8_t,
)
from axi.axis import axis_wave
from interface import interface
from interface_func import make_hw_func_from_interface_func

import auth_tag
import prep_auth_data
import verify_decrypt
from poly1305_select import IMPLEMENTATION, make_poly1305_mac
from aead_types import (
    CHACHA20_KEY_SIZE,
    CHACHA20_NONCE_SIZE,
    AAD_MAX_LEN,
    aead_axis_if_t,
    aead_axis_frag_t,
    aead_2broadcast,
    poly1305_auth_tag_uint_t,
    poly1305_auth_tag_stream_if_t,
    uint1_stream_if_t,
    decrypt_auth_fifo_sizing,
    decrypt_verify_fifo_sizing,
    make_aead_fifo,
)

port_axis_in_if: Wire[aead_axis_if_t]  # .stream is input, .ready is output
port_key: Wire[uint8_t[CHACHA20_KEY_SIZE]]  # input
port_nonce: Wire[uint8_t[CHACHA20_NONCE_SIZE]]  # input
port_aad: Wire[uint8_t[AAD_MAX_LEN]]  # input
port_aad_len: Wire[uint8_t]  # input
port_axis_out_if: Wire[aead_axis_if_t]  # .stream is output, .ready is input

# Authentication verdict for each valid plaintext output beat
port_is_verified_out: Wire[uint1_t]  # output


@sim_output
def decrypt_port_waves():
    """Record the converged wires under their flat hardware port names."""
    if sim_wave_enabled():
        axis_wave("/decrypt_s_axis", port_axis_in_if)
        axis_wave("/decrypt_m_axis", port_axis_out_if)
        sim_wave("/decrypt_key", array_to_uint_le(port_key))
        sim_wave("/decrypt_nonce", array_to_uint_le(port_nonce))
        sim_wave("/decrypt_aad", array_to_uint_le(port_aad))
        sim_wave("/decrypt_aad_len", port_aad_len)
        sim_wave("/decrypt_m_verified", port_is_verified_out)


@interface
class decrypt_dataflow_core_ports(NamedTuple):
    axis_out_if: aead_axis_if_t
    is_verified_out: uint1_t  # plain sideband, no reverse companion


@interface
class buffered_prep_ports(NamedTuple):
    axis_if: aead_axis_if_t


@interface
class buffered_verify_ports(NamedTuple):
    tags_match_if: uint1_stream_if_t


def make_decrypt_dataflow_core(
    chacha_func, mac_func=None, auth_fifo_depth=None, verify_fifo_depth=None,
    tag_fifo_depth=None,
):
    """Define the decrypt graph with the selected ChaCha20 and Poly1305 functions.

    chacha_func follows chacha20.chacha20_if_func's interface; omitting mac_func
    selects a private MAC. Widths and buffers are chosen during elaboration.

    None selects each FIFO's default depth. Auth/verify depths count packet
    beats; tag depth counts tags. Zero disables the auth or tag FIFO. The
    legacy MAC always leaves the authentication fork unbuffered.
    """

    if mac_func is None:
        mac_func = make_poly1305_mac("decrypt")

    # Hold plaintext until its packet's verdict arrives. Pipelined sizing covers
    # a maximum packet plus work admitted ahead of it, using the selected
    # ChaCha/MAC latencies and comparator handoffs. Legacy retains 128 beats.
    verify_sizing = None
    if verify_fifo_depth is None:
        if IMPLEMENTATION == "pipelined":
            verify_sizing = decrypt_verify_fifo_sizing(
                chacha_func, mac_func,
                verify_handoff_cycles=verify_decrypt.VERIFY_HANDOFF_CYCLES,
            )
            verify_fifo_depth = verify_sizing["memory_depth_beats"]
        else:
            verify_fifo_depth = 128
    else:
        verify_sizing = {"method": "explicit"}
    verify_func = verify_decrypt.make_wait_to_verify(
        verify_fifo_depth, sizing=verify_sizing
    )

    # Queue received tags so the stripper can start another packet while the
    # comparator waits for the preceding MAC result or verdict handoff.
    if tag_fifo_depth is None:
        tag_fifo_depth = 2 if IMPLEMENTATION == "pipelined" else 0
    if type(tag_fifo_depth) is not int or (tag_fifo_depth != 0 and tag_fifo_depth < 2):
        raise ValueError("tag_fifo_depth must be None, 0, or an integer >= 2")
    compare_func = verify_decrypt.poly1305_verify_decrypt
    if tag_fifo_depth:
        tag_fifo = make_aead_fifo(
            poly1305_auth_tag_uint_t, tag_fifo_depth, "tag_fifo", "decrypt",
            sizing={"method": "packet-tag-lookahead-v1", "entry_unit": "packet_tag"},
        )

        def buffered_compare(
            auth_tag_if: poly1305_auth_tag_stream_if_t,
            calc_tag_if: poly1305_auth_tag_stream_if_t,
        ) -> buffered_verify_ports:
            queued = tag_fifo(in_stream_if=auth_tag_if)
            compared = verify_decrypt.poly1305_verify_decrypt(
                auth_tag_if=queued.out_stream_if, calc_tag_if=calc_tag_if,
            )
            return buffered_verify_ports(tags_match_if=compared.tags_match_if)

        compare_func = make_hw_func_from_interface_func(buffered_compare)

    # Buffer ciphertext before authentication framing so the other fork can
    # feed ChaCha while the MAC waits for its key or initialization/completion. Sizing
    # includes ChaCha pipeline credits to keep the key response reachable.
    sizing = None
    if IMPLEMENTATION == "pipelined":
        if auth_fifo_depth is None:
            sizing = decrypt_auth_fifo_sizing(chacha_func, mac_func)
            auth_fifo_depth = sizing["memory_depth_beats"]
        elif type(auth_fifo_depth) is not int or (auth_fifo_depth != 0 and auth_fifo_depth < 2):
            raise ValueError("auth_fifo_depth must be None, 0, or an integer >= 2")
        else:
            sizing = {"method": "explicit"}

    # Match framing and tag stripping to the selected packet width.
    prep_func = prep_auth_data.prep_auth_data_fsm
    if wireguard_env.POLY1305_BLOCKS_PER_CYCLE == 2:
        prep_func = prep_auth_data.prep_auth_data_wide
    framing_func = prep_func  # Retain the unbuffered function for the wrapper.
    stripping_func = auth_tag.strip_auth_tag
    if wireguard_env.POLY1305_BLOCKS_PER_CYCLE == 2:
        stripping_func = auth_tag.strip_auth_tag_wide
    if IMPLEMENTATION == "pipelined" and auth_fifo_depth:
        auth_fifo = make_aead_fifo(
            aead_axis_frag_t, auth_fifo_depth, "auth_fifo", "decrypt", sizing=sizing
        )

        def buffered_prep(
            aad: uint8_t[AAD_MAX_LEN],
            aad_len: uint8_t,
            axis_in_if: aead_axis_if_t,
        ) -> buffered_prep_ports:
            queued = auth_fifo(in_stream_if=axis_in_if)
            framed = framing_func(
                aad=aad, aad_len=aad_len, axis_in_if=queued.out_stream_if
            )
            return buffered_prep_ports(axis_if=framed.axis_if)

        prep_func = make_hw_func_from_interface_func(buffered_prep)

    def decrypt_dataflow_core(
        axis_in_if: aead_axis_if_t,
        key: uint8_t[CHACHA20_KEY_SIZE],
        nonce: uint8_t[CHACHA20_NONCE_SIZE],
        aad: uint8_t[AAD_MAX_LEN],
        aad_len: uint8_t,
    ) -> decrypt_dataflow_core_ports:
        # Fork ciphertext to authentication and decryption; the tag stays separate.
        strip = stripping_func(axis_in_if=axis_in_if)
        bcast = aead_2broadcast(axis_in_if=strip.axis_out_if)

        # ChaCha supplies plaintext and a separate per-packet Poly1305 key.
        chacha = chacha_func(key=key, nonce=nonce, axis_in_if=bcast.axis_out_if[1])

        # Frame AAD, padded ciphertext, and lengths; buffering is selected above.
        prep = prep_func(
            aad=aad, aad_len=aad_len, axis_in_if=bcast.axis_out_if[0]
        )
        mac = mac_func(key_if=chacha.key_if, data_in_if=prep.axis_if)

        # Both tag streams preserve packet order; compare one pair per verdict.
        compare = compare_func(
            auth_tag_if=strip.auth_tag_out_if, calc_tag_if=mac.auth_tag_if
        )

        # Release plaintext after the verdict, with that bit on every valid beat,
        # including packets whose authentication failed.
        verified = verify_func(
            axis_in_if=chacha.axis_out_if, verify_bit_if=compare.tags_match_if
        )
        return decrypt_dataflow_core_ports(
            axis_out_if=verified.axis_out_if, is_verified_out=verified.is_verified_out
        )

    return make_hw_func_from_interface_func(decrypt_dataflow_core)


if wireguard_env.SHARING["chacha20"]:
    import chacha20_pipeline_shared

    chacha_func = chacha20_pipeline_shared.chacha20_decrypt_shared_adapter
else:
    import chacha20

    chacha_func = chacha20.chacha20_if_func
if wireguard_env.SHARING["poly1305"]:
    # Expose the shared compute units' MAINs and wires for discovery.
    import poly1305_compute_shared  # noqa: F401

decrypt_dataflow_core = make_decrypt_dataflow_core(
    chacha_func, make_poly1305_mac("decrypt", share_compute=wireguard_env.SHARING["poly1305"])
)


@MAIN(wireguard_env.TARGET_MHZ)
def decrypt_dataflow():
    # Connect the core's forward and feedback halves explicitly at the port boundary.
    core = decrypt_dataflow_core(
        axis_in_if=aead_axis_if_t.fwd_t(port_axis_in_if.stream),
        key=port_key,
        nonce=port_nonce,
        aad=port_aad,
        aad_len=port_aad_len,
        axis_out_if=aead_axis_if_t.fb_t(port_axis_out_if.ready),
    )
    port_axis_in_if.ready = core.axis_in_if.ready
    port_axis_out_if.stream = core.axis_out_if.stream
    port_is_verified_out = core.is_verified_out
