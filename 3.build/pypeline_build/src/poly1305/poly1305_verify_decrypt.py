# SPDX-FileCopyrightText: 2026 Julian Kemmerer
# SPDX-FileCopyrightText: 2026 Chili.CHIPS
#
# SPDX-License-Identifier: BSD-3-Clause

# pyright: reportInvalidTypeForm=none
"""Compare received and calculated authentication tags, emitting one match bit.

Pypeline port of ../pipelinec_build/src/poly1305/poly1305_verify_decrypt.c.
"""
import wireguard_env  # noqa: F401

from enum import auto

from pypeline import (
    NamedTuple,
    struct,
    hw_func,
    Reg,
    enum,
    uint1_t,
)

from stream import stream_perf_probe as perf_taps

from aead_types import (
    poly1305_auth_tag_uint_t,
    poly1305_auth_tag_stream_if_t,
    uint1_stream_if_t,
    uint1_stream_null,
)


@enum
class poly1305_verify_state_t:
    TAKE_AUTH_TAG = auto()
    TAKE_CALC_TAG = auto()
    COMPARE_TAGS = auto()
    OUTPUT_COMPARE_RESULT = auto()


# Declaration order matches the state histogram values.
POLY1305_VERIFY_STATE_NAMES = tuple(poly1305_verify_state_t.__members__)

# One cycle per state without stalls; used by plaintext FIFO sizing.
VERIFY_HANDOFF_CYCLES = len(POLY1305_VERIFY_STATE_NAMES)


@struct
class poly1305_verify_decrypt_out_t(NamedTuple):
    auth_tag_if: poly1305_auth_tag_stream_if_t.fb_t
    calc_tag_if: poly1305_auth_tag_stream_if_t.fb_t
    tags_match_if: uint1_stream_if_t.fwd_t


@hw_func
def poly1305_verify_decrypt(
    auth_tag_if: poly1305_auth_tag_stream_if_t.fwd_t,
    calc_tag_if: poly1305_auth_tag_stream_if_t.fwd_t,
    tags_match_if: uint1_stream_if_t.fb_t,
) -> poly1305_verify_decrypt_out_t:
    o: poly1305_verify_decrypt_out_t
    state: Reg[poly1305_verify_state_t]
    # Sample state before transitions.
    perf_taps.state("verify.fsm", state, POLY1305_VERIFY_STATE_NAMES)

    auth_tag_reg: Reg[poly1305_auth_tag_uint_t]
    calc_tag_reg: Reg[poly1305_auth_tag_uint_t]
    tags_match_reg: Reg[uint1_t]

    o.auth_tag_if.ready = 0
    o.calc_tag_if.ready = 0
    o.tags_match_if.stream = uint1_stream_null()

    if state == poly1305_verify_state_t.TAKE_AUTH_TAG:
        o.auth_tag_if.ready = 1

        if auth_tag_if.stream.valid & o.auth_tag_if.ready:
            auth_tag_reg = auth_tag_if.stream.data
            state = poly1305_verify_state_t.TAKE_CALC_TAG
    elif state == poly1305_verify_state_t.TAKE_CALC_TAG:
        o.calc_tag_if.ready = 1

        if calc_tag_if.stream.valid & o.calc_tag_if.ready:
            calc_tag_reg = calc_tag_if.stream.data
            state = poly1305_verify_state_t.COMPARE_TAGS
    elif state == poly1305_verify_state_t.COMPARE_TAGS:
        tags_match_reg = auth_tag_reg == calc_tag_reg
        state = poly1305_verify_state_t.OUTPUT_COMPARE_RESULT
    else:  # state == poly1305_verify_state_t.OUTPUT_COMPARE_RESULT
        # Hold the registered result until it is accepted.
        o.tags_match_if.stream.data = tags_match_reg
        o.tags_match_if.stream.valid = 1

        if tags_match_if.ready & o.tags_match_if.stream.valid:
            state = poly1305_verify_state_t.TAKE_AUTH_TAG

    # Sample handshakes after all output assignments.
    perf_taps.hs("verify.auth_tag", auth_tag_if.stream.valid, o.auth_tag_if.ready)
    perf_taps.hs("verify.calc_tag", calc_tag_if.stream.valid, o.calc_tag_if.ready)
    perf_taps.hs(
        "verify.tags_match", o.tags_match_if.stream.valid, tags_match_if.ready
    )
    return o
