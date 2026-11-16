# pyright: reportInvalidTypeForm=none
"""Frame the 128-bit ciphertext stream for Poly1305:
AAD || padding || ciphertext || padding || AAD length || ciphertext length

Pypeline port of ../pipelinec_build/src/prep_auth_data/prep_auth_data.h and
prep_auth_data.c.
"""
import wireguard_env  # noqa: F401

from enum import auto

from pypeline import (
    NamedTuple,
    struct,
    enum,
    hw_func,
    Reg,
    uint8_t,
    uint16_t,
)

from stream import stream_perf_probe as perf_taps

import aead_types
from aead_types import (
    AAD_MAX_LEN,
    axis128_if_t,
    axis128_stream_null,
)


@enum
class prep_auth_data_state_t:
    IDLE = auto()
    AAD_STATE = auto()
    CIPHERTEXT = auto()
    LENGTHS = auto()


# State histogram labels in declaration order.
PREP_AUTH_DATA_STATE_NAMES = tuple(prep_auth_data_state_t.__members__)


@struct
class prep_auth_data_fsm_t(NamedTuple):
    axis_in_if: axis128_if_t.fb_t  # input port's reverse half
    axis_if: axis128_if_t.fwd_t  # output port's feedforward half


@hw_func
def prep_auth_data_fsm(
    aad: uint8_t[AAD_MAX_LEN],
    aad_len: uint8_t,
    axis_in_if: axis128_if_t.fwd_t,
    axis_if: axis128_if_t.fb_t,
) -> prep_auth_data_fsm_t:
    o: prep_auth_data_fsm_t
    state: Reg[prep_auth_data_state_t]
    aad_reg: Reg[uint8_t[AAD_MAX_LEN]]
    counter: Reg[uint16_t]
    # Sample the occupied state before transitions (simulation only).
    perf_taps.state("prep.fsm", state, PREP_AUTH_DATA_STATE_NAMES)

    # No input transfer or output by default.
    o.axis_in_if.ready = 0
    o.axis_if.stream = axis128_stream_null()

    if state == prep_auth_data_state_t.IDLE:
        # Wait for ciphertext, holding it until any AAD has been emitted.
        if axis_in_if.stream.valid:
            if aad_len > 0:
                aad_reg = aad
                counter = aad_len
                state = prep_auth_data_state_t.AAD_STATE
            else:
                state = prep_auth_data_state_t.CIPHERTEXT
                counter = 0
    elif state == prep_auth_data_state_t.AAD_STATE:
        # Emit up to 16 AAD bytes, zero-padded to a full block.
        for i in range(16):
            if counter > i:
                o.axis_if.stream.data.frag.data[i] = aad_reg[i]
            o.axis_if.stream.data.frag.keep[i] = 1
        o.axis_if.stream.valid = 1

        if o.axis_if.stream.valid & axis_if.ready:
            if counter > 16:
                # Shift the next AAD bytes to the bottom of the array.
                for i in range(AAD_MAX_LEN - 16):
                    aad_reg[i] = aad_reg[i + 16]
                counter = counter - 16
            else:
                state = prep_auth_data_state_t.CIPHERTEXT
                counter = 0
    elif state == prep_auth_data_state_t.CIPHERTEXT:
        # Forward ciphertext, zero-padding unused bytes to a full block.
        o.axis_if = axis_in_if
        o.axis_in_if.ready = axis_if.ready
        # The lengths block, not ciphertext, ends the authentication stream.
        o.axis_if.stream.data.eod[0] = 0
        for i in range(16):
            o.axis_if.stream.data.frag.keep[i] = 1
            if ~axis_in_if.stream.data.frag.keep[i]:
                o.axis_if.stream.data.frag.data[i] = 0

        # Count transferred ciphertext bytes, excluding padding.
        if axis_in_if.stream.valid & o.axis_in_if.ready:
            counter = counter + aead_types.axis128_keep_count(axis_in_if.stream.data.frag)
            if axis_in_if.stream.data.eod[0]:
                state = prep_auth_data_state_t.LENGTHS
    else:  # LENGTHS
        # Two little-endian 64-bit byte lengths fill the final block.
        pos = 0
        # AAD length
        for i in range(8):
            o.axis_if.stream.data.frag.data[pos] = aad_len >> (i * 8)
            o.axis_if.stream.data.frag.keep[pos] = 1
            pos += 1
        # Ciphertext length
        for i in range(8):
            o.axis_if.stream.data.frag.data[pos] = counter >> (i * 8)
            o.axis_if.stream.data.frag.keep[pos] = 1
            pos += 1
        o.axis_if.stream.data.eod[0] = 1
        o.axis_if.stream.valid = 1

        if o.axis_if.stream.valid & axis_if.ready:
            state = prep_auth_data_state_t.IDLE

    # Simulation-only handshake probes at the formatter boundaries.
    perf_taps.hs(
        "prep.axis_in",
        axis_in_if.stream.valid,
        o.axis_in_if.ready,
        axis_in_if.stream.data.frag.keep,
    )
    perf_taps.hs(
        "prep.axis_out",
        o.axis_if.stream.valid,
        axis_if.ready,
        o.axis_if.stream.data.frag.keep,
    )
    return o
