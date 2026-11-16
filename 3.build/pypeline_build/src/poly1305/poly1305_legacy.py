# SPDX-FileCopyrightText: 2026 Julian Kemmerer
# SPDX-FileCopyrightText: 2026 Chili.CHIPS
#
# SPDX-License-Identifier: BSD-3-Clause

# pyright: reportInvalidTypeForm=none
"""Legacy Poly1305 MAC: a single-accumulator FSM with a private multi-cycle body.

Preserves the structure of the PipelineC poly1305.h and poly1305_mac.c port.
The corrected limb arithmetic lives in poly1305_math.py; see poly1305_design.md's
legacy architecture section for the differences from the original C design.
poly1305_mac_if_func defines the interface function used by each direction.
"""
import wireguard_env  # noqa: F401

from enum import auto

from pypeline import (
    NamedTuple,
    struct,
    enum,
    hw_func,
    Reg,
    uint1_t,
    uint8_t,
    concat,
    uint_to_array_le,
)
from interface import interface
from interface_func import make_hw_func_from_interface_func
from stream import make_stream_interface
from stream.stream_multi_cycle import make_stream_auto_multi_cycle

from stream import stream_perf_probe as perf_taps

from aead_types import (
    POLY1305_BLOCK_SIZE,
    POLY1305_KEY_SIZE,
    axis128_if_t,
    poly1305_key_stream_if_t,
    poly1305_auth_tag_stream_if_t,
)

from poly1305_math import (
    U320_NBYTES, u320_t,
    u320_stream_if_t, u320_null, u8_16_t, clamp, bytes_to_uint320,
    bytes16_to_uint320, uint320_add, uint320_mul,
    uint320_mod_prime,
)


# Inputs to one iteration of the per-block compute.
@struct
class poly1305_mac_loop_body_in_t(NamedTuple):
    block_bytes: uint8_t[POLY1305_BLOCK_SIZE]
    r: u320_t
    a: u320_t


poly1305_mac_loop_body_stream_if_t = make_stream_interface(poly1305_mac_loop_body_in_t)


def poly1305_mac_loop_body_in_null():
    return poly1305_mac_loop_body_in_t(
        block_bytes=[0] * POLY1305_BLOCK_SIZE, r=u320_null(), a=u320_null()
    )


@hw_func
def poly1305_mac_loop_body(inputs: poly1305_mac_loop_body_in_t) -> u320_t:
    n_bytes: uint8_t[U320_NBYTES] = [0] * U320_NBYTES
    for i in range(POLY1305_BLOCK_SIZE):
        n_bytes[i] = inputs.block_bytes[i]
    n: u320_t = bytes_to_uint320(n_bytes)

    # Set the high bit (2^128)
    n.limbs[2] = n.limbs[2] | 0x1

    # a += n
    a: u320_t = uint320_add(inputs.a, n)

    # a *= r
    temp: u320_t = a
    a = uint320_mul(temp, inputs.r)

    # a %= p
    a = uint320_mod_prime(a)

    return a


# FSM that uses compute iteratively to compute poly1305 MAC
@enum
class poly1305_state_t:
    IDLE = auto()  # Wait for poly1305_key
    START_ITER = auto()  # Put data into compute
    FINISH_ITER = auto()  # Wait for data out of compute
    A_PLUS_S = auto()  # Add s to a final step before output
    OUTPUT_AUTH_TAG = auto()  # Output the auth tag


# State histogram labels, indexed by the enum's declaration-order values.
POLY1305_STATE_NAMES = tuple(poly1305_state_t.__members__)


@struct
class poly1305_mac_fsm_t(NamedTuple):
    key_if: poly1305_key_stream_if_t.fb_t
    data_in_if: axis128_if_t.fb_t
    auth_tag_if: poly1305_auth_tag_stream_if_t.fwd_t
    to_compute_if: poly1305_mac_loop_body_stream_if_t.fwd_t
    from_compute_if: u320_stream_if_t.fb_t


@hw_func
def poly1305_mac_fsm(
    # Inputs
    key_if: poly1305_key_stream_if_t.fwd_t,
    data_in_if: axis128_if_t.fwd_t,
    auth_tag_if: poly1305_auth_tag_stream_if_t.fb_t,
    from_compute_if: u320_stream_if_t.fwd_t,
    to_compute_if: poly1305_mac_loop_body_stream_if_t.fb_t,
) -> poly1305_mac_fsm_t:
    o: poly1305_mac_fsm_t
    # Consume the compute result in the cycle it arrives.
    o.from_compute_if.ready = 1
    # Default not ready for incoming poly key
    o.key_if.ready = 0
    # Default not ready for incoming data
    o.data_in_if.ready = 0
    # Default not outputting an auth tag
    o.auth_tag_if.stream.data = 0
    o.auth_tag_if.stream.valid = 0
    # Default nothing into compute
    o.to_compute_if.stream.data = poly1305_mac_loop_body_in_null()
    o.to_compute_if.stream.valid = 0

    # The FSM
    state: Reg[poly1305_state_t]
    is_last_block: Reg[uint1_t]
    a: Reg[u320_t]
    r: Reg[u320_t]
    s: Reg[u320_t]

    # Sample before assignments: Reg reads see same-cycle updates, so a later
    # probe would count the next state rather than the current one.
    perf_taps.state("poly1305.fsm", state, POLY1305_STATE_NAMES)

    if state == poly1305_state_t.IDLE:
        # Reset state
        is_last_block = 0  # Not the last block yet
        u320_zero: u320_t = u320_null()
        a = u320_zero  # Initialize accumulator to 0
        r = u320_zero  # Initialize r to 0
        s = u320_zero  # Initialize s to 0
        # Wait for poly1305_key
        o.key_if.ready = 1
        if key_if.stream.valid & o.key_if.ready:
            key_bytes: uint8_t[POLY1305_KEY_SIZE] = uint_to_array_le(key_if.stream.data, 8)
            # Split key into r and s
            r_bytes: u8_16_t  # r part of the key
            s_bytes: u8_16_t  # s part of the key
            for i in range(POLY1305_KEY_SIZE // 2):
                r_bytes.bytes[i] = key_bytes[i]
                s_bytes.bytes[i] = key_bytes[i + 16]
            # Clamp r according to the spec
            r_bytes = clamp(r_bytes)
            # Convert r and s to u320_t and save in regs
            r = bytes16_to_uint320(r_bytes.bytes)
            s = bytes16_to_uint320(s_bytes.bytes)
            # Then start per block iterations
            state = poly1305_state_t.START_ITER
    elif state == poly1305_state_t.FINISH_ITER:
        # Wait for 'a' data out of compute
        if from_compute_if.stream.valid:
            a = from_compute_if.stream.data
            # if last block do final step
            if is_last_block:
                state = poly1305_state_t.A_PLUS_S
            else:
                # More blocks using 'a' next
                state = poly1305_state_t.START_ITER
    elif state == poly1305_state_t.A_PLUS_S:
        # a += s
        a = uint320_add(a, s)
        # Output a next
        state = poly1305_state_t.OUTPUT_AUTH_TAG
    elif state == poly1305_state_t.OUTPUT_AUTH_TAG:
        # First 16 bytes of 'a' are the output
        o.auth_tag_if.stream.data = concat(a.limbs[1], a.limbs[0])
        o.auth_tag_if.stream.valid = 1
        if o.auth_tag_if.stream.valid & auth_tag_if.ready:
            state = poly1305_state_t.IDLE

    # Keep this separate: same-cycle state readback lets FINISH_ITER launch
    # the next block immediately after receiving the accumulator result.
    if state == poly1305_state_t.START_ITER:
        # Ready to take an input data block
        o.data_in_if.ready = to_compute_if.ready
        # Put 'a' and data block into compute
        o.to_compute_if.stream.data.block_bytes = data_in_if.stream.data.frag.data
        o.to_compute_if.stream.data.a = a
        o.to_compute_if.stream.data.r = r
        o.to_compute_if.stream.valid = data_in_if.stream.valid & o.data_in_if.ready
        # Record if this is the last block
        is_last_block = data_in_if.stream.data.eod[0]
        # And then wait for the output once input into compute happens
        if o.to_compute_if.stream.valid & o.data_in_if.ready:
            state = poly1305_state_t.FINISH_ITER

    # Sample handshakes after all output assignments. data_in measures block
    # throughput; see poly1305_design.md for the legacy compute unit interval.
    perf_taps.hs(
        "poly1305.data_in",
        data_in_if.stream.valid,
        o.data_in_if.ready,
        data_in_if.stream.data.frag.keep,
    )
    perf_taps.hs("poly1305.key_in", key_if.stream.valid, o.key_if.ready)
    perf_taps.hs("poly1305.tag_out", o.auth_tag_if.stream.valid, auth_tag_if.ready)
    # Compute launches and completions; the result port is always ready.
    perf_taps.hs(
        "poly1305.to_compute", o.to_compute_if.stream.valid, to_compute_if.ready
    )
    perf_taps.hs("poly1305.from_compute", from_compute_if.stream.valid, 1)
    return o


# PypelineC selects the multi-cycle count to meet timing; the resolved count
# is available as compute_mcp.mcp.latency.
compute_mcp = make_stream_auto_multi_cycle(poly1305_mac_loop_body)


@interface
class poly1305_mac_ports(NamedTuple):
    """Output port of the MAC interface function."""

    auth_tag_if: poly1305_auth_tag_stream_if_t


# Each call site gets a private FSM and compute body. The interface function
# generates feedback wiring for the compute result and reverse ready signals.
def poly1305_mac_if_wiring(
    key_if: poly1305_key_stream_if_t,
    data_in_if: axis128_if_t,
) -> poly1305_mac_ports:
    fsm_out = poly1305_mac_fsm(
        key_if=key_if, data_in_if=data_in_if, from_compute_if=compute.stream_out_if
    )
    compute = compute_mcp(stream_in_if=fsm_out.to_compute_if)
    return poly1305_mac_ports(auth_tag_if=fsm_out.auth_tag_if)


poly1305_mac_if_func = make_hw_func_from_interface_func(
    poly1305_mac_if_wiring
)
