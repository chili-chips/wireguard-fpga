# SPDX-FileCopyrightText: 2026 Julian Kemmerer
# SPDX-FileCopyrightText: 2026 Chili.CHIPS
#
# SPDX-License-Identifier: BSD-3-Clause

# pyright: reportInvalidTypeForm=none
"""Append and strip packed authentication tags on 128-bit streams.

Adapted from ../pipelinec_build/src/auth_tag/{append,strip}_auth_tag.c for
packed framing. The 256-bit implementations live in auth_tag_wide.py.
"""
import wireguard_env  # noqa: F401

from enum import auto
from pypeline import (
    NamedTuple, struct, hw_func, Reg, Feedback, enum, uint1_t, uint8_t,
    uint_to_array_le, array_to_uint_le, sim_assert,
)
from stream import stream_perf_probe as perf_taps
from aead_types import (
    POLY1305_AUTH_TAG_SIZE, axis128_if_t, axis128_stream_null,
    axis128_keep_count, axis128_keep_count_t, axis128_count_to_keep,
    poly1305_auth_tag_stream_if_t, poly1305_auth_tag_stream_null,
)


@enum
class append_auth_tag_state_t:
    CIPHERTEXT = auto()
    MERGED_WORD = auto()
    TAG_TAIL = auto()


# Declaration order matches the state histogram values.
APPEND_AUTH_TAG_STATE_NAMES = tuple(append_auth_tag_state_t.__members__)


@struct
class append_auth_tag_out_t(NamedTuple):
    axis_in_if: axis128_if_t.fb_t
    auth_tag_in_if: poly1305_auth_tag_stream_if_t.fb_t
    axis_out_if: axis128_if_t.fwd_t


@hw_func
def append_auth_tag(
    axis_in_if: axis128_if_t.fwd_t,
    auth_tag_in_if: poly1305_auth_tag_stream_if_t.fwd_t,
    axis_out_if: axis128_if_t.fb_t,
) -> append_auth_tag_out_t:
    o: append_auth_tag_out_t
    state: Reg[append_auth_tag_state_t]
    # Sample state before transitions.
    perf_taps.state("append.fsm", state, APPEND_AUTH_TAG_STATE_NAMES)
    # One cover event per packet, when its final ciphertext beat is accepted: a
    # full beat waits for output ready and the tag follows alone; a partial beat
    # is buffered at once and merges with the tag (simulation only, no hardware).
    perf_taps.hs(
        "cover.append.tag_only",
        (state == append_auth_tag_state_t.CIPHERTEXT)
        & axis_in_if.stream.valid
        & axis_in_if.stream.data.eod[0]
        & axis_in_if.stream.data.frag.keep[15],
        axis_out_if.ready,
    )
    perf_taps.hs(
        "cover.append.two_beat",
        (state == append_auth_tag_state_t.CIPHERTEXT)
        & axis_in_if.stream.valid
        & axis_in_if.stream.data.eod[0]
        & ~axis_in_if.stream.data.frag.keep[15],
        1,
    )
    # Hold the final ciphertext beat and its valid-byte count, r in [1, 16].
    held_data_reg: Reg[uint8_t[POLY1305_AUTH_TAG_SIZE]]
    held_keep_count_reg: Reg[axis128_keep_count_t]

    o.axis_in_if.ready = 0
    o.auth_tag_in_if.ready = 0
    o.axis_out_if.stream = axis128_stream_null()

    # Pack ciphertext in lanes [0, r), then the tag in [r, r+16).
    # The low/high halves feed MERGED_WORD/TAG_TAIL respectively.
    tag_bytes: uint8_t[POLY1305_AUTH_TAG_SIZE] = uint_to_array_le(
        auth_tag_in_if.stream.data, 8
    )
    merged: uint8_t[2 * POLY1305_AUTH_TAG_SIZE]
    for i in range(POLY1305_AUTH_TAG_SIZE):
        merged[i] = held_data_reg[i]
        merged[POLY1305_AUTH_TAG_SIZE + i] = 0
    for i in range(POLY1305_AUTH_TAG_SIZE):
        merged[held_keep_count_reg + i] = tag_bytes[i]

    if state == append_auth_tag_state_t.CIPHERTEXT:
        # Forward ciphertext; TAG_TAIL emits the packet's final beat.
        o.axis_out_if = axis_in_if
        o.axis_in_if.ready = axis_out_if.ready
        o.axis_out_if.stream.data.eod[0] = 0
        keep_count: axis128_keep_count_t = axis128_keep_count(
            axis_in_if.stream.data.frag
        )
        if axis_in_if.stream.data.eod[0] & (keep_count != POLY1305_AUTH_TAG_SIZE):
            # Buffer a partial tail for merging, suppressing output even when
            # stalled. Keep ready independent of valid to avoid a loop through
            # the ciphertext fork. Waiting for the tag could deadlock that fork.
            o.axis_out_if.stream.valid = 0
            o.axis_in_if.ready = 1
        if axis_in_if.stream.data.eod[0] & axis_in_if.stream.valid & o.axis_in_if.ready:
            sim_assert(
                keep_count != 0,
                "append_auth_tag: zero-length payload (tlast beat with tkeep all zero)",
            )
            held_data_reg = axis_in_if.stream.data.frag.data
            held_keep_count_reg = keep_count
            if keep_count == POLY1305_AUTH_TAG_SIZE:
                # The full ciphertext beat was already forwarded.
                state = append_auth_tag_state_t.TAG_TAIL
            else:
                state = append_auth_tag_state_t.MERGED_WORD
    elif state == append_auth_tag_state_t.MERGED_WORD:
        # r ct bytes || tag[0 : 16-r], full keep, not yet eod (r < 16 here)
        for i in range(POLY1305_AUTH_TAG_SIZE):
            o.axis_out_if.stream.data.frag.data[i] = merged[i]
            o.axis_out_if.stream.data.frag.keep[i] = 1
        o.axis_out_if.stream.data.eod[0] = 0
        o.axis_out_if.stream.valid = auth_tag_in_if.stream.valid
        # Leave the tag unconsumed until TAG_TAIL.
        if o.axis_out_if.stream.valid & axis_out_if.ready:
            state = append_auth_tag_state_t.TAG_TAIL
    else:  # TAG_TAIL
        # tag[16-r : 16], keep = r ones, eod = 1 -- the true final beat
        for i in range(POLY1305_AUTH_TAG_SIZE):
            o.axis_out_if.stream.data.frag.data[i] = merged[POLY1305_AUTH_TAG_SIZE + i]
        o.axis_out_if.stream.data.frag.keep = axis128_count_to_keep(held_keep_count_reg)
        o.axis_out_if.stream.data.eod[0] = 1
        o.axis_out_if.stream.valid = auth_tag_in_if.stream.valid
        o.auth_tag_in_if.ready = axis_out_if.ready
        if o.axis_out_if.stream.valid & axis_out_if.ready:
            state = append_auth_tag_state_t.CIPHERTEXT

    # Sample handshakes after all output assignments.
    perf_taps.hs(
        "append.axis_in",
        axis_in_if.stream.valid,
        o.axis_in_if.ready,
        axis_in_if.stream.data.frag.keep,
    )
    perf_taps.hs(
        "append.axis_out",
        o.axis_out_if.stream.valid,
        axis_out_if.ready,
        o.axis_out_if.stream.data.frag.keep,
    )
    perf_taps.hs(
        "append.tag_in", auth_tag_in_if.stream.valid, o.auth_tag_in_if.ready
    )
    return o


@struct
class axis128_early_tlast_t(NamedTuple):
    axis_out_if: axis128_if_t.fwd_t
    next_axis_out_is_tlast: uint1_t
    stream_in_if: axis128_if_t.fb_t


@hw_func
def axis128_early_tlast(
    stream_in_if: axis128_if_t.fwd_t,
    axis_out_if: axis128_if_t.fb_t,
) -> axis128_early_tlast_t:
    o: axis128_early_tlast_t

    buffer_reg: Reg[axis128_if_t.stream_t]

    # A nonfinal buffered beat needs the following beat's last flag.
    buffer_is_tlast: uint1_t = buffer_reg.valid & buffer_reg.data.eod[0]
    buff_to_out_connected: uint1_t = (
        buffer_is_tlast | stream_in_if.stream.valid
    )
    o.axis_out_if.stream = axis128_stream_null()
    o.next_axis_out_is_tlast = 0
    if buff_to_out_connected:
        o.axis_out_if.stream = buffer_reg
        o.next_axis_out_is_tlast = (
            stream_in_if.stream.valid & stream_in_if.stream.data.eod[0]
        )

    # A consumed beat frees the buffer for replacement in the same cycle.
    if o.axis_out_if.stream.valid & axis_out_if.ready:
        buffer_reg.valid = 0

    o.stream_in_if.ready = ~buffer_reg.valid
    if stream_in_if.stream.valid & o.stream_in_if.ready:
        buffer_reg = stream_in_if.stream

    return o


@struct
class strip_auth_tag_out_t(NamedTuple):
    axis_in_if: axis128_if_t.fb_t
    axis_out_if: axis128_if_t.fwd_t
    auth_tag_out_if: poly1305_auth_tag_stream_if_t.fwd_t


@hw_func
def strip_auth_tag(
    axis_in_if: axis128_if_t.fwd_t,
    axis_out_if: axis128_if_t.fb_t,
    auth_tag_out_if: poly1305_auth_tag_stream_if_t.fb_t,
) -> strip_auth_tag_out_t:
    o: strip_auth_tag_out_t
    early_out_ready: Feedback[uint1_t]
    # Save the penultimate beat's tag prefix to combine with the final beat.
    prev_data_reg: Reg[uint8_t[POLY1305_AUTH_TAG_SIZE]]

    early_tlast = axis128_early_tlast(
        stream_in_if=axis_in_if, axis_out_if=axis128_if_t.fb_t(early_out_ready)
    )

    o.axis_in_if = early_tlast.stream_in_if
    stream_in: axis128_if_t.stream_t = early_tlast.axis_out_if.stream

    # Forward ciphertext, marking the penultimate input beat as its last.
    o.axis_out_if.stream = stream_in
    early_out_ready = axis_out_if.ready

    o.axis_out_if.stream.data.eod[0] = early_tlast.next_axis_out_is_tlast
    if early_tlast.next_axis_out_is_tlast:
        # The final tag beat's valid-byte count equals the ciphertext bytes
        # in this buffered beat. Check its contiguous keep mask and reuse it.
        recomputed_keep = axis128_count_to_keep(
            axis128_keep_count(axis_in_if.stream.data.frag)
        )
        keep_is_prefix: uint1_t = 1
        for i in range(16):
            if recomputed_keep[i] != axis_in_if.stream.data.frag.keep[i]:
                keep_is_prefix = 0
        sim_assert(
            keep_is_prefix,
            "strip_auth_tag: tag-tail beat's keep is not a Xilinx-style prefix",
        )
        o.axis_out_if.stream.data.frag.keep = axis_in_if.stream.data.frag.keep
        if o.axis_out_if.stream.valid & axis_out_if.ready:
            prev_data_reg = stream_in.data.frag.data
    o.auth_tag_out_if.stream = poly1305_auth_tag_stream_null()

    # Reassemble the tag from the saved prefix and the buffered final beat.
    if stream_in.valid & stream_in.data.eod[0]:
        last_keep_count: axis128_keep_count_t = axis128_keep_count(stream_in.data.frag)
        window: uint8_t[2 * POLY1305_AUTH_TAG_SIZE]
        for i in range(POLY1305_AUTH_TAG_SIZE):
            window[i] = prev_data_reg[i]
            window[POLY1305_AUTH_TAG_SIZE + i] = stream_in.data.frag.data[i]
        tag_bytes: uint8_t[POLY1305_AUTH_TAG_SIZE]
        for i in range(POLY1305_AUTH_TAG_SIZE):
            tag_bytes[i] = window[last_keep_count + i]

        # Route the final beat to the tag output only.
        o.axis_out_if.stream.valid = 0
        o.auth_tag_out_if.stream.data = array_to_uint_le(tag_bytes)
        o.auth_tag_out_if.stream.valid = stream_in.valid
        early_out_ready = auth_tag_out_if.ready

    # Sample handshakes after all output assignments.
    perf_taps.hs(
        "strip.axis_in",
        axis_in_if.stream.valid,
        o.axis_in_if.ready,
        axis_in_if.stream.data.frag.keep,
    )
    perf_taps.hs(
        "strip.axis_out",
        o.axis_out_if.stream.valid,
        axis_out_if.ready,
        o.axis_out_if.stream.data.frag.keep,
    )
    perf_taps.hs(
        "strip.tag_out", o.auth_tag_out_if.stream.valid, auth_tag_out_if.ready
    )
    # One cover event per packet, when its final input beat is taken: the tag fills
    # that beat exactly, or straddles it and the previous beat.
    perf_taps.hs(
        "cover.strip.exact",
        stream_in.valid & stream_in.data.eod[0] & stream_in.data.frag.keep[15],
        auth_tag_out_if.ready,
    )
    perf_taps.hs(
        "cover.strip.straddle",
        stream_in.valid & stream_in.data.eod[0] & ~stream_in.data.frag.keep[15],
        auth_tag_out_if.ready,
    )
    return o
