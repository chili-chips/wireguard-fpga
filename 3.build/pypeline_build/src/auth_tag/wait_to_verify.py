# SPDX-FileCopyrightText: 2026 Julian Kemmerer
# SPDX-FileCopyrightText: 2026 Chili.CHIPS
#
# SPDX-License-Identifier: BSD-3-Clause

# pyright: reportInvalidTypeForm=none
"""Buffer plaintext until its Poly1305 verdict arrives, then forward the packet
with that verdict on is_verified_out, whether verification passed or failed.

Pypeline port of ../pipelinec_build/src/auth_tag/wait_to_verify.c.
"""
import wireguard_env  # noqa: F401

from enum import auto

from pypeline import (
    NamedTuple,
    struct,
    hw_func,
    Reg,
    Feedback,
    enum,
    uint1_t,
    initial,
    sim_output,
)

from stream import stream_perf_probe as perf_taps

from aead_types import (
    aead_axis_if_t,
    aead_axis_frag_t,
    uint1_stream_if_t,
    make_aead_fifo,
)


@enum
class wait_to_verify_state_t:
    WAIT_TO_VERIFY_BIT = auto()
    OUTPUT_PLAINTEXT = auto()


# Declaration order matches the state histogram values.
WAIT_TO_VERIFY_STATE_NAMES = tuple(wait_to_verify_state_t.__members__)


@struct
class wait_to_verify_out_t(NamedTuple):
    axis_in_if: aead_axis_if_t.fb_t
    verify_bit_if: uint1_stream_if_t.fb_t
    axis_out_if: aead_axis_if_t.fwd_t
    is_verified_out: uint1_t  # plain sideband, no reverse companion


def make_wait_to_verify(depth=128, *, sizing=None):
    """Define a plaintext buffer with the caller's FIFO depth and sizing metadata."""
    if type(depth) is not int or depth < 2:
        raise ValueError("Verification FIFO memory depth must be an integer >= 2")
    verify_fifo_func = make_aead_fifo(
        aead_axis_frag_t, depth, "verify_fifo", "decrypt", sizing=sizing
    )
    # Simulation check: each output packet must have an accepted verdict.
    checked = {"verdicts": 0, "packets": 0}

    @initial(sim=True)
    def reset_verdict_check():
        checked.update(verdicts=0, packets=0)

    @sim_output
    def check_verdict_order(
        verdict_valid, verdict_ready, output_valid, output_ready, output_last
    ):
        if verdict_valid and verdict_ready:
            checked["verdicts"] += 1
        if output_valid:
            assert checked["verdicts"] > checked["packets"], (
                "Plaintext exposed before its verdict"
            )
            if output_ready and output_last:
                checked["packets"] += 1

    @hw_func
    def wait_to_verify(
        axis_in_if: aead_axis_if_t.fwd_t,
        verify_bit_if: uint1_stream_if_t.fwd_t,
        axis_out_if: aead_axis_if_t.fb_t,
    ) -> wait_to_verify_out_t:
        o: wait_to_verify_out_t
        state: Reg[wait_to_verify_state_t]
        # Sample before transitions; WAIT_TO_VERIFY_BIT also includes idle time.
        perf_taps.state("wtv.fsm", state, WAIT_TO_VERIFY_STATE_NAMES)
        tags_match_reg: Reg[uint1_t]

        # Close the FIFO data/ready feedback through the FSM.
        verify_fifo_in_ready: Feedback[uint1_t]
        verify_fifo_out: Feedback[aead_axis_if_t.stream_t]

        # Accept plaintext whenever the FIFO has room, in either state.
        verify_fifo_in_s: aead_axis_if_t.stream_t = axis_in_if.stream
        o.axis_in_if.ready = verify_fifo_in_ready

        # The FSM gates FIFO consumption and output validity.
        o.axis_out_if.stream = verify_fifo_out

        o.verify_bit_if.ready = 0
        verify_fifo_out_ready_s: uint1_t = 0
        o.axis_out_if.stream.valid = 0
        o.is_verified_out = 0

        # Timing corners, sampled before the transitions (simulation only): the
        # verdict arrives before or after the packet's plaintext is buffered, and
        # the next verdict waits while the current packet drains.
        perf_taps.hs(
            "cover.wtv.verdict_first",
            (state == wait_to_verify_state_t.WAIT_TO_VERIFY_BIT)
            & verify_bit_if.stream.valid
            & ~verify_fifo_out.valid,
            1,
        )
        perf_taps.hs(
            "cover.wtv.verdict_last",
            (state == wait_to_verify_state_t.WAIT_TO_VERIFY_BIT)
            & verify_bit_if.stream.valid
            & verify_fifo_out.valid,
            1,
        )
        perf_taps.hs(
            "cover.wtv.verdict_wait",
            (state == wait_to_verify_state_t.OUTPUT_PLAINTEXT) & verify_bit_if.stream.valid,
            1,
        )

        if state == wait_to_verify_state_t.WAIT_TO_VERIFY_BIT:
            # Hold plaintext until this packet's verdict is accepted.
            verify_fifo_out_ready_s = 0
            o.axis_out_if.stream.valid = 0
            o.verify_bit_if.ready = 1

            if verify_bit_if.stream.valid:
                tags_match_reg = verify_bit_if.stream.data
                state = wait_to_verify_state_t.OUTPUT_PLAINTEXT
        else:  # if state == wait_to_verify_state_t.OUTPUT_PLAINTEXT
            # Forward the packet with a constant verdict on every valid beat.
            verify_fifo_out_ready_s = axis_out_if.ready
            o.axis_out_if.stream.valid = verify_fifo_out.valid
            o.is_verified_out = tags_match_reg

            if o.axis_out_if.stream.valid & axis_out_if.ready:
                if o.axis_out_if.stream.data.eod[0]:
                    state = wait_to_verify_state_t.WAIT_TO_VERIFY_BIT

            # Accept the next verdict only after this packet has drained.
            o.verify_bit_if.ready = 0

        fifo_result = verify_fifo_func(
            in_stream_if=aead_axis_if_t.fwd_t(verify_fifo_in_s),
            out_stream_if=aead_axis_if_t.fb_t(verify_fifo_out_ready_s),
        )
        verify_fifo_out = fifo_result.out_stream_if.stream
        verify_fifo_in_ready = fifo_result.in_stream_if.ready

        # Sample handshakes after all output assignments.
        perf_taps.hs(
            "wtv.axis_in",
            axis_in_if.stream.valid,
            o.axis_in_if.ready,
            axis_in_if.stream.data.frag.keep,
        )
        perf_taps.hs(
            "wtv.axis_out",
            o.axis_out_if.stream.valid,
            axis_out_if.ready,
            o.axis_out_if.stream.data.frag.keep,
        )
        perf_taps.hs("wtv.verify_bit", verify_bit_if.stream.valid, o.verify_bit_if.ready)
        check_verdict_order(
            verify_bit_if.stream.valid,
            o.verify_bit_if.ready,
            o.axis_out_if.stream.valid,
            axis_out_if.ready,
            o.axis_out_if.stream.data.eod[0],
        )
        return o

    return wait_to_verify
