# SPDX-FileCopyrightText: 2026 Julian Kemmerer
# SPDX-FileCopyrightText: 2026 Chili.CHIPS
#
# SPDX-License-Identifier: BSD-3-Clause

# pyright: reportInvalidTypeForm=none
"""256-bit MAC: paired coefficients followed by interleaved accumulator feedback.

Each pair passes through both free-running pipelines. Only feedback latency
sets the lane count; accumulator reads follow coefficient processing.
See poly1305_design.md for the pipeline and packet-bank architecture.
"""
import wireguard_env  # noqa: F401

from enum import auto
from pypeline import (
    AUTO_PIPELINE, NamedTuple, Reg, Feedback, struct, enum, hw_func,
    uint1_t, uint8_t, make_uint_t, uint_to_array_le, array_to_uint_le, sim_assert,
)
from stream import make_stream_t, make_stream_interface
from poly1305_compute import make_compute_unit
from aead_types import (
    aead_axis_if_t, poly1305_key_stream_if_t, poly1305_auth_tag_stream_if_t,
)
from poly1305_math import (
    u8_16_t, uint128_t, uint130_t, clamp,
    residue_mul_add_mod, feedback_mul_add_mod,
)
from stream import stream_perf_probe as perf_taps


@struct
class body_in_t(NamedTuple):
    accumulator: uint130_t
    stride: uint130_t
    coefficient: uint130_t


body_in_stream_t = make_stream_t(body_in_t)
body_out_stream_t = make_stream_t(uint130_t)


@hw_func
def poly1305_pair_accumulate(x: body_in_stream_t) -> body_out_stream_t:
    o: body_out_stream_t
    o.data = feedback_mul_add_mod(x.data.accumulator, x.data.stride, x.data.coefficient)
    o.valid = x.valid
    return o


@struct
class coefficient_in_t(NamedTuple):
    r: uint130_t
    blocks: uint8_t[32]


coefficient_in_stream_t = make_stream_t(coefficient_in_t)


@hw_func
def poly1305_pair_coefficient(x: coefficient_in_stream_t) -> body_out_stream_t:
    lo: uint8_t[16]
    hi: uint8_t[16]
    for j in range(16):
        lo[j] = x.data.blocks[j]
        hi[j] = x.data.blocks[j + 16]
    c0: uint130_t = array_to_uint_le(lo)
    c1: uint130_t = array_to_uint_le(hi)
    c0 = c0 | (1 << 128)
    c1 = c1 | (1 << 128)
    o: body_out_stream_t
    o.data = residue_mul_add_mod(c0, x.data.r, c1)
    o.valid = x.valid
    return o


def get_coefficient_auto_pipeline(coefficient_latency=None):
    """Match coefficient depth across directions; fixed depth is for tests."""
    return AUTO_PIPELINE(
        poly1305_pair_coefficient,
        latency=coefficient_latency, name="poly1305_pair_coefficient",
    )


# Architectural storage/phase boundaries, also consumed by FIFO sizing.
PACKET_CONTEXTS = 2
KEY_CAPTURE_CYCLES = 1
PREPARED_REGISTER_CYCLES = 1
BODY_CONTEXT_REGISTER_CYCLES = 1
BODY_COMMIT_CYCLES = 1
COMPLETION_REGISTER_CYCLES = 1
TAG_REGISTER_CYCLES = 1


@enum
class init_state_t:
    IDLE = auto()
    INIT_LAUNCH = auto()
    INIT_WAIT = auto()
    OUTPUT_DESCRIPTOR = auto()


@enum
class bank_state_t:
    EMPTY = auto()
    READY = auto()
    STREAM_BODY = auto()
    DRAIN = auto()


@enum
class finish_state_t:
    IDLE = auto()
    FINISH_WAIT = auto()
    OUTPUT_TAG = auto()


# Histogram labels remain compatible with saved probe records.
INIT_STATE_NAMES = ("IDLE", "PROLOGUE_LAUNCH", "PROLOGUE_WAIT", "OUTPUT_DESCRIPTOR")
BANK_STATE_NAMES = tuple(bank_state_t.__members__)
FINISH_STATE_NAMES = ("IDLE", "EPILOGUE_WAIT", "OUTPUT_TAG")


@struct
class mac_result_t(NamedTuple):
    key_if: poly1305_key_stream_if_t.fb_t
    data_in_if: aead_axis_if_t.fb_t
    auth_tag_if: poly1305_auth_tag_stream_if_t.fwd_t


def get_body_auto_pipeline(body_latency=None):
    """Match feedback depth and shared-unit sizing; fixed depth is for tests."""
    return AUTO_PIPELINE(
        poly1305_pair_accumulate,
        latency=body_latency, name="poly1305_pair_accumulate",
    )


def make_poly1305_mac_paired(direction, share_compute=False, *, body_latency=None, coefficient_latency=None):
    """Define a paired MAC with private packet state and optional shared compute."""
    body_ap = get_body_auto_pipeline(body_latency)
    coefficient_ap = get_coefficient_auto_pipeline(coefficient_latency)
    coefficient_cycles = coefficient_ap.latency + 2
    lanes = body_ap.latency + 2
    FINAL_LANE_TAPS = tuple(f"cover.poly.final_lane{lane}" for lane in range(lanes))
    total_cycles = coefficient_cycles + lanes
    lane_t = make_uint_t(max(1, (lanes - 1).bit_length()))
    count_t = make_uint_t(total_cycles.bit_length())

    @hw_func
    def body_pipeline(x: body_in_stream_t) -> body_out_stream_t:
        input_reg: Reg[body_in_stream_t]
        output_reg: Reg[body_out_stream_t]
        result: body_out_stream_t = output_reg
        output_reg = body_ap(input_reg)
        input_reg = x
        return result

    @hw_func
    def coefficient_pipeline(x: coefficient_in_stream_t) -> body_out_stream_t:
        input_reg: Reg[coefficient_in_stream_t]
        output_reg: Reg[body_out_stream_t]
        result: body_out_stream_t = output_reg
        output_reg = coefficient_ap(input_reg)
        input_reg = x
        return result

    from poly1305_compute import make_paired_compute
    compute = make_paired_compute(lanes)
    powers_t, finish_in_t = compute.powers_t, compute.finish_in_t
    init, finish = compute.init, compute.finish

    if share_compute:
        from poly1305_compute_shared import make_shared_compute_adapters

        adapters = make_shared_compute_adapters(direction, lanes, powers_t, finish_in_t)
        init_unit = adapters.init
        finish_unit = adapters.finish
    else:
        # Both directions build equal compute units, which PypelineC merges into
        # one definition; each instance keeps its own state.
        init_unit = make_compute_unit(init, phase="init")
        finish_unit = make_compute_unit(finish, phase="finish")

    @struct
    class prepared_t(NamedTuple):
        context: uint1_t
        powers: powers_t
        r: uint130_t
        s: uint128_t

    @struct
    class completed_t(NamedTuple):
        context: uint1_t
        data: finish_in_t

    prepared_if_t = make_stream_interface(prepared_t)
    completed_if_t = make_stream_interface(completed_t)

    @struct
    class init_stage_result_t(NamedTuple):
        key_if: poly1305_key_stream_if_t.fb_t
        prepared_if: prepared_if_t.fwd_t
        computing: uint1_t

    @hw_func
    def init_stage(
        key_if: poly1305_key_stream_if_t.fwd_t,
        prepared_if: prepared_if_t.fb_t,
    ) -> init_stage_result_t:
        state: Reg[init_state_t]
        r: Reg[uint130_t]
        descriptor: Reg[prepared_t]
        next_context: Reg[uint1_t]
        result: Feedback[init_unit.return_t]
        o: init_stage_result_t
        o.key_if.ready = state == init_state_t.IDLE
        o.prepared_if.stream.data = descriptor
        o.prepared_if.stream.valid = state == init_state_t.OUTPUT_DESCRIPTOR
        o.computing = ((state == init_state_t.INIT_LAUNCH)
                       | (state == init_state_t.INIT_WAIT))
        request: init_unit.in_if_t.stream_t
        request.data = r
        request.valid = state == init_state_t.INIT_LAUNCH
        response_ready: uint1_t = state == init_state_t.INIT_WAIT
        perf_taps.state("poly1305.prologue.fsm", state, INIT_STATE_NAMES)

        if state == init_state_t.IDLE:
            if key_if.stream.valid:
                key_bytes: uint8_t[32] = uint_to_array_le(key_if.stream.data, 8)
                r_bytes: u8_16_t
                s_bytes: uint8_t[16]
                for j in range(16):
                    r_bytes.bytes[j] = key_bytes[j]
                    s_bytes[j] = key_bytes[j + 16]
                r_bytes = clamp(r_bytes)
                r = array_to_uint_le(r_bytes.bytes)
                descriptor.r = r
                descriptor.s = array_to_uint_le(s_bytes)
                descriptor.context = next_context
                next_context = ~next_context
                state = init_state_t.INIT_LAUNCH
        elif state == init_state_t.INIT_LAUNCH:
            if result.stream_in_if.ready:
                state = init_state_t.INIT_WAIT
        elif state == init_state_t.INIT_WAIT:
            if result.stream_out_if.stream.valid:
                descriptor.powers = result.stream_out_if.stream.data
                state = init_state_t.OUTPUT_DESCRIPTOR
        elif prepared_if.ready:
            state = init_state_t.IDLE

        result = init_unit(
            init_unit.in_fwd_t(stream=request),
            init_unit.out_fb_t(ready=response_ready),
        )
        perf_taps.hs("poly1305.prologue_in", request.valid, result.stream_in_if.ready)
        perf_taps.hs("poly1305.prologue_out", result.stream_out_if.stream.valid, response_ready)
        perf_taps.hs("poly1305.prepared.in", result.stream_out_if.stream.valid, response_ready)
        perf_taps.hs("poly1305.prepared.out", o.prepared_if.stream.valid, prepared_if.ready)
        perf_taps.occupancy("poly1305.prepared.occupancy",
                            result.stream_out_if.stream.valid, response_ready,
                            o.prepared_if.stream.valid, prepared_if.ready, 1)
        return o

    @struct
    class bank_t(NamedTuple):
        state: bank_state_t
        data: finish_in_t
        retire_lane: lane_t
        outstanding: count_t

    @struct
    class body_owner_t(NamedTuple):
        context: uint1_t
        lane: lane_t
        valid: uint1_t

    @struct
    class body_stage_result_t(NamedTuple):
        prepared_if: prepared_if_t.fb_t
        data_in_if: aead_axis_if_t.fb_t
        completed_if: completed_if_t.fwd_t

    @hw_func
    def body_stage(
        prepared_if: prepared_if_t.fwd_t,
        data_in_if: aead_axis_if_t.fwd_t,
        completed_if: completed_if_t.fb_t,
    ) -> body_stage_result_t:
        banks: Reg[bank_t[PACKET_CONTEXTS]]
        issue_context: Reg[uint1_t]
        complete_context: Reg[uint1_t]
        completion: Reg[completed_if_t.stream_t]
        owners: Reg[body_owner_t[lanes]]
        result: Feedback[body_out_stream_t]
        coefficients: Feedback[body_out_stream_t]
        coefficient_owners: Reg[body_owner_t[coefficient_cycles]]

        # Snapshot the old registers before writeback/issue mutate them.
        issuing_context: uint1_t = issue_context
        issuing_lane: lane_t = banks[issuing_context].data.next_lane
        owner: body_owner_t = owners[lanes - 1]
        retiring_context: uint1_t = owner.context
        retiring_lane: lane_t = owner.lane
        can_snapshot: uint1_t = (
            (banks[complete_context].state == bank_state_t.DRAIN)
            & (banks[complete_context].outstanding == 0)
        )
        streaming: uint1_t = (
            (banks[issuing_context].state == bank_state_t.READY)
            | (banks[issuing_context].state == bank_state_t.STREAM_BODY)
        )
        draining: uint1_t = (
            (banks[0].state == bank_state_t.DRAIN)
            | (banks[1].state == bank_state_t.DRAIN)
        )
        o: body_stage_result_t
        o.data_in_if.ready = streaming
        o.completed_if.stream = completion
        admitted: uint1_t = data_in_if.stream.valid & streaming
        paired: uint1_t = data_in_if.stream.data.frag.keep[31]
        coefficient_request: coefficient_in_stream_t
        coefficient_request.data.r = banks[issuing_context].data.r
        coefficient_request.data.blocks = data_in_if.stream.data.frag.data
        coefficient_request.valid = admitted & paired
        coefficient_owner: body_owner_t = coefficient_owners[coefficient_cycles - 1]
        feedback_context: uint1_t = coefficient_owner.context
        feedback_lane: lane_t = coefficient_owner.lane
        # Read the accumulator after preprocessing, so only feedback latency
        # determines how many lanes are needed to hide the recurrence.
        request: body_in_stream_t
        request.data.accumulator = banks[feedback_context].data.accumulators[feedback_lane]
        request.data.stride = banks[feedback_context].data.powers.values[lanes - 1]
        request.data.coefficient = coefficients.data
        request.valid = coefficients.valid
        sim_assert(coefficients.valid == coefficient_owner.valid,
                   "Poly1305 coefficient ownership delay mismatch")
        if admitted:
            for j in range(16):
                sim_assert(data_in_if.stream.data.frag.keep[j], "Incomplete first authentication block")
                sim_assert(data_in_if.stream.data.frag.keep[j + 16] == paired,
                           "Incomplete second authentication block")
            sim_assert(paired | data_in_if.stream.data.eod[0], "Single block must terminate authentication")

        perf_taps.state("poly1305.body.bank0", banks[0].state, BANK_STATE_NAMES)
        perf_taps.state("poly1305.body.bank1", banks[1].state, BANK_STATE_NAMES)
        perf_taps.state("poly1305.body.fsm", streaming, ("WAIT_CONTEXT", "STREAM_BODY"))
        perf_taps.state("poly1305.fsm", streaming, ("WAIT_CONTEXT", "STREAM_BODY"))
        perf_taps.hs("poly1305.drain", draining, 1)
        perf_taps.hs("poly1305.body_drain_overlap", request.valid & draining, 1)

        # Both ownership lines advance every clock, including bubbles, with
        # their arithmetic pipelines. Returning results cannot be stalled.
        sim_assert(result.valid == owner.valid, "Poly1305 body ownership delay mismatch")
        if result.valid:
            sim_assert(banks[retiring_context].state != bank_state_t.EMPTY,
                       "Poly1305 writeback into a released context")
            sim_assert(banks[retiring_context].outstanding != 0,
                       "Poly1305 outstanding result underflow")
            sim_assert(banks[retiring_context].retire_lane == retiring_lane,
                       "Poly1305 result lane ordering mismatch")
            if (feedback_context == retiring_context) & (feedback_lane == retiring_lane):
                request.data.accumulator = result.data
            banks[retiring_context].data.accumulators[retiring_lane] = result.data
            banks[retiring_context].outstanding -= 1
            if retiring_lane == lanes - 1:
                banks[retiring_context].retire_lane = 0
            else:
                banks[retiring_context].retire_lane = retiring_lane + 1

        if admitted:
            banks[issuing_context].state = bank_state_t.STREAM_BODY
            if paired:
                sim_assert(banks[issuing_context].outstanding < total_cycles,
                           "Poly1305 too many outstanding pairs")
                banks[issuing_context].outstanding += 1
                if issuing_lane == lanes - 1:
                    banks[issuing_context].data.next_lane = 0
                else:
                    banks[issuing_context].data.next_lane = issuing_lane + 1
            else:
                tail_bytes: uint8_t[16]
                for j in range(16):
                    tail_bytes[j] = data_in_if.stream.data.frag.data[j]
                tail: uint130_t = array_to_uint_le(tail_bytes)
                banks[issuing_context].data.tail = tail | (1 << 128)
                banks[issuing_context].data.has_tail = 1
            if data_in_if.stream.data.eod[0]:
                banks[issuing_context].state = bank_state_t.DRAIN
                issue_context = ~issuing_context

        if completion.valid & completed_if.ready:
            completion.valid = 0
        snapshot: uint1_t = can_snapshot & ~completion.valid
        if snapshot:
            # can_snapshot uses the old outstanding count: this boundary
            # includes the final committed writeback, while the other bank
            # remains free to issue arithmetic work.
            completion.data.context = complete_context
            completion.data.data = banks[complete_context].data
            completion.valid = 1
            banks[complete_context].state = bank_state_t.EMPTY
            complete_context = ~complete_context

        # A released bank may accept the next descriptor on this same edge.
        # Issue eligibility above still came from the old bank state.
        o.prepared_if.ready = banks[prepared_if.stream.data.context].state == bank_state_t.EMPTY
        if prepared_if.stream.valid & o.prepared_if.ready:
            context: uint1_t = prepared_if.stream.data.context
            sim_assert(banks[context].outstanding == 0,
                       "Poly1305 context reused before drain")
            banks[context].state = bank_state_t.READY
            banks[context].data.powers = prepared_if.stream.data.powers
            banks[context].data.s = prepared_if.stream.data.s
            banks[context].data.r = prepared_if.stream.data.r
            banks[context].data.tail = 0
            banks[context].data.has_tail = 0
            banks[context].data.lane_count = lanes
            banks[context].data.next_lane = 0
            banks[context].retire_lane = 0
            for j in range(lanes):
                banks[context].data.accumulators[j] = 0

        for k in range(lanes - 1, 0, -1):
            owners[k] = owners[k - 1]
        owners[0].context = feedback_context
        owners[0].lane = feedback_lane
        owners[0].valid = request.valid
        result = body_pipeline(request)
        for k in range(coefficient_cycles - 1, 0, -1):
            coefficient_owners[k] = coefficient_owners[k - 1]
        coefficient_owners[0].context = issuing_context
        coefficient_owners[0].lane = issuing_lane
        coefficient_owners[0].valid = coefficient_request.valid
        coefficients = coefficient_pipeline(coefficient_request)

        perf_taps.hs("poly1305.coefficient_in", coefficient_request.valid, 1)
        perf_taps.hs("poly1305.coefficient_out", coefficients.valid, 1)
        perf_taps.hs("poly1305.tail_in", admitted & ~paired, 1)
        # One cover event per packet whose block count is even: the lane that
        # takes its final pair, which decides what wraps around the accumulators.
        for lane in range(lanes):
            perf_taps.hs(
                FINAL_LANE_TAPS[lane],
                admitted & paired & data_in_if.stream.data.eod[0] & (issuing_lane == lane),
                1,
            )

        perf_taps.hs("poly1305.to_compute", request.valid, 1)
        perf_taps.hs("poly1305.from_compute", result.valid, 1)
        perf_taps.hs("poly1305.contexts.in", prepared_if.stream.valid, o.prepared_if.ready)
        perf_taps.hs("poly1305.contexts.out", snapshot, 1)
        perf_taps.occupancy("poly1305.contexts.occupancy",
                            prepared_if.stream.valid, o.prepared_if.ready, snapshot, 1,
                            PACKET_CONTEXTS)
        perf_taps.hs("poly1305.completion.in", snapshot, 1)
        perf_taps.hs("poly1305.completion.out", o.completed_if.stream.valid, completed_if.ready)
        perf_taps.occupancy("poly1305.completion.occupancy", snapshot, 1,
                            o.completed_if.stream.valid, completed_if.ready, 1)
        return o

    @struct
    class finish_stage_result_t(NamedTuple):
        completed_if: completed_if_t.fb_t
        auth_tag_if: poly1305_auth_tag_stream_if_t.fwd_t
        computing: uint1_t

    @hw_func
    def finish_stage(
        completed_if: completed_if_t.fwd_t,
        auth_tag_if: poly1305_auth_tag_stream_if_t.fb_t,
    ) -> finish_stage_result_t:
        state: Reg[finish_state_t]
        owner_context: Reg[uint1_t]
        tag_context: Reg[uint1_t]
        tag: Reg[uint128_t]
        result: Feedback[finish_unit.return_t]
        o: finish_stage_result_t
        o.completed_if.ready = (state == finish_state_t.IDLE) & result.stream_in_if.ready
        o.auth_tag_if.stream.data = tag
        o.auth_tag_if.stream.valid = state == finish_state_t.OUTPUT_TAG
        o.computing = ((state == finish_state_t.FINISH_WAIT)
                       | ((state == finish_state_t.IDLE) & completed_if.stream.valid))
        request: finish_unit.in_if_t.stream_t
        request.data = completed_if.stream.data.data
        request.valid = completed_if.stream.valid & (state == finish_state_t.IDLE)
        response_ready: uint1_t = state == finish_state_t.FINISH_WAIT
        perf_taps.state("poly1305.epilogue.fsm", state, FINISH_STATE_NAMES)

        if state == finish_state_t.IDLE:
            if request.valid & result.stream_in_if.ready:
                owner_context = completed_if.stream.data.context
                state = finish_state_t.FINISH_WAIT
        elif state == finish_state_t.FINISH_WAIT:
            if result.stream_out_if.stream.valid:
                tag = result.stream_out_if.stream.data
                tag_context = owner_context
                state = finish_state_t.OUTPUT_TAG
        elif auth_tag_if.ready:
            sim_assert(tag_context == owner_context, "Poly1305 tag ownership mismatch")
            state = finish_state_t.IDLE

        result = finish_unit(
            finish_unit.in_fwd_t(stream=request),
            finish_unit.out_fb_t(ready=response_ready),
        )
        perf_taps.hs("poly1305.epilogue_in", request.valid, result.stream_in_if.ready)
        perf_taps.hs("poly1305.epilogue_out", result.stream_out_if.stream.valid, response_ready)
        perf_taps.hs("poly1305.tags.in", result.stream_out_if.stream.valid, response_ready)
        perf_taps.hs("poly1305.tags.out", o.auth_tag_if.stream.valid, auth_tag_if.ready)
        perf_taps.occupancy("poly1305.tags.occupancy",
                            result.stream_out_if.stream.valid, response_ready,
                            o.auth_tag_if.stream.valid, auth_tag_if.ready, 1)
        return o

    @hw_func
    def poly1305_mac_paired(
        key_if: poly1305_key_stream_if_t.fwd_t,
        data_in_if: aead_axis_if_t.fwd_t,
        auth_tag_if: poly1305_auth_tag_stream_if_t.fb_t,
    ) -> mac_result_t:
        body_result: Feedback[body_stage_result_t]
        finish_result: Feedback[finish_stage_result_t]
        prepared = init_stage(key_if, prepared_if_t.fb_t(body_result.prepared_if.ready))
        body_result = body_stage(prepared.prepared_if, data_in_if,
                                 completed_if_t.fb_t(finish_result.completed_if.ready))
        finish_result = finish_stage(body_result.completed_if, auth_tag_if)
        o: mac_result_t
        o.key_if = prepared.key_if
        o.data_in_if = body_result.data_in_if
        o.auth_tag_if = finish_result.auth_tag_if
        perf_taps.hs("poly1305.key_in", key_if.stream.valid, o.key_if.ready)
        perf_taps.hs("poly1305.data_in", data_in_if.stream.valid, o.data_in_if.ready,
                     data_in_if.stream.data.frag.keep)
        perf_taps.hs("poly1305.tag_out", o.auth_tag_if.stream.valid, auth_tag_if.ready)
        issuing: uint1_t = data_in_if.stream.valid & o.data_in_if.ready
        perf_taps.hs("poly1305.setup_body_overlap", prepared.computing & issuing, 1)
        perf_taps.hs("poly1305.epilogue_body_overlap", finish_result.computing & issuing, 1)
        return o

    # Plain Python metadata/test hooks; these do not add hardware ports.
    poly1305_mac_paired.coefficient_auto_pipeline = coefficient_ap
    poly1305_mac_paired.coefficient_pipeline = coefficient_pipeline
    poly1305_mac_paired.coefficient_latency = coefficient_cycles
    poly1305_mac_paired.total_body_latency = total_cycles
    poly1305_mac_paired.body_auto_pipeline = body_ap
    poly1305_mac_paired.body_pipeline = body_pipeline
    poly1305_mac_paired.accumulator_count = lanes
    poly1305_mac_paired.init_unit = init_unit
    poly1305_mac_paired.finish_unit = finish_unit
    poly1305_mac_paired.init = init
    poly1305_mac_paired.finish = finish
    poly1305_mac_paired.shared_compute = bool(share_compute)
    poly1305_mac_paired.packet_architecture = "overlapped"
    poly1305_mac_paired.init_handoff_cycles = (
        KEY_CAPTURE_CYCLES + PREPARED_REGISTER_CYCLES + BODY_CONTEXT_REGISTER_CYCLES
    )
    poly1305_mac_paired.body_commit_cycles = BODY_COMMIT_CYCLES
    poly1305_mac_paired.finish_handoff_cycles = (
        COMPLETION_REGISTER_CYCLES + TAG_REGISTER_CYCLES
    )
    poly1305_mac_paired.packet_buffers = {
        "poly1305.prepared": 1, "poly1305.contexts": PACKET_CONTEXTS,
        "poly1305.completion": 1, "poly1305.tags": 1,
    }
    return poly1305_mac_paired
