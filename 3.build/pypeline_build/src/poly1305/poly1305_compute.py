# SPDX-FileCopyrightText: 2026 Julian Kemmerer
# SPDX-FileCopyrightText: 2026 Chili.CHIPS
#
# SPDX-License-Identifier: BSD-3-Clause

# pyright: reportInvalidTypeForm=none
"""Poly1305 initialization/finalization kernels and compute-unit definitions.

The 128-bit private and capacity-aware kernels retain their distinct payloads;
the paired kernel serves both private and shared 256-bit MACs. See
poly1305_design.md for key precomputation, reduction, and scheduling.
"""
import wireguard_env  # noqa: F401

from types import SimpleNamespace
from pypeline import NamedTuple, struct, hw_func, uint1_t, make_uint_t
from stream.stream_auto_fsm import make_stream_auto_fsm
from stream.stream_multi_cycle import make_stream_auto_multi_cycle
from poly1305_math import (
    uint128_t, uint130_t, residue_mul_mod, residue_add_mod, residue_square_mod, SQUARE_POWERS,
)


def make_compute_unit(func, phase):
    """Return a unit definition; hardware instances keep separate state.

    Equal calls give equal definitions, which PypelineC merges into one.
    compute_tag.latency excludes the wrapper's one result/handshake cycle.
    """
    if phase not in ("init", "finish"):
        raise ValueError(f"Poly1305 compute phase must be init or finish, got {phase!r}")
    if wireguard_env.POLY1305_COMPUTE_IMPL == "fsm":
        cap = (
            wireguard_env.POLY1305_PROLOGUE_MAX_LATENCY
            if phase == "init"
            else wireguard_env.POLY1305_EPILOGUE_MAX_LATENCY
        )
        unit = make_stream_auto_fsm(func, max_latency=cap)
        unit.compute_tag = unit.fsm
    else:
        unit = make_stream_auto_multi_cycle(func)
        unit.compute_tag = unit.mcp
    return unit


def make_pipelined_compute(lanes):
    """Initialization/finalization kernels and payload types specialized by lane count."""
    lane_t = make_uint_t(max(1, (lanes - 1).bit_length()))
    # Signed subtraction is unnecessary in the finalization's rotated index.
    index_t = make_uint_t((2 * lanes).bit_length())
    tree_size = 1 << (lanes - 1).bit_length()

    @struct
    class powers_t(NamedTuple):
        values: uint130_t[lanes]

    @hw_func
    def init(r: uint130_t) -> powers_t:
        o: powers_t
        o.values[0] = r
        for k in range(2, lanes + 1):
            if SQUARE_POWERS and k % 2 == 0:
                o.values[k - 1] = residue_square_mod(o.values[k // 2 - 1])
            else:
                o.values[k - 1] = residue_mul_mod(
                    o.values[k // 2 - 1], o.values[(k + 1) // 2 - 1]
                )
        return o

    @struct
    class finish_in_t(NamedTuple):
        accumulators: uint130_t[lanes]
        powers: powers_t
        next_lane: lane_t
        s: uint128_t

    @hw_func
    def finish(x: finish_in_t) -> uint128_t:
        tree: uint130_t[2 * tree_size]
        for j in range(tree_size):
            tree[tree_size + j] = 0
        for j in range(lanes):
            power_index: index_t = x.next_lane + lanes - 1 - j
            # next_lane < lanes, so the last slot never wraps.
            if j + 1 < lanes:
                if x.next_lane > j:
                    power_index = x.next_lane - 1 - j
            tree[tree_size + j] = residue_mul_mod(
                x.accumulators[j], x.powers.values[power_index]
            )
        for k in range(tree_size - 1, 0, -1):
            tree[k] = residue_add_mod(tree[2 * k], tree[2 * k + 1])
        low: uint128_t = tree[1]
        tag: uint128_t = low + x.s
        return tag

    return SimpleNamespace(init=init, finish=finish,
                           powers_t=powers_t, finish_in_t=finish_in_t)


def make_shared_compute(capacity):
    """128-bit kernels and payloads supporting local lane counts up to capacity."""
    lane_t = make_uint_t(max(1, (capacity - 1).bit_length()))
    count_t = make_uint_t(capacity.bit_length())
    index_t = make_uint_t((2 * capacity).bit_length())
    tree_size = 1 << (capacity - 1).bit_length()

    @struct
    class powers_t(NamedTuple):
        values: uint130_t[capacity]

    @struct
    class finish_in_t(NamedTuple):
        accumulators: uint130_t[capacity]
        powers: powers_t
        lane_count: count_t
        next_lane: lane_t
        s: uint128_t

    @hw_func
    def init(r: uint130_t) -> powers_t:
        o: powers_t
        o.values[0] = r
        for k in range(2, capacity + 1):
            if SQUARE_POWERS and k % 2 == 0:
                o.values[k - 1] = residue_square_mod(o.values[k // 2 - 1])
            else:
                o.values[k - 1] = residue_mul_mod(
                    o.values[k // 2 - 1], o.values[(k + 1) // 2 - 1]
                )
        return o

    @hw_func
    def finish(x: finish_in_t) -> uint128_t:
        tree: uint130_t[2 * tree_size]
        for j in range(tree_size):
            tree[tree_size + j] = 0
        for j in range(capacity):
            weight: uint130_t = 0
            if j < x.lane_count:
                power_index: index_t = x.next_lane
                power_index += x.lane_count
                power_index -= 1 + j
                # next_lane < lanes <= capacity, so the last slot never wraps.
                if j + 1 < capacity:
                    if x.next_lane > j:
                        power_index = x.next_lane - 1 - j
                weight = x.powers.values[power_index]
            # Exactly one product per capacity slot, not one set per direction.
            tree[tree_size + j] = residue_mul_mod(x.accumulators[j], weight)
        for k in range(tree_size - 1, 0, -1):
            tree[k] = residue_add_mod(tree[2 * k], tree[2 * k + 1])
        low: uint128_t = tree[1]
        tag: uint128_t = low + x.s
        return tag

    return SimpleNamespace(
        init=init,
        finish=finish,
        powers_t=powers_t,
        finish_in_t=finish_in_t,
    )


def make_paired_compute(capacity):
    """Initialization/finalization kernels and payload types specialized by lane capacity."""
    lane_t = make_uint_t(max(1, (capacity - 1).bit_length()))
    count_t = make_uint_t(capacity.bit_length())
    index_t = make_uint_t((2 * capacity).bit_length())
    tree_size = 1 << (capacity - 1).bit_length()

    @struct
    class powers_t(NamedTuple):
        values: uint130_t[capacity]

    @struct
    class finish_in_t(NamedTuple):
        accumulators: uint130_t[capacity]
        powers: powers_t
        lane_count: count_t
        next_lane: lane_t
        r: uint130_t
        tail: uint130_t
        has_tail: uint1_t
        s: uint128_t

    @hw_func
    def init(r: uint130_t) -> powers_t:
        o: powers_t
        if SQUARE_POWERS:
            o.values[0] = residue_square_mod(r)
        else:
            o.values[0] = residue_mul_mod(r, r)
        for k in range(2, capacity + 1):
            if SQUARE_POWERS and k % 2 == 0:
                o.values[k - 1] = residue_square_mod(o.values[k // 2 - 1])
            else:
                o.values[k - 1] = residue_mul_mod(
                    o.values[k // 2 - 1], o.values[(k + 1) // 2 - 1])
        return o

    @hw_func
    def finish(x: finish_in_t) -> uint128_t:
        tree: uint130_t[2 * tree_size]
        for j in range(tree_size):
            tree[tree_size + j] = 0
        # Lane weights q^0 .. q^capacity; q^0 is one.
        weights: uint130_t[capacity + 1]
        weights[0] = 1
        for k in range(capacity):
            weights[k + 1] = x.powers.values[k]
        for j in range(capacity):
            weight: uint130_t = 0
            if j < x.lane_count:
                power_index: index_t = x.next_lane + x.lane_count - 1 - j
                # next_lane < lanes <= capacity, so the last slot never wraps.
                if j + 1 < capacity:
                    if x.next_lane > j:
                        power_index = x.next_lane - 1 - j
                weight = weights[power_index]
            tree[tree_size + j] = residue_mul_mod(x.accumulators[j], weight)
        for k in range(tree_size - 1, 0, -1):
            tree[k] = residue_add_mod(tree[2 * k], tree[2 * k + 1])
        # For an odd block count, (r*S + tail)*r = q*S + tail*r.
        # Select the scale before the final product so the optional tail does
        # not add a third serial multiplication to the lane reduction.
        scale: uint130_t = x.r
        tail_product: uint130_t = 0
        if x.has_tail:
            scale = x.powers.values[0]
            tail_product = residue_mul_mod(x.tail, x.r)
        h: uint130_t = residue_mul_mod(tree[1], scale)
        h = residue_add_mod(h, tail_product)
        low: uint128_t = h
        tag: uint128_t = low + x.s
        return tag

    return SimpleNamespace(init=init, finish=finish,
                           powers_t=powers_t, finish_in_t=finish_in_t)
