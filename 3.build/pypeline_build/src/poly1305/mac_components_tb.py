# SPDX-FileCopyrightText: 2026 Julian Kemmerer
# SPDX-FileCopyrightText: 2026 Chili.CHIPS
#
# SPDX-License-Identifier: BSD-3-Clause

# pyright: reportInvalidTypeForm=none
"""Hardware-style checks for the one-block MAC and Poly1305 components.

POLY1305_TB_MODE selects mac, body, arithmetic, components (private initialization/finalization),
or sharing (shared compute units at either width). MAC tags come from cryptography;
component expectations use independent Python integer arithmetic. Stimulus and
assertions run in native or GHDL simulation. See poly1305_design.md#verification and
paired_path_tb.py for the native paired-MAC/framing/tag checks.
"""
import os
import sys

# Direct PypelineC entrypoint: find the bootstrap in the parent source directory.
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import wireguard_env  # noqa: F401

import random

from cryptography.hazmat.primitives.poly1305 import Poly1305
from pypeline import (
    MAIN,
    PART,
    DesignParamError,
    Reg,
    hw_func,
    param,
    uint1_t,
    uint8_t,
    uint32_t,
    array_to_uint_le,
    make_uint_t,
    sim_assert,
    sim_finish,
)
from aead_types import (
    axis128_if_t,
    poly1305_key_stream_if_t,
    poly1305_auth_tag_stream_if_t,
)
import poly1305_math as arithmetic
import poly1305_mac_pipelined as design

PART("xc7a200tffg1156-2")
MODE = param(
    "POLY1305_TB_MODE",
    "mac",
    choices=("mac", "body", "arithmetic", "components", "sharing"),
    help="which standalone Poly1305 check to build",
)
DIRECTION = param(
    "POLY1305_TB_DIRECTION",
    "encrypt",
    choices=("encrypt", "decrypt"),
    help="the direction whose MAC is built (both use one body latency group)",
)
DEPTH = param(
    "POLY1305_TB_BODY_DEPTH",
    type=int,
    choices=(0, 1, 3, 6),
    help="testbench-only fixed body stages (L = DEPTH + 2); default: automatic",
)
if DEPTH is not None and MODE in ("arithmetic", "sharing"):
    raise DesignParamError("POLY1305_TB_BODY_DEPTH applies to the mac, body and components modes")
P = (1 << 130) - 5
MASK128 = (1 << 128) - 1
MASK320 = (1 << 320) - 1
uint128_t = make_uint_t(128)
uint256_t = make_uint_t(256)
uint260_t = arithmetic.uint260_t
uint320_t = arithmetic.uint320_t
uint130_t = arithmetic.uint130_t

if MODE not in ("arithmetic", "sharing"):
    # Use the resolved body latency unless an isolated fixed-depth test is requested.
    mac = design.make_poly1305_mac_pipelined(DIRECTION, body_latency=DEPTH)
    LANES = mac.accumulator_count
    body_pipeline = mac.body_pipeline
    init = mac.init
    finish = mac.finish
    finish_stream_t = mac.finish_unit.in_if_t.stream_t
    print(f"Poly1305 {MODE} TB: {DIRECTION}, P={mac.body_auto_pipeline.latency}, D=L={LANES}")

if MODE == "sharing":
    import poly1305_compute_shared as shared

    RATE = wireguard_env.POLY1305_BLOCKS_PER_CYCLE
    CAPACITY = shared.CAPACITY
    REQUESTS = 12
    rng = random.Random(130513)
    CLAMP_MASK = 0x0FFFFFFC0FFFFFFC0FFFFFFC0FFFFFFF
    R = [0, 1, CLAMP_MASK] + [rng.getrandbits(128) & CLAMP_MASK for _ in range(7)]
    R += [R[-1], R[-1]]  # Repeated keys must still run the initialization.
    # Flattened tables contain encrypt requests first, then decrypt requests.
    INIT_R = R + list(reversed(R))
    INIT_EXPECTED = [pow(r, RATE * (j + 1), P) for r in INIT_R for j in range(CAPACITY)]
    COUNTS = [(i % CAPACITY) + 1 for i in range(2 * REQUESTS)]
    NEXT = [i % COUNTS[i] for i in range(2 * REQUESTS)]
    SALTS = [rng.getrandbits(128) for _ in range(2 * REQUESTS)]
    ACCUM = [rng.randrange(P) for _ in range(2 * REQUESTS * CAPACITY)]
    FINISH_POWERS = [
        pow(INIT_R[i], RATE * (j + 1), P) for i in range(2 * REQUESTS) for j in range(CAPACITY)
    ]
    # Rotate active lanes relative to the next write slot, then add the tag salt.
    FINISH_EXPECTED = [
        (
            (
                sum(
                    ACCUM[i * CAPACITY + j]
                    * FINISH_POWERS[i * CAPACITY + (NEXT[i] - 1 - j) % COUNTS[i]]
                    for j in range(COUNTS[i])
                )
                % P
            )
            + SALTS[i]
        )
        & MASK128
        for i in range(2 * REQUESTS)
    ]
    INIT_ARRAY_SIZE = 2 * REQUESTS * CAPACITY

    # A pure five-slot kernel checks the important unequal-lane case without
    # inserting guessed/fixed stages into either production body pipeline.
    compute5 = shared.make_shared_compute(5)
    PURE_CASES = [
        (lanes, q, r)
        for lanes in (2, 3, 5)
        for q in range(lanes)
        for r in (0, 1, CLAMP_MASK, P - 1)
    ]
    PURE_N = len(PURE_CASES)
    PURE_LANES = [x[0] for x in PURE_CASES]
    PURE_NEXT = [x[1] for x in PURE_CASES]
    PURE_R = [x[2] for x in PURE_CASES]
    PURE_S = [rng.getrandbits(128) for _ in PURE_CASES]
    PURE_A = [rng.randrange(P) for _ in range(5 * PURE_N)]
    PURE_POW = [pow(r, RATE * (j + 1), P) for r in PURE_R for j in range(5)]
    PURE_TAG = [
        (
            (
                sum(
                    PURE_A[i * 5 + j] * PURE_POW[i * 5 + (PURE_NEXT[i] - 1 - j) % PURE_LANES[i]]
                    for j in range(PURE_LANES[i])
                )
                % P
            )
            + PURE_S[i]
        )
        & MASK128
        for i in range(PURE_N)
    ]
    if RATE == 2:
        # Paired lanes advance in r^2. Fold with the final r factor; odd cases
        # then append one unpaired block before adding s.
        FINISH_EXPECTED = []
        for i in range(2 * REQUESTS):
            h = (
                sum(
                    ACCUM[i * CAPACITY + j] * pow(INIT_R[i], 2 * ((NEXT[i] - 1 - j) % COUNTS[i]), P)
                    for j in range(COUNTS[i])
                )
                * INIT_R[i]
                % P
            )
            if i % 2:
                h = (h + (1 << 128) + i) * INIT_R[i] % P
            FINISH_EXPECTED.append((h + SALTS[i]) & MASK128)
        PURE_TAG = []
        for i in range(PURE_N):
            h = (
                sum(
                    PURE_A[i * 5 + j]
                    * pow(PURE_R[i], 2 * ((PURE_NEXT[i] - 1 - j) % PURE_LANES[i]), P)
                    for j in range(PURE_LANES[i])
                )
                * PURE_R[i]
                % P
            )
            if i % 2:
                h = (h + (1 << 129) - 1) * PURE_R[i] % P
            PURE_TAG.append((h + PURE_S[i]) & MASK128)
    PURE_ARRAY_SIZE = 5 * PURE_N

    @hw_func
    def run_testbench() -> uint128_t:
        cycle: Reg[uint32_t]
        # Four independent streams: initialization encrypt/decrypt, finalization encrypt/decrypt.
        sent: Reg[uint32_t[4]]
        received: Reg[uint32_t[4]]
        held: Reg[uint1_t[4]]
        relaunch_seen: Reg[uint1_t]
        independent_seen: Reg[uint1_t]
        stall_seen: Reg[uint1_t]
        init_launches: Reg[uint32_t]
        last_init_encrypt: Reg[uint1_t]

        r: uint130_t[2 * REQUESTS] = INIT_R
        expected_powers: uint130_t[INIT_ARRAY_SIZE] = INIT_EXPECTED
        counts: uint32_t[2 * REQUESTS] = COUNTS
        next_lane: uint32_t[2 * REQUESTS] = NEXT
        salts: uint128_t[2 * REQUESTS] = SALTS
        accum: uint130_t[INIT_ARRAY_SIZE] = ACCUM
        finish_powers: uint130_t[INIT_ARRAY_SIZE] = FINISH_POWERS
        expected_tags: uint128_t[2 * REQUESTS] = FINISH_EXPECTED

        init_enc: shared.init_in_if_t.stream_t
        init_dec: shared.init_in_if_t.stream_t
        finish_enc: shared.finish_in_if_t.stream_t
        finish_dec: shared.finish_in_if_t.stream_t

        # Early requests stay continuously asserted to check alternating ties;
        # later absolute start times add lone requesters without withdrawing a
        # valid that is stalled. Payload changes only after an input handshake.
        init_enc.valid = (sent[0] < REQUESTS) & ((sent[0] < 6) | (cycle >= sent[0] * 9))
        init_dec.valid = (sent[1] < REQUESTS) & ((sent[1] < 6) | (cycle >= sent[1] * 13))
        finish_enc.valid = (sent[2] < REQUESTS) & ((sent[2] < 6) | (cycle >= sent[2] * 11))
        finish_dec.valid = (sent[3] < REQUESTS) & ((sent[3] < 6) | (cycle >= sent[3] * 7))
        init_enc.data = r[sent[0] % REQUESTS]
        init_dec.data = r[REQUESTS + sent[1] % REQUESTS]
        enc_index: uint32_t = sent[2] % REQUESTS
        dec_index: uint32_t = REQUESTS + sent[3] % REQUESTS
        finish_enc.data.lane_count = counts[enc_index]
        finish_dec.data.lane_count = counts[dec_index]
        finish_enc.data.next_lane = next_lane[enc_index]
        finish_dec.data.next_lane = next_lane[dec_index]
        finish_enc.data.s = salts[enc_index]
        finish_dec.data.s = salts[dec_index]
        if RATE == 2:
            finish_enc.data.r = r[enc_index]
            finish_dec.data.r = r[dec_index]
            finish_enc.data.tail = (1 << 128) + enc_index
            finish_dec.data.tail = (1 << 128) + dec_index
            finish_enc.data.has_tail = enc_index % 2
            finish_dec.data.has_tail = dec_index % 2
        for j in range(CAPACITY):
            # Inactive slots deliberately contain nonzero values. They must
            # contribute zero even when local lane count is less than capacity.
            finish_enc.data.accumulators[j] = accum[enc_index * CAPACITY + j]
            finish_dec.data.accumulators[j] = accum[dec_index * CAPACITY + j]
            finish_enc.data.powers.values[j] = finish_powers[enc_index * CAPACITY + j]
            finish_dec.data.powers.values[j] = finish_powers[dec_index * CAPACITY + j]

        # Check the actual production-capacity request arithmetic separately
        # from arbitration/capture, including nonzero inactive slots.
        enc_direct = shared.compute.finish(finish_enc.data)
        dec_direct = shared.compute.finish(finish_dec.data)
        sim_assert(enc_direct == expected_tags[enc_index], "direct encrypt finalization mismatch")
        sim_assert(
            dec_direct == expected_tags[dec_index],
            f"direct decrypt finalization mismatch: cycle={cycle}, got={dec_direct}, "
            f"expected={expected_tags[dec_index]}",
        )

        # Different output stalls exercise independence between the two compute units.
        ready: uint1_t[4]
        ready[0] = (cycle >= 30) & (cycle % 11 >= 4)
        ready[1] = (cycle >= 16) & (cycle % 13 >= 3)
        ready[2] = (cycle >= 12) & (cycle % 7 >= 2)
        ready[3] = (cycle >= 7) & (cycle % 9 >= 2)
        p_enc = shared.encrypt_init_shared_adapter(
            shared.init_in_if_t.fwd_t(init_enc), shared.init_out_if_t.fb_t(ready[0])
        )
        p_dec = shared.decrypt_init_shared_adapter(
            shared.init_in_if_t.fwd_t(init_dec), shared.init_out_if_t.fb_t(ready[1])
        )
        e_enc = shared.encrypt_finish_shared_adapter(
            shared.finish_in_if_t.fwd_t(finish_enc), shared.finish_out_if_t.fb_t(ready[2])
        )
        e_dec = shared.decrypt_finish_shared_adapter(
            shared.finish_in_if_t.fwd_t(finish_dec), shared.finish_out_if_t.fb_t(ready[3])
        )

        launches: uint1_t[4]
        launches[0] = init_enc.valid & p_enc.stream_in_if.ready
        launches[1] = init_dec.valid & p_dec.stream_in_if.ready
        launches[2] = finish_enc.valid & e_enc.stream_in_if.ready
        launches[3] = finish_dec.valid & e_dec.stream_in_if.ready
        valid: uint1_t[4]
        valid[0] = p_enc.stream_out_if.stream.valid
        valid[1] = p_dec.stream_out_if.stream.valid
        valid[2] = e_enc.stream_out_if.stream.valid
        valid[3] = e_dec.stream_out_if.stream.valid

        # Each compute unit grants one owner and returns only that owner's response.
        sim_assert(~(launches[0] & launches[1]), "initialization accepted both clients")
        sim_assert(~(launches[2] & launches[3]), "finalization accepted both clients")
        sim_assert(~(valid[0] & valid[1]), "initialization response delivered twice")
        sim_assert(~(valid[2] & valid[3]), "finalization response delivered twice")
        if launches[0] | launches[1]:
            if init_launches == 0:
                sim_assert(launches[1], "initial tied grant did not go to decrypt")
            elif (sent[0] < 6) & (sent[1] < 6):
                sim_assert(launches[0] != last_init_encrypt, "continuous ties did not alternate")
            last_init_encrypt = launches[0]
            init_launches += 1

        # Compare on valid, including stalled cycles, against the next response.
        for j in range(CAPACITY):
            if valid[0]:
                sim_assert(
                    p_enc.stream_out_if.stream.data.values[j]
                    == expected_powers[(received[0] % REQUESTS) * CAPACITY + j],
                    "encrypt initialization ordering/data/stability mismatch",
                )
            if valid[1]:
                sim_assert(
                    p_dec.stream_out_if.stream.data.values[j]
                    == expected_powers[(REQUESTS + received[1] % REQUESTS) * CAPACITY + j],
                    "decrypt initialization ordering/data/stability mismatch",
                )
        if valid[2]:
            sim_assert(
                e_enc.stream_out_if.stream.data == expected_tags[received[2] % REQUESTS],
                "encrypt finalization ownership/rotation/stability mismatch",
            )
        if valid[3]:
            sim_assert(
                e_dec.stream_out_if.stream.data == expected_tags[REQUESTS + received[3] % REQUESTS],
                f"decrypt finalization ownership/rotation/stability mismatch: cycle={cycle}, "
                f"response={received[3]}, got={e_dec.stream_out_if.stream.data}, "
                f"expected={expected_tags[REQUESTS + received[3] % REQUESTS]}",
            )

        # Require finalization progress before any initialization response, and a compute unit
        # accepting its next request while the previous response is consumed.
        if ((valid[2] & ready[2]) | (valid[3] & ready[3])) & (received[0] + received[1] == 0):
            independent_seen = 1
        if ((launches[0] | launches[1]) & ((valid[0] & ready[0]) | (valid[1] & ready[1]))) | (
            (launches[2] | launches[3]) & ((valid[2] & ready[2]) | (valid[3] & ready[3]))
        ):
            relaunch_seen = 1

        for i in range(4):
            if held[i]:
                sim_assert(valid[i], "shared MCP withdrew a stalled response")
            held[i] = valid[i] & ~ready[i]
            if held[i]:
                stall_seen = 1
            if valid[i]:
                sim_assert(received[i] < sent[i], "response without a matching accepted request")
            if launches[i]:
                sent[i] += 1
            if valid[i] & ready[i]:
                received[i] += 1

        # Separately check the five-slot kernels with 2, 3, or 5 active lanes.
        pure_counts: uint32_t[PURE_N] = PURE_LANES
        pure_next: uint32_t[PURE_N] = PURE_NEXT
        pure_r: uint130_t[PURE_N] = PURE_R
        pure_s: uint128_t[PURE_N] = PURE_S
        pure_a: uint130_t[PURE_ARRAY_SIZE] = PURE_A
        pure_pow: uint130_t[PURE_ARRAY_SIZE] = PURE_POW
        pure_tag: uint128_t[PURE_N] = PURE_TAG
        idx: uint32_t = cycle % PURE_N
        x: compute5.finish_in_t
        x.lane_count = pure_counts[idx]
        x.next_lane = pure_next[idx]
        x.s = pure_s[idx]
        if RATE == 2:
            x.r = pure_r[idx]
            x.tail = (1 << 129) - 1
            x.has_tail = idx % 2
        for j in range(5):
            x.accumulators[j] = pure_a[idx * 5 + j]
            x.powers.values[j] = pure_pow[idx * 5 + j]
        tag = compute5.finish(x)
        power = compute5.init(pure_r[idx])
        sim_assert(tag == pure_tag[idx], "unequal-lane shared finalization mismatch")
        for j in range(5):
            sim_assert(power.values[j] == pure_pow[idx * 5 + j], "shared power graph mismatch")

        if (
            (received[0] == REQUESTS)
            & (received[1] == REQUESTS)
            & (received[2] == REQUESTS)
            & (received[3] == REQUESTS)
            & (cycle >= PURE_N)
        ):
            sim_assert(
                relaunch_seen & independent_seen & stall_seen,
                "directed sharing scenarios were not all exercised",
            )
            sim_finish()
        sim_assert(cycle < 1000, "shared MCP testbench timed out/starved")
        cycle += 1
        return tag

elif MODE == "mac":
    # Block counts cross lane-wrap boundaries; keys cover clamping and reuse.
    counts = sorted(set(range(1, 2 * LANES + 2)) | {4 * LANES + 1})
    rng = random.Random(8439)
    key_bytes = [
        bytes(32),
        (1).to_bytes(16, "little") + bytes([255] * 16),
        bytes([255] * 32),
        rng.getrandbits(256).to_bytes(32, "little"),
    ]
    cases = [
        (n, key, k == 2, 40 if k == 3 else 7) for n in counts for k, key in enumerate(key_bytes)
    ]
    repeated_key = bytes(range(32))
    cases += [
        (17, repeated_key, False, 40),
        (17, repeated_key, True, 40),
        (3, repeated_key[:16] + bytes([255] * 16), True, 40),
    ]
    COUNTS = [case[0] for case in cases]
    KEYS = [int.from_bytes(case[1], "little") for case in cases]
    GAPS = [int(case[2]) for case in cases]
    STALLS = [case[3] for case in cases]
    EXPECTED = []
    for index, (count, key, _, _) in enumerate(cases):
        message = bytes(
            (block * 17 + byte + index) & 255 for block in range(count) for byte in range(16)
        )
        EXPECTED.append(int.from_bytes(Poly1305.generate_tag(key, message), "little"))
    NUM_CASES = len(cases)
    # Bound runtime using the selected compute unit latencies and per-packet stalls.
    MAX_CYCLES = 4 * sum(
        n
        + LANES
        + mac.init_unit.compute_tag.latency
        + mac.finish_unit.compute_tag.latency
        + stall
        + 32
        for n, _, _, stall in cases
    )

    @hw_func
    def run_testbench() -> uint128_t:
        keys: uint256_t[NUM_CASES] = KEYS
        counts: uint32_t[NUM_CASES] = COUNTS
        tags: uint128_t[NUM_CASES] = EXPECTED
        gaps: uint1_t[NUM_CASES] = GAPS
        stalls: uint32_t[NUM_CASES] = STALLS
        packet: Reg[uint32_t]
        block_index: Reg[uint32_t]
        key_sent: Reg[uint1_t]
        cycle: Reg[uint32_t]
        last_launch: Reg[uint32_t]
        tag_stalls: Reg[uint32_t]
        held_tag: Reg[uint128_t]
        held_valid: Reg[uint1_t]

        # Send the key once, then blocks; selected cases insert input gaps.
        gap: uint1_t = gaps[packet] & ((cycle % 5 == 1) | (cycle % 5 == 2))
        key_stream: poly1305_key_stream_if_t.stream_t
        key_stream.data = keys[packet]
        key_stream.valid = ~key_sent  # This test sends one packet at a time.
        data_stream: axis128_if_t.stream_t
        data_stream.valid = key_sent & (block_index < counts[packet]) & ~gap
        data_stream.data.eod[0] = block_index == counts[packet] - 1
        for j in range(16):
            value: uint8_t = block_index * 17 + j + packet
            data_stream.data.frag.data[j] = value
            data_stream.data.frag.keep[j] = 1

        # Hold each completed tag for its configured number of valid cycles.
        tag_ready: uint1_t = tag_stalls >= stalls[packet]
        o = mac(
            poly1305_key_stream_if_t.fwd_t(stream=key_stream),
            axis128_if_t.fwd_t(stream=data_stream),
            poly1305_auth_tag_stream_if_t.fb_t(ready=tag_ready),
        )

        if key_stream.valid & o.key_if.ready:
            key_sent = 1
        if data_stream.valid & o.data_in_if.ready:
            if ~gaps[packet] & (block_index > 0):
                sim_assert(cycle == last_launch + 1, "body inserted a bubble")
            last_launch = cycle
            block_index += 1

        if o.auth_tag_if.stream.valid:
            sim_assert(block_index == counts[packet], "tag arrived before all input blocks")
            sim_assert(cycle > last_launch + LANES, "tag observed unfinished body results")
            sim_assert(o.auth_tag_if.stream.data == tags[packet], "Poly1305 reference tag mismatch")
            if held_valid:
                sim_assert(o.auth_tag_if.stream.data == held_tag, "tag changed while stalled")
            held_tag = o.auth_tag_if.stream.data
            held_valid = 1
            if tag_ready:
                if packet == NUM_CASES - 1:
                    sim_finish()
                else:
                    packet += 1
                    block_index = 0
                    key_sent = 0
                    tag_stalls = 0
                    held_valid = 0
            else:
                tag_stalls += 1
        sim_assert(cycle < MAX_CYCLES, "standalone MAC timed out")
        cycle += 1
        return o.auth_tag_if.stream.data

elif MODE == "body":
    # A free-running pipeline must preserve both arithmetic results and bubbles.
    NUM_CASES = 64
    rng = random.Random(26)
    A = [rng.randrange(P) for _ in range(NUM_CASES)]
    B = [rng.randrange(P) for _ in range(NUM_CASES)]
    RAW = [rng.getrandbits(128) for _ in range(NUM_CASES)]
    EXPECTED = [(a * b + raw + (1 << 128)) % P for a, b, raw in zip(A, B, RAW)]

    @hw_func
    def run_testbench() -> uint128_t:
        a: uint130_t[NUM_CASES] = A
        b: uint130_t[NUM_CASES] = B
        raw: uint128_t[NUM_CASES] = RAW
        expected: uint130_t[NUM_CASES] = EXPECTED
        cycle: Reg[uint32_t]

        x: design.body_in_stream_t
        x.valid = (cycle < NUM_CASES) & (cycle % 5 != 2)
        index: uint32_t = cycle % NUM_CASES
        x.data.accumulator = a[index]
        x.data.stride = b[index]
        for j in range(16):
            x.data.block[j] = raw[index] >> (8 * j)
        o = body_pipeline(x)

        # LANES includes the body's input/output registers.
        issued: uint32_t = cycle - LANES
        valid: uint1_t = (cycle >= LANES) & (issued < NUM_CASES) & (issued % 5 != 2)
        sim_assert(o.valid == valid, "body valid/bubble latency differs from D")
        if valid:
            sim_assert(o.data == expected[issued % NUM_CASES], "body arithmetic/ordering mismatch")
        if cycle == NUM_CASES + LANES:
            sim_finish()
        cycle += 1
        return o.data

elif MODE == "arithmetic":
    # Exercise limb carries, reduction boundaries, and full-width residues.
    rng = random.Random(84391305)
    boundaries = [
        0,
        1,
        P - 1,
        P,
        P + 1,
        2 * P - 1,
        2 * P,
        2 * P + 1,
        (1 << 130) - 1,
        1 << 130,
        (1 << 260) - 1,
        MASK320,
    ]
    reductions = boundaries + [rng.getrandbits(320) for _ in range(100)]
    narrow = boundaries[:-1] + [rng.getrandbits(260) for _ in range(200)]
    mul = [((1 << 64) - 1, (1 << 64) - 1), (P - 1, P - 1), (1 << 128, 1 << 129), (MASK320, MASK320)]
    mul += [(rng.getrandbits(130), rng.getrandbits(130)) for _ in range(60)]
    add = [((1 << 64) - 1, 1), (P - 1, P - 1), (MASK320, 1)]
    add += [(rng.getrandbits(320), rng.getrandbits(320)) for _ in range(60)]
    edges = [0, 1, P - 1, P, P + 1, (1 << 130) - 1]
    triples = [(a, b, c) for a in edges for b in edges for c in (0, edges[-1])]
    triples += [tuple(rng.getrandbits(130) for _ in range(3)) for _ in range(100)]
    # Repeat shorter input tables so every operation runs on every test cycle.
    NUM_CASES = max(map(len, (reductions, narrow, mul, add, triples)))
    RED = [reductions[i % len(reductions)] for i in range(NUM_CASES)]
    NARROW = [narrow[i % len(narrow)] for i in range(NUM_CASES)]
    MA = [mul[i % len(mul)][0] for i in range(NUM_CASES)]
    MB = [mul[i % len(mul)][1] for i in range(NUM_CASES)]
    AA = [add[i % len(add)][0] for i in range(NUM_CASES)]
    AB = [add[i % len(add)][1] for i in range(NUM_CASES)]
    A = [triples[i % len(triples)][0] for i in range(NUM_CASES)]
    B = [triples[i % len(triples)][1] for i in range(NUM_CASES)]
    C = [triples[i % len(triples)][2] for i in range(NUM_CASES)]
    # Keep the oracle independent of the hardware arithmetic helpers.
    ER = [x % P for x in RED]
    EN = [x % P for x in NARROW]
    EM = [(a * b) & MASK320 for a, b in zip(MA, MB)]
    EA = [(a + b) & MASK320 for a, b in zip(AA, AB)]
    ERM = [(a * b) % P for a, b in zip(A, B)]
    ERMA = [(a * b + c) % P for a, b, c in zip(A, B, C)]
    ERA = [(a + b) % P for a, b in zip(A, B)]

    @hw_func
    def limbs(x: uint320_t) -> arithmetic.u320_t:
        o: arithmetic.u320_t
        for j in range(5):
            o.limbs[j] = x >> (64 * j)
        return o

    @hw_func
    def run_testbench() -> uint128_t:
        red: uint320_t[NUM_CASES] = RED
        narrow: uint260_t[NUM_CASES] = NARROW
        ma: uint320_t[NUM_CASES] = MA
        mb: uint320_t[NUM_CASES] = MB
        aa: uint320_t[NUM_CASES] = AA
        ab: uint320_t[NUM_CASES] = AB
        a: uint130_t[NUM_CASES] = A
        b: uint130_t[NUM_CASES] = B
        c: uint130_t[NUM_CASES] = C
        er: uint130_t[NUM_CASES] = ER
        en: uint130_t[NUM_CASES] = EN
        em: uint320_t[NUM_CASES] = EM
        ea: uint320_t[NUM_CASES] = EA
        erm: uint130_t[NUM_CASES] = ERM
        erma: uint130_t[NUM_CASES] = ERMA
        era: uint130_t[NUM_CASES] = ERA
        i: Reg[uint32_t]

        reduced = arithmetic.uint320_mod_prime(limbs(red[i]))
        multiplied = arithmetic.uint320_mul(limbs(ma[i]), limbs(mb[i]))
        added = arithmetic.uint320_add(limbs(aa[i]), limbs(ab[i]))
        sim_assert(array_to_uint_le(reduced.limbs) == er[i], "320-bit reduction mismatch")
        sim_assert(
            array_to_uint_le(multiplied.limbs) == em[i], "limb multiplication/carry mismatch"
        )
        sim_assert(array_to_uint_le(added.limbs) == ea[i], "limb addition/carry mismatch")
        sim_assert(arithmetic.uint260_mod_prime(narrow[i]) == en[i], "260-bit reduction mismatch")
        sim_assert(arithmetic.residue_mul_mod(a[i], b[i]) == erm[i], "residue multiply mismatch")
        sim_assert(
            arithmetic.residue_mul_add_mod(a[i], b[i], c[i]) == erma[i],
            "residue multiply-add mismatch",
        )
        sim_assert(arithmetic.residue_add_mod(a[i], b[i]) == era[i], "residue add mismatch")
        if i == NUM_CASES - 1:
            sim_finish()
        i += 1
        return reduced.limbs[0]

else:  # Pure production initialization/finalization with arbitrary full-width residues.
    rng = random.Random(84391305)
    NUM_CASES = 10 * LANES
    NEXT = [i % LANES for i in range(NUM_CASES)]
    ACCUM = [rng.randrange(P) for _ in range(NUM_CASES * LANES)]
    POWERS = [rng.randrange(P) for _ in range(NUM_CASES * LANES)]
    SALTS = [rng.getrandbits(128) for _ in range(NUM_CASES)]
    R = [0, 1, P - 1] + [rng.randrange(P) for _ in range(NUM_CASES - 3)]
    EXPECTED_POWERS = [pow(r, j + 1, P) for r in R for j in range(LANES)]
    # Deliberately arbitrary powers test rotation independently of the initialization.
    EXPECTED = [
        (
            (
                sum(
                    ACCUM[i * LANES + j] * POWERS[i * LANES + (NEXT[i] - 1 - j) % LANES]
                    for j in range(LANES)
                )
                % P
            )
            + SALTS[i]
        )
        & MASK128
        for i in range(NUM_CASES)
    ]
    ARRAY_SIZE = NUM_CASES * LANES

    @hw_func
    def run_testbench() -> uint128_t:
        accum: uint130_t[ARRAY_SIZE] = ACCUM
        powers: uint130_t[ARRAY_SIZE] = POWERS
        salts: uint128_t[NUM_CASES] = SALTS
        next_lane: uint32_t[NUM_CASES] = NEXT
        r: uint130_t[NUM_CASES] = R
        expected_powers: uint130_t[ARRAY_SIZE] = EXPECTED_POWERS
        expected: uint128_t[NUM_CASES] = EXPECTED
        i: Reg[uint32_t]

        x: finish_stream_t
        x.data.next_lane = next_lane[i]
        x.data.s = salts[i]
        for j in range(LANES):
            x.data.accumulators[j] = accum[i * LANES + j]
            x.data.powers.values[j] = powers[i * LANES + j]
        tag = finish(x.data)
        computed_powers = init(r[i])
        sim_assert(tag == expected[i], "rotated full-width finalization mismatch")
        for j in range(LANES):
            sim_assert(
                computed_powers.values[j] == expected_powers[i * LANES + j],
                "initialization powers mismatch",
            )
        if i == NUM_CASES - 1:
            sim_finish()
        i += 1
        return tag


@MAIN(wireguard_env.TARGET_MHZ)
def mac_components_tb() -> uint128_t:
    return run_testbench()
