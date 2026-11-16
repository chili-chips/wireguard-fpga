# SPDX-FileCopyrightText: 2026 Julian Kemmerer
# SPDX-FileCopyrightText: 2026 Chili.CHIPS
#
# SPDX-License-Identifier: BSD-3-Clause

"""Shared packet generation, checking and AXI helpers for native testbenches.

tb_constants.py supplies KEY/NONCE/AAD without generating fixed reference
packets. Stress patterns and packet lengths serve the random correctness
testbenches; see ../../README.md#simulation for run instructions.
"""

import random

from pypeline import param, sim_print

from aead_ref_model import generate_encrypt_vector
from tb_constants import AAD, AAD_LEN, AAD_MAX_LEN, AAD_TEST_STR, KEY, NONCE

# Present inputs in @sim_input; commit transfers using the final ready/valid
# values in @sim_output, after combinational evaluation has settled.
from axi.axis_sim import (
    ConvergedAxisSimSink as ConvergedAxisSink,
    ConvergedAxisSimSource as ConvergedAxisSource,
)


# Select traffic and checking policy without changing the hardware profile.
PERF = param("PERF", False, help="native testbench: measure packet-size phases")

# Functional stress only; performance mode uses continuous traffic.
STRESS = param(
    "TB_STRESS",
    False,
    help="random testbenches: 20 directed packets, input gaps and output backpressure",
)


def input_paused(direction, cycle):
    offset = 0 if direction == "encrypt" else 9
    return STRESS and (cycle + offset) % 37 < 6


def output_ready(direction, cycle):
    if not STRESS:
        return 1
    offset = 0 if direction == "encrypt" else 173
    slot = (cycle + offset) % 1100
    return int(not (200 <= slot < 500 or slot % 23 < 5))


# Random packet generation
NUM_RANDOM_PACKETS = 20 if STRESS else 12
PACKET_LEN_MIN = 1
PACKET_LEN_MAX = 1024

# Exercise partial/full 16-byte Poly1305 words and 64-byte ChaCha20 blocks.
# Subsequent packets use uniform-random lengths.
CORNER_CASE_LENS = [15, 16, 17, 31, 64, 128]
if STRESS:
    # Also cover 32-byte beat boundaries and sustained near-maximum packets.
    CORNER_CASE_LENS = [
        1, 15, 16, 17, 31, 32, 33, 63, 64, 65, 128, 511, 512, 513,
        1024, 1420, 1920, 2032, 1920, 1920,
    ]

# Reproducible seed, printed by each correctness testbench at startup.
DEFAULT_SEED = 8439


def next_packet_length(rng: random.Random, packet_idx: int) -> int:
    """Return the byte length for a zero-based packet index, corner cases first."""
    if packet_idx < len(CORNER_CASE_LENS):
        return CORNER_CASE_LENS[packet_idx]
    return rng.randint(PACKET_LEN_MIN, PACKET_LEN_MAX)


def generate_packet(rng: random.Random, length: int):
    """Return random plaintext and its reference ciphertext/tag using the caller's RNG."""
    plaintext = bytes(rng.randrange(256) for _ in range(length))
    ciphertext, tag = generate_encrypt_vector(
        bytes(KEY), bytes(NONCE), bytes(AAD[:AAD_LEN]), plaintext
    )
    return plaintext, ciphertext, tag


def check_packet_result(direction, payload_name, state, result):
    """Count and report a scoreboard mismatch; verdict checks stay in the caller."""
    if result["passed"]:
        return
    state["errors"] += 1
    idx = result.get("idx", "?")
    if "error" in result:
        sim_print(f"ERROR: {direction}: {result['error']} (packet {idx})")
    else:
        expected, got = result["expected"], result["got"]
        n = min(len(expected), len(got))
        first_diff = next((i for i in range(n) if expected[i] != got[i]), n)
        sim_print(
            f"ERROR: {direction}: {payload_name} mismatch packet {idx}. "
            f"expected {len(expected)} bytes got {len(got)} bytes, "
            f"first differing byte[{first_diff}]"
        )


def check_completion(direction, state, num_packets, scoreboard):
    """Fail on mismatches or an incomplete run, including pending expectations."""
    assert state["errors"] == 0, (
        f"{direction}: {state['errors']} ERROR(s) -- see the ERROR lines above"
    )
    assert state["out_packet_idx"] == num_packets and scoreboard.pending() == 0, (
        f"{direction}: simulation ended with {state['out_packet_idx']} of {num_packets} "
        f"packets checked ({scoreboard.pending()} still expected)"
    )
    sim_print(f"{direction}: all {num_packets} packets PASSED")
