# SPDX-FileCopyrightText: 2026 Julian Kemmerer
# SPDX-FileCopyrightText: 2026 Chili.CHIPS
#
# SPDX-License-Identifier: BSD-3-Clause

"""Shared packet generation, checking and AXI helpers for native testbenches.

tb_constants.py supplies KEY/NONCE/AAD without generating fixed reference
packets. Stress patterns and packet lengths serve the random correctness
testbenches; see ../../README.md#simulation for run instructions.
"""

import json
import random

from pypeline import param, sim_print

from aead_ref_model import generate_encrypt_vector
from stream import stream_perf_probe
from tb_constants import AAD, AAD_LEN, AAD_MAX_LEN, AAD_TEST_STR, KEY, NONCE

# Present inputs in @sim_input; commit transfers using the final ready/valid
# values in @sim_output, after combinational evaluation has settled.
from axi.axis_sim import (
    ConvergedAxisSimSink as ConvergedAxisSink,
    ConvergedAxisSimSource as ConvergedAxisSource,
)


# MAIN name -> short label that qualifies tap names (`encrypt/chacha20.in`).
# Update in place: the probes read this exact dict object.
stream_perf_probe.MAIN_LABELS.update(
    {
        "encrypt_dataflow": "encrypt",
        "decrypt_dataflow": "decrypt",
        "chacha20_pipeline_shared": "shared",
        "poly1305_init_shared": "shared",
        "poly1305_finish_shared": "shared",
    }
)

# Select traffic and checking policy without changing the hardware profile.
PERF = param("PERF", False, help="native testbench: measure packet-size phases")

# Functional stress only; performance mode uses continuous traffic.
STRESS = param(
    "TB_STRESS",
    False,
    help="random testbenches: 20 directed packets, input gaps and output backpressure",
)


# Functional coverage: record the run's raw facts (packets, probe taps) for
# measure.py --coverage. Without it the probes stay off and nothing is written.
COVERAGE_JSON = param(
    "TB_COVERAGE_JSON",
    "",
    help="random testbenches: write raw coverage facts here (measure.py --coverage sets it)",
)
if COVERAGE_JSON:
    stream_perf_probe.REGISTRY.enable(["all"])

WATCHDOG_CYCLES = param(
    "TB_WATCHDOG_CYCLES",
    2000,
    help="random testbenches: fail when no beat is accepted for this many cycles "
    "while packets are pending",
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


# Reproducible seed, printed by each correctness testbench at startup.
DEFAULT_SEED = 8439

SEED = param("TB_SEED", DEFAULT_SEED, help="random testbenches: payload and length seed")
PACKETS = param(
    "TB_PACKETS",
    0,
    help="random testbenches: packets per direction (0: 12, 20 with TB_STRESS, "
    "or the plan's count with TB_CLOSURE)",
)
CLOSURE = param(
    "TB_CLOSURE",
    False,
    help="random testbenches: replace the random lengths with the coverage-closing "
    "plan from func_coverage_goals.py",
)

# Random packet generation
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
if CLOSURE:
    # Deterministic and independent of the profile, so every width and lane
    # count meets its length-dependent bins; see func_coverage_goals.closure_lengths.
    from func_coverage_goals import closure_lengths

    CORNER_CASE_LENS = closure_lengths()
NUM_RANDOM_PACKETS = PACKETS or (
    len(CORNER_CASE_LENS) if CLOSURE else 20 if STRESS else 12
)


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


def check_progress(direction, state, num_packets):
    """Fail a stuck design instead of letting the run spin to the cycle limit.

    state["last_move"] is the cycle of the direction's last accepted input or
    output beat; a direction with every packet checked is done and may idle.
    """
    idle = state["cycle"] - state["last_move"]
    assert state["out_packet_idx"] >= num_packets or idle <= WATCHDOG_CYCLES, (
        f"{direction}: no beat accepted for {idle} cycles with "
        f"{num_packets - state['out_packet_idx']} of {num_packets} packets still "
        f"pending ({state['in_packet_idx']} sent); TB_WATCHDOG_CYCLES={WATCHDOG_CYCLES}"
    )


class PacketLog:
    """Raw per-packet facts for functional coverage, in the testbench's cycles.

    note_input() sees every cycle's converged input handshake and times each
    packet's first offered and last accepted beat, counting the gap cycles the
    source inserted and the cycles the design held ready low. note_output()
    adds the packet's completion time and the output stalls its beats saw once
    the scoreboard has checked it. func_coverage_goals.py turns these facts
    into bins, so this class only records and never interprets them.
    """

    def __init__(self, direction):
        self.direction = direction
        self.packets = []
        self._inputs = []
        self._open = None
        self._stalled_seen = 0

    def note_input(self, cycle, valid, ready, eod):
        if self._open is None:
            if not valid:
                return
            self._open = {"first": cycle, "gap": 0, "stall": 0}
        packet = self._open
        if not valid:
            packet["gap"] += 1
        elif not ready:
            packet["stall"] += 1
        elif eod:
            packet["last"] = cycle
            self._inputs.append(packet)
            self._open = None

    def note_output(self, cycle, result, stalled_cycles, verified=None):
        """Record a checked packet; stalled_cycles is the sink's running total."""
        idx = result.get("idx")
        if not isinstance(idx, int) or not 0 <= idx < len(self._inputs):
            return
        packet = dict(self._inputs[idx])
        packet.update(
            idx=idx,
            length=result["length"],
            done=cycle,
            out_stall=stalled_cycles - self._stalled_seen,
            passed=bool(result["passed"]),
        )
        if verified is not None:
            packet.update(
                verified=int(verified), expected_verified=int(result["expected_verified"])
            )
        self._stalled_seen = stalled_cycles
        self.packets.append(packet)


def write_coverage(path, metadata, logs):
    """Write the run's raw facts: metadata, each direction's packets, probe taps.

    A StateTap snapshot lists only the states it visited, so its declared
    states travel with it; without them an unvisited state would be invisible.
    """
    registry = stream_perf_probe.REGISTRY
    taps = registry.snapshot()
    for name in registry.active_names():
        tap = registry.tap(name)
        if tap.kind == "state":
            taps[name]["declared"] = list(tap.state_names)
    record = {
        "schema_version": 1,
        "metadata": metadata,
        "packets": {log.direction: log.packets for log in logs},
        "taps": taps,
    }
    with open(path, "w") as f:
        json.dump(record, f, indent=1)
    sim_print(f"COVERAGE: wrote {path}")


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
