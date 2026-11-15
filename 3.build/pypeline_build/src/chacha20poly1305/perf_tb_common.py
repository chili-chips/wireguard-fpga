# SPDX-FileCopyrightText: 2026 Chili.CHIPS*ba
#
# SPDX-License-Identifier: BSD-3-Clause

"""Shared configuration, reference frames, and runners for native performance tests.

PypelineC's stream_perf library supplies measurement and phase coordination;
stream_perf_probe supplies the shared probe registry. PERF_* build parameters
control simulation-only traffic and recording without changing the hardware.
See ../../README.md#throughput-measurement for commands and metric definitions.
"""

import wireguard_env

import os
from pypeline import param

from stream import stream_perf_probe
from stream.stream_perf import PerfRecorder, PhaseBarrier, PhaseRunner, packet_size_phases
from poly1305_select import implementation_metadata
from aead_types import (
    AEAD_BEAT_BYTES,
    AEAD_MAX_PLAINTEXT_BYTES,
    buffering_metadata,
    stream_slice_metadata,
)
import tb_common_sim as common

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

# Supported plaintext envelope; FIFO rounding does not increase this limit.
MAX_PACKET_BYTES = AEAD_MAX_PLAINTEXT_BYTES
BUS_BYTES = AEAD_BEAT_BYTES

# Packet-size sweep followed by a longer phase with back-to-back packets.
DEFAULT_SIZES = (16, 64, 256, 1024, 1420)
DEFAULT_PACKETS = 4
DEFAULT_PEAK_BYTES = 1920
DEFAULT_PEAK_PACKETS = 4
DEFAULT_MAX_CYCLES_PER_PHASE = 20000
DEFAULT_STALL_TIMEOUT = 1000  # cycles with no beat in or out => deadlock


def _tap_names(text):
    return tuple(t for t in text.replace(" ", "").split(",") if t)


JSON_PATH = param("PERF_JSON", "", help="results JSON path (measure.py sets it)")
SIZES = list(param("PERF_SIZES", DEFAULT_SIZES, help="packet sizes in bytes, comma-separated"))
PACKETS = param("PERF_PACKETS", DEFAULT_PACKETS, help="back-to-back packets per size")
PEAK_BYTES = param("PERF_PEAK_BYTES", DEFAULT_PEAK_BYTES, help="long-packet peak phase size")
PEAK_PACKETS = param("PERF_PEAK_PACKETS", DEFAULT_PEAK_PACKETS, help="packets in the peak phase")
SEED = param("PERF_SEED", common.DEFAULT_SEED, help="payload seed")
MAX_CYCLES_PER_PHASE = param("PERF_MAX_CYCLES_PER_PHASE", DEFAULT_MAX_CYCLES_PER_PHASE)
STALL_TIMEOUT = param(
    "PERF_STALL_TIMEOUT",
    DEFAULT_STALL_TIMEOUT,
    help="cycles with no beat in or out that count as a deadlock",
)
SETTLE_CYCLES = param("PERF_SETTLE", 8)
DIRS = param(
    "PERF_DIRS",
    "both",
    choices=("both", "all", "enc", "encrypt", "dec", "decrypt"),
    help="measured directions",
)
TAP_NAMES = list(param("PERF_TAPS", (), type=_tap_names, help="extra probe taps, comma-separated"))

_ALL_DIRS = ("encrypt", "decrypt")
if DIRS in ("both", "all"):
    ENABLED_DIRS = list(_ALL_DIRS)
elif DIRS in ("enc", "encrypt"):
    ENABLED_DIRS = ["encrypt"]
else:
    ENABLED_DIRS = ["decrypt"]


PHASES = packet_size_phases(SIZES, PACKETS, PEAK_BYTES, PEAK_PACKETS, MAX_PACKET_BYTES)

CONFIG = {
    "design": wireguard_env.DESIGN,
    "target_mhz": wireguard_env.TARGET_MHZ,
    "poly1305_mult_impl": wireguard_env.POLY1305_MULT_IMPL,
    "poly1305_compute_impl": wireguard_env.POLY1305_COMPUTE_IMPL,
    "poly1305_prologue_max_latency": wireguard_env.POLY1305_PROLOGUE_MAX_LATENCY,
    "poly1305_epilogue_max_latency": wireguard_env.POLY1305_EPILOGUE_MAX_LATENCY,
    "poly1305_blocks_per_cycle": wireguard_env.POLY1305_BLOCKS_PER_CYCLE,
    "data_bitwidth": wireguard_env.DATA_BITWIDTH,
    "poly1305": implementation_metadata(),
    "sharing": wireguard_env.SHARING,
    "buffering": buffering_metadata(),
    "stream_slices": stream_slice_metadata(),
    "source_handshake": "converged",
    "native_arithmetic": "hw-functions",
    "native_soft_ops": os.environ.get("PYPELINE_SIM_SOFT_OPS", "all"),
    "decrypt_verification_retained": True,
    "bus_bytes": BUS_BYTES,
    "dirs": ENABLED_DIRS,
    "seed": SEED,
    # PhaseRunner's string seed reproduces payload bytes across processes.
    "payload_seeding": "string seed/phase/runner (reproducible)",
    "sizes": SIZES,
    "packets_per_size": PACKETS,
    "peak_bytes": PEAK_BYTES,
    "peak_packets": PEAK_PACKETS,
    "max_cycles_per_phase": MAX_CYCLES_PER_PHASE,
    "stall_timeout_cycles": STALL_TIMEOUT,
    "settle_cycles": SETTLE_CYCLES,
    "taps": TAP_NAMES,
    "phase_plan": PHASES,
    "max_packet_bytes": MAX_PACKET_BYTES,
    "key": bytes(common.KEY).hex(),
    "nonce": bytes(common.NONCE).hex(),
    "aad_len": common.AAD_LEN,
}

BARRIER = PhaseBarrier(ENABLED_DIRS)
RECORDER = PerfRecorder(JSON_PATH, CONFIG)
# Enable the design's existing registry in place so all probes share it.
TAPS = stream_perf_probe.REGISTRY
TAPS.enable(TAP_NAMES)

_RUNNERS = {}


def is_enabled(direction):
    return direction in ENABLED_DIRS


def encrypt_frame_builder(length, rng):
    """Return plaintext input and reference ciphertext/tag output."""
    plaintext, ciphertext, tag = common.generate_packet(rng, length)
    return plaintext, ciphertext + tag, {}


def decrypt_frame_builder(length, rng):
    """Return valid ciphertext/tag input and reference plaintext/verdict output."""
    plaintext, ciphertext, tag = common.generate_packet(rng, length)
    return ciphertext + tag, plaintext, {"expected_verified": 1}


def keep_count(stream):
    """Count the valid byte lanes in a sampled beat."""
    keep = stream.data.frag.keep
    return sum(1 for i in range(BUS_BYTES) if keep[i])


def packet_mismatch_message(result, payload_name):
    """Describe a scoreboard failure, or return None for a matching packet."""
    if result["passed"]:
        return None
    idx = result.get("idx", "?")
    if "error" in result:
        return f"{result['error']} (packet {idx})"
    expected, got = result["expected"], result["got"]
    n = min(len(expected), len(got))
    first_diff = next((i for i in range(n) if expected[i] != got[i]), n)
    return (
        f"{payload_name} mismatch packet {idx}: expected {len(expected)} "
        f"bytes got {len(got)} bytes, first differing byte[{first_diff}]"
    )


def make_runner(direction, src, snk, scoreboard, frame_builder):
    """Register a direction's runner; disabled directions get an empty plan."""
    runner = PhaseRunner(
        name=direction,
        phases=PHASES if is_enabled(direction) else [],
        barrier=BARRIER,
        recorder=RECORDER,
        src=src,
        snk=snk,
        scoreboard=scoreboard,
        frame_builder=frame_builder,
        bus_bytes=BUS_BYTES,
        seed=SEED,
        max_cycles_per_phase=MAX_CYCLES_PER_PHASE,
        settle_cycles=SETTLE_CYCLES,
        stall_timeout_cycles=STALL_TIMEOUT,
        taps=TAPS,
    )
    _RUNNERS[direction] = runner
    return runner


def all_done():
    """Check completion after the top has imported and registered both runners."""
    return bool(_RUNNERS) and all(r.done for r in _RUNNERS.values())


def total_cycles():
    return max((r.meter.cycle for r in _RUNNERS.values()), default=0)


def finalize():
    """Add run totals to the incrementally written phase results."""
    # Counters reset each phase; retain active names to identify unmatched taps.
    RECORDER.config["taps_active"] = TAPS.active_names()
    RECORDER.finalize(total_cycles=total_cycles())


def summary_lines():
    lines = []
    for phase in RECORDER.as_dict()["phases"]:
        for direction in ENABLED_DIRS:
            result = phase.get(direction)
            if not result or not result.get("bytes_per_cycle"):
                continue
            lines.append(
                f"{phase['name']:>12} {direction:<8} {result['bytes_per_cycle']:6.3f} B/cyc "
                f"window={result['window_cycles']} cold_head="
                f"{result['latency_cycles']['cold_head']}"
            )
    return lines
