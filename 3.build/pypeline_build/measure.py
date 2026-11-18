#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Chili.CHIPS*ba
#
# SPDX-License-Identifier: BSD-3-Clause

"""Measure timing, area, throughput and latency for a WireGuard build profile.

Build or reuse the external-port hardware top, run its native performance
simulation, then validate and save the combined results. Timing comes from
PypelineC's final sweep records; area comes from the retained Vivado report.
Cycle-domain simulation data stays separate from MHz conversion.

The compiler's stream_perf_report library handles generic report formatting;
this script adds WireGuard's block analysis. See README.md#throughput-measurement
for usage. --coverage runs the random testbenches instead and judges which
corners they reached (README.md#functional-coverage). --selftest checks the
tooling using synthetic data.
"""

import argparse
import copy
import datetime
import glob
import hashlib
import json
import math
import os
import re
import socket
import shutil
import subprocess
import sys
import time
import tempfile
from pathlib import Path

HERE = os.path.dirname(os.path.abspath(__file__))
DEFAULT_PIPELINEC_REPO = os.path.abspath(os.path.join(HERE, "..", "..", "..", "PipelineC"))

# Host-side analysis needs the stream library, but not the Pypeline compiler.
# PYPELINEC selects its checkout; otherwise use the sibling PipelineC repository.
_PYPELINEC = os.environ.get("PYPELINEC")
PIPELINEC_REPO = (
    os.path.dirname(os.path.dirname(os.path.abspath(_PYPELINEC)))
    if _PYPELINEC
    else DEFAULT_PIPELINEC_REPO
)
_PYPELINE_INCLUDE = os.path.join(PIPELINEC_REPO, "include", "pypeline")
# The stream package imports the pypeline module (PipelineC src/) since 973a2cbf
for _path in (os.path.join(PIPELINEC_REPO, "src"), _PYPELINE_INCLUDE):
    if _path not in sys.path:
        sys.path.insert(0, _path)

from stream import stream_bottleneck as lib  # noqa: E402
from stream.stream_bottleneck import (  # noqa: E402
    get_tap,
    num,
    pct,
    TAP_CSV_COLUMNS,
    tap_rows,
)

from stream import stream_perf_report as perf_report
from stream.stream_bottleneck import buffer_tap_errors
from stream.stream_perf import stream_fifo_capacity_beats

sys.path.insert(0, os.path.join(HERE, "src"))
from wireguard_env import (
    IMPLEMENTATIONS,
    implementation_out_dir,
    selected_target,
    default_target_mhz,
    target_out_dir,
    GENERATED_FILES,
    generated_out_dir,
    MULT_IMPLEMENTATIONS,
    mult_out_dir,
    DATA_BITWIDTHS,
    blocks_out_dir,
    COMPUTE_IMPLEMENTATIONS,
    compute_out_dir,
    selected_prologue_cap,
    selected_epilogue_cap,
    prologue_cap_out_dir,
    epilogue_cap_out_dir,
    profile_from_args,
    resolve_profile,
    hardware_out_dir,
    BUILT_HARDWARE_FILE,
    add_sharing_arguments,
    add_soc_argument,
    sharing_from_args,
    sharing_name,
    sharing_out_dir,
    DEFAULT_PROFILE,
    SYN_CACHE_DIR,
)

import func_coverage_goals as goals  # noqa: E402

BUS_BYTES = 16

# AEAD block analysis and bottleneck reports.
# Records without MAC metadata used a five-cycle MCP plus one handshake cycle.
# Current records supply the resolved body II, latencies and packet width.
POLY1305_BLOCK_PERIOD_CYCLES = 6
POLY1305_BLOCK_BYTES = 16
# Model costs start at 128 bits and scale by the recorded blocks_per_cycle.
CHACHA20_BLOCK_BYTES = 64
CHACHA20_BEATS_PER_BLOCK = 4

# Tap names are relative to the direction. Downstream lists cover both directions
# and buffered/unbuffered variants; analysis follows only blocks with traffic.
# At forks it follows the most stalled consumer. The combinational broadcast has
# no independent service rate, so it needs no separate block entry.
BLOCKS = {
    "chacha20": {
        "consumes": "chacha20.axis_in",
        "produces": "chacha20.axis_out",
        "downstream": (
            "auth_buffer",
            "append_buffer",
            "prep_auth_data",
            "append_auth_tag",
            "wait_to_verify",
        ),
        "state": "chacha20.in_state",
        "what": "ChaCha20 keystream XOR (shared II=1 pipeline)",
    },
    "prep_auth_data": {
        "consumes": "prep.axis_in",
        "produces": "prep.axis_out",
        "downstream": ("poly1305",),
        "state": "prep.fsm",
        "what": "AAD||ciphertext||lengths framing for the MAC",
    },
    "auth_buffer": {
        "consumes": "auth_fifo.in",
        "produces": "auth_fifo.out",
        "downstream": ("prep_auth_data",),
        "state": None,
        "what": "ciphertext FIFO decoupling authentication setup waits",
    },
    "poly1305": {
        "consumes": "poly1305.data_in",
        "produces": "poly1305.tag_out",
        "downstream": (),
        "state": "poly1305.fsm",
        "what": "Poly1305 MAC (selected architecture)",
    },
    "append_auth_tag": {
        "consumes": "append.axis_in",
        "produces": "append.axis_out",
        "downstream": ("output_slice",),
        "state": "append.fsm",
        "what": "tag merge into the ciphertext tail (encrypt out)",
    },
    "append_buffer": {
        "consumes": "append_fifo.in",
        "produces": "append_fifo.out",
        "downstream": ("append_auth_tag",),
        "state": None,
        "what": "ciphertext FIFO decoupling tag append from authentication",
    },
    "output_slice": {
        "consumes": "output_slice.in",
        "produces": "output_slice.out",
        "downstream": (),
        "state": None,
        "what": "II=1 registered encrypt AXIS output boundary",
    },
    "strip_auth_tag": {
        "consumes": "strip.axis_in",
        "produces": "strip.axis_out",
        "downstream": ("chacha20", "auth_buffer", "prep_auth_data"),
        "state": None,
        "what": "tag split off the ciphertext tail (decrypt in)",
    },
    "tag_buffer": {
        "consumes": "tag_fifo.in",
        "produces": "tag_fifo.out",
        "downstream": ("verify",),
        "state": None,
        "what": "extracted packet tags queued independently of ciphertext",
    },
    "wait_to_verify": {
        "consumes": "wtv.axis_in",
        "produces": "wtv.axis_out",
        "downstream": (),
        "state": "wtv.fsm",
        "what": "plaintext FIFO held until the tag verdict (decrypt out)",
    },
    "verify": {
        "consumes": "verify.calc_tag",
        "produces": "verify.tags_match",
        "downstream": (),
        "state": "verify.fsm",
        "what": "tag comparison (decrypt)",
    },
}

DIRECTIONS = ("encrypt", "decrypt")


def block_rollup(taps, label):
    """Per-block achieved throughput, in-situ ceiling and stall split."""
    return lib.block_rollup(taps, label, BLOCKS, BUS_BYTES)


def find_bottleneck(blocks):
    """Name the block whose own slowness limits the direction (see
    stream_find_bottleneck)."""
    return lib.find_bottleneck(blocks, BLOCKS)


def model_for(packet_bytes, aad_len, measured_period, poly_tap=None, mac_config=None):
    """First-principles per-packet cycle cost, against the measured period.

    Poly1305 sees ceil(aad/16) AAD blocks + ceil(len/16) ciphertext blocks + 1
    length block. ceil(count / blocks_per_cycle) times the recorded body II
    is the input service cost. Setup, drain, finalization, framing, arbitration and tag stalls are
    separate costs. Missing metadata denotes historical legacy measurements.
    """
    aad_blocks = math.ceil(aad_len / POLY1305_BLOCK_BYTES) if aad_len else 0
    ct_blocks = math.ceil(packet_bytes / POLY1305_BLOCK_BYTES)
    blocks = aad_blocks + ct_blocks + 1  # +1 for the aad_len||ct_len block
    measured_block_period = (poly_tap or {}).get("service_period_cycles")
    mac_config = mac_config or {}
    block_period = mac_config.get("body_ii", POLY1305_BLOCK_PERIOD_CYCLES)
    rate = mac_config.get("blocks_per_cycle", 1)
    beats = math.ceil(blocks / rate)
    model = {
        "poly1305_blocks": blocks,
        "poly1305_input_beats": beats,
        "poly1305_blocks_per_cycle": rate,
        "poly1305_block_period_cycles": block_period / rate,
        "poly1305_model_cycles": beats * block_period,
        "poly1305_body_ii": block_period,
        "poly1305_accumulator_count": mac_config.get("accumulator_count", 1),
        "poly1305_body_latency": mac_config.get("body_latency"),
        "poly1305_coefficient_latency": mac_config.get("coefficient_latency", 0),
        "poly1305_total_body_latency": mac_config.get(
            "total_body_latency", mac_config.get("body_latency")
        ),
        "poly1305_prologue_response_cycles": mac_config.get("prologue_response_cycles"),
        "poly1305_epilogue_response_cycles": mac_config.get("epilogue_response_cycles"),
        "poly1305_measured_block_period_cycles": measured_block_period,
        "chacha20_model_cycles": (
            math.ceil(packet_bytes / CHACHA20_BLOCK_BYTES) * CHACHA20_BEATS_PER_BLOCK / rate
        ),
        "measured_packet_period_cycles": measured_period,
    }
    if measured_block_period:
        model["poly1305_measured_cycles"] = beats * measured_block_period
    if measured_period:
        model["poly1305_frac_of_period"] = model["poly1305_model_cycles"] / measured_period
        model["residual_cycles"] = measured_period - model["poly1305_model_cycles"]
    # Structural ceilings, for the headline block comparison.
    model["poly1305_ceiling_bytes_per_cycle"] = POLY1305_BLOCK_BYTES * rate / block_period
    model["chacha20_ceiling_bytes_per_cycle"] = CHACHA20_BLOCK_BYTES / (
        CHACHA20_BEATS_PER_BLOCK / rate
    )
    return model


def poly1305_lifecycle(taps, direction):
    """Disjoint FSM phase counts plus body service and tag-stall counters.

    Input backpressure outside STREAM_BODY belongs to packet setup/drain,
    not to the body's II. Only new-architecture states support this split.
    Per-packet values average over completed tags in this measurement window;
    IDLE includes both upstream key wait and measurement settle cycles.
    """
    overlapped = get_tap(taps, direction, "poly1305.body.fsm")
    state = overlapped or get_tap(taps, direction, "poly1305.fsm") or {}
    states = state.get("states") or {}
    if "STREAM_BODY" not in states:
        return None
    tag = get_tap(taps, direction, "poly1305.tag_out") or {}
    body = get_tap(taps, direction, "poly1305.to_compute") or {}
    retire = get_tap(taps, direction, "poly1305.from_compute") or {}
    packets = tag.get("xfer_cycles", 0)
    groups = {
        "idle": ("IDLE",),
        "setup": ("PROLOGUE_LAUNCH", "PROLOGUE_WAIT"),
        "body": ("STREAM_BODY",),
        "drain": ("DRAIN",),
        "finalization": ("EPILOGUE_LAUNCH", "EPILOGUE_WAIT"),
        "tag_output": ("OUTPUT_TAG",),
    }
    cycles = {
        name: sum(states.get(s, {}).get("cycles", 0) for s in names)
        for name, names in groups.items()
    }
    if overlapped:

        def state_cycles(tap_name, names):
            histogram = (get_tap(taps, direction, tap_name) or {}).get("states", {})
            return sum(histogram.get(name, {}).get("cycles", 0) for name in names)

        finish_request = get_tap(taps, direction, "poly1305.epilogue_in") or {}
        cycles.update(
            {
                "idle": state_cycles("poly1305.body.fsm", ("WAIT_CONTEXT",)),
                "setup": state_cycles(
                    "poly1305.prologue.fsm", ("PROLOGUE_LAUNCH", "PROLOGUE_WAIT")
                ),
                "drain": sum(
                    state_cycles("poly1305.body.bank" + str(bank), ("DRAIN",)) for bank in range(2)
                ),
                "finalization": (
                    state_cycles("poly1305.epilogue.fsm", ("EPILOGUE_WAIT",))
                    + finish_request.get("xfer_cycles", 0)
                    + finish_request.get("stall_cycles", 0)
                ),
                "tag_output": state_cycles("poly1305.epilogue.fsm", ("OUTPUT_TAG",)),
            }
        )
    result = {
        "architecture": "overlapped" if overlapped else "sequential",
        "completed_packets": packets,
        "phase_cycles": cycles,
        "cycles_per_packet": {k: v / packets for k, v in cycles.items()} if packets else {},
        "body_launches": body.get("xfer_cycles"),
        "body_retirements": retire.get("xfer_cycles"),
        "body_service_cycles": body.get("service_period_cycles"),
        "body_input_gap_cycles": cycles["body"] - body.get("xfer_cycles", 0),
        "tag_stall_cycles": tag.get("stall_cycles"),
        "tag_stalls_per_packet": tag.get("stall_cycles", 0) / packets if packets else None,
        "prologue_launches": (get_tap(taps, direction, "poly1305.prologue_in") or {}).get(
            "xfer_cycles"
        ),
        "epilogue_launches": (get_tap(taps, direction, "poly1305.epilogue_in") or {}).get(
            "xfer_cycles"
        ),
        "prologue_request_wait_cycles": (
            get_tap(taps, direction, "poly1305.prologue_in") or {}
        ).get("stall_cycles"),
        "epilogue_request_wait_cycles": (
            get_tap(taps, direction, "poly1305.epilogue_in") or {}
        ).get("stall_cycles"),
    }
    coefficient_in = get_tap(taps, direction, "poly1305.coefficient_in")
    if coefficient_in is not None:
        data = get_tap(taps, direction, "poly1305.data_in") or {}
        result["body_input_gap_cycles"] = cycles["body"] - data.get("xfer_cycles", 0)
        result.update(
            {
                "coefficient_launches": coefficient_in.get("xfer_cycles", 0),
                "coefficient_retirements": (
                    get_tap(taps, direction, "poly1305.coefficient_out") or {}
                ).get("xfer_cycles", 0),
                "unmatched_tails": (get_tap(taps, direction, "poly1305.tail_in") or {}).get(
                    "xfer_cycles", 0
                ),
                "authentication_blocks": data.get("bytes", 0) // 16,
            }
        )
    if overlapped:
        result["body_overlap_cycles"] = {
            name: (get_tap(taps, direction, tap) or {}).get("xfer_cycles", 0)
            for name, tap in (
                ("setup", "poly1305.setup_body_overlap"),
                ("drain", "poly1305.body_drain_overlap"),
                ("finalization", "poly1305.epilogue_body_overlap"),
            )
        }
    return result


def analyze_phase(phase, aad_len=0, mac_config=None):
    """Add the library's `taps_check`/`blocks`/`bottleneck`/`arbitration`, plus
    WireGuard's `throughput_comparison`, `model`, `poly1305_lifecycle` and
    `poly1305_shared_services`, to one phase dict, in place."""
    comparison = concurrent_throughput(phase)
    if comparison:
        phase["throughput_comparison"] = comparison
    taps = phase.get("taps")
    if not taps:
        return phase
    # A direction disabled via PERF_DIRS (measure.py --dirs enc|dec) still
    # has probes firing; the library drops a label whose blocks moved nothing.
    rate = (mac_config or {}).get("blocks_per_cycle", 1)
    lib.analyze_phase(phase, BLOCKS, DIRECTIONS, BUS_BYTES * rate)
    model = {}
    for label in phase.get("blocks", {}):
        direction = phase.get(label) or {}
        model[label] = model_for(
            phase.get("packet_bytes"),
            aad_len,
            direction.get("packet_period_cycles"),
            get_tap(taps, label, BLOCKS["poly1305"]["consumes"]),
            ((mac_config or {}).get("directions") or {}).get(label),
        )
        lifecycle = poly1305_lifecycle(taps, label)
        if lifecycle:
            phase.setdefault("poly1305_lifecycle", {})[label] = lifecycle
    if model:
        phase["model"] = model
    compute_units = {}
    for name in ("prologue", "epilogue"):
        prefix = "shared/poly1305." + name
        unit_state = (taps.get(prefix + ".service") or {}).get("states", {})
        if unit_state:
            compute_units[name] = {
                "compute_cycles": unit_state.get("COMPUTE", {}).get("cycles", 0),
                "response_valid_cycles": unit_state.get("OUTPUT", {}).get("cycles", 0),
                "response_stall_cycles": (taps.get(prefix + ".service_out") or {}).get(
                    "stall_cycles"
                ),
                "launches": (taps.get(prefix + ".service_in") or {}).get("xfer_cycles"),
                "responses": (taps.get(prefix + ".service_out") or {}).get("xfer_cycles"),
            }
    if compute_units:
        phase["poly1305_shared_services"] = compute_units
    if "decrypt/strip.tag_out" in taps:
        phase["decrypt_flow_control"] = {
            "strip_tag_stall_cycles": taps["decrypt/strip.tag_out"].get("stall_cycles", 0),
            "strip_input_stall_cycles": taps.get("decrypt/strip.axis_in", {}).get(
                "stall_cycles", 0
            ),
            "key_stall_cycles": taps.get("decrypt/chacha20.key_out", {}).get("stall_cycles", 0),
            "buffers": {
                name: {
                    key: value.get(key)
                    for key in (
                        "capacity_beats",
                        "high_water_beats",
                        "full_cycles",
                        "accepted_beats",
                        "retired_beats",
                    )
                }
                for name, value in taps.items()
                if name.startswith("decrypt/") and value.get("kind") == "buffer"
            },
        }
    return phase


def analyze(phases, aad_len=0, mac_config=None):
    for phase in phases:
        analyze_phase(phase, aad_len=aad_len, mac_config=mac_config)
    return phases


def concurrent_throughput(phase):
    """Compare equal-size traffic, with a separate genuinely contending window.

    The full-phase metric intentionally preserves historical interpretation.
    The overlap metric drops the first two output completions and stops when
    either direction admits its final ChaCha request. It never includes an
    interval straddling either boundary. Short bursts may have no such interval.
    """
    directions = {d: phase.get(d, {}) for d in DIRECTIONS}
    rates = {d: v.get("sustained_bytes_per_cycle") for d, v in directions.items()}
    if not all(rates.values()):
        return None
    result = {
        "full_phase_decrypt_to_encrypt_ratio": rates["decrypt"] / rates["encrypt"],
        "parity_ratio": min(rates.values()) / max(rates.values()),
    }
    packets = {d: v.get("packets", []) for d, v in directions.items()}
    ends = [
        (phase.get("taps", {}).get(d + "/chacha20.to_pipeline") or {}).get("last_transfer_cycle")
        for d in DIRECTIONS
    ]
    if any(len(p) < 3 for p in packets.values()) or any(e is None for e in ends):
        result["contention_window"] = {"available": False}
        return result
    first = max(p[1]["last_out"] for p in packets.values())
    last = min(ends)
    steady = [v.get("steady_state", {}) for v in directions.values()]
    if all(s.get("available") for s in steady):
        first = max(first, *(s["first_cycle"] for s in steady))
        last = min(last, *(s["last_cycle"] for s in steady))
    overlap = {"available": True, "first_cycle": first, "last_cycle": last}
    for d, entries in packets.items():
        periods = [
            b["last_out"] - a["last_out"]
            for a, b in zip(entries, entries[1:])
            if first <= a["last_out"] < b["last_out"] <= last
        ]
        period = sum(periods) / len(periods) if periods else None
        overlap[d] = {
            "intervals": len(periods),
            "packet_period_cycles": period,
            "bytes_per_cycle": phase["packet_bytes"] / period if period else None,
        }
    overlap["enough_intervals"] = all(overlap[d]["intervals"] >= 8 for d in DIRECTIONS)
    if all(overlap[d]["bytes_per_cycle"] for d in DIRECTIONS):
        overlap["decrypt_to_encrypt_ratio"] = (
            overlap["decrypt"]["bytes_per_cycle"] / overlap["encrypt"]["bytes_per_cycle"]
        )
        overlap["parity_ratio"] = min(overlap[d]["bytes_per_cycle"] for d in DIRECTIONS) / max(
            overlap[d]["bytes_per_cycle"] for d in DIRECTIONS
        )
    result["contention_window"] = overlap
    return result


# --- reporting ---------------------------------------------------------------
# WireGuard's block CSV keeps its historical `direction` column name.
BLOCK_CSV_COLUMNS = ("label", "phase", "packet_bytes", "direction") + lib.BLOCK_CSV_COLUMNS[4:]
block_rows = lib.block_rows

HEADLINE_COMPARE = ("chacha20", "poly1305")
HEADLINE_NAMES = {"chacha20": "ChaCha20", "poly1305": "Poly1305"}

# WireGuard wording for the generic report renderer.
TEXT = {
    "label_header": "dir",
    "label_noun": "direction",
    "no_taps": (
        "_No internal taps in this run — re-measure with "
        "`./measure.py --taps all` to populate this section._"
    ),
    "arbitration_intro": (
        "**Shared-pipeline arbitration** — includes ChaCha20 and each shared "
        "Poly1305 compute separately. *Resource not ready* means the selected "
        "request cannot launch (compute busy or output backpressure); "
        "*contention* means the other side holds the slot and wants it; "
        "*wasted slot* means the other side holds an empty slot. Current "
        "request-aware arbiters recover lone requests; historical arbiters "
        "may have wasted slots. These waits are not body-pipeline II:"
    ),
}


def headline(phases):
    """One generated sentence per direction: which of ChaCha20/Poly1305 is the
    slower block, by how much, and how close the datapath runs to its ceiling."""
    return lib.headline(phases, DIRECTIONS, HEADLINE_COMPARE, HEADLINE_NAMES)


def markdown_blocks(phases):
    """The generated block-level table + per-phase bottleneck verdicts."""
    return lib.markdown_blocks(
        phases,
        DIRECTIONS,
        BLOCKS,
        HEADLINE_COMPARE,
        HEADLINE_NAMES,
        extra_sections=(
            markdown_model(phases),
            markdown_poly1305_lifecycle(phases),
            markdown_poly1305_compute_units(phases),
            markdown_parity(phases),
        ),
        text=TEXT,
    )


def markdown_parity(phases):
    rows = []
    for phase in phases:
        comparison = phase.get("throughput_comparison", {})
        if not comparison:
            continue
        flow = phase.get("decrypt_flow_control", {})
        tag = flow.get("buffers", {}).get("decrypt/tag_fifo.occupancy", {})
        rows.append(
            "| %s | %s | %s | %s | %s | %s |"
            % (
                phase["name"],
                pct(comparison.get("parity_ratio")),
                pct(comparison.get("contention_window", {}).get("parity_ratio")),
                flow.get("strip_tag_stall_cycles", "-"),
                tag.get("high_water_beats", "-"),
                tag.get("capacity_beats", "-"),
            )
        )
    if not rows:
        return []
    return [
        "**Direction parity and decrypt admission** — payload payload throughput; interior "
        "packet completions are used when requested. The concurrent-demand window "
        "ends before either direction's final ChaCha request. Tag storage counts packets, "
        "independent of payload bus width.",
        "",
        "| phase | parity | concurrent parity | splitter tag stalls (clk) | tag high water | tag capacity |",
        "|---|---|---|---|---|---|",
    ] + rows


def markdown_poly1305_lifecycle(phases):
    rows = []
    overlap_rows = []
    paired_rows = []
    for phase in phases:
        for direction, lifecycle in (phase.get("poly1305_lifecycle") or {}).items():
            per = lifecycle["cycles_per_packet"]
            rows.append(
                f"| {phase['name']} | {direction} "
                f"| {num(lifecycle.get('body_service_cycles'))} "
                + "".join(
                    f"| {num(per.get(key))} "
                    for key in ("setup", "body", "drain", "finalization", "tag_output")
                )
                + f"| {num(lifecycle.get('tag_stalls_per_packet'))} "
                + f"| {num(lifecycle.get('prologue_request_wait_cycles'))} "
                + f"| {num(lifecycle.get('epilogue_request_wait_cycles'))} |"
            )
            overlap = lifecycle.get("body_overlap_cycles")
            if "coefficient_launches" in lifecycle:
                paired_rows.append(
                    f"| {phase['name']} | {direction} | {lifecycle['authentication_blocks']} "
                    f"| {lifecycle['coefficient_launches']} | {lifecycle['unmatched_tails']} "
                    f"| {lifecycle['coefficient_retirements']} | {lifecycle['body_launches']} "
                    f"| {lifecycle['body_retirements']} | {lifecycle['completed_packets']} |"
                )
            if overlap is not None:
                overlap_rows.append(
                    f"| {phase['name']} | {direction} | {overlap['setup']} "
                    f"| {overlap['drain']} | {overlap['finalization']} |"
                )
    if not rows:
        return []
    unit = "pair" if paired_rows else "block"
    lines = [
        f"**Poly1305 lifecycle** — measured body service cycles per offered {unit} "
        "are separate from FSM cycles per completed packet. Body time includes "
        "input gaps; initialization includes the initialization handshake; finalization includes "
        "the finalization handshake. Tag stalls are a subset of tag-output cycles, "
        "not an additional cost. IDLE/key wait and settle cycles remain in JSON. "
        "Compute request waits (total clocks in the window) are subsets of "
        "initialization/finalization, including sharing contention. These are MAC-local "
        "costs, not additive whole-datapath latency:",
        "",
        f"| phase | dir | body service (clk/{unit}) | initialization (clk/pkt) | body (clk/pkt) "
        "| drain (clk/pkt) | finalization (clk/pkt) | tag output (clk/pkt) | tag stalls (clk/pkt) "
        "| initialization request wait (clk) | finalization request wait (clk) |",
        "|---|---|---|---|---|---|---|---|---|---|---|",
    ] + rows
    if paired_rows:
        lines += [
            "",
            "Paired arithmetic conservation: blocks = 2 × pairs + tails; "
            "coefficient and feedback launch/retirement counts must agree. "
            "Tails bypass both pipelines. Tags count completed packets.",
            "",
            "| phase | dir | auth blocks | pairs | tails | coefficient retirements "
            "| feedback launches | feedback retirements | tags |",
            "|---|---|---|---|---|---|---|---|---|",
        ] + paired_rows
    if overlap_rows:
        lines += [
            "",
            "Overlapped MAC stage costs run concurrently and must not be summed "
            "into a packet period. Drain counts bank clocks; the following "
            "counts clocks actually issuing body work during other stages:",
            "",
            "| phase | dir | body + setup | body + drain | body + finalization |",
            "|---|---|---|---|---|",
        ] + overlap_rows
    return lines


def markdown_poly1305_compute_units(phases):
    phase_names = {"prologue": "initialization", "epilogue": "finalization"}
    rows = []
    for phase in phases:
        for name, unit in (phase.get("poly1305_shared_services") or {}).items():
            launches = unit.get("launches")
            compute = unit.get("compute_cycles")
            per_request = compute / launches if launches and compute is not None else None
            rows.append(
                f"| {phase['name']} | {phase_names.get(name, name)} | {num(launches, '.0f')} "
                f"| {num(unit.get('responses'), '.0f')} | {num(compute, '.0f')} "
                f"| {num(per_request)} | {num(unit.get('response_valid_cycles'), '.0f')} "
                f"| {num(unit.get('response_stall_cycles'), '.0f')} |"
            )
    if not rows:
        return []
    return [
        "**Shared Poly1305 compute units** — shared-unit occupancy, separate "
        "from each requester's arbitration wait and private body II. Compute "
        "cycles run from accepted launch until a valid response; output stalls "
        "are a subset of response-valid cycles, not additional compute time:",
        "",
        "| phase | compute unit | requests | responses | compute (clk) | compute (clk/request) "
        "| response valid (clk) | response stalls (clk) |",
        "|---|---|---|---|---|---|---|---|",
    ] + rows


def markdown_model(phases):
    rows = []
    paired = any(
        m.get("poly1305_blocks_per_cycle", 1) == 2
        for p in phases
        for m in (p.get("model") or {}).values()
    )
    for phase in phases:
        for direction in DIRECTIONS:
            m = (phase.get("model") or {}).get(direction)
            if not m or not m.get("measured_packet_period_cycles"):
                continue
            rows.append(
                f"| {phase['name']} | {phase['packet_bytes']} | {direction} "
                f"| {m['poly1305_blocks']} "
                + (f"| {m['poly1305_input_beats']} " if paired else "")
                + f"| {m['poly1305_model_cycles']} "
                f"| {num(m.get('poly1305_measured_block_period_cycles'))} "
                f"| {num(m['measured_packet_period_cycles'], '.1f')} "
                f"| {pct(m.get('poly1305_frac_of_period'))} "
                f"| {num(m.get('residual_cycles'), '.1f')} |"
            )
    if not rows:
        return []
    transfer_count = "ceil(authentication blocks / blocks per transfer)" if paired else "block count"
    head = [
        f"**Model cross-check** — Poly1305 {transfer_count} x its recorded body "
        "initiation interval, against the "
        "measured packet period. The residual is everything that is not the MAC "
        "loop (initialization, body drain, finalization, poly key round trip, framing, "
        "tag stalls, arbitration). This is a body-cost model, not a claim "
        "of one-cycle whole-packet service:",
        "",
        "| phase | bytes | dir | poly blocks "
        + ("| input transfers " if paired else "")
        + "| model (clk) | measured input period "
        "| measured period (clk) | model / measured | residual (clk) |",
        "|---|---|---|---|---|---|---|---|---|" + ("---|" if paired else ""),
    ]
    return head + rows


# --- selftest ----------------------------------------------------------------


def _bottleneck_selftest():
    """Attribution and model math, against hand-built synthetic taps."""
    failures = []

    def check(name, got, want, tol=1e-9):
        ok = (
            abs(got - want) < tol
            if isinstance(want, float) and isinstance(got, (int, float))
            else got == want
        )
        if not ok:
            failures.append(f"{name}: expected {want!r} got {got!r}")

    # A phase where Poly1305 is the limiter: its input stalls hard and is never
    # starved, while ChaCha20's input is mostly starved (it is waiting for the
    # backpressure to clear), and prep only RELAYS poly's stall.
    cycles = 600
    taps = {
        "encrypt/chacha20.axis_in": {
            "kind": "handshake",
            "cycles": cycles,
            "xfer_cycles": 100,
            "stall_cycles": 60,
            "starved_cycles": 440,
            "idle_cycles": 0,
            "accept_rate": 100 / 160,
            "service_period_cycles": 1.6,
            "beats_per_cycle": 100 / cycles,
            "bytes_per_cycle": 1600 / cycles,
            "bytes_per_beat": 16.0,
            "stall_frac": 0.10,
            "starve_frac": 440 / cycles,
        },
        "encrypt/chacha20.axis_out": {
            "kind": "handshake",
            "cycles": cycles,
            "xfer_cycles": 100,
            "stall_cycles": 300,
            "stall_frac": 0.50,
            "starve_frac": 0.1,
            "service_period_cycles": 4.0,
            "bytes_per_beat": 16.0,
        },
        "encrypt/prep.axis_in": {
            "kind": "handshake",
            "cycles": cycles,
            "xfer_cycles": 100,
            "stall_cycles": 300,
            "starved_cycles": 200,
            "idle_cycles": 0,
            "accept_rate": 0.25,
            "service_period_cycles": 4.0,
            "bytes_per_beat": 16.0,
            "bytes_per_cycle": 1600 / cycles,
            "stall_frac": 0.50,
            "starve_frac": 200 / cycles,
        },
        # prep's OUTPUT is stalled just as hard as its input -> it is relaying.
        "encrypt/prep.axis_out": {
            "kind": "handshake",
            "cycles": cycles,
            "xfer_cycles": 100,
            "stall_cycles": 500,
            "stall_frac": 0.83,
            "starve_frac": 0.0,
            "service_period_cycles": 6.0,
            "bytes_per_beat": 16.0,
        },
        "encrypt/poly1305.data_in": {
            "kind": "handshake",
            "cycles": cycles,
            "xfer_cycles": 100,
            "stall_cycles": 500,
            "starved_cycles": 0,
            "idle_cycles": 0,
            "accept_rate": 100 / 600,
            "service_period_cycles": 6.0,
            "bytes_per_beat": 16.0,
            "bytes_per_cycle": 1600 / cycles,
            "stall_frac": 500 / cycles,
            "starve_frac": 0.0,
        },
        "encrypt/poly1305.tag_out": {
            "kind": "handshake",
            "cycles": cycles,
            "xfer_cycles": 4,
            "stall_cycles": 0,
            "stall_frac": 0.0,
            "starve_frac": 0.2,
            "service_period_cycles": 1.0,
        },
        "encrypt/poly1305.fsm": {
            "kind": "state",
            "cycles": cycles,
            "dominant": "FINISH_ITER",
            "states": {
                "START_ITER": {"cycles": 100, "frac": 100 / cycles},
                "FINISH_ITER": {"cycles": 500, "frac": 500 / cycles},
            },
        },
    }
    phase = {
        "name": "b2b-1420",
        "packet_bytes": 1420,
        "num_packets": 4,
        "taps": taps,
        "encrypt": {"packet_period_cycles": 565.667},
    }
    analyze_phase(phase, aad_len=29)

    blocks = phase["blocks"]["encrypt"]
    check("blocks found", sorted(blocks), ["chacha20", "poly1305", "prep_auth_data"])
    # Ceiling: 16 B per beat over 6.0 cycles/beat while offered -> 2.667 B/cyc.
    check("poly ceiling", blocks["poly1305"]["ceiling_bytes_per_cycle"], 16 / 6.0)
    # ChaCha20: 16 B per beat over 1.6 cycles/beat -> 10 B/cyc, far above poly.
    check("chacha ceiling", blocks["chacha20"]["ceiling_bytes_per_cycle"], 10.0)
    check(
        "chacha faster than poly",
        blocks["chacha20"]["ceiling_bytes_per_cycle"]
        > blocks["poly1305"]["ceiling_bytes_per_cycle"],
        True,
    )

    verdict = phase["bottleneck"]["encrypt"]
    # prep_auth_data has the joint-highest input stall but its own output is
    # stalled harder still, so the walk must land on poly1305, not prep.
    check("bottleneck", verdict["block"], "poly1305")
    check("bottleneck stall", verdict["in_stall_frac"], 500 / cycles)
    check("bottleneck state", verdict["dominant_state"], "FINISH_ITER")
    if "poly1305" not in verdict["evidence"] or "FINISH_ITER" not in verdict["evidence"]:
        failures.append(f"evidence line unhelpful: {verdict['evidence']!r}")

    model = phase["model"]["encrypt"]
    # 2 AAD blocks (29 B) + 89 ciphertext blocks (1420 B) + 1 length block.
    check("poly blocks", model["poly1305_blocks"], 92)
    check("poly model cycles", model["poly1305_model_cycles"], 552)
    check("poly measured cycles", model["poly1305_measured_cycles"], 552.0)
    check("poly frac of period", round(model["poly1305_frac_of_period"], 4), 0.9758)
    check("residual", round(model["residual_cycles"], 3), 13.667)
    check("poly ceiling (model)", model["poly1305_ceiling_bytes_per_cycle"], 16 / 6)
    check("chacha ceiling (model)", model["chacha20_ceiling_bytes_per_cycle"], 16.0)

    # A fork must be followed toward the sink that is actually stalling. Here
    # strip relays, and of its two sinks only prep (-> poly1305) is backed up;
    # chacha20 is wide open. The verdict must not stop at chacha20.
    fork = dict(taps)
    fork["encrypt/strip.axis_in"] = {
        "kind": "handshake",
        "cycles": cycles,
        "xfer_cycles": 100,
        "stall_cycles": 520,
        "starved_cycles": 0,
        "idle_cycles": 0,
        "accept_rate": 100 / 620,
        "service_period_cycles": 6.2,
        "bytes_per_beat": 16.0,
        "bytes_per_cycle": 1600 / cycles,
        "stall_frac": 0.87,
        "starve_frac": 0.0,
    }
    fork["encrypt/strip.axis_out"] = {
        "kind": "handshake",
        "cycles": cycles,
        "xfer_cycles": 100,
        "stall_cycles": 520,
        "stall_frac": 0.87,
        "starve_frac": 0.0,
        "service_period_cycles": 6.2,
        "bytes_per_beat": 16.0,
    }
    fv = find_bottleneck(block_rollup(fork, "encrypt"))
    check("fork walk lands on poly1305", fv["block"], "poly1305")

    # A relay chain with nothing downstream must not loop forever.
    lonely = {
        "encrypt/append.axis_in": {
            "kind": "handshake",
            "cycles": 10,
            "xfer_cycles": 1,
            "stall_cycles": 9,
            "stall_frac": 0.9,
            "starve_frac": 0.0,
            "service_period_cycles": 10.0,
            "bytes_per_beat": 16.0,
        }
    }
    v = find_bottleneck(block_rollup(lonely, "encrypt"))
    check("single-block verdict", v["block"], "append_auth_tag")

    # A direction that never streamed (measure.py --dirs enc|dec) must not get a
    # verdict: its probes fired all run, but every block sat idle.
    idle = {
        "name": "b2b-64",
        "packet_bytes": 64,
        "num_packets": 2,
        "taps": {
            "decrypt/poly1305.data_in": {
                "kind": "handshake",
                "cycles": 100,
                "xfer_cycles": 0,
                "stall_cycles": 0,
                "starved_cycles": 0,
                "idle_cycles": 100,
                "accept_rate": None,
                "service_period_cycles": None,
                "stall_frac": 0.0,
                "starve_frac": 0.0,
            }
        },
    }
    analyze_phase(idle, aad_len=29)
    check("idle direction gets no blocks", "blocks" in idle, False)
    check("idle direction gets no verdict", "bottleneck" in idle, False)

    # No taps at all: analysis is a no-op, never an exception.
    bare = {"name": "x", "packet_bytes": 64, "num_packets": 1}
    analyze_phase(bare)
    check("no taps -> no blocks", "blocks" in bare, False)

    # The once-per-cycle invariant guard must catch a tap that inflated.
    good = lib.check_taps({"a": {"cycles": 10}, "b": {"cycles": 10}})
    check("taps_check consistent", good["consistent"], True)
    check("taps_check cycles", good["cycles"], 10)
    bad = lib.check_taps({"a": {"cycles": 10}, "b": {"cycles": 30}})
    check("taps_check inconsistent", bad["consistent"], False)
    check("taps_check names", bad["disagreeing_taps"], ["b"])
    check("phase taps_check present", phase["taps_check"]["consistent"], True)

    phase["arbitration"] = {
        "shared/pipe.arb": {
            "kind": "arb",
            "cycles": cycles,
            "labels": ["encrypt", "decrypt"],
            "per_requester": {
                "encrypt": {
                    "req_cycles": 40,
                    "sel_cycles": 300,
                    "xfer_cycles": 20,
                    "contention_cycles": 0,
                    "wasted_slot_cycles": 20,
                    "arb_loss_frac": 0.5,
                    "contention_frac": 0.0,
                    "wasted_slot_frac": 0.5,
                },
                "decrypt": {
                    "req_cycles": 0,
                    "sel_cycles": 300,
                    "xfer_cycles": 0,
                    "contention_cycles": 0,
                    "wasted_slot_cycles": 0,
                    "arb_loss_frac": 0.0,
                    "contention_frac": 0.0,
                    "wasted_slot_frac": 0.0,
                },
            },
        }
    }
    # The headline must name the slower block and quantify the gap.
    phase["encrypt"]["sustained_bytes_per_cycle"] = 2.51
    head = "\n".join(headline([phase]))
    for needle in ("ChaCha20", "Poly1305", "slower block", "ceiling"):
        if needle not in head:
            failures.append(f"headline missing {needle!r}: {head!r}")
    if "10.00 B/cyc" not in head or "2.67 B/cyc" not in head:
        failures.append(f"headline ceilings wrong: {head!r}")
    if "3.8x" not in head:  # 10.0 / 2.667
        failures.append(f"headline ratio wrong: {head!r}")
    if "94%" not in head:  # 2.51 / 2.667
        failures.append(f"headline saturation wrong: {head!r}")

    # Relay-limited blocks: in that fixture ChaCha20's output stalls 50% vs 10%
    # on its input -> flagged, ceiling rendered as a lower bound. Poly1305's
    # output never stalls -> exact.
    check("chacha relay_limited", blocks["chacha20"]["relay_limited"], True)
    check("poly not relay_limited", blocks["poly1305"]["relay_limited"], False)
    # Across a sweep, a relay-limited block is quoted at its BEST observation
    # (tightest lower bound), a clean one at the largest packet size.
    small = {
        "name": "b2b-256",
        "packet_bytes": 256,
        "blocks": {
            "encrypt": {
                "chacha20": {"ceiling_bytes_per_cycle": 14.2, "relay_limited": True},
                "poly1305": {"ceiling_bytes_per_cycle": 2.79, "relay_limited": False},
            }
        },
    }
    big = {
        "name": "peak-1920",
        "packet_bytes": 1920,
        "encrypt": {"sustained_bytes_per_cycle": 2.532},
        "blocks": {
            "encrypt": {
                "chacha20": {"ceiling_bytes_per_cycle": 2.98, "relay_limited": True},
                "poly1305": {"ceiling_bytes_per_cycle": 2.70, "relay_limited": False},
            }
        },
    }
    c = lib.best_ceiling([small, big], "encrypt", "chacha20")
    check("relay-limited best ceiling", (c[0], c[1]["packet_bytes"], c[2]), (14.2, 256, False))
    pl = lib.best_ceiling([small, big], "encrypt", "poly1305")
    check(
        "clean block ceiling at largest size",
        (pl[0], pl[1]["packet_bytes"], pl[2]),
        (2.70, 1920, True),
    )
    sweep_head = "\n".join(headline([small, big]))
    for needle in ("≥14.20 B/cyc", "2.70 B/cyc", "at least **5.3x", "94% of Poly1305"):
        if needle not in sweep_head:
            failures.append(f"sweep headline missing {needle!r}: {sweep_head!r}")

    table = markdown_blocks([phase])
    unit_table = markdown_poly1305_compute_units(
        [
            {
                "name": "b2b-16",
                "poly1305_shared_services": {
                    "epilogue": {
                        "launches": 8,
                        "responses": 8,
                        "compute_cycles": 24,
                        "response_valid_cycles": 12,
                        "response_stall_cycles": 4,
                    }
                },
            }
        ]
    )
    if "| b2b-16 | finalization | 8 | 8 | 24 | 3.00 | 12 | 4 |" not in "\n".join(unit_table):
        failures.append("shared MCP service occupancy table missing or malformed")
    if "≥10.000" not in table:
        failures.append("relay-limited ceiling not marked as a lower bound in the table")
    if "Shared-pipeline arbitration" not in table or "| 40 | 20 |" not in table:
        failures.append("arbitration table missing or malformed")
    # "pipeline not ready" derived from the identity for a snapshot without
    # blocked_cycles: 100 wanted - 10 launched - 30 contention - 20 wasted = 40%.
    phase["arbitration"]["shared/pipe.arb"]["per_requester"]["decrypt"] = {
        "req_cycles": 100,
        "sel_cycles": 300,
        "xfer_cycles": 10,
        "contention_cycles": 30,
        "wasted_slot_cycles": 20,
        "arb_loss_frac": 0.5,
        "contention_frac": 0.3,
        "wasted_slot_frac": 0.2,
    }
    if "| decrypt | 100 | 10 | 40% | 30% | 20% |" not in markdown_blocks([phase]):
        failures.append("pipeline-not-ready share not derived for an old snapshot")
    phase["arbitration"]["shared/pipe.arb"]["per_requester"]["decrypt"]["req_cycles"] = 0
    # A direction that never asked for the pipeline must not appear as a row.
    if table.count("| b2b-1420 | 1420 | decrypt | 0 |"):
        failures.append("idle requester should be omitted from the arb table")
    for needle in ("poly1305", "FINISH_ITER", "Model cross-check", "| 92 |"):
        if needle not in table:
            failures.append(f"markdown missing {needle!r}")

    for f in failures:
        print("FAIL: " + f)
    print("bottleneck selftest: " + ("PASS" if not failures else f"{len(failures)} FAILURE(S)"))
    return 1 if failures else 0


# Timing and area records.
# pypelinec stdout lines worth keeping as a cross-check on sweep_history.json.
RE_FMAX = re.compile(r"(?:(PASS|FAIL)\s+)?Clock (\S+) FMAX: ([\d.]+) MHz \(([\d.]+) ns\)")
RE_SWEEP_ITER = re.compile(r"\[sweep\] iter=(\d+) main=(\S+) goal=([\d.]+)MHz got=([\d.]+)MHz")
RE_TIMING_NOT_MET = re.compile(r"ERROR: TIMING NOT MET: .*")
# The FINAL per-MAIN outcome lines. A schema-2/3 sweep_history.json's "final"
# records are authoritative and these are the cross-check; for a schema-1 file
# (an iteration log that could stop before the iteration that met timing, its
# last entry a mid-sweep number) these lines are the only final numbers.
RE_MET = re.compile(
    r"\[sweep\]\s+(\S+): met timing, (\d+) slice\(s\) built \((\d+) pipeline stages\), "
    r"cuts=(\d+), locked=(\d+) inst\(s\), iterations=(\d+)"
)
RE_STANDALONE = re.compile(
    r"\[sweep\]\s+(\S+) synthesized as written \(standalone check\): "
    r"([\d.]+) MHz vs ([\d.]+) MHz goal - (PASS|FAIL)"
)
RE_CONFIRM = re.compile(
    r"^(PASS|FAIL)\s+(\S+): ([\d.]+) MHz vs ([\d.]+) MHz goal"
    r"(?:; worst reported path)? \(confirmation run\)"
)
RE_NOT_MET_MAIN = re.compile(
    r"ERROR: TIMING NOT MET: (\S+) achieved ([\d.]+) MHz vs ([\d.]+) MHz goal"
)
RE_NOT_AUTOPIPELINED = re.compile(r"\[sweep\]\s+(\S+): not auto-?pipelined")
RE_DEPTH = re.compile(r"\[sweep\]\s+(\S+): (\d+) slice\(s\) total \((\d+) pipeline stages")
RE_CLOCK_LINE = re.compile(r"^Clock:\s+\d+\s*$")
RE_SIM_SPEED = re.compile(r"(\d+) cycles in ([\d.]+)s")


# Report row name (exact, after stripping indent and any trailing '*') -> key.
# Section-qualified so e.g. a "RAMB18" row can never be confused with a
# same-named primitive row.
_ROW_KEYS = {
    "slice logic": {
        "Slice LUTs": "lut_total",
        "CLB LUTs": "lut_total",  # UltraScale naming, harmless here
        "LUT as Logic": "lut_logic",
        "LUT as Memory": "lut_memory",
        "LUT as Distributed RAM": "lut_dram",
        "LUT as Shift Register": "lut_srl",
        "Slice Registers": "ff_total",
        "CLB Registers": "ff_total",
        "Register as Flip Flop": "ff_flipflop",
        "Register as Latch": "latches",
        "F7 Muxes": "muxf7",
        "F8 Muxes": "muxf8",
    },
    "memory": {
        "Block RAM Tile": "bram_tiles",
        "RAMB36/FIFO": "ramb36",
        "RAMB18": "ramb18",
    },
    "dsp": {
        "DSPs": "dsp48",
    },
    "primitives": {
        "CARRY4": "carry4",
    },
}

# Resources whose Available/Util% columns are worth keeping.
_AVAIL_KEYS = {
    "lut_total": "lut",
    "ff_total": "ff",
    "dsp48": "dsp",
    "bram_tiles": "bram_tiles",
}

_SECTION_RE = re.compile(r"^\d+(?:\.\d+)*\.\s+(.*?)\s*$")
_HEADER_RE = re.compile(r"^\|\s*(Design|Device|Design State|Tool Version)\s*:\s*(.*?)\s*$")
_TABLE_HEADER_CELLS = ("Site Type", "Ref Name")


def _num(cell):
    """Vivado cells are ints ('26917'), floats ('8.5') or blank."""
    cell = cell.strip()
    if not cell:
        return None
    try:
        return int(cell)
    except ValueError:
        pass
    try:
        return float(cell)
    except ValueError:
        return None


def _row_cells(line):
    """'| Slice LUTs* | 26917 | 0 | 134600 | 20.00 |' -> ['Slice LUTs*', '26917', ...]

    Column widths vary per run (a small module's table is much narrower), so
    split on '|' rather than slicing fixed offsets.
    """
    if not line.startswith("|"):
        return None
    inner = line.strip()
    if inner.startswith("|"):
        inner = inner[1:]
    if inner.endswith("|"):
        inner = inner[:-1]
    return [c.strip() for c in inner.split("|")]


def _split_blocks(text):
    """One entry per `report_utilization` in the log. A synthesis-only run (the
    pypelinec default, VIVADO.DO_PNR is None) has exactly one; a PnR run has
    more, so callers must be able to choose."""
    marker = "Utilization Design Information"
    blocks = []
    for m in re.finditer(re.escape(marker), text):
        start = text.rfind("\n# report_utilization", 0, m.start())
        if start == -1:
            # No echoed command (e.g. hand-saved report): fall back to the
            # report's own '---' header banner just above the marker.
            start = max(0, m.start() - 2000)
        # A block ends at the next echoed tcl command after the marker.
        end = text.find("\n# ", m.end())
        blocks.append(text[start : end if end != -1 else len(text)])
    return blocks


def parse_utilization(text):
    """Parse one utilization block's text into a flat dict of area numbers."""
    out = {
        "design": None,
        "part": None,
        "design_state": None,
        "vivado_version": None,
        "available": {},
        "util_pct": {},
    }
    section = None
    in_table = False
    for line in text.splitlines():
        stripped = line.rstrip()
        header = _HEADER_RE.match(stripped)
        if header:
            field, value = header.group(1), header.group(2)
            if field == "Design":
                out["design"] = value
            elif field == "Device":
                out["part"] = value
            elif field == "Design State":
                out["design_state"] = value
            elif field == "Tool Version":
                m = re.search(r"Vivado v\.?([\w.]+)", value)
                out["vivado_version"] = m.group(1) if m else value
            continue
        sect = _SECTION_RE.match(stripped)
        if sect:
            section = sect.group(1).strip().lower()
            in_table = False
            continue
        cells = _row_cells(stripped)
        if not cells:
            continue
        if cells[0] in _TABLE_HEADER_CELLS:
            in_table = True
            continue
        if not in_table or len(cells) < 2:
            continue
        name = cells[0].rstrip("*").strip()
        keys = _ROW_KEYS.get(section, {})
        key = keys.get(name)
        if key is None:
            continue
        value = _num(cells[1])
        if value is None:
            continue
        # First occurrence wins: Vivado's sub-rows ("1.1 Summary of Registers
        # by Type") repeat names with different meanings.
        out.setdefault(key, value)
        avail_key = _AVAIL_KEYS.get(key)
        if avail_key and len(cells) >= 5:
            # Available and Util% are the last two columns; newer Vivado
            # (e.g. 2026.1) inserts a Prohibited column before them
            avail, pct = _num(cells[-2]), _num(cells[-1])
            if avail is not None:
                out["available"].setdefault(avail_key, avail)
            if pct is not None:
                out["util_pct"].setdefault(avail_key, pct)
    return out


def parse_log(path, prefer="last"):
    """Parse the chosen utilization block of a pypelinec vivado log.

    prefer: 'last' (default) takes the final block, preferring a routed report
    over a synthesized one when both exist -- the routed numbers are the real
    ones. With pypelinec's default synthesis-only flow there is just one block.
    """
    with open(path, "r", errors="replace") as f:
        text = f.read()
    blocks = _split_blocks(text)
    if not blocks:
        raise ValueError(f"no report_utilization block found in {path}")
    parsed = [parse_utilization(b) for b in blocks]
    routed = [p for p in parsed if (p.get("design_state") or "").lower().find("rout") >= 0]
    if prefer == "last" and routed:
        chosen = routed[-1]
    else:
        chosen = parsed[-1]
    chosen["log"] = os.path.abspath(path)
    chosen["blocks_found"] = len(blocks)
    return chosen


_MODULE_LOG_RE = re.compile(r"vivado_(\d+)CLK_[0-9a-f]+(?:_[0-9a-f]+)?\.log$")
_TOP_LOG_RE = re.compile(r"vivado_([0-9a-f]+)(?:_[0-9a-f]+)?\.log$")


def find_top_dir(out_dir):
    """Support the default 'top' and hardware builds using --top <name>.

    Module characterization logs have NCLK in their names; whole-design
    sweep logs do not. Signed caches copied from other tops are not active
    builds: prefer directories with sweep history or final top HDL. Keep
    log-only historical support, and refuse genuinely mixed output directories.
    """
    histories = {
        os.path.dirname(path)
        for path in glob.glob(os.path.join(out_dir, "*", "sweep_history.json"))
    }
    log_dirs = {
        os.path.dirname(path)
        for path in glob.glob(os.path.join(out_dir, "*", "vivado_*.log"))
        if _TOP_LOG_RE.fullmatch(os.path.basename(path))
    }
    built = histories | {
        path
        for path in log_dirs
        if os.path.isfile(os.path.join(path, os.path.basename(path) + ".vhd"))
    }
    candidates = built or log_dirs
    if len(candidates) > 1:
        raise ValueError(
            "multiple hardware tops in output directory: " + ", ".join(sorted(candidates))
        )
    return next(iter(candidates)) if candidates else os.path.join(out_dir, "top")


def _instantiated_entities(path):
    if not os.path.exists(path):
        return None
    with open(path) as source:
        return set(re.findall(r"\bentity\s+work\.([a-z][a-z0-9_]*)", source.read().lower()))


def _select_top_log(top_dir, logs):
    # The final top drops the timing-snapshot hash, but instantiates the
    # content-hashed MAIN entities that identify its actual built depths.
    # Match those before using mtime: a sweep can restore an earlier winner.
    top_name = os.path.basename(top_dir)
    history_path = os.path.join(top_dir, "sweep_history.json")
    if os.path.isfile(history_path):
        with open(history_path) as source:
            history = json.load(source)
        retained = history.get("retained_observation") or {}
        log = retained.get("log_path")
        # Basename permits moving a complete output directory without losing provenance.
        if history.get("build_complete") and log:
            candidate = os.path.join(top_dir, os.path.basename(log))
            if candidate in logs:
                return candidate, "retained implementation and constraints from sweep history"
    final_entities = _instantiated_entities(os.path.join(top_dir, top_name + ".vhd"))
    if final_entities:
        matching = []
        for log in logs:
            digest = _TOP_LOG_RE.fullmatch(os.path.basename(log)).group(1)
            snapshot = os.path.join(top_dir, top_name + "_" + digest + ".vhd")
            if _instantiated_entities(snapshot) == final_entities:
                matching.append(log)
        if not matching:
            raise ValueError("no utilization snapshot matches the final HDL MAIN entities")
        return max(matching, key=os.path.getmtime), "final HDL MAIN entities; latest matching run"
    return max(logs, key=os.path.getmtime), "latest top-level run; no final HDL available"


def parse_out_dir(out_dir, per_module=True):
    """Parse a whole pypelinec output directory: the top-level design plus, if
    asked, every module's out-of-context synthesis."""
    result = {"out_dir": os.path.abspath(out_dir), "top": None, "per_module": {}}
    top_dir = find_top_dir(out_dir)
    top_logs = [
        path
        for path in glob.glob(os.path.join(top_dir, "vivado_*.log"))
        if _TOP_LOG_RE.fullmatch(os.path.basename(path))
    ]
    if top_logs:
        top_log, basis = _select_top_log(top_dir, top_logs)
        result["top"] = parse_log(top_log)
        result["top"]["logs_available"] = len(top_logs)
        result["top"]["selection_basis"] = basis
    if not per_module:
        return result
    for log in glob.glob(os.path.join(out_dir, "**", "vivado_*CLK_*.log"), recursive=True):
        rel = os.path.relpath(os.path.dirname(log), out_dir)
        m = _MODULE_LOG_RE.search(os.path.basename(log))
        latency = int(m.group(1)) if m else None
        try:
            parsed = parse_log(log)
        except ValueError:
            continue
        parsed["latency_clks"] = latency
        prev = result["per_module"].get(rel)
        # These are characterization data, not necessarily the final instance.
        # Keep the deepest tried depth and label it explicitly.
        parsed["selection_basis"] = "deepest characterized latency; not necessarily instantiated"
        if prev is None or (latency or 0) >= (prev.get("latency_clks") or 0):
            result["per_module"][rel] = parsed
    return result


_AREA_FIELDS = (
    "lut_total",
    "lut_logic",
    "lut_memory",
    "lut_dram",
    "lut_srl",
    "ff_total",
    "ff_flipflop",
    "latches",
    "muxf7",
    "muxf8",
    "dsp48",
    "bram_tiles",
    "ramb36",
    "ramb18",
    "carry4",
)


def format_area(parsed):
    lines = [
        f"design      : {parsed.get('design')}",
        f"part        : {parsed.get('part')}",
        f"state       : {parsed.get('design_state')}  (vivado {parsed.get('vivado_version')})",
    ]
    for field in _AREA_FIELDS:
        if parsed.get(field) is not None:
            lines.append(f"{field:<12}: {parsed[field]}")
    if parsed.get("util_pct"):
        lines.append(f"util%       : {parsed['util_pct']}")
    return "\n".join(lines)


def git_describe(repo):
    def run(*args):
        try:
            return subprocess.run(
                ["git", "-C", repo] + list(args),
                capture_output=True,
                text=True,
                check=True,
            ).stdout.strip()
        except (subprocess.CalledProcessError, FileNotFoundError):
            return None

    sha = run("rev-parse", "HEAD")
    if sha is None:
        return None
    dirty = run("status", "--porcelain")
    return sha + ("-dirty" if dirty else "")


def correct_frozen_compiler_revision(provenance, log_path):
    """Repair old records that used this repository's revision for a frozen compiler.

    Resolve the compiler named in the build log and preserve the original value.
    """
    recorded = provenance.get("pipelinec_git")
    if not recorded or recorded != provenance.get("wireguard_fpga_git"):
        return
    try:
        with open(log_path) as f:
            head = "".join(f.readline() for _ in range(20))
    except OSError:
        return
    match = re.search(r"Command: (\S+)/src/pypelinec\b", head)
    if match:
        fixed = compiler_revision(match.group(1))
        if fixed and fixed != recorded:
            provenance["pipelinec_git_recorded"] = recorded
            provenance["pipelinec_git"] = fixed


def compiler_revision(repo):
    """The PypelineC source revision a build used.

    A frozen snapshot (<snap>/compiler beside <snap>/compiler-snapshot.json) is not a git
    checkout of its own; inside this repository, git would answer with WireGuard's commit.
    Report the snapshot's recorded base and source-tree hash instead."""
    snapshot = Path(repo).parent / "compiler-snapshot.json"
    if snapshot.is_file():
        manifest = json.loads(snapshot.read_text())
        return f"{manifest['base_revision']}-frozen-{manifest['src_tree_sha256'][:12]}"
    try:
        top = subprocess.run(
            ["git", "-C", repo, "rev-parse", "--show-toplevel"],
            capture_output=True,
            text=True,
            check=True,
        ).stdout.strip()
    except (subprocess.CalledProcessError, FileNotFoundError):
        return None
    if os.path.realpath(top) != os.path.realpath(repo):
        return None
    return git_describe(repo)


def historical_target_mhz(implementation, sharing=None):
    """Clock fallback for saved records created before the multiplier selector."""
    if (
        implementation == "pipelined"
        and sharing is not None
        and sharing["chacha20"]
        and sharing["poly1305"]
    ):
        return 60
    return 80 if implementation == "legacy" else 30


def out_dir_for(
    comb, implementation, target_mhz=None, sharing=None, multiplier=None, compute=None, blocks=1
):
    if target_mhz is None:
        # Records without sharing metadata predate the sharing-both default.
        target_mhz = (
            historical_target_mhz(implementation, sharing)
            if multiplier is None
            else default_target_mhz(implementation, sharing)
        )
    base = os.path.join(HERE, GENERATED_FILES, f"perf-{'comb' if comb else 'pipe'}-shared-native")
    base = implementation_out_dir(base, implementation)
    # None means a historical record, whose directory predates sharing flags.
    if sharing is not None:
        base = sharing_out_dir(base, sharing)
    return blocks_out_dir(
        target_out_dir(compute_out_dir(mult_out_dir(base, multiplier), compute), target_mhz), blocks
    )


def build_metadata(out_dir):
    """Read emitted selections once; missing provenance leaves them unknown.

    Defaults here describe older records, not today's default build profile.
    An explicitly recorded None cap is resolved using that build's width.
    """
    fields = ("multiplier", "compute", "prologue_cap", "epilogue_cap", "blocks_per_cycle")
    path = Path(out_dir) / "source_provenance.json"
    if not path.is_file():
        return dict.fromkeys(fields)
    params = {
        entry["name"]: entry["value"]
        for entry in json.loads(path.read_text()).get("design_params", [])
    }
    width = _emitted_cap_width(params)
    return {
        "multiplier": params.get("POLY1305_MULT_IMPL", "inferred"),
        "compute": params.get("POLY1305_COMPUTE_IMPL", "mcp"),
        "prologue_cap": selected_prologue_cap(
            params.get("POLY1305_PROLOGUE_MAX_LATENCY", 64), width
        ),
        "epilogue_cap": selected_epilogue_cap(
            params.get("POLY1305_EPILOGUE_MAX_LATENCY", 64), width
        ),
        "blocks_per_cycle": recorded_data_bitwidth(
            {
                "data_bitwidth": params.get("DATA_BITWIDTH"),
                "poly1305_blocks_per_cycle": params.get("POLY1305_BLOCKS_PER_CYCLE") or 1,
            }
        )
        // 128,
    }


def build_blocks_per_cycle(out_dir):
    """Emitted block rate, also used by standalone profile diagnostics."""
    return build_metadata(out_dir)["blocks_per_cycle"]


def _emitted_cap_width(params):
    """Resolve width for direct compiler runs using the deprecated block flag."""
    width = params.get("DATA_BITWIDTH")
    if width is None and params.get("POLY1305_BLOCKS_PER_CYCLE") is not None:
        width = 128 * params["POLY1305_BLOCKS_PER_CYCLE"]
    if width is None and params.get("POLY1305_IMPL") == "legacy":
        width = 128
    return width


def recorded_data_bitwidth(config):
    """Resolve both current width records and historical block-rate records."""
    width = config.get("data_bitwidth")
    return width if width is not None else 128 * config.get("poly1305_blocks_per_cycle", 1)


def _profile_flags(args):
    """build.py flags selecting this measurement's profile and output directory."""
    flags = [
        "--poly1305",
        args.poly1305,
        "--target-mhz",
        str(args.target_mhz),
        "--poly1305-mult",
        args.poly1305_mult,
        "--poly1305-compute",
        args.poly1305_compute,
        "--poly1305-prologue-cap",
        str(args.poly1305_prologue_cap),
        "--poly1305-epilogue-cap",
        str(args.poly1305_epilogue_cap),
        "--data-bitwidth",
        str(args.data_bitwidth),
    ]
    for name in ("chacha20", "poly1305"):
        if args.sharing[name]:
            flags.append("--share-" + name)
    if not (args.sharing["chacha20"] or args.sharing["poly1305"]):
        flags.append("--share-none")
    if args.jobs is not None:
        flags.extend(["-j", str(args.jobs)])
    if args.out_dir:
        flags.extend(["--out-dir", args.out_dir])
    if args.syn_cache is not None:
        flags.extend(["--syn-cache", args.syn_cache])
    return flags


def _run_build_py(cmd, log_path):
    """Run build.py, teeing its (very chatty) stdout to log_path.

    The per-cycle 'Clock: N' lines are dropped from the saved log -- they are
    the bulk of it and carry no information the JSON doesn't -- but they are
    counted, which is how cycles_run is recovered.
    """
    env = dict(os.environ)
    if not env.get("PYPELINEC"):
        candidate = os.path.join(DEFAULT_PIPELINEC_REPO, "src", "pypelinec")
        if os.path.exists(candidate):
            env["PYPELINEC"] = candidate
            # Mirror it into our own environment so provenance below records the
            # same PypelineC checkout the build actually used.
            os.environ["PYPELINEC"] = candidate
            print(f"--> $PYPELINEC not set, using {candidate}")
    print(f"--> {' '.join(cmd)}")
    print(f"--> log: {log_path}")
    # Capture the PypelineC revision at launch; the checkout may change during a sweep.
    pipelinec_git = compiler_revision(
        os.path.dirname(os.path.dirname(env.get("PYPELINEC", DEFAULT_PIPELINEC_REPO + "/src/x")))
    )
    clock_lines = 0
    started = time.time()
    with open(log_path, "w") as log:
        proc = subprocess.Popen(
            cmd,
            cwd=HERE,
            env=env,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            bufsize=1,
        )
        for line in proc.stdout:
            if RE_CLOCK_LINE.match(line):
                clock_lines += 1
                continue
            log.write(line)
            log.flush()
        rc = proc.wait()
    elapsed = time.time() - started
    return {
        "cmd": " ".join(cmd),
        "returncode": rc,
        "wall_s": elapsed,
        "clock_lines": clock_lines,
        "pipelinec_git": pipelinec_git,
        "log": os.path.relpath(log_path, HERE),
    }


def run_hardware_build(args, log_path):
    """Build the real top (build.py without --sim): the source of fmax, area and
    every latency the performance simulation then simulates."""
    cmd = [os.path.join(HERE, "build.py")] + _profile_flags(args)
    output = args.out_dir or os.path.join(
        HERE,
        hardware_out_dir(
            "shared",
            args.poly1305,
            args.sharing,
            args.poly1305_mult,
            args.poly1305_compute,
            args.target_mhz,
            args.data_bitwidth,
            args.poly1305_prologue_cap,
            args.poly1305_epilogue_cap,
        ),
    )
    if os.path.isfile(os.path.join(output, BUILT_HARDWARE_FILE)):
        cmd.append("--continue")
    if args.rebuild:
        cmd.append("--rebuild")
    info = _run_build_py(cmd, log_path)
    info["up_to_date"] = hardware_log_up_to_date(log_path)
    return info


def hardware_log_up_to_date(log_path):
    """Whether pypelinec found the hardware already built from these exact
    inputs and built nothing: a replay, like --reuse-syn, whose log holds no
    timing lines."""
    with open(log_path) as f:
        return any(line.startswith("Up to date: ") for line in f)


def run_build(args, json_path, log_path):
    """Run build.py --perf: the native simulation of the built hardware (with
    --comb, the zero-latency rig check, which builds nothing)."""
    # The perf testbench's phase plan: simulation-only design parameters
    defines = [f"PERF_JSON={json_path}"]
    if args.sizes:
        defines.append(f"PERF_SIZES={args.sizes}")
    if args.packets:
        defines.append(f"PERF_PACKETS={args.packets}")
    if args.peak_bytes is not None:
        defines.append(f"PERF_PEAK_BYTES={args.peak_bytes}")
    if args.dirs:
        defines.append(f"PERF_DIRS={args.dirs}")
    if args.taps is not None:
        defines.append(f"PERF_TAPS={args.taps}")
    if args.seed is not None:
        defines.append(f"PERF_SEED={args.seed}")
    cmd = [os.path.join(HERE, "build.py"), "--perf"] + _profile_flags(args)
    for define in defines:
        cmd.extend(["-D", define])
    if args.comb:
        cmd.append("--comb")
    return _run_build_py(cmd, log_path)


def parse_stdout(log_path):
    """Cross-check numbers + provenance from pypelinec's own printed output."""
    info = {
        "fmax_lines": [],
        "sweep_iters": [],
        "timing_not_met": [],
        "pipeline_depth_summary": [],
        "final": {},  # main -> final outcome (see RE_MET above)
        "sim_cycles": None,
        "sim_wall_s": None,
    }
    if not os.path.exists(log_path):
        return info

    def final(name):
        return info["final"].setdefault(name, {})

    in_depth_summary = False
    with open(log_path, errors="replace") as f:
        for line in f:
            line = line.rstrip("\n")
            m = RE_FMAX.search(line)
            if m:
                info["fmax_lines"].append(
                    {
                        "passfail": m.group(1),
                        "clock": m.group(2),
                        "mhz": float(m.group(3)),
                        "ns": float(m.group(4)),
                    }
                )
            m = RE_SWEEP_ITER.search(line)
            if m:
                info["sweep_iters"].append(line.strip())
            if RE_TIMING_NOT_MET.search(line):
                info["timing_not_met"].append(line.strip())

            m = RE_MET.search(line)
            if m:
                # Met its goal, but pypelinec prints no achieved MHz in this
                # case ("no failing timing path reported ... assuming met"), so
                # achieved_mhz stays unknown and the goal is a lower bound.
                entry = final(m.group(1))
                entry.update(
                    met=True,
                    slices=int(m.group(2)),
                    pipeline_stages=int(m.group(3)),
                    final_cuts=int(m.group(4)),
                    locked_instances=int(m.group(5)),
                    iterations=int(m.group(6)),
                    outcome="met timing (achieved MHz not reported)",
                )
            m = RE_STANDALONE.search(line)
            if m:
                entry = final(m.group(1))
                entry.update(
                    standalone_mhz=float(m.group(2)),
                    goal_mhz=float(m.group(3)),
                    met=m.group(4) == "PASS",
                    autopipelined=False,
                    outcome="synthesized as written (standalone check)",
                )
            m = RE_CONFIRM.match(line.strip())
            if m:
                entry = final(m.group(2))
                entry.update(
                    achieved_mhz=float(m.group(3)),
                    goal_mhz=float(m.group(4)),
                    met=m.group(1) == "PASS",
                    outcome="confirmation run",
                )
            m = RE_NOT_MET_MAIN.search(line)
            if m:
                entry = final(m.group(1))
                entry.update(
                    achieved_mhz=float(m.group(2)),
                    goal_mhz=float(m.group(3)),
                    met=False,
                    outcome="TIMING NOT MET",
                )
            m = RE_NOT_AUTOPIPELINED.search(line)
            if m:
                final(m.group(1)).setdefault("autopipelined", False)
            m = RE_DEPTH.search(line)
            if m:
                entry = final(m.group(1))
                entry.setdefault("slices", int(m.group(2)))
                entry.setdefault("pipeline_stages", int(m.group(3)))
                entry["autopipelined"] = True
            if "[sweep] Pipeline depth summary:" in line:
                in_depth_summary = True
                info["pipeline_depth_summary"].append(line.strip())
                continue
            if in_depth_summary:
                if line.startswith("[sweep]"):
                    info["pipeline_depth_summary"].append(line.strip())
                else:
                    in_depth_summary = False
            m = RE_SIM_SPEED.search(line)
            if m:
                info["sim_cycles"] = int(m.group(1))
                info["sim_wall_s"] = float(m.group(2))
    return info


# Schema-2/3 sweep_history.json "final" field -> per_main field (the names the
# stdout parser above already uses, so both sources merge the same way)
HISTORY_FINAL_FIELDS = (
    ("met", "met"),
    ("achieved_mhz", "achieved_mhz"),
    ("mhz_is_lower_bound", "mhz_is_lower_bound"),
    ("met_basis", "met_basis"),
    ("source", "outcome"),
    ("standalone_mhz", "standalone_mhz"),
    ("autopipelined", "autopipelined"),
    ("auto_pipelined", "autopipelined"),  # sweep_history key after the AUTO_PIPELINE rename
    ("slices_built", "slices"),
    ("pipeline_stages", "pipeline_stages"),
    ("cuts", "final_cuts"),
    ("locked_instances", "locked_instances"),
    ("failure_reason", "failure_reason"),
)
# Verdict numbers compared against stdout. Depth is not: the sweep's "met
# timing, N slice(s)" line predates any pin-and-confirm re-realization, which
# the final record (read off the final table) already includes.
CROSS_CHECK_FIELDS = ("met", "achieved_mhz", "standalone_mhz")


def final_from_history(final):
    """Map one schema-2 "final" record onto per_main fields. The mapping keeps
    a met-but-unmeasured MAIN's achieved_mhz None -- its goal is a lower bound."""
    mapped = {}
    for src, dst in HISTORY_FINAL_FIELDS:
        if src in final and (final[src] is not None or src == "achieved_mhz"):
            mapped[dst] = final[src]
    return mapped


def cross_check_final(from_history, from_stdout):
    """{field: {"sweep_history": a, "stdout": b}} where both sources state a
    value and disagree (MHz compared to the 2 decimals stdout prints)."""
    mismatches = {}
    for key in CROSS_CHECK_FIELDS:
        a, b = from_history.get(key), from_stdout.get(key)
        if a is None or b is None:
            continue
        if isinstance(a, bool) or isinstance(b, bool):
            same = a == b
        else:
            same = abs(float(a) - float(b)) <= 0.01
        if not same:
            mismatches[key] = {"sweep_history": a, "stdout": b}
    return mismatches


def parse_fmax(out_dir, stdout_info):
    """fmax + per-MAIN pipelining from pypelinec's own numbers.

    A schema-2/3 `sweep_history.json` from a complete build carries one "final"
    record per MAIN describing the design as built (after any confirmation run,
    restored snapshot or as-written check); those records are authoritative and
    the build's stdout outcome lines are only a cross-check
    (`source.cross_check_mismatches`). A schema-1 file is only the sweep's
    iteration log -- it could stop before the iteration that met timing -- so
    for those the stdout outcome lines stay authoritative and the history is
    kept as diagnostics (`last_sweep_iter.mid_sweep_mhz`).

    A MAIN that met its goal with no MHz ever measured for it ("no failing
    timing path reported ... assuming met") has an unknown exact fmax; its goal
    is a lower bound -- `design_mhz_is_lower_bound` says when that is the case.
    """
    sweep_path = os.path.join(find_top_dir(out_dir), "sweep_history.json")
    result = {
        "design_mhz": None,
        "design_mhz_is_lower_bound": False,
        "design_mhz_basis": None,
        "min_reported_mhz": None,
        "limiting_main": None,
        "target_mhz": None,
        "timing_met": None,
        "per_main": {},
        "source": {
            "sweep_history": None,
            "sweep_history_schema": None,
            # "sweep_history.json final records" or "stdout outcome lines"
            "final_basis": None,
            "cross_check_mismatches": {},
            "stdout_fmax_lines": stdout_info["fmax_lines"],
            "final_outcomes": stdout_info["final"],
        },
        "pipeline_depth_summary": stdout_info["pipeline_depth_summary"],
        "timing_not_met": stdout_info["timing_not_met"],
    }
    history_finals = {}  # main -> schema-2 "final" record (complete builds only)
    if os.path.exists(sweep_path):
        result["source"]["sweep_history"] = sweep_path
        with open(sweep_path) as f:
            history = json.load(f)
        if "schema_version" in history:
            result["source"]["sweep_history_schema"] = history["schema_version"]
            for main, record in history.get("mains", {}).items():
                entry = result["per_main"].setdefault(main, {})
                entry["sweep_iters"] = len(record.get("iterations", []))
                entry.setdefault("goal_mhz", record.get("goal_mhz"))
                # A provisional file (build died after the sweep) has no
                # verdict for the design as built
                if history.get("build_complete") and record.get("final"):
                    history_finals[main] = record["final"]
        else:
            result["source"]["sweep_history_schema"] = 1
            for main, iters in history.items():
                entry = result["per_main"].setdefault(main, {})
                entry["sweep_iters"] = len(iters)
                if not iters:
                    continue
                last = iters[-1]
                # Explicitly NOT the final fmax -- see this function's docstring.
                entry["last_sweep_iter"] = {
                    "iter": last.get("iter"),
                    "mid_sweep_mhz": last.get("achieved_mhz"),
                    "cuts": last.get("cuts"),
                    "pipeline_stages": last.get("pipeline_stages"),
                    "bottleneck": last.get("bottleneck"),
                    "action": last.get("action"),
                }
                entry.setdefault("goal_mhz", last.get("goal_mhz"))
                entry.setdefault("bottleneck", last.get("bottleneck"))
    if stdout_info["fmax_lines"] and not stdout_info["final"]:
        # --comb builds run no sweep: the printed per-clock FMAX lines are all
        # there is.
        for entry in stdout_info["fmax_lines"]:
            result["per_main"].setdefault(entry["clock"], {}).update(
                achieved_mhz=entry["mhz"],
                met=entry["passfail"] != "FAIL",
                outcome="comb FMAX line",
            )

    # Merge the authoritative final outcomes over the diagnostics.
    if history_finals:
        result["source"]["final_basis"] = "sweep_history.json final records"
        for main, final in history_finals.items():
            mapped = final_from_history(final)
            mismatches = cross_check_final(mapped, stdout_info["final"].get(main, {}))
            if mismatches:
                result["source"]["cross_check_mismatches"][main] = mismatches
            result["per_main"].setdefault(main, {}).update(mapped)
    elif stdout_info["final"]:
        result["source"]["final_basis"] = "stdout outcome lines"
        for main, final in stdout_info["final"].items():
            result["per_main"].setdefault(main, {}).update(final)

    with_goal = {name: info for name, info in result["per_main"].items() if info.get("goal_mhz")}
    goals = [info["goal_mhz"] for info in with_goal.values()]
    result["target_mhz"] = max(goals) if goals else None

    if with_goal:
        result["timing_met"] = (
            all(info.get("met") for info in with_goal.values())
            and not stdout_info["timing_not_met"]
        )

    # Lowest MHz anyone actually printed (a standalone/confirmation/comb number).
    reported = [
        v
        for info in result["per_main"].values()
        for v in (info.get("achieved_mhz"), info.get("standalone_mhz"))
        if v
    ]
    result["min_reported_mhz"] = min(reported) if reported else None

    unknown = sorted(
        name
        for name, info in with_goal.items()
        if info.get("met") and not (info.get("achieved_mhz") or info.get("standalone_mhz"))
    )
    if result["timing_met"] and with_goal:
        if unknown:
            # Every goal met, but the limiting MAIN's exact fmax was never
            # printed: the goal is the honest, conservative number to quote.
            result["design_mhz"] = result["target_mhz"]
            result["design_mhz_is_lower_bound"] = True
            result["limiting_main"] = unknown[0]
            result["design_mhz_basis"] = (
                f"all MAINs met the {result['target_mhz']} MHz goal; "
                f"{', '.join(unknown)} met timing with no failing path reported, so "
                f"its exact achieved MHz is not printed -- the goal is a lower bound "
                f"(lowest reported elsewhere: {result['min_reported_mhz']} MHz)"
            )
        else:
            per_main_mhz = {
                name: info.get("achieved_mhz") or info.get("standalone_mhz")
                for name, info in with_goal.items()
            }
            limiting = min(per_main_mhz, key=per_main_mhz.get)
            result["design_mhz"] = per_main_mhz[limiting]
            result["limiting_main"] = limiting
            result["design_mhz_basis"] = "slowest MAIN's reported achieved MHz"
    else:
        failing = {
            name: info.get("achieved_mhz")
            for name, info in with_goal.items()
            if info.get("achieved_mhz") and not info.get("met")
        }
        candidates = failing or {
            name: info.get("achieved_mhz")
            for name, info in result["per_main"].items()
            if info.get("achieved_mhz")
        }
        if candidates:
            limiting = min(candidates, key=candidates.get)
            result["design_mhz"] = candidates[limiting]
            result["limiting_main"] = limiting
            result["design_mhz_basis"] = (
                "slowest MAIN that failed its goal"
                if failing
                else "slowest reported MHz (no goal met/failed verdict available)"
            )
    return result


def parse_area(out_dir, per_module=True, scope="hardware_top"):
    """Area from a build's top-level Vivado log. scope "hardware_top": the real top
    (external ports); "perf_tb_top": a historical synthesized perf testbench, whose
    constant key/nonce/aad let Vivado fold logic away."""
    try:
        parsed = parse_out_dir(out_dir, per_module=per_module)
    except Exception as exc:  # a missing/incomplete build must not lose the sim data
        return {"available": False, "reason": f"{type(exc).__name__}: {exc}"}
    if not parsed["top"]:
        return {
            "available": False,
            "reason": (
                "no top-level vivado*.log in this build (a --comb build runs no "
                "synthesis, so it reports no area)"
            ),
            "per_module": parsed["per_module"],
        }
    area = dict(parsed["top"])
    area["resources_available"] = area.pop("available", {})
    area["available"] = True
    area["over_capacity"] = {
        name: percent
        for name, percent in area.get("util_pct", {}).items()
        if percent is not None and percent > 100
    }
    area["fits_device"] = not area["over_capacity"] if area.get("util_pct") else None
    area["scope"] = scope
    area["constant_key_folding"] = scope == "perf_tb_top"
    area["per_module"] = parsed["per_module"]
    return area




def derive_throughput(perf_raw, fmax_mhz, target_mhz, steady_trim=0):
    """Add MHz-dependent columns to the testbench's cycle-domain numbers."""
    phases = perf_report.derive_throughput(
        perf_raw,
        fmax_mhz,
        target_mhz,
        perf_raw.get("config", {}).get("bus_bytes", BUS_BYTES),
        DIRECTIONS,
    )
    if steady_trim:
        for phase in phases:
            for direction in DIRECTIONS:
                stats = phase.get(direction)
                if not stats:
                    continue
                steady = steady_packet_window(
                    stats.get("packets", []), phase["packet_bytes"], steady_trim
                )
                stats["steady_state"] = steady
                if not steady["available"]:
                    continue
                for key in (
                    "packet_period_cycles",
                    "sustained_bytes_per_cycle",
                    "throughput_bytes_per_cycle",
                    "throughput_basis",
                    "line_rate_frac",
                    "gbps_at_fmax",
                    "gbps_at_target",
                ):
                    stats["burst_" + key] = stats.get(key)
                rate = steady["bytes_per_cycle"]
                stats.update(
                    packet_period_cycles=steady["packet_period_cycles"],
                    sustained_bytes_per_cycle=rate,
                    throughput_bytes_per_cycle=rate,
                    throughput_basis="packet completions, warm-up/drain excluded",
                    line_rate_frac=rate / perf_raw.get("config", {}).get("bus_bytes", BUS_BYTES),
                    gbps_at_fmax=rate * fmax_mhz * 0.008 if fmax_mhz else None,
                    gbps_at_target=rate * target_mhz * 0.008 if target_mhz else None,
                )
    return phases


def steady_packet_window(packets, packet_bytes, trim=8):
    """Payload rate between interior completions; do not count fill or drain."""
    selected = packets[trim:-trim] if trim else packets
    result = {"available": False, "trim_packets": trim, "total_packets": len(packets)}
    if len(selected) < 3:
        return result
    periods = [b["last_out"] - a["last_out"] for a, b in zip(selected, selected[1:])]
    if any(p <= 0 for p in periods):
        return result
    split = len(periods) // 2
    first = sum(periods[:split]) / split
    second = sum(periods[split:]) / (len(periods) - split)
    period = sum(periods) / len(periods)
    stability = min(first, second) / max(first, second)
    result.update(
        available=True,
        first_packet=selected[0]["idx"],
        last_packet=selected[-1]["idx"],
        first_cycle=selected[0]["last_out"],
        last_cycle=selected[-1]["last_out"],
        intervals=len(periods),
        packet_period_cycles=period,
        bytes_per_cycle=packet_bytes / period,
        first_half_period_cycles=first,
        second_half_period_cycles=second,
        stability_ratio=stability,
        stable=stability >= 0.99,
    )
    return result


def throughput_parity_errors(results):
    """Near-max decision gate; small-packet curves are collected afterward."""
    if not results.get("config", {}).get("require_throughput_parity"):
        return []
    errors = []
    config = results["config"]
    if config.get("dirs") != list(DIRECTIONS):
        errors.append("Throughput parity requires both directions")
    trim = config.get("steady_trim_packets", 0)
    seen = set()
    for phase in results.get("phases", []):
        if phase["packet_bytes"] < 1420:
            continue
        seen.add(phase["packet_bytes"])
        rates = []
        for direction in DIRECTIONS:
            stats = phase.get(direction, {})
            packets = stats.get("packets", [])
            selected = packets[trim:-trim] if trim else packets
            label = phase["name"] + "/" + direction
            window = steady_packet_window(packets, phase["packet_bytes"], trim)
            if len(selected) < 4 or not window["available"]:
                errors.append(
                    label
                    + ": parity requires at least four completed packets in the measurement window"
                )
                continue
            periods = [b["last_out"] - a["last_out"] for a, b in zip(selected, selected[1:])]
            if min(periods) / max(periods) < 0.95:
                errors.append(label + ": completion intervals vary by more than 5%; extend run")
            rate = window["bytes_per_cycle"]
            rates.append(rate)
            if (
                any(
                    abs(stats.get(key, 0) - rate) > 1e-9
                    for key in ("throughput_bytes_per_cycle", "sustained_bytes_per_cycle")
                )
                or abs(stats.get("gbps_at_target", 0) - rate * config.get("target_mhz", 0) * 0.008)
                > 1e-9
            ):
                errors.append(label + ": headline rate disagrees with packet completions")
            if (
                phase["packet_bytes"] == 1420
                and rate * config.get("target_mhz", 0) * 0.008 < 17.986666666666668
            ):
                errors.append(label + ": throughput below 17.986667 Gb/s")
        if len(rates) == 2 and min(rates) / max(rates) < 0.95:
            errors.append(phase["name"] + ": encrypt/decrypt throughput differs by more than 5%")
    if not {1420, 1920} <= seen:
        errors.append("Throughput parity requires 1420- and 1920-byte decision phases")
    return errors


def summarize(phases):
    return perf_report.summarize(phases, DIRECTIONS)


# WireGuard's summary.csv keeps its historical `direction` column name.
CSV_COLUMNS = perf_report.CSV_COLUMNS[:4] + ("direction",) + perf_report.CSV_COLUMNS[5:]


def write_csv(path, label, phases):
    perf_report.write_csv(path, CSV_COLUMNS, perf_report.csv_rows(label, phases, DIRECTIONS))


def write_tap_csvs(meas_dir, label, phases):
    """Per-tap and per-block rows, one file each -- the internal-stall curve, in
    the same flat shape as summary.csv so the two diff/plot the same way."""
    written = []
    for name, columns, rows in (
        ("taps.csv", TAP_CSV_COLUMNS, list(tap_rows(label, phases))),
        ("blocks.csv", BLOCK_CSV_COLUMNS, list(block_rows(label, phases))),
    ):
        if rows:  # no empty files for a run without taps
            path = os.path.join(meas_dir, name)
            perf_report.write_csv(path, columns, rows)
            written.append(path)
    return written


_fmt = perf_report.fmt


def markdown_table(results, include_mac_details=True):
    lines = []
    fmax = results["fmax"].get("design_mhz")
    area = results["area"]
    lines.append(
        f"Design `{results['config']['design']}` | target "
        f"{_fmt(results['fmax'].get('target_mhz'), '.1f')} MHz | measured fmax "
        f"**{_fmt(fmax, '.2f')} MHz** | limiting MAIN `{results['fmax'].get('limiting_main')}`"
    )
    lines.append(
        "Packet datapath: `"
        + str(recorded_data_bitwidth(results["config"]))
        + "` bits; Poly1305 blocks/cycle: `"
        + str(results["config"].get("poly1305_blocks_per_cycle", 1))
        + "`."
    )
    lines.append(
        "Poly1305 multiplier: `" + results["config"].get("poly1305_mult_impl", "inferred") + "`."
    )
    if results["config"].get("poly1305_impl") == "pipelined":
        lines.append(
            "Poly1305 initialization/finalization: `"
            + results["config"].get("poly1305_compute_impl", "mcp")
            + "`."
        )
    if area.get("available"):
        lines.append(
            f"Area ({area['scope']}): **{area.get('lut_total')} LUT** "
            f"({area.get('lut_logic')} logic + {area.get('lut_memory')} mem), "
            f"**{area.get('ff_total')} FF**, **{area.get('dsp48')} DSP48**, "
            f"**{area.get('bram_tiles')} BRAM tiles**, {area.get('carry4')} CARRY4"
        )
    hardware_area = results.get("area_hw_build") or {}
    if hardware_area.get("available"):
        lines.append(
            f"DUT-only area (external key/data ports): **{hardware_area.get('lut_total')} LUT**, "
            f"**{hardware_area.get('ff_total')} FF**, **{hardware_area.get('dsp48')} DSP48**, "
            f"**{hardware_area.get('bram_tiles')} BRAM tiles**."
        )
    hardware_fmax = results.get("fmax_hw_build") or {}
    if hardware_fmax:
        hardware_outcome = "PASS" if hardware_fmax.get("timing_met") is True else "not confirmed"
        lines.append(
            f"Hardware-top timing: {hardware_outcome}, "
            f"{_fmt(hardware_fmax.get('design_mhz'), '.2f')} MHz "
            f"against {_fmt(hardware_fmax.get('target_mhz'), '.1f')} MHz."
        )
    mac = results.get("config", {}).get("poly1305") or {}
    sharing = results.get("config", {}).get("sharing")
    if sharing is not None:
        lines.append(f"Shared resources: `{sharing_name(sharing)}`.")
    else:
        lines.append("Historical sharing metadata absent: interpreted as ChaCha20-only sharing.")
    for name, buffer in sorted(results.get("config", {}).get("buffering", {}).items()):
        lines.append(
            f"Buffer `{name}`: {buffer['memory_depth_beats']} memory beats + "
            f"{buffer['output_register_beats']} output beat; "
            f"{buffer['capacity_beats']} total capacity."
        )
        sizing = buffer.get("sizing", {})
        if sizing.get("method") == "chacha-credit-bound-v1":
            lines.append(
                f"Automatic sizing: {sizing['required_beats']} required beats; "
                f"ChaCha core={sizing['chacha20_core_latency']}, "
                f"credits={sizing['chacha20_max_in_flight_blocks']} blocks, "
                f"initialization MCP={sizing['prologue_mcp_latency']} cycles."
            )
        elif sizing.get("method") == "poly1305-overlap-fork-v2":
            terms = ", ".join(f"{key}={value}" for key, value in sizing["terms_beats"].items())
            lines.append(
                f"Automatic overlap sizing: {sizing['required_beats']} required beats "
                f"({terms}); memory rounded to a power of two."
            )
        elif sizing.get("method") == "plaintext-verdict-credit-bound-v1":
            terms = ", ".join(f"{key}={value}" for key, value in sizing["terms_beats"].items())
            lines.append(
                f"Automatic verification sizing: {sizing['required_beats']} required beats "
                f"({terms}); memory rounded to a power of two."
            )
    for name, stream_slice in sorted(results.get("config", {}).get("stream_slices", {}).items()):
        lines.append(
            f"Register slice `{name}`: mode `{stream_slice['mode']}`, "
            f"{stream_slice['capacity_beats']} slots, "
            f"{stream_slice['latency_cycles']} unstalled cycle(s), II=1."
        )
    if mac:
        lines.append(f"Poly1305 implementation: `{mac['implementation']}`.")
        unit = mac.get("shared_mcps")
        if unit and include_mac_details:
            lines.append(
                f"Shared compute capacity={unit['capacity_lanes']} lanes; "
                f"initialization compute={unit['prologue_mcp_latency']} cycles, "
                f"finalization compute={unit['epilogue_mcp_latency']} cycles. "
                "Each response adds one handshake cycle; arbitration waits are measured separately."
            )
        for direction, timing in (
            sorted(mac.get("directions", {}).items()) if include_mac_details else []
        ):
            details = (
                f"{direction}: body II={timing['body_ii']}, "
                f"accumulators={timing['accumulator_count']}"
            )
            if "body_latency" in timing:
                if timing.get("blocks_per_cycle", 1) == 2:
                    details += (
                        f", coefficient response={timing['coefficient_latency']} cycles"
                        f", feedback response={timing['body_latency']} cycles"
                        f", total body response={timing['total_body_latency']} cycles"
                    )
                else:
                    details += f", body response={timing['body_latency']} cycles"
                details += (
                    f", initialization response={timing['prologue_response_cycles']} cycles"
                    f", finalization response={timing['epilogue_response_cycles']} cycles"
                )
            lines.append(details + ".")
            if timing.get("packet_architecture") == "overlapped":
                capacities = ", ".join(
                    f"{name.rsplit('.', 1)[-1]}={capacity}"
                    for name, capacity in timing["packet_buffers"].items()
                )
                lines.append(
                    f"{direction}: independent packet stages ({capacities}); "
                    "stage costs overlap."
                )
    lines.append("")
    lines.extend(
        perf_report.markdown_boundary_table(
            results["phases"],
            DIRECTIONS,
            fmax,
            results["fmax"].get("target_mhz"),
            label_header="dir",
        )
    )
    return "\n".join(lines)


README_BEGIN = "<!-- MEASURED-RESULTS:BEGIN -->"
README_END = "<!-- MEASURED-RESULTS:END -->"
BLOCKS_BEGIN = "<!-- BLOCK-RESULTS:BEGIN -->"
BLOCKS_END = "<!-- BLOCK-RESULTS:END -->"


def readme_table(results):
    """Compact publication view; detailed local reports use markdown_table."""
    timing = results["fmax"]
    area = results["area"]
    fmax_label = (
        "Synthesis fmax lower bound"
        if timing.get("design_mhz_is_lower_bound")
        else "Synthesis fmax"
    )
    lines = [
        "| Target clock | " + fmax_label + " | LUT | FF | DSP48 | BRAM tiles |",
        "| ---: | ---: | ---: | ---: | ---: | ---: |",
        f"| {_fmt(timing.get('target_mhz'), '.0f')} MHz "
        f"| {_fmt(timing.get('design_mhz'), '.2f')} MHz "
        f"| {_fmt(area.get('lut_total'), ',.0f')} | {_fmt(area.get('ff_total'), ',.0f')} "
        f"| {_fmt(area.get('dsp48'), '.0f')} | {_fmt(area.get('bram_tiles'), '.1f')} |",
        "",
    ]
    config = results["config"]
    directions = ", ".join(config.get("dirs", DIRECTIONS))
    lines.extend(
        [
            f"Native pipelined simulation; directions: {directions}; "
            f"{config.get('packets_per_size', '-')} packets per size/direction; "
            f"seed {config.get('seed', '-')}. Throughput uses packet-completion intervals.",
            "",
            "| Payload bytes | Direction | Sustained B/cycle | Packet period (cycles) | "
            f"Gb/s @{_fmt(timing.get('target_mhz'), '.0f')} MHz | Cold first output (cycles) | "
            "Median total latency (cycles) |",
            "| ---: | --- | ---: | ---: | ---: | ---: | ---: |",
        ]
    )
    for phase in results["phases"]:
        for direction in DIRECTIONS:
            measured = phase.get(direction)
            if not measured:
                continue
            latency = measured.get("latency_cycles", {})
            lines.append(
                f"| {phase['packet_bytes']} | {direction} "
                f"| {_fmt(measured.get('throughput_bytes_per_cycle'))} "
                f"| {_fmt(measured.get('packet_period_cycles'), '.1f')} "
                f"| {_fmt(measured.get('gbps_at_target'))} "
                f"| {_fmt(latency.get('cold_head'), '.0f')} "
                f"| {_fmt(latency.get('total_med'), '.1f')} |"
            )
    return "\n".join(lines)


def provenance_stamp(results):
    provenance = results["provenance"]

    def revision(value):
        value = value or "?"
        base, frozen, snapshot = value.partition("-frozen-")
        text = f"`{base[:12]}`"
        if base.endswith("-dirty"):
            text += " (with local changes)"
        if frozen:
            text += f" (frozen source snapshot `{snapshot[:12]}`)"
        return text

    return (
        f"_Measured sources: wireguard-fpga {revision(provenance.get('wireguard_fpga_git'))}; "
        f"PypelineC {revision(provenance.get('pipelinec_git'))}; "
        f"Vivado {provenance.get('vivado_version', '-')}. "
        "Full provenance and raw artifacts are retained in local measurement outputs._"
    )


_splice = perf_report.splice_markers


def profile_from_record(record):
    """The build profile a measurement record was taken on, in DEFAULT_PROFILE's form."""
    c = record["config"]
    return dict(
        design="shared",
        implementation=c["poly1305"]["implementation"],
        data_bitwidth=c.get("data_bitwidth", 128 * c.get("poly1305_blocks_per_cycle", 1)),
        multiplier=c["poly1305_mult_impl"],
        compute=c["poly1305_compute_impl"],
        sharing=c["sharing"],
        target_mhz=int(c["target_mhz"]),
        prologue_cap=c.get("poly1305_prologue_max_latency") or 64,
        epilogue_cap=c.get("poly1305_epilogue_max_latency") or 64,
    )


def published_default_errors(record):
    """Why record cannot be README's current QoR table, which describes the
    published default: it must be a validated hardware measurement of
    wireguard_env.DEFAULT_PROFILE. The local archive location is unrestricted."""
    errors = []
    if not record.get("validation", {}).get("passed") or record["config"].get("comb"):
        errors.append("only a validated hardware measurement can be published")
    if profile_from_record(record) != DEFAULT_PROFILE:
        errors.append("its profile differs from DEFAULT_PROFILE")
    return errors


def update_readme(table, results, block_summary=None):
    """Splice the generated results into README.md so their numbers are never
    hand-copied (and so re-measuring a variant updates the docs in one step).

    Replace the current boundary QoR table and local block-report note, leaving
    the historical baseline summary intact. Full block tables stay in the
    ignored measurement directory. Only validated DEFAULT_PROFILE results can
    be published; promoting a different profile requires changing that default."""
    errors = published_default_errors(results)
    if errors:
        raise ValueError(
            "--update-readme publishes only the published default's record: "
            + "; ".join(errors)
            + ". To promote this record, set "
            "wireguard_env.DEFAULT_PROFILE to its profile first"
        )
    path = os.path.join(HERE, "README.md")
    with open(path) as f:
        text = f.read()
    stamp = provenance_stamp(results)
    spliced = _splice(text, README_BEGIN, README_END, f"{stamp}\n\n{table}")
    if spliced is None:
        raise ValueError(f"{path} has no {README_BEGIN} / {README_END} markers; not publishing")
    else:
        text = spliced
        print("--> README.md results table updated")
    if block_summary:
        # No second stamp: both regions come from the same run, and the README
        # holds only the current record -- one provenance line is enough.
        spliced = _splice(text, BLOCKS_BEGIN, BLOCKS_END, block_summary)
        if spliced is None:
            print(
                f"!! {path} has no {BLOCKS_BEGIN} / {BLOCKS_END} markers; "
                f"block summary not updated",
                file=sys.stderr,
            )
        else:
            text = spliced
            print("--> README.md block summary updated")
    with open(path, "w") as f:
        f.write(text)


ENTITY = re.compile(r"^\s*entity\s+(\w+)\s+is\b", re.MULTILINE | re.IGNORECASE)
CHILD = re.compile(r":\s*entity\s+work\.(\w+)", re.IGNORECASE)
LATENCY = re.compile(r"ADDED_PIPELINE_LATENCY\s*:\s*integer\s*:=\s*(\d+)", re.IGNORECASE)
# The initialization/finalization arithmetic roots. Both directions instantiate the same
# kernels (one set per lane count), so a root names its phase, not a direction.
COMPUTE_BODY = re.compile(
    r"^(?:(prologue|epilogue)_from_poly1305_(?:mac_pipelined_make_pipelined_compute_lanes"
    r"|paired_compute_make_paired_compute_capacity|mcp_shared_make_shared_compute_capacity)"
    r"|(init|finish)_from_poly1305_compute_(?:make_pipelined_compute_lanes"
    r"|make_paired_compute_capacity|make_shared_compute_capacity))_\d+_\d+clk_",
    re.IGNORECASE,
)


def audit_poly1305_hdl(out_dir, directions=("encrypt", "decrypt"), top_vhdl=None, shared=False):
    """Check existing MCP HDL for combinational arithmetic and physical sharing.

    Follow only entities reachable from the final top; this does not generate HDL.
    """
    out_dir = Path(out_dir).resolve()
    if top_vhdl is None:
        top_dir = Path(find_top_dir(str(out_dir)))
        top_vhdl = top_dir / (top_dir.name + ".vhd")
    top_vhdl = Path(top_vhdl).resolve()
    if not top_vhdl.is_file():
        raise ValueError(f"Final top HDL is missing: {top_vhdl}")
    entities = {}
    for path in out_dir.rglob("*.vhd"):
        text = re.sub(r"--[^\n]*", "", path.read_text())
        name = ENTITY.search(text)
        if name:
            latency = LATENCY.search(text)
            entities[name.group(1).lower()] = {
                "file": str(path.relative_to(out_dir)),
                "latency": int(latency.group(1)) if latency else None,
                "clocked": bool(re.search(r"\b(?:rising|falling)_edge\s*\(", text, re.IGNORECASE)),
                "children": [child.lower() for child in CHILD.findall(text)],
            }
    top_match = ENTITY.search(re.sub(r"--[^\n]*", "", top_vhdl.read_text()))
    if not top_match:
        raise ValueError(f"No entity declaration in {top_vhdl}")
    errors = []

    def walk(root):
        seen = set()
        pending = [root]
        while pending:
            entity = pending.pop()
            if entity in seen:
                continue
            seen.add(entity)
            info = entities.get(entity)
            if info is None:
                errors.append(f"Missing emitted entity: {entity}")
                continue
            pending.extend(info["children"])
            yield entity, info

    roots, physical_counts = {}, {}
    # Counting distinct entity TYPES would miss two physical instances of the
    # same kernel. Traverse instantiation edges (duplicates included),
    # stopping at the arithmetic roots, then audit each root's descendants.
    pending = [(top_match.group(1).lower(), ())]
    while pending:
        entity, ancestors = pending.pop()
        if entity in ancestors:
            errors.append("Cyclic HDL instantiation: " + entity)
            continue
        match = COMPUTE_BODY.match(entity)
        if match:
            phase = (match.group(1) or {"init": "prologue", "finish": "epilogue"}[
                match.group(2).lower()
            ]).lower()
            roots.setdefault(phase, set()).add(entity)
            physical_counts[phase] = physical_counts.get(phase, 0) + 1
            continue
        info = entities.get(entity)
        if info is None:
            errors.append("Missing emitted entity: " + entity)
            continue
        pending.extend((child, ancestors + (entity,)) for child in info["children"])
    # One physical instance per phase when the MCPs are shared, else one per
    # direction. Shared and private kernels can have the same name, so the
    # requested architecture decides which count is right.
    expected = 1 if shared else len(directions)
    reports = {}
    for phase in ("prologue", "epilogue"):
        if phase not in roots:
            errors.append(f"Missing reachable MCP arithmetic: {phase}")
            continue
        if len(roots[phase]) != 1:
            errors.append(
                f"{phase}: expected one MCP arithmetic kernel, got "
                + ", ".join(sorted(roots[phase]))
            )
        count = physical_counts[phase]
        if count != expected:
            errors.append(
                f"{phase}: expected {expected} physical MCP arithmetic "
                f"instance(s) ({'shared' if shared else 'one per direction'}), "
                f"got {count}"
            )
        for root in sorted(roots[phase]):
            label = phase if len(roots[phase]) == 1 else f"{phase}/{root}"
            descendants = list(walk(root))
            bad = [
                entity
                for entity, info in descendants
                if info["latency"] not in (None, 0) or info["clocked"]
            ]
            reports[label] = {
                "entity": root,
                "file": entities[root]["file"],
                "physical_instances": count,
                "entities_checked": len(descendants),
                "registered_entities": bad,
            }
            for entity in bad:
                errors.append(f"{label}: registered arithmetic inside MCP: {entity}")
    return {
        "out_dir": str(out_dir),
        "top_vhdl": str(top_vhdl),
        "scope": "emitted MCP arithmetic only; not timing/constraint sign-off",
        "shared": shared,
        "mcps": reports,
        "passed": not errors,
        "errors": errors,
    }


def auth_fifo_sizing_errors(config):
    """Check new automatic budgets; historical/explicit records stay readable."""
    buffer = config.get("buffering", {}).get("decrypt/auth_fifo", {})
    sizing = buffer.get("sizing", {})
    if sizing.get("method") != "chacha-credit-bound-v1":
        return []
    label = "decrypt/auth_fifo: "
    keys = (
        "chacha20_core_latency",
        "chacha20_max_in_flight_blocks",
        "chacha20_block_beats",
        "prologue_mcp_latency",
        "max_aad_beats",
    )
    values = [sizing.get(key) for key in keys]
    if any(type(value) is not int or value < 0 for value in values):
        return [label + "automatic sizing inputs are missing/invalid"]
    core, credits, ratio, init_latency, aad = values
    minimum_compute_latency = 0 if config.get("comb") else 1
    if credits != core + 5 or ratio < 1 or init_latency < minimum_compute_latency:
        return [label + "automatic sizing inputs disagree with stream contracts"]
    shared = sizing.get("shared_mcps")
    if type(shared) is not bool:
        return [label + "automatic sizing lacks MCP sharing selection"]
    expected = {
        "pipeline_credits": ratio * credits,
        "widening_storage": ratio + 1,
        "fork_copy_lead": 1,
        "fifo_startup": 2,
        "framing_idle": 1,
        "prologue_service": (1 + int(shared)) * (init_latency + 1),
        "mac_transitions": 2,
        "aad_framing": aad,
    }
    required = sum(expected.values())
    depth = 1 << (max(2, required) - 1).bit_length()
    errors = []
    if sizing.get("terms_beats") != expected or sizing.get("required_beats") != required:
        errors.append(label + "automatic sizing budget disagrees with resolved inputs")
    if sizing.get("memory_depth_beats") != depth or buffer.get("memory_depth_beats") != depth:
        errors.append(label + "automatic sizing disagrees with allocated memory")
    mac = config.get("poly1305", {}).get("directions", {}).get("decrypt", {})
    if mac.get("prologue_mcp_latency") != init_latency or bool(mac.get("shared_mcps")) != shared:
        errors.append(label + "automatic sizing disagrees with selected MAC metadata")
    return errors


def overlap_fifo_sizing_errors(config):
    """Validate the latency ledger and allocated fork storage."""
    errors = []
    buffers = config.get("buffering", {})
    for name, buffer in buffers.items():
        sizing = buffer.get("sizing", {})
        if sizing.get("method") != "poly1305-overlap-fork-v2":
            continue
        direction = name.split("/")[0]
        mac = config.get("poly1305", {}).get("directions", {}).get(direction, {})
        label = name + ": "
        try:
            shared = sizing["shared_mcps"]
            if type(shared) is not bool or shared != mac["shared_mcps"]:
                raise ValueError("sharing selection")
            for key in (
                "prologue_mcp_latency",
                "epilogue_mcp_latency",
                "body_latency",
                "prologue_handoff_cycles",
                "body_commit_cycles",
                "epilogue_handoff_cycles",
            ):
                expected_value = (
                    mac.get("total_body_latency", mac.get(key))
                    if key == "body_latency"
                    else mac[key]
                )
                minimum = (
                    0
                    if config.get("comb")
                    and key in ("prologue_mcp_latency", "epilogue_mcp_latency")
                    else 1
                )
                if (
                    type(sizing[key]) is not int
                    or sizing[key] < minimum
                    or sizing[key] != expected_value
                ):
                    raise ValueError(key)
            core = sizing["chacha20_core_latency"]
            credits = sizing["chacha20_max_in_flight_blocks"]
            ratio = sizing["chacha20_block_beats"]
            beat_bytes = config.get("bus_bytes", 16)
            if (
                credits != core + 5
                or ratio != 64 // beat_bytes
                or sizing["max_aad_beats"] != (32 + beat_bytes - 1) // beat_bytes
            ):
                raise ValueError("ChaCha/framing storage")
            if (
                sizing["preceding_peer_requests"] != int(shared)
                or sizing["max_packed_tag_beats"] != 2
            ):
                raise ValueError("peer/tag bound")
            setup = (1 + int(shared)) * (sizing["prologue_mcp_latency"] + 1) + sizing[
                "prologue_handoff_cycles"
            ]
            completion = (
                sizing["body_latency"]
                + sizing["body_commit_cycles"]
                + (1 + int(shared)) * (sizing["epilogue_mcp_latency"] + 1)
                + sizing["epilogue_handoff_cycles"]
                + sizing["max_packed_tag_beats"]
            )
            terms = {
                "setup_service_and_handoffs": setup,
                "aad_framing": sizing["max_aad_beats"],
                "framing_idle": 1,
                "length_framing": 1,
                "fifo_startup": 2,
                "fork_copy_lead": 1,
            }
            if name == "encrypt/auth_fifo":
                terms["narrowing_storage"] = ratio + 1
            elif name == "encrypt/append_fifo":
                capacity = buffers["encrypt/auth_fifo"]["capacity_beats"]
                if sizing["authentication_capacity_beats"] != capacity:
                    raise ValueError("authentication queue capacity")
                terms["authentication_queue"] = capacity
                terms["completion_service_and_handoffs"] = completion
            elif name == "decrypt/auth_fifo":
                terms["pipeline_credits"] = ratio * credits
                terms["widening_storage"] = ratio + 1
                terms["completion_service_and_handoffs"] = completion
            else:
                raise ValueError("unknown buffer")
            if beat_bytes == 32:
                terms["formatter_storage"] = 2
            required = sum(terms.values())
            depth = 1 << (max(2, required) - 1).bit_length()
            if (
                sizing["buffer"] != name
                or sizing["terms_beats"] != terms
                or sizing["required_beats"] != required
            ):
                raise ValueError("budget terms")
            if sizing["memory_depth_beats"] != depth or buffer["memory_depth_beats"] != depth:
                raise ValueError("allocated depth")
        except (KeyError, TypeError, ValueError) as exc:
            errors.append(label + "overlap sizing metadata disagree: " + str(exc))
    return errors


def verify_fifo_sizing_errors(config):
    """Reject stale credit, packet-limit, handoff or allocation metadata."""
    buffer = config.get("buffering", {}).get("decrypt/verify_fifo", {})
    sizing = buffer.get("sizing", {})
    if sizing.get("method") != "plaintext-verdict-credit-bound-v1":
        return []  # Historical records and explicit sizing experiments.
    label = "decrypt/verify_fifo: "
    try:
        packet_bytes = sizing["max_plaintext_bytes"]
        beat_bytes = sizing["axis_beat_bytes"]
        if (
            type(packet_bytes) is not int
            or packet_bytes < 1
            or packet_bytes != config["max_packet_bytes"]
        ):
            raise ValueError("supported plaintext limit")
        if beat_bytes != config.get("bus_bytes", BUS_BYTES) or sizing["verify_handoff_cycles"] != 4:
            raise ValueError("converter/verdict handoffs")
        terms = dict(sizing["terms_beats"])
        expected_extra = {
            "held_maximum_packet": (packet_bytes + beat_bytes - 1) // beat_bytes,
            "narrowing_storage": sizing["chacha20_block_beats"] + 1,
            "verification_handoffs": sizing["verify_handoff_cycles"],
            "release_handoff": 1,
        }
        for key, value in expected_extra.items():
            if terms.pop(key) != value:
                raise ValueError(key)
        # Revalidate the inherited admission/service bound against the actual
        # selected MAC, independently of the verification FIFO's allocation.
        inherited = copy.deepcopy(sizing)
        method = inherited["authentication_sizing_method"]
        if method not in ("chacha-credit-bound-v1", "poly1305-overlap-fork-v2"):
            raise ValueError("authentication sizing method")
        inherited.update(
            method=method,
            buffer="decrypt/auth_fifo",
            terms_beats=terms,
            required_beats=sum(terms.values()),
            memory_depth_beats=1 << (max(2, sum(terms.values())) - 1).bit_length(),
        )
        derived_config = copy.deepcopy(config)
        derived_config["buffering"] = {
            "decrypt/auth_fifo": {
                "sizing": inherited,
                "memory_depth_beats": inherited["memory_depth_beats"],
            }
        }
        errors = auth_fifo_sizing_errors(derived_config) + overlap_fifo_sizing_errors(
            derived_config
        )
        if errors:
            raise ValueError("; ".join(errors))
        required = sum(sizing["terms_beats"].values())
        depth = 1 << (max(2, required) - 1).bit_length()
        if sizing["buffer"] != "decrypt/verify_fifo" or sizing["required_beats"] != required:
            raise ValueError("required budget")
        if sizing["memory_depth_beats"] != depth or buffer["memory_depth_beats"] != depth:
            raise ValueError("allocated depth")
        return []
    except (KeyError, TypeError, ValueError) as exc:
        return [label + "verification sizing metadata disagree: " + str(exc)]


def measurement_errors(results):
    """Acceptance checks; failed runs still retain all diagnostic artifacts."""
    config = results.get("config", {})
    errors = _profile_errors(results)
    errors.extend(auth_fifo_sizing_errors(config))
    errors.extend(overlap_fifo_sizing_errors(config))
    errors.extend(verify_fifo_sizing_errors(config))
    errors.extend(throughput_parity_errors(results))
    errors.extend(_run_errors(results))
    for phase in results.get("phases", []):
        errors.extend(_phase_errors(phase, config))
    errors.extend(_poly1305_errors(results))
    for scope, audit in results.get("mcp_hdl_audits", {}).items():
        if not audit.get("passed"):
            errors.append(scope + ": emitted MCP arithmetic audit failed")
    return errors


def _profile_errors(results):
    """Requested, simulated and emitted build selections must agree."""
    errors = []
    config = results.get("config", {})
    width = recorded_data_bitwidth(config)
    rate = config.get("poly1305_blocks_per_cycle", width // 128)
    if (
        width not in DATA_BITWIDTHS
        or width != 128 * rate
        or config.get("bus_bytes", 16) * 8 != width
    ):
        errors.append("Packet width disagrees with Poly1305 block rate")
    requested_width = config.get("requested_data_bitwidth")
    if requested_width is not None:
        if requested_width != width:
            errors.append("Performance simulation data bitwidth differs from the request")
        for scope, actual in results.get("build_block_rates", {}).items():
            if scope == "perf" and config.get("comb"):
                continue
            if actual is None or actual * 128 != requested_width:
                errors.append(
                    scope + ": emitted data bitwidth differs from the request or is unknown"
                )
    requested_rate = config.get("requested_poly1305_blocks_per_cycle")
    if requested_rate is not None:
        if requested_rate != rate:
            errors.append("Performance simulation block rate differs from the request")
        for scope, actual in results.get("build_block_rates", {}).items():
            if scope == "perf" and config.get("comb"):
                continue  # Native --comb does not emit hardware provenance.
            if actual != requested_rate:
                errors.append(scope + ": emitted block rate differs from the request or is unknown")
    requested_mult = config.get("requested_poly1305_mult_impl")
    if requested_mult is not None:
        if config.get("poly1305_mult_impl") != requested_mult:
            errors.append(
                "Performance simulation multiplier differs from the requested implementation"
            )
        for scope, actual in results.get("build_mult_impls", {}).items():
            if scope == "perf" and config.get("comb"):
                continue  # Native --comb does not emit hardware provenance.
            if actual != requested_mult:
                errors.append(
                    scope + ": emitted multiplier selection differs from the request or is unknown"
                )
    requested_compute = config.get("requested_poly1305_compute_impl")
    if requested_compute is not None and config.get("poly1305_impl") == "pipelined":
        if config.get("poly1305_compute_impl") != requested_compute:
            errors.append(
                "Performance simulation compute differs from the requested implementation"
            )
        if config.get("poly1305", {}).get("compute_impl") != requested_compute:
            errors.append("Resolved Poly1305 compute metadata differs from the request")
        for scope, actual in results.get("build_compute_impls", {}).items():
            if scope == "perf" and config.get("comb"):
                continue  # Native --comb does not emit hardware provenance.
            if actual != requested_compute:
                errors.append(
                    scope + ": emitted compute selection differs from the request or is unknown"
                )
    if config.get("poly1305_impl") == "pipelined" and config.get("poly1305_compute_impl") == "fsm":
        for phase in ("prologue", "epilogue"):
            key = "poly1305_" + phase + "_max_latency"
            requested = config.get("requested_" + key)
            actual = config.get(key)
            if requested is not None and actual != requested:
                errors.append("Emitted " + phase + " cap differs from the request")
            simulated = config.get("simulated_" + key)
            if simulated is not None and simulated != actual:
                errors.append("Performance simulation " + phase + " cap differs from the hardware")
            if actual is not None:
                for direction, meta in config.get("poly1305", {}).get("directions", {}).items():
                    latency = meta.get(phase + "_mcp_latency")
                    if latency is not None and latency > actual:
                        errors.append(direction + ": " + phase + " latency exceeds its cap")
    return errors


def _run_errors(results):
    """Require completed simulation and valid timing/area for hardware runs."""
    errors = []
    returncode = results.get("provenance", {}).get("build_returncode")
    if returncode:
        errors.append(f"Build/simulation exited {returncode}")
    hardware_returncode = results.get("provenance", {}).get("hardware_build", {}).get("returncode")
    if hardware_returncode:
        errors.append(f"Hardware build exited {hardware_returncode}")
    checks = results.get("checks", {})
    if not checks.get("functional_pass", False):
        errors.append(f"Functional checks did not pass: {checks.get('errors')}")
    if not results.get("sim", {}).get("finalized", False):
        errors.append("Performance simulation did not finalize all phases")
    area = results.get("area", {})
    if not results.get("config", {}).get("comb", False):
        if results.get("fmax", {}).get("timing_met") is not True:
            errors.append("Measurement lacks a confirmed timing pass")
        if area.get("available") is not True:
            errors.append("Measurement lacks a synthesis area report")
        requested = results.get("config", {}).get("requested_target_mhz")
        if requested is not None and results.get("fmax", {}).get("target_mhz") != requested:
            errors.append("Measurement timing clock differs from the requested clock")
    hardware_area = results.get("area_hw_build")
    if hardware_area is not None:
        if hardware_area.get("available") is not True:
            errors.append("Requested hardware-top area report is unavailable")
        if results.get("fmax_hw_build", {}).get("timing_met") is not True:
            errors.append("Hardware-top build lacks a confirmed timing pass")
        requested = results.get("config", {}).get("requested_target_mhz")
        if (
            requested is not None
            and results.get("fmax_hw_build", {}).get("target_mhz") != requested
        ):
            errors.append("Hardware-top timing clock differs from the requested clock")
    for scope, report in (("Measurement", area), ("Hardware-top", hardware_area or {})):
        if report.get("fits_device") is False:
            errors.append(f"{scope} synthesis exceeds the selected device's resource capacity")
    return errors


def _phase_errors(phase, config):
    """Check completion windows, buffer capacities and transfer accounting."""
    errors = []
    if config.get("steady_trim_packets", 0):
        for direction in config.get("dirs", []):
            stats = phase.get(direction, {})
            window = steady_packet_window(
                stats.get("packets", []), phase["packet_bytes"], config["steady_trim_packets"]
            )
            if not window["available"] or stats.get("steady_state") != window:
                errors.append(
                    phase["name"] + "/" + direction + ": invalid interior completion window"
                )
    if phase.get("taps_check", {}).get("consistent") is False:
        errors.append(f"Phase {phase.get('name')}: performance taps disagree on cycle count")
    # Metadata must match each buffer's implementation; the occupancy taps
    # are then checked against that capacity by the library's buffer checks
    # (capacity, overflow, conservation, drained when settled, in/out taps).
    buffers = {}
    for name, buffer in config.get("buffering", {}).items():
        depth = buffer.get("memory_depth_beats", 0)
        if depth < 2 or buffer.get("capacity_beats") != stream_fifo_capacity_beats(depth):
            errors.append(name + ": FIFO capacity metadata disagree")
            continue
        buffers[name] = buffer["capacity_beats"]
    for name, stream_slice in config.get("stream_slices", {}).items():
        if (
            stream_slice.get("mode") != "full"
            or stream_slice.get("capacity_beats") != 2
            or stream_slice.get("latency_cycles") != 1
        ):
            errors.append(
                f"Phase {phase.get('name')}/{name}: output slice metadata disagree with its implementation"
            )
        buffers[name] = 2  # a full-mode skid buffer always holds two beats
    for direction, metadata in config.get("poly1305", {}).get("directions", {}).items():
        if metadata.get("packet_architecture") == "overlapped":
            expected = {
                "poly1305.prepared": 1,
                "poly1305.contexts": 2,
                "poly1305.completion": 1,
                "poly1305.tags": 1,
            }
            if metadata.get("packet_buffers") != expected:
                errors.append(direction + ": packet stage capacities disagree")
            buffers.update(
                {direction + "/" + name: capacity for name, capacity in expected.items()}
            )
    errors.extend(
        buffer_tap_errors(
            phase, buffers, taps_required="all" in config.get("taps", []), settled=True
        )
    )
    # New rigs commit source acceptance after convergence. Keep old records
    # readable, but require exact byte accounting from the corrected rig.
    if config.get("source_handshake") == "converged":
        for direction in config.get("dirs", []):
            stats = phase.get(direction, {})
            payload = phase["packet_bytes"] * phase["num_packets"]
            tags = 16 * phase["num_packets"]
            expected_in = payload + (tags if direction == "decrypt" else 0)
            expected_out = payload + (tags if direction == "encrypt" else 0)
            label = f"Phase {phase.get('name')}/{direction}"
            if stats.get("in_payload_bytes") != expected_in:
                errors.append(label + ": input bytes differ from the planned frames")
            if stats.get("out_payload_bytes") != expected_out:
                errors.append(label + ": output bytes differ from the planned frames")
            tap = phase.get("taps", {}).get(direction + "/chacha20.axis_in")
            if tap and tap.get("bytes") != payload:
                errors.append(
                    label + ": source byte accounting disagrees with converged DUT acceptance"
                )
    for direction, life in phase.get("poly1305_lifecycle", {}).items():
        label = f"Phase {phase.get('name')}/{direction}"
        if life.get("body_launches") != life.get("body_retirements"):
            errors.append(label + ": body launches/retirements differ")
        for phase_name in ("prologue", "epilogue"):
            launches = life.get(phase_name + "_launches")
            if launches is not None and launches != life.get("completed_packets"):
                errors.append(label + ": " + phase_name + " launches differ from completed tags")
    return errors


def _poly1305_errors(results):
    """Validate resolved MAC latencies and private/shared pipeline accounting."""
    errors = []
    config = results.get("config", {})
    width = recorded_data_bitwidth(config)
    rate = config.get("poly1305_blocks_per_cycle", width // 128)
    mac = config.get("poly1305") or {}
    if mac.get("implementation") == "pipelined":
        if not mac.get("directions"):
            errors.append("Pipelined measurement lacks resolved per-direction MAC metadata")
        errors.extend(direction_latency_errors(mac.get("directions", {})))
        for direction, meta in mac.get("directions", {}).items():
            depth = meta.get("body_core_latency")
            latency = meta.get("body_latency")
            if depth is None or latency != depth + 2 or meta.get("accumulator_count") != latency:
                errors.append(direction + ": body D=P+2 and L=D metadata disagree")
            if meta.get("body_ii") != 1:
                errors.append(direction + ": pipelined body II is not 1")
            if meta.get("blocks_per_cycle", 1) != rate:
                errors.append(direction + ": resolved body block rate differs from the profile")
            if meta.get("axis_beat_bytes", 16 if rate == 1 else None) != 16 * rate:
                errors.append(direction + ": resolved packet width differs from the profile")
            if rate == 2:
                coefficient = meta.get("coefficient_latency")
                coefficient_core = meta.get("coefficient_core_latency")
                if (
                    type(coefficient) is not int
                    or type(coefficient_core) is not int
                    or coefficient_core < 0
                    or coefficient != coefficient_core + 2
                    or meta.get("total_body_latency") != coefficient + latency
                ):
                    errors.append(direction + ": coefficient/feedback latency metadata disagree")
                for phase in results.get("phases", []):
                    life = phase.get("poly1305_lifecycle", {}).get(direction, {})
                    counts = [
                        life.get(k)
                        for k in (
                            "coefficient_launches",
                            "coefficient_retirements",
                            "body_launches",
                            "body_retirements",
                        )
                    ]
                    if None in counts or len(set(counts)) != 1:
                        errors.append(direction + ": paired arithmetic conservation failed")
                    nblocks = life.get("authentication_blocks")
                    tails = life.get("unmatched_tails")
                    expected_blocks = phase.get("model", {}).get(direction, {}).get(
                        "poly1305_blocks", 0
                    ) * life.get("completed_packets", 0)
                    if (
                        nblocks is None
                        or tails is None
                        or nblocks != 2 * (counts[0] or 0) + (tails or 0)
                        or nblocks != expected_blocks
                    ):
                        errors.append(
                            direction + ": authentication block/pair/tail conservation failed"
                        )
        sharing = config.get("sharing") or {}
        if sharing.get("poly1305"):
            if config.get("source_handshake") != "converged":
                errors.append("Shared MCP measurement lacks converged source handshakes")
            if config.get("decrypt_verification_retained") is not True:
                errors.append("Shared MCP measurement does not retain decrypt verification in HDL")
            unit = mac.get("shared_mcps") or {}
            counts = [m.get("accumulator_count") for m in mac.get("directions", {}).values()]
            capacity = unit.get("capacity_lanes")
            # Historical records may carry a fixed capacity above the lanes; unused slots are zero.
            fixed = config.get("requested_poly1305_compute_capacity")
            if (
                not counts
                or None in counts
                or type(capacity) is not int
                or capacity < max(counts)
                or capacity != (fixed if fixed is not None else max(counts))
            ):
                errors.append("Shared MCP capacity does not match the maximum local lane count")
            for direction, meta in mac.get("directions", {}).items():
                if meta.get("shared_mcps") is not True:
                    errors.append(direction + ": expected shared MCP metadata")
                for phase in ("prologue", "epilogue"):
                    key = phase + "_mcp_latency"
                    if unit.get(key) is None or meta.get(key) != unit[key]:
                        errors.append(
                            direction + ": shared " + phase + " latency metadata disagree"
                        )
            for phase in results.get("phases", []):
                completed = sum(
                    life.get("completed_packets", 0)
                    for life in phase.get("poly1305_lifecycle", {}).values()
                )
                for name, unit_counts in phase.get("poly1305_shared_services", {}).items():
                    if (
                        unit_counts.get("launches") != completed
                        or unit_counts.get("responses") != completed
                    ):
                        errors.append(
                            f"Phase {phase.get('name')}: shared {name} request/response accounting differs from completed tags"
                        )
    return errors


# The MAC latencies the compiler decides per direction: the AUTO_PIPELINE body and
# coefficient depths and the AUTO_FSM initialization/finalization latencies
DIRECTION_LATENCY_FIELDS = (
    "body_core_latency",
    "coefficient_core_latency",
    "prologue_mcp_latency",
    "epilogue_mcp_latency",
)


def direction_latency_errors(directions):
    """Require identical AUTO latencies for encrypt/decrypt's identical MAC arithmetic."""
    if not {"encrypt", "decrypt"} <= set(directions):
        return []
    encrypt, decrypt = directions["encrypt"], directions["decrypt"]
    differ = [
        f"{field} {encrypt.get(field)} vs {decrypt.get(field)}"
        for field in DIRECTION_LATENCY_FIELDS
        if encrypt.get(field) != decrypt.get(field)
    ]
    if not differ:
        return []
    return ["Encrypt and decrypt MAC latencies differ (encrypt vs decrypt): " + "; ".join(differ)]


def compare_block_rates(before, after):
    """Matched one-/two-block QoR: gate 1920-byte payload throughput in both directions.

    Short-packet changes are reported without applying the large-packet threshold.
    """
    errors = []
    for label, record in (("baseline", before), ("paired", after)):
        errors.extend(label + ": " + error for error in measurement_errors(record))
        if record.get("config", {}).get("comb"):
            errors.append(label + ": requires synthesized timing and area")
    old_config, new_config = before.get("config", {}), after.get("config", {})
    if recorded_data_bitwidth(old_config) != 128 or recorded_data_bitwidth(new_config) != 256:
        errors.append("Comparison requires 128-bit baseline and 256-bit result")
    for key in (
        "target_mhz",
        "dirs",
        "seed",
        "sizes",
        "packets_per_size",
        "peak_bytes",
        "peak_packets",
        "sharing",
        "poly1305_mult_impl",
        "poly1305_compute_impl",
        "native_arithmetic",
        "native_soft_ops",
    ):
        if old_config.get(key) != new_config.get(key):
            errors.append("Comparison workload/config differs: " + key)
    compiler = before.get("provenance", {}).get("pipelinec_git")
    if not compiler or compiler != after.get("provenance", {}).get("pipelinec_git"):
        errors.append("Comparison requires the same recorded compiler revision")
    baseline = {(p["packet_bytes"], p["num_packets"]): p for p in before.get("phases", [])}
    comparisons = []
    for phase in after.get("phases", []):
        key = (phase["packet_bytes"], phase["num_packets"])
        old = baseline.get(key)
        if old is None:
            errors.append("Missing matched baseline phase: " + str(key))
            continue
        gains = {}
        for direction in ("encrypt", "decrypt"):
            old_rate = old.get(direction, {}).get("sustained_bytes_per_cycle", 0)
            new_rate = phase.get(direction, {}).get("sustained_bytes_per_cycle", 0)
            if not old_rate or not new_rate:
                errors.append(str(key) + ": missing concurrent " + direction + " payload throughput")
                continue
            gains[direction] = new_rate / old_rate
            if key[0] == 1920 and new_rate < old_rate:
                errors.append("1920-byte " + direction + " payload throughput regressed")
        comparisons.append(
            {"packet_bytes": key[0], "num_packets": key[1], "after_to_before_goodput": gains}
        )
    if not any(p["packet_bytes"] == 1920 for p in comparisons):
        errors.append("Comparison lacks a matched 1920-byte phase")
    return {
        "passed": not errors,
        "errors": errors,
        "phases": comparisons,
        "criteria": {"minimum_1920_encrypt_gain": 1.0, "minimum_1920_decrypt_gain": 1.0},
    }


def evidence_scopes(results):
    """(archive prefix, area key, timing key) of each synthesized build a record
    measured: its own build ("hardware" for a real top, "perf" for a historical
    synthesized perf testbench) and a historical separate hardware-top build."""
    scopes = []
    if "area" in results:
        own = "hardware" if results["area"].get("scope") == "hardware_top" else "perf"
        scopes.append((own, "area", "fmax"))
    if "area_hw_build" in results:
        scopes.append(("hardware", "area_hw_build", "fmax_hw_build"))
    return scopes


def check_record(measurement_dir):
    """Read-only acceptance/integrity check, also usable after caches are deleted.

    Old records need no new metadata or manifest. When an archive manifest is
    present, every listed byte is verified and the retained signatures and XDC
    are checked together. Historical workspace paths are never dereferenced.
    """
    directory = Path(measurement_dir)
    results = json.loads((directory / "results.json").read_text())
    errors = measurement_errors(results)
    manifest_path = directory / "artifact-manifest.json"
    if manifest_path.exists():
        manifest = json.loads(manifest_path.read_text())
        artifacts = manifest.get("artifacts", {})
        if not artifacts:
            errors.append("Archive inventory is empty")
        for name, expected in artifacts.items():
            if Path(name).name != name:
                errors.append("Unsafe archive filename: " + name)
                continue
            path = directory / name
            if not path.is_file():
                errors.append("Missing archive artifact: " + name)
            elif (
                path.stat().st_size != expected["bytes"]
                or hashlib.sha256(path.read_bytes()).hexdigest() != expected["sha256"]
            ):
                errors.append("Archive bytes/checksum mismatch: " + name)
        for prefix, area_key, timing_key in evidence_scopes(results):
            try:
                inputs = json.loads((directory / (prefix + "-inputs.json")).read_text())
                history = json.loads((directory / (prefix + "-sweep-history.json")).read_text())
                retained = history.get("retained_observation") or {}
                if not history.get("build_complete") or retained.get(
                    "input_signature"
                ) != inputs.get("signature"):
                    errors.append(prefix + ": incomplete/mismatched retained sweep observation")
                original_log = results[area_key].get("log")
                if (
                    not original_log
                    or Path(original_log).name != Path(retained.get("log_path", "")).name
                ):
                    errors.append(prefix + ": area and retained timing observation differ")
                entries = [
                    entry
                    for entry in inputs.get("inputs", [])
                    if entry.get("kind") == "xdc" and entry.get("name") == "clocks.xdc"
                ]
                constraints = directory / (prefix + "-clocks.xdc")
                if (
                    len(entries) != 1
                    or hashlib.sha256(constraints.read_bytes()).hexdigest() != entries[0]["sha256"]
                ):
                    errors.append(prefix + ": constraints differ from retained input manifest")
                log = directory / (prefix + "-vivado.log")
                text = log.read_text(errors="replace")
                if re.search(r"^ERROR:", text, re.MULTILINE) or "Exiting Vivado at" not in text:
                    errors.append(prefix + ": retained Vivado run has errors or is unfinished")
                area = parse_log(log)
                for field in _AREA_FIELDS:
                    if field in results[area_key] and results[area_key][field] != area.get(field):
                        errors.append(prefix + ": saved area differs from retained log: " + field)
                for main, record in history.get("mains", {}).items():
                    final = final_from_history(record.get("final") or {})
                    saved = results[timing_key].get("per_main", {}).get(main, {})
                    if not final.get("met") or cross_check_final(final, saved):
                        errors.append(
                            prefix + ": saved timing differs from confirmed final: " + main
                        )
            except (OSError, KeyError, ValueError) as exc:
                errors.append(prefix + ": incomplete archived evidence: " + str(exc))
    return {
        "measurement_dir": str(directory),
        "passed": not errors,
        "errors": errors,
        "archive_verified": manifest_path.exists(),
    }


def save_evidence(measurement_dir, results):
    """Archive the retained build evidence and verify its checksums and constraints."""
    directory = Path(measurement_dir)
    if measurement_errors(results):
        raise ValueError("Only accepted measurements can be packaged")
    sources = {}
    for prefix, area_key, timing_key in evidence_scopes(results):
        area, timing = results[area_key], results[timing_key]
        log = Path(area["log"])
        input_path = log.with_suffix(".inputs.json")
        inputs = json.loads(input_path.read_text())
        entries = [
            entry
            for entry in inputs.get("inputs", [])
            if entry.get("kind") == "xdc" and entry.get("name") == "clocks.xdc"
        ]
        constraints = log.parent.parent / "clocks.xdc"
        if (
            len(entries) != 1
            or hashlib.sha256(constraints.read_bytes()).hexdigest() != entries[0]["sha256"]
        ):
            raise ValueError(prefix + ": current constraints no longer match retained observation")
        sources.update(
            {
                prefix + "-vivado.log": log,
                prefix + "-inputs.json": input_path,
                prefix + "-sweep-history.json": Path(timing["source"]["sweep_history"]),
                prefix + "-clocks.xdc": constraints,
            }
        )
        # A dirty checkout's revision alone cannot identify the design bytes.
        # Preserve the compiler's frozen design/include hashes when available;
        # historical outputs legitimately predate this manifest.
        provenance = log.parent.parent / "source_provenance.json"
        if provenance.is_file():
            sources[prefix + "-source-provenance.json"] = provenance
    for name, source in sources.items():
        destination = directory / name
        if source.resolve() != destination.resolve():
            shutil.copyfile(source, destination)
    artifacts = {}
    for path in sorted(directory.iterdir()):
        if path.is_file() and path.name != "artifact-manifest.json":
            artifacts[path.name] = {
                "original_path": str(sources.get(path.name, path)),
                "bytes": path.stat().st_size,
                "sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
            }
    manifest = {
        "schema_version": 1,
        "archived_utc": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "artifacts": artifacts,
        "note": "Packaging retained evidence, not a new synthesis or simulation.",
    }
    (directory / "artifact-manifest.json").write_text(json.dumps(manifest, indent=2) + "\n")
    report = check_record(directory)
    if not report["passed"]:
        raise ValueError("; ".join(report["errors"]))


_SELFTEST_UTILIZATION = """# report_utilization
Utilization Design Information
| Tool Version : Vivado v2019.2
| Design : fixture
| Device : 7a200tffg1156-2
| Design State : Synthesized
1. Slice Logic
| Site Type | Used | Fixed | Available | Util% |
| Slice LUTs* | 100 | 0 | 134600 | 0.07 |
| LUT as Logic | 90 | 0 | 134600 | 0.07 |
| LUT as Memory | 10 | 0 | 46200 | 0.02 |
| Slice Registers | 200 | 0 | 269200 | 0.07 |
2. Memory
| Site Type | Used | Fixed | Available | Util% |
| Block RAM Tile | 1.5 | 0 | 365 | 0.41 |
3. DSP
| Site Type | Used | Fixed | Available | Util% |
| DSPs | 2 | 0 | 740 | 0.27 |
Exiting Vivado at fixture completion
"""


def _area_selftest():
    """Check report selection and numeric parsing using temporary fixtures."""
    with tempfile.TemporaryDirectory(prefix="wg-area-") as directory:
        path = Path(directory) / "vivado.log"
        path.write_text(_SELFTEST_UTILIZATION)
        expected = dict(
            lut_total=100,
            lut_logic=90,
            lut_memory=10,
            ff_total=200,
            dsp48=2,
            bram_tiles=1.5,
            part="7a200tffg1156-2",
        )
        parsed = parse_log(path)
        for key, want in expected.items():
            if parsed.get(key) != want:
                raise ValueError(f"Area parser: {key} expected {want!r}, got {parsed.get(key)!r}")
        # Prefer routed utilization even when a synthesis report appears last.
        routed = _SELFTEST_UTILIZATION.replace("Synthesized", "Routed").replace(
            "Slice LUTs* | 100", "Slice LUTs* | 110"
        )
        path.write_text(routed + _SELFTEST_UTILIZATION)
        parsed = parse_log(path)
        if parsed["lut_total"] != 110 or parsed["blocks_found"] != 2:
            raise ValueError("Area parser did not prefer the routed report")
    print("area selftest: PASS (numeric fields and routed-report selection)")
    return 0


def _selftest_record():
    """Synthetic single-phase record for acceptance, reporting and archive checks.

    These arbitrary numbers are test data, never published QoR evidence.
    """
    meta = dict(
        body_core_latency=0,
        body_latency=2,
        accumulator_count=2,
        body_ii=1,
        prologue_mcp_latency=1,
        epilogue_mcp_latency=2,
        prologue_response_cycles=2,
        epilogue_response_cycles=3,
    )
    phase = dict(name="b2b-16", packet_bytes=16, num_packets=4, poly1305_lifecycle={})
    for direction in DIRECTIONS:
        phase[direction] = dict(
            in_payload_bytes=128 if direction == "decrypt" else 64,
            out_payload_bytes=128 if direction == "encrypt" else 64,
            bytes_per_cycle=1,
            sustained_bytes_per_cycle=1,
            packet_period_cycles=16,
            packets=[dict(idx=i, last_out=100 + i * 16) for i in range(4)],
        )
        phase["poly1305_lifecycle"][direction] = dict(
            body_launches=8,
            body_retirements=8,
            prologue_launches=4,
            epilogue_launches=4,
            completed_packets=4,
        )
    final = dict(met=True, achieved_mhz=31)
    timing = dict(timing_met=True, target_mhz=30, design_mhz=31, per_main={"fixture": final})
    area = dict(
        available=True,
        fits_device=True,
        scope="perf_tb_top",
        log="vivado_fixture.log",
        lut_total=100,
        ff_total=200,
        dsp48=2,
        bram_tiles=1.5,
    )
    return dict(
        label="synthetic",
        generated_utc="2000-01-01T00:00:00+00:00",
        config=dict(
            design="shared",
            target_mhz=30,
            requested_target_mhz=30,
            bus_bytes=16,
            dirs=list(DIRECTIONS),
            comb=False,
            poly1305_mult_impl="inferred",
            poly1305_compute_impl="mcp",
            poly1305=dict(
                implementation="pipelined",
                directions={d: copy.deepcopy(meta) for d in DIRECTIONS},
            ),
        ),
        provenance=dict(build_returncode=0, wireguard_fpga_git="fixture", pipelinec_git="fixture"),
        checks=dict(functional_pass=True),
        sim=dict(finalized=True),
        validation=dict(passed=True),
        phases=[phase],
        fmax=timing,
        area=area,
        fmax_hw_build=copy.deepcopy(timing),
        area_hw_build=dict(area, scope="hardware_top"),
    )


def _write_selftest_archive(directory, record):
    """Create a tiny consistent archive; all files disappear after --selftest."""

    def write_json(name, value):
        (directory / name).write_text(json.dumps(value))

    write_json("results.json", record)
    write_json("perf_raw.json", record)
    (directory / "pypelinec.log").write_text("synthetic native replay fixture\n")
    for prefix, _, _ in evidence_scopes(record):
        constraints = b"create_clock -period 33.333 [get_ports clk]\n"
        (directory / (prefix + "-clocks.xdc")).write_bytes(constraints)
        write_json(
            prefix + "-inputs.json",
            dict(
                signature="fixture",
                inputs=[
                    dict(
                        kind="xdc",
                        name="clocks.xdc",
                        sha256=hashlib.sha256(constraints).hexdigest(),
                    )
                ],
            ),
        )
        write_json(
            prefix + "-sweep-history.json",
            dict(
                build_complete=True,
                retained_observation=dict(input_signature="fixture", log_path="vivado_fixture.log"),
                mains={"fixture": {"final": dict(met=True, achieved_mhz=31)}},
            ),
        )
        (directory / (prefix + "-vivado.log")).write_text(_SELFTEST_UTILIZATION)
    inventory = {
        path.name: dict(
            bytes=path.stat().st_size, sha256=hashlib.sha256(path.read_bytes()).hexdigest()
        )
        for path in directory.iterdir()
    }
    write_json("artifact-manifest.json", dict(artifacts=inventory))


def saved_bottleneck_report(path):
    """Analyze a saved record in memory; leave its files and measurements intact."""
    with open(path) as source:
        results = json.load(source)
    if not isinstance(results, dict):
        raise ValueError("Saved results must be a JSON object")
    phases = results.get("phases")
    config = results.get("config", {})
    if not isinstance(phases, list) or not all(isinstance(p, dict) for p in phases):
        raise ValueError("Saved results must contain a list of phase objects")
    if not isinstance(config, dict):
        raise ValueError("Saved results config must be an object")
    mac_config = config.get("poly1305")
    if mac_config is not None and not isinstance(mac_config, dict):
        raise ValueError("Saved results Poly1305 metadata must be an object")
    try:
        analyze(phases, aad_len=config.get("aad_len", 0), mac_config=mac_config)
        return markdown_blocks(phases)
    except (TypeError, AttributeError, ZeroDivisionError) as exc:
        raise ValueError("Malformed saved performance data: " + str(exc)) from exc


def _report_selftest(directory):
    """Exercise report dispatch, historical inputs, and arithmetic-name audits."""
    fixture = directory / "report-results.json"
    for record in ({"phases": []}, {"phases": [{"name": "b2b-16", "packet_bytes": 16, "num_packets": 4}]}):
        fixture.write_text(json.dumps(record))
        before = fixture.read_bytes()
        report = saved_bottleneck_report(fixture)
        if not isinstance(report, str) or fixture.read_bytes() != before:
            raise ValueError("Saved-result reporting changed the record")
    for contents in ("{", "[]", '{}', '{"phases": [1]}',
                     '{"phases": [], "config": []}',
                     '{"phases": [], "config": {"poly1305": 1}}'):
        fixture.write_text(contents)
        try:
            saved_bottleneck_report(fixture)
        except ValueError:
            pass
        else:
            raise ValueError("Malformed saved results accepted: " + contents)
    missing = directory / "missing-results.json"
    try:
        saved_bottleneck_report(missing)
    except OSError:
        pass
    else:
        raise ValueError("Missing saved results accepted")
    factories = (
        "mac_pipelined_make_pipelined_compute_lanes",
        "paired_compute_make_paired_compute_capacity",
        "mcp_shared_make_shared_compute_capacity",
    )
    for factory in factories:
        for phase in ("prologue", "epilogue"):
            if not COMPUTE_BODY.match(f"{phase}_from_poly1305_{factory}_7_0clk_hash"):
                raise ValueError("Historical arithmetic name no longer recognized")
    for factory in ("make_pipelined_compute_lanes", "make_paired_compute_capacity",
                    "make_shared_compute_capacity"):
        for phase in ("init", "finish"):
            if not COMPUTE_BODY.match(f"{phase}_from_poly1305_compute_{factory}_7_0clk_hash"):
                raise ValueError("Moved arithmetic name not recognized")
    for name in ("init_from_poly1305_compute_unrelated_7_0clk_hash",
                 "body_from_poly1305_compute_make_paired_compute_capacity_7_0clk_hash",
                 "init_from_poly1305_compute_make_paired_compute_capacity_bad_0clk_hash"):
        if COMPUTE_BODY.match(name):
            raise ValueError("Arithmetic-name audit accepted an unrelated entity")
    # Audit synthetic HDL trees without running elaboration or generating HDL.
    hdl = directory / "arithmetic-audit"
    hdl.mkdir()
    for names in (
        ("prologue_from_poly1305_paired_compute_make_paired_compute_capacity_7_0clk_hash",
         "epilogue_from_poly1305_paired_compute_make_paired_compute_capacity_7_0clk_hash"),
        ("init_from_poly1305_compute_make_paired_compute_capacity_7_0clk_hash",
         "finish_from_poly1305_compute_make_paired_compute_capacity_7_0clk_hash"),
    ):
        for name in names:
            (hdl / (name + ".vhd")).write_text(
                f"entity {name} is end; architecture rtl of {name} is begin end;"
            )
        top = hdl / "top.vhd"
        children = "".join(f"u{i}: entity work.{name};" for i, name in enumerate(names))
        top.write_text("entity top is end; architecture rtl of top is begin " + children + " end;")
        report = audit_poly1305_hdl(hdl, top_vhdl=top, shared=True)
        if not report["passed"] or set(report["mcps"]) != {"prologue", "epilogue"}:
            raise ValueError("Arithmetic audit lost old/new phase recognition")
        top.write_text("entity top is end; architecture rtl of top is begin "
                       + children + f"duplicate: entity work.{names[0]}; end;")
        report = audit_poly1305_hdl(hdl, top_vhdl=top, shared=True)
        if report["passed"] or not any("physical MCP" in e for e in report["errors"]):
            raise ValueError("Arithmetic audit missed duplicate physical compute")
        top.write_text("entity top is end; architecture rtl of top is begin " + children + " end;")
        (hdl / (names[0] + ".vhd")).write_text(
            f"entity {names[0]} is end; architecture rtl of {names[0]} is begin "
            "process(clk) begin if rising_edge(clk) then null; end if; end process; end;"
        )
        if audit_poly1305_hdl(hdl, top_vhdl=top, shared=True)["passed"]:
            raise ValueError("Arithmetic audit accepted registered MCP arithmetic")
    # Exercise the public command, with the normal measurement path unreachable.
    fixture.write_text(json.dumps({"phases": [{"name": "b2b-16", "packet_bytes": 16, "num_packets": 4}]}))
    before = fixture.read_bytes()
    proc = subprocess.run([sys.executable, __file__, "--bottleneck-report", str(fixture)],
                          stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    if proc.returncode or proc.stdout.rstrip() != saved_bottleneck_report(fixture).rstrip():
        raise ValueError("Saved report command failed: " + proc.stderr)
    if fixture.read_bytes() != before:
        raise ValueError("Saved report command modified its input")
    for path in (missing, directory / "malformed-results.json"):
        if path != missing:
            path.write_text("[]")
        proc = subprocess.run([sys.executable, __file__, "--bottleneck-report", str(path)],
                              stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        if proc.returncode != 1 or "ERROR:" not in proc.stderr or "Traceback" in proc.stderr:
            raise ValueError("Invalid report command did not fail cleanly")
    print("saved-report selftest: PASS (read-only dispatch, malformed inputs, arithmetic names)")


# ---------------------------------------------------------------------------
# Functional coverage (--coverage): run the random testbenches, bin what they
# reached, and fail on a lost corner. The goals live in
# src/chacha20poly1305/func_coverage_goals.py; README.md#functional-coverage
# describes the workflow.
# ---------------------------------------------------------------------------
COVERAGE_SCHEMA = 1
# Performance-measurement flags, which --coverage rejects unless left at their defaults.
COVERAGE_REJECTED = (
    "rebuild",
    "reuse_syn",
    "require_parity",
    "steady_trim",
    "update_readme",
    "save_evidence",
    "no_per_module_area",
    "dirs",
    "sizes",
    "packets",
    "peak_bytes",
    "taps",
)
# The run facts measure.py adds to a mode's raw file after simulating it, so that
# file alone is enough to re-judge the mode (--parse-only).
COVERAGE_RUN_KEYS = ("cmd", "returncode", "wall_s", "comb", "pipelinec_git", "wireguard_fpga_git")


def coverage_modes(text):
    """Split --coverage MODES, keeping the order and rejecting unknown names."""
    modes = []
    for mode in (name.strip() for name in text.split(",")):
        if mode and mode not in modes:
            modes.append(mode)
    unknown = [mode for mode in modes if mode not in goals.MODES]
    if unknown or not modes:
        raise ValueError(f"--coverage takes modes from {', '.join(goals.MODES)}; got {text!r}")
    return modes


def coverage_files(meas_dir, mode):
    return (
        os.path.join(meas_dir, f"coverage-{mode}.json"),
        os.path.join(meas_dir, f"coverage-{mode}.log"),
    )


def run_coverage_mode(args, mode, meas_dir):
    """Simulate one mode through build.py --sim --native, which writes its raw facts.

    The run's command, exit code, build kind and revisions are added to that
    file (COVERAGE_RUN_KEYS), so re-judging the mode needs nothing else.
    """
    raw_path, log_path = coverage_files(meas_dir, mode)
    if os.path.exists(raw_path):
        os.remove(raw_path)  # a stale file must not pass for this run's
    cmd = [os.path.join(HERE, "build.py"), "--sim", "--native"] + _profile_flags(args)
    defines = dict(goals.MODES[mode], TB_COVERAGE_JSON=raw_path)
    if args.seed is not None:
        defines["TB_SEED"] = args.seed
    for name, value in defines.items():
        cmd.extend(["-D", f"{name}={value}"])
    if args.comb:
        cmd.append("--comb")
    source = git_describe(os.path.join(HERE, "..", ".."))
    info = dict(_run_build_py(cmd, log_path), comb=bool(args.comb), wireguard_fpga_git=source)
    if os.path.isfile(raw_path):
        with open(raw_path) as f:
            raw = json.load(f)
        raw["run"] = {key: info.get(key) for key in COVERAGE_RUN_KEYS}
        with open(raw_path, "w") as f:
            json.dump(raw, f, indent=1)
    return info


def _kind_totals(bins):
    """{kind: [hit, total]} over {id: [kind, hits]} entries."""
    totals = {"functional": [0, 0], "timing": [0, 0]}
    for kind, hits in bins.values():
        totals[kind][0] += bool(hits)
        totals[kind][1] += 1
    return totals


def judge_coverage_run(raw, mode):
    """Bin one run and compare it with the mode's waivers; the result is the saved record."""
    metadata = raw["metadata"]
    bins = goals.collect(raw)
    gated = goals.gated(metadata)
    by_id = {b["id"]: b for b in bins}
    waivers = goals.waivers(mode, metadata) if gated else {}
    empty = [b["id"] for b in bins if b["kind"] == "functional" and not b["hits"]]
    must_hit = goals.must_hit(mode, metadata) if gated else []
    run = {
        "mode": mode,
        # From run_coverage_mode; None for raw facts that build.py wrote alone.
        **{key: (raw.get("run") or {}).get(key) for key in COVERAGE_RUN_KEYS},
        "gated": gated,
        "profile": {
            "design": metadata["design"],
            "sharing": metadata["sharing"],
            "data_bitwidth": metadata["data_bitwidth"],
            "poly1305": metadata["poly1305"]["implementation"],
            "lanes": {
                d: v.get("accumulator_count")
                for d, v in metadata["poly1305"].get("directions", {}).items()
            },
        },
        "geometry": {
            "beat_bytes": metadata["beat_bytes"],
            "aad_len": metadata["aad_len"],
            "max_packet_bytes": metadata.get("max_packet_bytes", goals.MAX_PACKET_BYTES),
            "lanes": {
                d: v.get("accumulator_count")
                for d, v in metadata["poly1305"].get("directions", {}).items()
            },
        },
        "params": metadata.get("params", {}),
        "cycles": metadata.get("cycles", {}),
        "packets": {d: len(p) for d, p in raw["packets"].items()},
        "bins": {b["id"]: [b["kind"], b["hits"]] for b in bins},
        "lost": [i for i in empty if i not in waivers] if gated else [],
        "waived": {i: waivers[i] for i in empty if i in waivers},
        "stale": sorted(i for i, b in by_id.items() if i in waivers and b["hits"]),
        "must_hit": [i for i in must_hit if not by_id.get(i, {}).get("hits")],
        "model": goals.model_errors(bins),
    }
    run["errors"] = coverage_run_errors(run)
    return run


def coverage_run_errors(run):
    """Failures that fail the run; a profile without waivers is report-only."""
    if not run["gated"]:
        return []
    errors = [f"lost corner: {i}" for i in run["lost"]]
    errors += [f"stale waiver, now hit: {i}" for i in run["stale"]]
    errors += [f"timing bin required but empty: {i}" for i in run["must_hit"]]
    errors += [f"model: {message}" for message in run["model"]]
    return errors


def judge_coverage_suite(runs):
    """Union the modes and judge it against the permanent waivers."""
    union = {}
    for run in runs:
        for bin_id, (kind, hits) in run["bins"].items():
            entry = union.setdefault(bin_id, [kind, 0])
            entry[1] += hits
    functional_empty = [i for i, (kind, hits) in union.items() if kind == "functional" and not hits]
    fixed = goals.fixed_vector_bins(runs[0]["geometry"])
    suite = {
        "modes": [run["mode"] for run in runs],
        "bins": union,
        "unclosed": [i for i in functional_empty if i not in goals.PERMANENT],
        "permanent": {i: goals.PERMANENT[i] for i in functional_empty if i in goals.PERMANENT},
        "stale": sorted(i for i in goals.PERMANENT if union.get(i, ["", 0])[1]),
        # None when the fixed-vector lengths could not be imported.
        "fixed_only": None if fixed is None else [i for i in functional_empty if i in fixed],
    }
    suite["errors"] = [f"suite hole: {i}" for i in suite["unclosed"]] + [
        f"stale permanent waiver, now hit: {i}" for i in suite["stale"]
    ]
    return suite


def coverage_record(label, args, runs):
    """The saved coverage.json: per-mode judgments, the suite when all modes ran.

    Each mode keeps its own run facts (command, exit code, revisions); the
    provenance here says where, and from which tree, the record was judged.
    """
    # The runs know whether they were comb builds; --comb only fills in for old files.
    built = {run["comb"] for run in runs if run.get("comb") is not None}
    record = {
        "schema_version": COVERAGE_SCHEMA,
        "label": label,
        "generated_utc": datetime.datetime.now(datetime.timezone.utc).isoformat(timespec="seconds"),
        "comb": built.pop() if len(built) == 1 else bool(args.comb),
        "provenance": {
            "wireguard_fpga_git": git_describe(os.path.join(HERE, "..", "..")),
            "pipelinec_git": next((r["pipelinec_git"] for r in runs if r.get("pipelinec_git")), None),
            "host": socket.gethostname(),
        },
        "modes": {run["mode"]: run for run in runs},
        "suite": None,
    }
    gated = [run for run in runs if run["gated"]]
    if gated and len(gated) == len(runs) and {r["mode"] for r in runs} == set(goals.SUITE):
        record["suite"] = judge_coverage_suite(runs)
    record["errors"] = coverage_record_errors(record)
    record["passed"] = not record["errors"]
    return record


def coverage_record_errors(record):
    errors = []
    for mode, run in record["modes"].items():
        if run.get("returncode"):
            errors.append(f"{mode}: simulation exited {run['returncode']}")
        errors += [f"{mode}: {e}" for e in run["errors"]]
    if record["suite"]:
        errors += [f"suite: {e}" for e in record["suite"]["errors"]]
    return errors


def _group_bins(ids):
    """'enc/len_tail16:3' ... -> {'enc/len_tail16': ['3', ...]} in first-seen order."""
    groups = {}
    for bin_id in ids:
        coverpoint, _, name = bin_id.rpartition(":")
        groups.setdefault(coverpoint, []).append(name)
    return groups


def _bin_list(ids, indent="  "):
    return [f"{indent}- `{cp}`: {' '.join(names)}" for cp, names in _group_bins(ids).items()]


def coverage_markdown(record):
    """The report for coverage.md and --coverage-report: tables first, then the holes."""
    modes = record["modes"]
    suite = record["suite"]
    lines = [f"# Functional coverage: {record['label']}", ""]
    first = next(iter(modes.values()), None)
    if first:
        profile = first["profile"]
        lanes = sorted({v for v in profile["lanes"].values() if v is not None})
        lines.append(
            f"{profile['data_bitwidth']}-bit {profile['design']} design, {profile['poly1305']} "
            f"Poly1305, {'comb' if record['comb'] else 'built hardware'}, "
            f"MAC lanes {'/'.join(map(str, lanes)) or '-'}; "
            + ("gated against the checked-in waivers" if first["gated"] else "report only: no waivers for this profile")
        )
        lines.append("")
    lines.append("**Result: " + ("PASS" if record["passed"] else "FAIL") + "**")
    lines.append("")
    lines.append("| mode | packets | cycles | functional | timing | waived | lost | stale | req. timing | model |")
    lines.append("|---|---|---|---|---|---|---|---|---|---|")
    for mode, run in modes.items():
        totals = _kind_totals(run["bins"])
        lines.append(
            f"| {mode} | {'/'.join(str(n) for n in run['packets'].values())} "
            f"| {max(run['cycles'].values(), default='-')} "
            f"| {totals['functional'][0]}/{totals['functional'][1]} "
            f"| {totals['timing'][0]}/{totals['timing'][1]} "
            f"| {len(run['waived'])} | {len(run['lost'])} | {len(run['stale'])} "
            f"| {len(run['must_hit'])} | {len(run['model'])} |"
        )
    if suite:
        totals = _kind_totals(suite["bins"])
        lines.append(
            f"| suite | | | {totals['functional'][0]}/{totals['functional'][1]} "
            f"| {totals['timing'][0]}/{totals['timing'][1]} | {len(suite['permanent'])} "
            f"| {len(suite['unclosed'])} | {len(suite['stale'])} | | |"
        )
    columns = list(modes) + (["suite"] if suite else [])
    sources = [run["bins"] for run in modes.values()] + ([suite["bins"]] if suite else [])

    def cells(kind, keep, bin_ok=lambda bin_id: True):
        """Rows (coverpoint, [hit/total per source]) of one bin kind that `keep` accepts."""
        names = []
        for bins in sources:
            for bin_id, (bin_kind, _) in bins.items():
                name = bin_id.rpartition(":")[0]
                if bin_kind == kind and bin_ok(bin_id) and name not in names:
                    names.append(name)
        rows = []
        for name in names:
            counts = []
            for bins in sources:
                mine = [
                    h
                    for i, (k, h) in bins.items()
                    if k == kind and bin_ok(i) and i.rpartition(":")[0] == name
                ]
                counts.append((sum(1 for h in mine if h), len(mine)))
            if keep(name, counts):
                rows.append((name, [f"{hit}/{total}" if total else "-" for hit, total in counts]))
        return names, rows

    def table(title, rows, note=""):
        lines.extend(["", f"## {title}", ""] + ([note, ""] if note else []))
        if rows:
            lines.append("| coverpoint | " + " | ".join(columns) + " |")
            lines.append("|---|" + "---|" * len(columns))
            lines.extend(f"| `{name}` | " + " | ".join(row) + " |" for name, row in rows)

    def stimulus(name, counts):
        return "." not in name.rpartition("/")[2]

    _, rows = cells("functional", stimulus)
    table("Stimulus coverpoints (functional bins hit/total)", rows)
    # cells() returns every coverpoint of the kind, and the rows that `keep` accepts.
    names, rows = cells("functional", lambda n, c: not stimulus(n, c) and any(h < t for h, t in c))
    designed = [n for n in names if not stimulus(n, [])]
    table(
        "Design coverpoints with holes (FSM states, edge transfers, arbiters)",
        rows,
        f"{len(designed) - len(rows)} of {len(designed)} design coverpoints have every "
        "functional bin hit."
        if designed
        else "",
    )
    # Edge backpressure is one bin per edge; packet timing, FIFO levels, arbitration
    # and races are the rest.
    def not_stall(bin_id):
        return not bin_id.endswith(":stall")

    timing_all, rows = cells("timing", lambda n, c: any(h < t for h, t in c), not_stall)
    stalls = [
        "{}/{}".format(
            sum(1 for i, (k, h) in bins.items() if i.endswith(":stall") and h),
            sum(1 for i in bins if i.endswith(":stall")),
        )
        for bins in sources
    ]
    table(
        "Timing gaps (reported; bins hit/total)",
        rows,
        f"{len(timing_all) - len(rows)} of {len(timing_all)} timing coverpoints (packet "
        "timing, FIFO levels, arbitration, races) have every bin hit. Edges that saw "
        "backpressure, by "
        + ", ".join(f"{c} {n}" for c, n in zip(columns, stalls))
        + ".",
    )
    for mode, run in modes.items():
        lines += ["", f"## {mode}", ""]
        if run.get("returncode"):
            lines.append(f"The simulation exited {run['returncode']}: see coverage-{mode}.log.")
        if not run["gated"]:
            lines.append("No waivers are checked in for this profile, so nothing here gates.")
        for title, ids in (
            ("Lost corners (empty functional bins no waiver covers)", run["lost"]),
            ("Stale waivers (waived, but hit now: delete them)", run["stale"]),
            ("Required timing bins that are empty", run["must_hit"]),
        ):
            if ids:
                lines += [f"**{title}**", ""] + _bin_list(ids) + [""]
        if run["model"]:
            lines += ["**Model mismatches (stimulus and probes disagree)**", ""]
            lines += [f"- {message}" for message in run["model"]] + [""]
        if run["waived"]:
            lines += [f"**Waived holes ({len(run['waived'])})**", ""]
            by_reason = {}
            for bin_id, reason in run["waived"].items():
                by_reason.setdefault(reason, []).append(bin_id)
            for reason, ids in by_reason.items():
                lines += [f"- {reason}:"] + _bin_list(ids, "  ")
            lines.append("")
    if suite:
        lines += ["", "## suite", ""]
        if suite["unclosed"]:
            lines += ["**Holes no mode closes**", ""] + _bin_list(suite["unclosed"]) + [""]
        if suite["stale"]:
            lines += ["**Stale permanent waivers**", ""] + _bin_list(suite["stale"]) + [""]
        if suite["fixed_only"] is None:
            lines += [
                "The fixed-vector lengths could not be imported (tb_common needs the "
                "cryptography package), so this view leaves them out.",
                "",
            ]
        elif suite["fixed_only"]:
            lines += [
                f"**Reached only by the fixed-vector testbenches** ({len(suite['fixed_only'])}; "
                "not simulated here, so still holes above)",
                "",
            ] + _bin_list(suite["fixed_only"]) + [""]
        if suite["permanent"]:
            by_reason = {}
            for bin_id, reason in suite["permanent"].items():
                by_reason.setdefault(reason, []).append(bin_id)
            lines += [f"**Permanent holes ({len(suite['permanent'])})**", ""]
            for reason, ids in by_reason.items():
                lines += [f"- {reason}:"] + _bin_list(ids, "  ")
            lines.append("")
    return "\n".join(lines).rstrip() + "\n"


def coverage_diff(before, after):
    """Compare two saved records: bins gained, lost, and redefined by a different build."""
    lines = [f"# Coverage diff: {before['label']} -> {after['label']}", ""]
    for key in ("comb",):
        if before[key] != after[key]:
            lines.append(f"- {key}: {before[key]} -> {after[key]}")
    for mode in [m for m in before["modes"] if m in after["modes"]]:
        a, b = before["modes"][mode], after["modes"][mode]
        lines += ["", f"## {mode}", ""]
        if a["profile"] != b["profile"]:
            lines.append(f"- profile: {a['profile']} -> {b['profile']}")
        gained = [i for i in b["bins"] if i in a["bins"] and not a["bins"][i][1] and b["bins"][i][1]]
        lost = [i for i in b["bins"] if i in a["bins"] and a["bins"][i][1] and not b["bins"][i][1]]
        only_before = [i for i in a["bins"] if i not in b["bins"]]
        only_after = [i for i in b["bins"] if i not in a["bins"]]
        if not (gained or lost or only_before or only_after):
            lines.append("same bins, same hits")
        for title, ids in (
            ("Corners lost", lost),
            ("Corners gained", gained),
            ("Bins only in the first (redefined or gone)", only_before),
            ("Bins only in the second (redefined or new)", only_after),
        ):
            if ids:
                lines += [f"**{title}** ({len(ids)})", ""] + _bin_list(ids) + [""]
    for mode in before["modes"]:
        if mode not in after["modes"]:
            lines.append(f"- {mode}: only in the first record")
    for mode in after["modes"]:
        if mode not in before["modes"]:
            lines.append(f"- {mode}: only in the second record")
    return "\n".join(lines).rstrip() + "\n"


def load_coverage_record(path):
    """A coverage.json, or the measurement directory / label that holds one."""
    candidates = [path, os.path.join(path, "coverage.json")]
    candidates.append(os.path.join(HERE, GENERATED_FILES, "measurements", path, "coverage.json"))
    for candidate in candidates:
        if os.path.isfile(candidate):
            with open(candidate) as f:
                record = json.load(f)
            if record.get("schema_version") != COVERAGE_SCHEMA:
                raise ValueError(f"{candidate}: not a coverage record this script reads")
            return record
    raise ValueError(f"no coverage.json for {path!r}")


def coverage_main(args, ap):
    """--coverage MODES: simulate (or --parse-only re-read) each mode, judge, report."""
    try:
        modes = coverage_modes(args.coverage)
    except ValueError as exc:
        ap.error(str(exc))
    for name in COVERAGE_REJECTED:
        if getattr(args, name) != ap.get_default(name):
            ap.error(f"--{name.replace('_', '-')} applies to the performance measurement only")
    # Resolve the profile when re-judging too, so both find the same default label.
    try:
        args.sharing = profile_from_args(args)["sharing"]
    except ValueError as exc:
        ap.error(str(exc))
    label = args.label or f"coverage-{'comb' if args.comb else 'pipe'}-{args.data_bitwidth}"
    meas_dir = os.path.join(HERE, GENERATED_FILES, "measurements", label)
    os.makedirs(meas_dir, exist_ok=True)
    runs = []
    for mode in modes:
        raw_path, log_path = coverage_files(meas_dir, mode)
        info = None if args.parse_only else run_coverage_mode(args, mode, meas_dir)
        if not os.path.isfile(raw_path):
            exited = f"simulation exited {info['returncode']}, " if info else ""
            print(
                f"ERROR: {mode}: {exited}no raw coverage at {raw_path} (see {log_path})",
                file=sys.stderr,
            )
            return 1
        with open(raw_path) as f:
            runs.append(judge_coverage_run(json.load(f), mode))
    record = coverage_record(label, args, runs)
    with open(os.path.join(meas_dir, "coverage.json"), "w") as f:
        json.dump(record, f, indent=1)
    report = coverage_markdown(record)
    with open(os.path.join(meas_dir, "coverage.md"), "w") as f:
        f.write(report)
    print()
    print(report)
    print(f"--> {os.path.join(meas_dir, 'coverage.md')}")
    print(f"--> {os.path.join(meas_dir, 'coverage.json')}")
    # The report above lists every bin; summarise the failures by kind.
    titles = (
        ("lost", "lost corners"),
        ("stale", "stale waivers"),
        ("must_hit", "required timing bins empty"),
        ("model", "model mismatches"),
    )
    for mode, run in record["modes"].items():
        if run.get("returncode"):
            print(f"!! {mode}: simulation exited {run['returncode']}", file=sys.stderr)
        for key, title in titles:
            if run["gated"] and run[key]:
                print(f"!! {mode}: {len(run[key])} {title}", file=sys.stderr)
    for key, title in (("unclosed", "holes no mode closes"), ("stale", "stale permanent waivers")):
        if record["suite"] and record["suite"][key]:
            print(f"!! suite: {len(record['suite'][key])} {title}", file=sys.stderr)
    return 0 if record["passed"] else 1


def _coverage_selftest():
    """Judge synthetic runs: bins, each failure kind, the model check, the suite, the
    diff and the closure plan. Nothing is simulated and no saved run is read."""
    import types
    from unittest.mock import patch

    def edge(xfer, stall=0):
        return {"kind": "handshake", "cycles": 99, "xfer_cycles": xfer, "stall_cycles": stall}

    def run_taps(direction, rows, lanes, beat_bytes):
        """The probe taps a design would record: the model's own count of each event."""
        taps = {
            f"{direction}/prep.fsm": {
                "kind": "state",
                "cycles": 99,
                "declared": ["IDLE", "AAD_STATE", "DRAIN"],
                "states": {"IDLE": {"cycles": 9}, "AAD_STATE": {"cycles": 3}},
            },
            f"{direction}/chacha20.axis_in": edge(len(rows)),
            f"{direction}/verify_fifo.occupancy": {
                "kind": "buffer",
                "cycles": 99,
                "capacity_beats": 129,
                "high_water_beats": 70,
            },
        }
        counts = {}
        for row in rows:
            for item in goals.packet_bins(direction, row["length"], beat_bytes, 29, lanes):
                counts[item] = counts.get(item, 0) + 1
        for event, (only, coverpoint, name) in goals.EVENTS.items():
            if only in (None, direction) and goals._probed(event, beat_bytes):
                taps[f"{direction}/{event}"] = edge(counts.get((coverpoint, name), 0))
        for lane in range(lanes if beat_bytes in goals.PAIRED_BEATS else 0):
            count = counts.get(("poly_final", f"lane{lane}"), 0)
            taps[f"{direction}/{goals.LANE_TAP}lane{lane}"] = edge(count)
        return taps

    def synthetic(lengths, lanes=2, bitwidth=256):
        """A run sending `lengths` back to back; decrypt ends with a rejected copy of the last."""
        packets, taps = {}, {}
        for direction in goals.DIRECTIONS:
            plan = list(lengths) + ([lengths[-1]] if direction == "decrypt" else [])
            rows = []
            for i, length in enumerate(plan):
                row = dict(idx=i, length=length, first=3 * i + 1, last=3 * i + 3, done=3 * i + 40)
                row.update(gap=0, stall=0, out_stall=0, passed=True)
                if direction == "decrypt":
                    row.update(verified=int(i < len(lengths)), expected_verified=int(i < len(lengths)))
                rows.append(row)
            packets[direction] = rows
            taps.update(run_taps(direction, rows, lanes, bitwidth // 8))
        taps["shared/pipe.arb"] = {
            "kind": "arb",
            "cycles": 99,
            "per_requester": {
                label: {"xfer_cycles": 5, "blocked_cycles": 0, "contention_cycles": 1}
                for label in goals.DIRECTIONS
            },
        }
        metadata = {
            "design": "shared",
            "sharing": {"chacha20": True, "poly1305": False},
            "data_bitwidth": bitwidth,
            "beat_bytes": bitwidth // 8,
            "aad_len": 29,
            "max_packet_bytes": 2032,
            "cycles": {"encrypt": 99, "decrypt": 99},
            "params": {},
            "poly1305": {
                "implementation": "pipelined",
                "directions": {d: {"accumulator_count": lanes} for d in goals.DIRECTIONS},
            },
            "buffering": {
                "decrypt/verify_fifo": {"sizing": {"terms_beats": {"held_maximum_packet": 64}}}
            },
        }
        return {"metadata": metadata, "packets": packets, "taps": taps}

    def hits(bins, bin_id):
        return next(b["hits"] for b in bins if b["id"] == bin_id)

    # Binning, by hand: 15 and 16 bytes end in one merged beat, 17 and 31 in two,
    # 32 and 64 in a tag-only beat; 33 and 100 leave 1 and 4 bytes in the final beat.
    lengths = [15, 16, 17, 31, 32, 33, 64, 100]
    raw = synthetic(lengths)
    bins = goals.collect(raw)
    assert len({b["id"] for b in bins}) == len(bins), "bin ids are unique"
    assert not goals.model_errors(bins), goals.model_errors(bins)
    got = [hits(bins, f"encrypt/append_path:{p}") for p in ("one_beat", "two_beat", "tag_only")]
    assert got == [4, 2, 2], got
    # With the tag, the final input beat holds 31, 32, 33, 47, 48, 49, 80 and 116 bytes.
    got = [hits(bins, f"decrypt/strip_path:{p}") for p in ("single_beat", "straddle", "exact", "two_tail")]
    assert got == [2, 2, 2, 3], got  # decrypt's extra packet repeats 100 bytes
    assert hits(bins, "encrypt/len_tail16:16") == 3 and hits(bins, "encrypt/len_tail_beat:32") == 2
    assert [hits(bins, f"encrypt/prep_final:{p}") for p in ("single", "pair")] == [4, 4]
    assert [hits(bins, f"encrypt/poly_final:{p}") for p in ("lane0", "lane1", "tail")] == [2, 2, 4]
    assert hits(bins, "encrypt/start:cold") == 1 and hits(bins, "encrypt/start:back_to_back") == 7
    assert hits(bins, "decrypt/verdict:fail") == 1 and hits(bins, "decrypt/verdict_seq:pass_to_fail") == 1
    assert hits(bins, "decrypt/prep.fsm:DRAIN") == 0 and hits(bins, "decrypt/prep.fsm:AAD_STATE") == 3
    assert hits(bins, "decrypt/verify_fifo.occupancy:held_packet") == 1
    assert hits(bins, "shared/pipe.arb:encrypt.xfer") == 5
    # Packet timing depends on the design, so it is reported; the verdicts gate.
    kinds = {b["id"]: b["kind"] for b in bins}
    assert kinds["encrypt/start:gap"] == kinds["decrypt/out_stall:some"] == "timing"
    assert kinds["decrypt/verdict_seq:fail_to_pass"] == "functional"
    # Packet context: cold, back to back, a gap, and a restart after the design drained.
    rows = [
        dict(first=1, last=3, done=50, gap=0, stall=0, out_stall=0, expected_verified=1),
        dict(first=4, last=6, done=60, gap=2, stall=1, out_stall=0, expected_verified=1),
        dict(first=9, last=10, done=70, gap=0, stall=0, out_stall=4, expected_verified=0),
        dict(first=80, last=81, done=99, gap=0, stall=0, out_stall=0, expected_verified=1),
    ]
    context = goals.context_bins("decrypt", rows)
    assert [dict(c)["start"] for c in context] == ["cold", "back_to_back", "gap", "drained"]
    assert ("in_gap", "some") in context[1] and ("out_stall", "some") in context[2]
    assert ("verdict_seq", "pass_to_fail") in context[2] and ("verdict_seq", "fail_to_pass") in context[3]
    assert goals._expand("1 3..5 lane2 17-31") == ["1", "3", "4", "5", "lane2", "17-31"]
    try:
        coverage_modes("default,nope")
    except ValueError:
        pass
    else:
        raise AssertionError("an unknown mode must be rejected")
    assert coverage_modes("default,stress,default") == ["default", "stress"]

    # The checked-in baseline names real bins (a typo would waive nothing).
    valid = set()
    for lanes in (2, 5):
        for direction in goals.DIRECTIONS:
            universe = goals.stimulus_universe(direction, 32, lanes)
            universe.update({c: list(n) for c, n in goals.CONTEXT_BINS.items()})
            valid |= {f"{direction}/{c}:{n}" for c, names in universe.items() for n in names}
    for table in (goals.PERMANENT, *goals.HOLES.values()):
        assert set(table) <= valid, sorted(set(table) - valid)
    # Required packet-timing bins are real bins too (the other required ones are taps).
    required = {i for ids in goals.MUST_HIT.values() for i in ids if "." not in i}
    assert required and required <= valid, sorted(required - valid)
    assert set(goals.MODES) == set(goals.HOLES) and set(goals.SUITE) <= set(goals.MODES)

    def judge(raw, waived=None, required=()):
        """Judge as a gated run whose baseline is `waived`: by default exactly its empty bins."""
        empty = {
            b["id"]: "test" for b in goals.collect(raw) if b["kind"] == "functional" and not b["hits"]
        }
        table = empty if waived is None else waived
        with patch.object(goals, "gated", lambda _m: True), patch.object(
            goals, "waivers", lambda _mode, _m: table
        ), patch.object(goals, "must_hit", lambda _mode, _m: list(required)):
            return judge_coverage_run(raw, "default")

    run = judge(raw)
    assert not run["errors"] and run["waived"] and not run["lost"] and not run["stale"], run["errors"]
    # Dropping a waiver exposes the hole; waiving a hit bin is stale.
    empty = [i for i, (kind, n) in run["bins"].items() if kind == "functional" and not n]
    run = judge(raw, {i: "test" for i in empty if i != empty[0]})
    assert run["lost"] == [empty[0]] and run["errors"] == [f"lost corner: {empty[0]}"]
    run = judge(raw, {**{i: "test" for i in empty}, "encrypt/len_class:2-15": "test"})
    assert run["stale"] == ["encrypt/len_class:2-15"] and run["errors"]
    # A required timing bin that stays empty, and one that is reached.
    assert not judge(raw, required=["decrypt/verify_fifo.occupancy:held_packet"])["errors"]
    slow = copy.deepcopy(raw)
    slow["taps"]["decrypt/verify_fifo.occupancy"]["high_water_beats"] = 10
    run = judge(slow, required=["decrypt/verify_fifo.occupancy:held_packet"])
    assert run["must_hit"] == ["decrypt/verify_fifo.occupancy:held_packet"] and run["errors"]
    # The model check: a probe that counts differently, or is missing, fails the run.
    off = copy.deepcopy(raw)
    off["taps"]["encrypt/cover.append.tag_only"]["xfer_cycles"] += 1
    run = judge(off)
    assert len(run["model"]) == 1 and "encrypt/append_path:tag_only" in run["model"][0], run["model"]
    gone = copy.deepcopy(raw)
    del gone["taps"]["decrypt/cover.chacha.last_partial"]
    assert any("no probe" in m for m in judge(gone)["model"])
    # Another profile is reported, never failed.
    with patch.object(goals, "gated", lambda _m: False):
        run = judge_coverage_run(off, "default")
    assert run["model"] and not run["errors"] and not run["lost"]
    # 128-bit designs have no paired MAC, so no pairing bins, but model their framing.
    narrow = goals.collect(synthetic([15, 16, 17], bitwidth=128))
    assert not goals.model_errors(narrow) and not any("poly_final" in b["id"] for b in narrow)
    assert [hits(narrow, f"encrypt/append_path:{p}") for p in ("two_beat", "tag_only")] == [2, 1]
    assert [hits(narrow, f"decrypt/strip_path:{p}") for p in ("straddle", "exact")] == [3, 1]

    # The suite: modes union, and only the permanent holes may remain.
    plan = goals.closure_lengths()
    runs = [
        judge(synthetic(plan)),
        judge(synthetic(lengths)),
    ]
    runs[0]["mode"], runs[1]["mode"] = "closure", "default"
    union = judge_coverage_suite(runs)
    assert union["bins"]["encrypt/len_tail_beat:32"][1] > 0
    with patch.object(
        goals, "PERMANENT", {**goals.PERMANENT, **{i: "test" for i in union["unclosed"]}}
    ):
        assert not judge_coverage_suite(runs)["unclosed"]
    assert union["unclosed"], "the two runs leave holes without waivers"
    fixed = goals.fixed_vector_bins(runs[0]["geometry"])
    if fixed is not None:  # None without the cryptography package; the report says so
        assert {"encrypt/len_tail_beat:3", "decrypt/verdict:fail"} <= fixed, sorted(fixed)
        assert all(union["bins"][i][1] == 0 for i in union["fixed_only"])
    # Closure serves every width and lane count at once, with mostly short packets.
    assert plan == sorted(plan) and len(plan) <= 48 and max(plan) <= 2032, plan
    for beat_bytes in (16, 32):
        for lanes in range(1, 9):
            for direction in goals.DIRECTIONS:
                reached = {
                    item
                    for length in plan
                    for item in goals.packet_bins(direction, length, beat_bytes, 29, lanes)
                }
                universe = goals.stimulus_universe(direction, beat_bytes, lanes)
                missing = {
                    (c, n)
                    for c, names in universe.items()
                    for n in names
                    if c != "aad_class" and (c, n) not in reached
                }
                assert missing <= {("pairs_class", "one")}, (beat_bytes, lanes, direction, missing)

    # Records: saved, reported and compared; a build with more lanes redefines bins.
    # Each mode's run facts come from its raw file, and its build kind outranks --comb.
    args = types.SimpleNamespace(comb=False)
    ran = {"cmd": "c", "returncode": 0, "wall_s": 1, "comb": True, "pipelinec_git": "x"}

    def record(label, lanes, lengths_by_mode, run_facts=ran):
        made = []
        for mode, lens in lengths_by_mode.items():
            made.append(judge(dict(synthetic(lens, lanes), run=run_facts)))
            made[-1]["mode"] = mode
        return json.loads(json.dumps(coverage_record(label, args, made)))

    first = record("a", 2, {"default": lengths, "stress": lengths, "closure": plan})
    second = record("b", 5, {"default": lengths, "stress": lengths[:-2], "closure": plan})
    assert first["suite"] and first["modes"]["default"]["gated"]
    assert first["comb"] and first["provenance"]["pipelinec_git"] == "x"
    assert "**Result:" in coverage_markdown(first) and "closure" in coverage_markdown(first)
    diff = coverage_diff(first, second)
    assert "only in the second" in diff and "poly_final" in diff and "lane4" in diff, diff
    assert "same bins" in coverage_diff(first, first)
    # A simulation that failed after writing its facts fails every judgment of them.
    failed = record("c", 2, {"default": lengths}, dict(ran, returncode=3))
    assert coverage_record_errors(failed) == ["default: simulation exited 3"]
    print(
        "coverage selftest: PASS (bins, waivers, model check, suite, diff, closure plan"
        + ("" if fixed is not None else "; fixed vectors skipped without cryptography")
        + ")"
    )


def _selftest():
    """Run without saved measurements, a compiler build, or Vivado."""
    with tempfile.TemporaryDirectory(prefix="wg-measure-fixture-") as directory:
        measurement = _measurement_selftest(Path(directory))
        analysis = _bottleneck_selftest()
        _report_selftest(Path(directory))
        _coverage_selftest()
        return measurement or analysis


def _measurement_selftest(fixture_dir):
    _workflow_selftest()
    # Four completions yield three service intervals without charging cold
    # first-packet latency. Small-packet asymmetry must not block the decision.
    phases = []
    for size, periods in ((1420, (50, 49, 49)), (1920, (64, 64, 64))):
        phase = {"name": "b2b-" + str(size), "packet_bytes": size, "num_packets": 4}
        for direction in DIRECTIONS:
            clocks = [100]
            for period in periods:
                clocks.append(clocks[-1] + period)
            entries = [{"idx": i, "last_out": clock} for i, clock in enumerate(clocks)]
            rate = steady_packet_window(entries, size, 0)["bytes_per_cycle"]
            phase[direction] = {
                "packets": entries,
                "sustained_bytes_per_cycle": rate,
                "throughput_bytes_per_cycle": rate,
                "gbps_at_target": rate * 80 * 0.008,
            }
        phases.append(phase)
    parity = {
        "config": {
            "require_throughput_parity": True,
            "dirs": list(DIRECTIONS),
            "steady_trim_packets": 0,
            "target_mhz": 80,
        },
        "phases": phases,
    }
    if throughput_parity_errors(parity):
        raise ValueError(
            "Valid near-max parity fixture rejected: " + repr(throughput_parity_errors(parity))
        )
    with_small = copy.deepcopy(parity)
    with_small["phases"].append(
        {
            "name": "b2b-16",
            "packet_bytes": 16,
            "num_packets": 4,
            "encrypt": {"sustained_bytes_per_cycle": 1},
            "decrypt": {"sustained_bytes_per_cycle": 0.1},
        }
    )
    if throughput_parity_errors(with_small):
        raise ValueError("Small-packet asymmetry incorrectly blocks the near-max decision")
    for label, mutate in (
        (
            "direction asymmetry",
            lambda r: r["phases"][0]["decrypt"].update(
                packets=[{"idx": i, "last_out": 100 + 70 * i} for i in range(4)]
            ),
        ),
        (
            "too few completions",
            lambda r: r["phases"][0]["decrypt"].update(
                packets=[{"idx": i, "last_out": 100 + 49 * i} for i in range(3)]
            ),
        ),
        ("missing near-max size", lambda r: r["phases"].pop()),
        (
            "inconsistent intervals",
            lambda r: r["phases"][0]["decrypt"].update(
                packets=[{"idx": i, "last_out": c} for i, c in enumerate((100, 149, 248, 297))]
            ),
        ),
        ("missing direction", lambda r: r["config"].update(dirs=["encrypt"])),
    ):
        changed = copy.deepcopy(parity)
        mutate(changed)
        if not throughput_parity_errors(changed):
            raise ValueError("Near-max parity guard accepted " + label)
    default = resolve_profile()
    if any(default[k] != value for k, value in DEFAULT_PROFILE.items()):
        raise ValueError("Default profile differs from the published QoR profile")
    published = _selftest_record()
    published["config"].update(
        data_bitwidth=default["data_bitwidth"],
        poly1305_mult_impl=default["multiplier"],
        poly1305_compute_impl=default["compute"],
        sharing=default["sharing"],
        target_mhz=default["target_mhz"],
        poly1305_prologue_max_latency=default["prologue_cap"],
        poly1305_epilogue_max_latency=default["epilogue_cap"],
    )
    published["config"]["poly1305"]["implementation"] = default["implementation"]
    errors = published_default_errors(published)
    if errors:
        raise ValueError(
            "Published default differs from its validated measurement: " + "; ".join(errors)
        )
    for label, mutate in (
        ("an unvalidated record", lambda r: r["validation"].update(passed=False)),
        (
            "another clock goal",
            lambda r: r["config"].update(target_mhz=r["config"]["target_mhz"] + 5),
        ),
        ("a combinational run", lambda r: r["config"].update(comb=True)),
    ):
        changed = copy.deepcopy(published)
        mutate(changed)
        if not published_default_errors(changed):
            raise ValueError("--update-readme would publish " + label)
    published["label"] = "/local-only/measurement"
    if published_default_errors(published) or "/local-only" in provenance_stamp(published):
        raise ValueError("Publication must accept local archives without exposing their paths")
    if resolve_profile(compute="mcp")["sharing"] != {"chacha20": True, "poly1305": True}:
        raise ValueError("Automatic MCP profile must share both compute units")
    if resolve_profile(share="both")["sharing"]["poly1305"] is not True:
        raise ValueError("Explicit sharing selection was overridden")
    narrow = resolve_profile(data_bitwidth=128)
    legacy = resolve_profile(implementation="legacy")
    if (narrow["prologue_cap"], narrow["epilogue_cap"]) != (64, 64):
        raise ValueError("128-bit default caps must stay loose")
    if (legacy["data_bitwidth"], legacy["multiplier"], legacy["target_mhz"]) != (
        128,
        "inferred",
        80,
    ):
        raise ValueError("Legacy profile defaults changed")
    for selector in (selected_prologue_cap, selected_epilogue_cap):
        for invalid in (0, -1, True, 1.5, "40"):
            try:
                selector(invalid)
            except ValueError:
                pass
            else:
                raise ValueError("Invalid compute cap was accepted: " + repr(invalid))
    if prologue_cap_out_dir("historical", 64) != "historical":
        raise ValueError("Historical initialization directory identity changed")
    if epilogue_cap_out_dir("historical", 64) != "historical":
        raise ValueError("Historical finalization directory identity changed")
    if epilogue_cap_out_dir(prologue_cap_out_dir("run", 44), 45) != "run-procap44-epicap45":
        raise ValueError("Nonhistorical caps must have distinct directory identities")
    with tempfile.TemporaryDirectory(prefix="wg-caps-") as directory:
        path = Path(directory) / "source_provenance.json"
        path.write_text(json.dumps({"design_params": []}))
        emitted = build_metadata(directory)
        if (emitted["prologue_cap"], emitted["epilogue_cap"]) != (64, 64):
            raise ValueError("Historical emitted caps must default to 64")
        path.write_text(
            json.dumps(
                {
                    "design_params": [
                        {"name": "DATA_BITWIDTH", "value": 256},
                        {"name": "POLY1305_PROLOGUE_MAX_LATENCY", "value": None},
                        {"name": "POLY1305_EPILOGUE_MAX_LATENCY", "value": None},
                    ]
                }
            )
        )
        emitted = build_metadata(directory)
        if (emitted["prologue_cap"], emitted["epilogue_cap"]) != (
            default["prologue_cap"],
            default["epilogue_cap"],
        ):
            raise ValueError("Direct compiler defaults disagree with emitted profile caps")
        for width_params in (
            [{"name": "POLY1305_BLOCKS_PER_CYCLE", "value": 1}],
            [{"name": "POLY1305_IMPL", "value": "legacy"}],
        ):
            path.write_text(
                json.dumps(
                    {
                        "design_params": width_params
                        + [
                            {"name": "POLY1305_PROLOGUE_MAX_LATENCY", "value": None},
                            {"name": "POLY1305_EPILOGUE_MAX_LATENCY", "value": None},
                        ]
                    }
                )
            )
            emitted = build_metadata(directory)
            if (emitted["prologue_cap"], emitted["epilogue_cap"]) != (64, 64):
                raise ValueError("Direct legacy/block-rate width must retain 64/64 caps")
    if _area_selftest():
        return 1
    # Resolved credits and MCP selection must drive allocation, not a stale
    # starting guess or a requested depth mistaken for physical memory.
    sizing_config = {
        "poly1305": {
            "directions": {
                "decrypt": {
                    "prologue_mcp_latency": 6,
                    "shared_mcps": True,
                }
            }
        },
        "buffering": {
            "decrypt/auth_fifo": {
                "memory_depth_beats": 128,
                "sizing": {
                    "method": "chacha-credit-bound-v1",
                    "chacha20_core_latency": 17,
                    "chacha20_max_in_flight_blocks": 22,
                    "chacha20_block_beats": 4,
                    "prologue_mcp_latency": 6,
                    "shared_mcps": True,
                    "max_aad_beats": 2,
                    "terms_beats": {
                        "pipeline_credits": 88,
                        "widening_storage": 5,
                        "fork_copy_lead": 1,
                        "fifo_startup": 2,
                        "framing_idle": 1,
                        "prologue_service": 14,
                        "mac_transitions": 2,
                        "aad_framing": 2,
                    },
                    "required_beats": 115,
                    "memory_depth_beats": 128,
                },
            }
        },
    }
    if auth_fifo_sizing_errors(sizing_config):
        raise ValueError("Valid automatic FIFO sizing rejected")
    for section, key, value in (
        ("buffer", "memory_depth_beats", 64),
        ("sizing", "chacha20_max_in_flight_blocks", 9),
        ("sizing", "prologue_mcp_latency", 1),
        ("sizing", "required_beats", 64),
        ("sizing", "shared_mcps", False),
        ("sizing", "memory_depth_beats", 64),
    ):
        changed = copy.deepcopy(sizing_config)
        buffer = changed["buffering"]["decrypt/auth_fifo"]
        target = buffer if section == "buffer" else buffer["sizing"]
        target[key] = value
        if not auth_fifo_sizing_errors(changed):
            raise ValueError("Sizing guard accepted stale " + key)
    verify_config = copy.deepcopy(sizing_config)
    verify_config["max_packet_bytes"] = 2032
    verify = copy.deepcopy(verify_config["buffering"]["decrypt/auth_fifo"])
    verify["memory_depth_beats"] = 256
    verify["sizing"].update(
        method="plaintext-verdict-credit-bound-v1",
        buffer="decrypt/verify_fifo",
        authentication_sizing_method="chacha-credit-bound-v1",
        max_plaintext_bytes=2032,
        axis_beat_bytes=16,
        verify_handoff_cycles=4,
        required_beats=252,
        memory_depth_beats=256,
    )
    verify["sizing"]["terms_beats"].update(
        held_maximum_packet=127, narrowing_storage=5, verification_handoffs=4, release_handoff=1
    )
    verify_config["buffering"] = {"decrypt/verify_fifo": verify}
    if verify_fifo_sizing_errors(verify_config):
        raise ValueError("Valid verification FIFO sizing rejected")
    for section, key, value in (
        ("buffer", "memory_depth_beats", 128),
        ("sizing", "chacha20_max_in_flight_blocks", 9),
        ("sizing", "max_plaintext_bytes", 1920),
        ("sizing", "verify_handoff_cycles", 1),
        ("sizing", "required_beats", 128),
        ("sizing", "memory_depth_beats", 128),
        ("terms", "held_maximum_packet", 120),
        ("terms", "narrowing_storage", 0),
        ("terms", "release_handoff", 0),
    ):
        changed = copy.deepcopy(verify_config)
        buffer = changed["buffering"]["decrypt/verify_fifo"]
        target = {
            "buffer": buffer,
            "sizing": buffer["sizing"],
            "terms": buffer["sizing"]["terms_beats"],
        }[section]
        target[key] = value
        if not verify_fifo_sizing_errors(changed):
            raise ValueError("Verification sizing guard accepted stale " + key)
    original = _selftest_record()
    directory = fixture_dir
    _write_selftest_archive(directory, original)
    report = check_record(directory)
    if not report["passed"]:
        raise ValueError("; ".join(report["errors"]))
    mutations = [
        ("functional", lambda r: r["checks"].update(functional_pass=False)),
        ("unfinished", lambda r: r["sim"].update(finalized=False)),
        ("build failure", lambda r: r["provenance"].update(build_returncode=7)),
        ("timing", lambda r: r["fmax"].update(timing_met=False)),
        ("missing area", lambda r: r["area"].update(available=False)),
        ("capacity", lambda r: r["area"].update(fits_device=False)),
        ("hardware timing", lambda r: r["fmax_hw_build"].update(timing_met=False)),
        ("missing hardware area", lambda r: r["area_hw_build"].update(available=False)),
        ("clock mismatch", lambda r: r["fmax"].update(target_mhz=80)),
        ("tap mismatch", lambda r: r["phases"][0].update(taps_check={"consistent": False})),
        (
            "lane mismatch",
            lambda r: r["config"]["poly1305"]["directions"]["encrypt"].update(accumulator_count=3),
        ),
        (
            "II mismatch",
            lambda r: r["config"]["poly1305"]["directions"]["encrypt"].update(body_ii=2),
        ),
        (
            "direction latency mismatch",
            lambda r: r["config"]["poly1305"]["directions"]["decrypt"].update(
                body_core_latency=r["config"]["poly1305"]["directions"]["encrypt"][
                    "body_core_latency"
                ]
                + 1,
                body_latency=r["config"]["poly1305"]["directions"]["encrypt"]["body_latency"] + 1,
                accumulator_count=r["config"]["poly1305"]["directions"]["encrypt"][
                    "accumulator_count"
                ]
                + 1,
            ),
        ),
        (
            "unfinished body",
            lambda r: r["phases"][0]["poly1305_lifecycle"]["encrypt"].update(body_retirements=0),
        ),
        ("MCP audit", lambda r: r.update(mcp_hdl_audits={"perf": {"passed": False}})),
    ]
    for label, mutate in mutations:
        changed = copy.deepcopy(original)
        mutate(changed)
        if not measurement_errors(changed):
            raise ValueError("Guard accepted " + label)
    # Exercise shared metadata/accounting as well as the private-service fixture.
    shared = copy.deepcopy(original)
    shared["config"]["sharing"] = {"chacha20": True, "poly1305": True}
    shared["config"].update(source_handshake="converged", decrypt_verification_retained=True)
    directions = shared["config"]["poly1305"]["directions"]
    unit = {"capacity_lanes": max(m["accumulator_count"] for m in directions.values())}
    for name in ("prologue", "epilogue"):
        key = name + "_mcp_latency"
        unit[key] = directions["encrypt"][key]
        for meta in directions.values():
            meta["shared_mcps"] = True
            meta[key] = unit[key]
    shared["config"]["poly1305"]["shared_mcps"] = unit
    for phase in shared["phases"]:
        completed = sum(life["completed_packets"] for life in phase["poly1305_lifecycle"].values())
        phase["poly1305_shared_services"] = {
            name: {"launches": completed, "responses": completed}
            for name in ("prologue", "epilogue")
        }
    if measurement_errors(shared):
        raise ValueError("Valid shared metadata rejected: " + repr(measurement_errors(shared)))
    fixed = copy.deepcopy(shared)
    fixed["config"]["requested_poly1305_compute_capacity"] = 99
    fixed["config"]["poly1305"]["shared_mcps"]["capacity_lanes"] = 99
    if measurement_errors(fixed):
        raise ValueError("Valid fixed shared capacity rejected: " + repr(measurement_errors(fixed)))
    for label, mutate in (
        (
            "shared capacity",
            lambda r: r["config"]["poly1305"]["shared_mcps"].update(capacity_lanes=99),
        ),
        (
            "fixed capacity below lanes",
            lambda r: (
                r["config"].update(requested_poly1305_compute_capacity=1),
                r["config"]["poly1305"]["shared_mcps"].update(capacity_lanes=1),
            ),
        ),
        (
            "shared latency",
            lambda r: r["config"]["poly1305"]["shared_mcps"].update(epilogue_mcp_latency=99),
        ),
        (
            "shared owner",
            lambda r: r["config"]["poly1305"]["directions"]["decrypt"].update(shared_mcps=False),
        ),
        (
            "shared accounting",
            lambda r: r["phases"][0]["poly1305_shared_services"]["epilogue"].update(responses=0),
        ),
        ("source handshake", lambda r: r["config"].update(source_handshake="early")),
        ("verification output", lambda r: r["config"].update(decrypt_verification_retained=False)),
        ("source bytes", lambda r: r["phases"][0]["encrypt"].update(in_payload_bytes=0)),
        ("output bytes", lambda r: r["phases"][0]["encrypt"].update(out_payload_bytes=0)),
    ):
        changed = copy.deepcopy(shared)
        mutate(changed)
        if not measurement_errors(changed):
            raise ValueError("Guard accepted " + label)
    # Metadata-free historical records remain valid without a packaged archive.
    historical = copy.deepcopy(original)
    historical["config"].pop("poly1305")
    with tempfile.TemporaryDirectory(prefix="wg-legacy-record-") as legacy_dir:
        (Path(legacy_dir) / "results.json").write_text(json.dumps(historical))
        if not check_record(legacy_dir)["passed"]:
            raise ValueError("Historical metadata-free record rejected")
    if model_for(1420, 29, None)["poly1305_body_ii"] != 6:
        raise ValueError("Historical six-cycle fallback changed")
    meta = original["config"]["poly1305"]["directions"]["encrypt"]
    if model_for(1420, 29, None, mac_config=meta)["poly1305_body_ii"] != 1:
        raise ValueError("Pipelined II model changed")
    with tempfile.TemporaryDirectory(prefix="wg-measure-check-") as scratch:
        scratch = Path(scratch)
        # Confirmation overrides provisional standalone checks. Support both
        # compiler print formats, including a final FAIL (never mask it).
        stdout = scratch / "confirmation.log"
        for qualifier in ("", "; worst reported path"):
            for verdict in ("PASS", "FAIL"):
                stdout.write_text(
                    "[sweep] example synthesized as written (standalone check): "
                    "34.34 MHz vs 60.00 MHz goal - FAIL\n"
                    f"{verdict} example: 69.42 MHz vs 60.00 MHz goal{qualifier} "
                    "(confirmation run)\n"
                )
                final = parse_stdout(str(stdout))["final"]["example"]
                expected = {
                    "met": verdict == "PASS",
                    "achieved_mhz": 69.42,
                    "standalone_mhz": 34.34,
                }
                if final.get("outcome") != "confirmation run" or cross_check_final(expected, final):
                    raise ValueError("Confirmation stdout parsing changed: " + repr(final))
        # Cache seeding can carry logs from another named hardware top,
        # without importing that top's HDL/history into the current build.
        mixed = scratch / "mixed-cache"
        active, cached = mixed / "top", mixed / "other_hardware"
        active.mkdir(parents=True)
        cached.mkdir()
        (active / "sweep_history.json").write_text("{}")
        (cached / "vivado_abcd_1234.log").write_text("cache fixture")
        if find_top_dir(str(mixed)) != str(active):
            raise ValueError("Copied top logs were mistaken for an active build")
        # Real second builds must still be rejected, with either final HDL
        # or a sweep history claiming that output directory.
        for artifact in ("other_hardware.vhd", "sweep_history.json"):
            path = cached / artifact
            path.write_text("fixture")
            try:
                find_top_dir(str(mixed))
            except ValueError:
                pass
            else:
                raise ValueError("Ambiguous active tops accepted: " + artifact)
            path.unlink()
        (active / "sweep_history.json").unlink()
        if find_top_dir(str(mixed)) != str(cached):
            raise ValueError("Historical log-only top discovery changed")
        # Mutate only copies. Refreshing the outer inventory must not conceal
        # a bad retained input signature or stale production constraints.
        archived = scratch / "archive"
        shutil.copytree(directory, archived)
        for name in ("perf-clocks.xdc", "perf-inputs.json", "perf-sweep-history.json"):
            path = archived / name
            if name.endswith(".xdc"):
                path.write_bytes(path.read_bytes() + b"\n# stale constraint test\n")
            else:
                changed = json.loads(path.read_text())
                if name.endswith("inputs.json"):
                    changed["signature"] = "bad signature"
                else:
                    changed["build_complete"] = False
                path.write_text(json.dumps(changed))
            inventory = json.loads((directory / "artifact-manifest.json").read_text())
            inventory["artifacts"][name].update(
                bytes=path.stat().st_size, sha256=hashlib.sha256(path.read_bytes()).hexdigest()
            )
            (archived / "artifact-manifest.json").write_text(json.dumps(inventory))
            if check_record(archived)["passed"]:
                raise ValueError("Archive guard accepted stale " + name)
            shutil.copyfile(directory / name, path)
        saved = copy.deepcopy(original)
        saved["config"]["out_dir"] = str(scratch / "deleted-cache")
        (scratch / "results.json").write_text(json.dumps(saved))
        shutil.copyfile(directory / "perf_raw.json", scratch / "perf_raw.json")
        shutil.copyfile(directory / "pypelinec.log", scratch / "pypelinec.log")
        proc = subprocess.run(
            [
                sys.executable,
                str(Path(HERE) / "measure.py"),
                "--label",
                str(scratch),
                "--parse-only",
                "--no-per-module-area",
            ],
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
        )
        if proc.returncode:
            raise ValueError("Cache-free parse-only failed: " + proc.stdout[-2000:])
        parsed = json.loads((scratch / "results.json").read_text())
        for key in ("provenance", "fmax", "area", "fmax_hw_build", "area_hw_build"):
            if parsed.get(key) != saved.get(key):
                raise ValueError("Cache-free parse-only replaced saved " + key)
    print("measurement selftest: PASS (guards, models, saved provenance, archive integrity)")
    return 0


def _workflow_selftest():
    """Check dispatch without launching a compiler, synthesis or simulation: the
    hardware step runs unless --reuse-syn (pypelinec itself does nothing for an
    up-to-date build, and refuses stale hardware when the perf testbench replays
    it), --rebuild reaches pypelinec, and an up-to-date hardware log is told apart."""
    import contextlib
    import io
    from unittest.mock import patch

    with tempfile.TemporaryDirectory(prefix="wg-workflow-") as temporary:
        root = Path(temporary)
        out = root / "hardware"
        out.mkdir()
        arguments = [
            "measure.py",
            "--label",
            str(root / "record"),
            "--out-dir",
            str(out),
            "--syn-cache",
            "none",
        ]
        for extra, expected in (
            ([], "hardware"),
            (["--rebuild"], "hardware"),
            (["--reuse-syn"], "perf"),
        ):
            with patch.object(sys, "argv", arguments + extra), contextlib.redirect_stdout(
                io.StringIO()
            ), patch.object(
                sys.modules[__name__], "run_hardware_build", side_effect=StopIteration("hardware")
            ) as hardware, patch.object(
                sys.modules[__name__], "run_build", side_effect=StopIteration("perf")
            ) as perf:
                try:
                    main()
                except StopIteration as stop:
                    assert str(stop) == expected
                else:
                    raise AssertionError("Workflow did not reach expected dispatch")
                called = perf if expected == "perf" else hardware
                resolved = called.call_args[0][0]
                assert (resolved.sizes, resolved.packets, resolved.peak_bytes) == (
                    "1420,1920",
                    4,
                    0,
                )
                assert hardware.call_count == (expected == "hardware")
                assert resolved.rebuild == ("--rebuild" in extra)
        log = root / "pypelinec-hardware.log"
        log.write_text("Output directory: x\nUp to date: x holds the timing-met build of y\n")
        assert hardware_log_up_to_date(log)
        log.write_text("Synthesis results: 0 reused from the output directory, 2 new run(s)\n")
        assert not hardware_log_up_to_date(log)
    print(
        "workflow selftest: PASS (hardware step unless --reuse-syn, requested rebuild, up-to-date log)"
    )


def _argument_parser():
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument(
        "--label",
        default=None,
        help="name under generated-files/measurements/, or an absolute directory",
    )
    ap.add_argument("--shared", action="store_true", help="Explicitly share both resources")
    add_sharing_arguments(ap)
    add_soc_argument(ap)
    ap.add_argument(
        "--poly1305",
        choices=IMPLEMENTATIONS,
        default=None,
        help="MAC architecture (default pipelined)",
    )
    ap.add_argument(
        "--data-bitwidth",
        type=int,
        choices=DATA_BITWIDTHS,
        help="Encrypt/decrypt packet datapath width in bits (default 256; legacy 128)",
    )
    ap.add_argument(
        "--poly1305-mult",
        choices=MULT_IMPLEMENTATIONS,
        help="130-bit multiply implementation (default inferred_body; legacy inferred)",
    )
    ap.add_argument(
        "--poly1305-compute",
        choices=COMPUTE_IMPLEMENTATIONS,
        help="Prologue/finalization implementation (default: published QoR profile)",
    )
    ap.add_argument(
        "--poly1305-prologue-cap",
        type=int,
        default=None,
        metavar="N",
        help="AUTO_FSM initialization cap (default: published QoR profile; fsm only)",
    )
    ap.add_argument(
        "--poly1305-epilogue-cap",
        type=int,
        default=None,
        metavar="N",
        help="AUTO_FSM finalization cap (default: published QoR profile; fsm only)",
    )
    ap.add_argument(
        "--target-mhz",
        type=selected_target,
        default=None,
        help="Clock goal (default: 256-bit inferred_body 80 MHz; other profiles retain their clock)",
    )
    ap.add_argument(
        "-j",
        "--jobs",
        type=int,
        default=None,
        help="Maximum simultaneous synthesis jobs (use 1 on low-RAM systems)",
    )
    ap.add_argument(
        "--comb",
        action="store_true",
        help="combinational build: fast rig check, no Vivado, no area/fmax",
    )
    reuse = ap.add_mutually_exclusive_group()
    reuse.add_argument(
        "--reuse-syn",
        action="store_true",
        help="simulate the existing hardware build without running the hardware build step (refused when its sources or compiler changed)",
    )
    reuse.add_argument(
        "--rebuild",
        action="store_true",
        help="run the hardware build even when the existing build is up to date (pypelinec --rebuild)",
    )
    ap.add_argument(
        "--show-config",
        action="store_true",
        help="Print the resolved profile and cache paths without building or simulating",
    )
    ap.add_argument(
        "--out-dir", help="Explicit hardware build directory (same rules as build.py --out-dir)"
    )
    ap.add_argument(
        "--syn-cache",
        default=None,
        metavar="DIR|none",
        help="Synthesis store (default: build.py's, generated-files/syn_cache)",
    )
    ap.add_argument(
        "--parse-only",
        action="store_true",
        help="run nothing; re-merge an existing run's perf JSON + build log",
    )
    ap.add_argument(
        "--no-per-module-area",
        action="store_true",
        help="skip per-module out-of-context area parsing",
    )
    ap.add_argument(
        "--sizes", default="1420,1920", help="comma-separated packet sizes (default: 1420,1920)"
    )
    ap.add_argument(
        "--packets", type=int, default=4, help="back-to-back packets per size (default: 4)"
    )
    ap.add_argument(
        "--steady-trim",
        type=int,
        default=None,
        metavar="N",
        help="exclude N warm-up and N drain packets from headline completion throughput",
    )
    ap.add_argument(
        "--require-parity",
        action="store_true",
        help="require 1420/1920-byte phases, 4+ packets, 5%% direction parity and consistent completion intervals",
    )
    ap.add_argument(
        "--peak-bytes", type=int, default=0, help="extra peak phase size (default: 0, disabled)"
    )
    ap.add_argument(
        "--dirs", default=None, choices=("both", "enc", "dec"), help="which directions to stream"
    )
    ap.add_argument(
        "--taps",
        default="all",
        help="internal taps to enable: 'all' (default), a block or direction prefix ('poly1305', 'encrypt'), or exact names; pass --taps '' to measure boundaries only (see PipelineC stream/stream_perf_probe.py)",
    )
    ap.add_argument(
        "--seed",
        type=int,
        default=None,
        help="packet payload RNG seed (with --coverage: TB_SEED of the random modes)",
    )
    ap.add_argument(
        "--coverage",
        metavar="MODES",
        help="functional coverage instead of performance: simulate these comma-separated "
        f"modes ({', '.join(goals.MODES)}), bin what they reached, fail on a lost corner, "
        "and write coverage.md/.json; with --comb nothing is built, otherwise the "
        "already-built hardware is simulated; --parse-only re-judges saved runs",
    )
    ap.add_argument(
        "--update-readme",
        action="store_true",
        help="splice the results table into README.md between its MEASURED-RESULTS markers",
    )
    inspection = ap.add_mutually_exclusive_group()
    inspection.add_argument(
        "--check-record",
        metavar="DIRECTORY",
        help="read-only acceptance/archive-integrity check; never reformat original results",
    )
    inspection.add_argument(
        "--audit-mcps",
        metavar="OUT_DIR",
        help="read-only recursive audit of emitted Poly1305 MCP arithmetic",
    )
    inspection.add_argument(
        "--area-report",
        metavar="LOG_OR_OUT_DIR",
        help="print Vivado utilization without building or measuring",
    )
    inspection.add_argument(
        "--bottleneck-report",
        metavar="RESULTS_JSON",
        help="print bottleneck analysis of saved results without building or changing the record",
    )
    inspection.add_argument(
        "--coverage-report",
        metavar="RUN",
        help="print a saved --coverage run (its label or directory) without simulating",
    )
    inspection.add_argument(
        "--coverage-diff",
        nargs=2,
        metavar=("A", "B"),
        help="compare two saved --coverage runs: corners gained or lost, bins redefined",
    )
    inspection.add_argument(
        "--selftest",
        action="store_true",
        help="check measurement guards, models, saved provenance and retained evidence; no synthesis",
    )
    ap.add_argument(
        "--audit-directions",
        choices=("encrypt", "decrypt", "encrypt,decrypt"),
        default="encrypt,decrypt",
    )
    ap.add_argument(
        "--per-module", action="store_true", help="include OOC modules in --area-report"
    )
    ap.add_argument("--json", action="store_true", help="JSON output for --area-report")
    ap.add_argument(
        "--save-evidence",
        action="store_true",
        help="package retained Vivado/input/sweep/constraint evidence and checksums with an accepted measurement",
    )
    return ap


def _restore_run_config(args, perf_raw, mac_config, meas_dir):
    """Use the saved run's profile, even when current defaults differ."""
    previous = {}
    recorded_multiplier = perf_raw.get("config", {}).get("poly1305_mult_impl")
    recorded_compute = perf_raw.get("config", {}).get("poly1305_compute_impl")
    args.data_bitwidth = recorded_data_bitwidth(perf_raw.get("config", {}))
    args.poly1305_blocks_per_cycle = args.data_bitwidth // 128
    args.poly1305_compute = recorded_compute or "mcp"
    args.poly1305_mult = recorded_multiplier or "inferred"
    previous_path = os.path.join(meas_dir, "results.json")
    if os.path.exists(previous_path):
        with open(previous_path) as f:
            previous = json.load(f)
        args.comb = previous.get("config", {}).get("comb", args.comb)
        if args.steady_trim is None:
            args.steady_trim = previous.get("config", {}).get("steady_trim_packets", 0)
        args.require_parity = args.require_parity or previous.get("config", {}).get(
            "require_throughput_parity", False
        )
    if mac_config:
        args.poly1305 = mac_config["implementation"]
        recorded_sharing = perf_raw.get("config", {}).get("sharing")
        args.target_mhz = (
            previous.get("config", {}).get("target_mhz")
            or perf_raw.get("config", {}).get("target_mhz")
            or historical_target_mhz(args.poly1305, recorded_sharing)
        )
        out_dir = out_dir_for(
            args.comb,
            args.poly1305,
            args.target_mhz,
            recorded_sharing,
            recorded_multiplier,
            recorded_compute,
            args.poly1305_blocks_per_cycle,
        )
    else:
        args.poly1305 = "legacy"
        args.target_mhz = 80
        out_dir = os.path.join(
            HERE, GENERATED_FILES, f"perf-{'comb' if args.comb else 'pipe'}-shared-native"
        )
    recorded_dir = previous.get("config", {}).get("out_dir")
    if recorded_dir:
        out_dir = generated_out_dir(os.path.join(HERE, recorded_dir))
    args.sharing = perf_raw.get("config", {}).get("sharing", {"chacha20": True, "poly1305": False})
    for phase in ("prologue", "epilogue"):
        key = "poly1305_" + phase + "_max_latency"
        cap = previous.get("config", {}).get(key)
        if cap is None:
            cap = perf_raw.get("config", {}).get(key, 64)
        setattr(args, "poly1305_" + phase + "_cap", cap)

    return previous, out_dir


def main():
    ap = _argument_parser()
    args = ap.parse_args()
    if args.steady_trim is not None and args.steady_trim < 0:
        ap.error("--steady-trim must be nonnegative")
    if args.require_parity:
        if args.steady_trim is None:
            args.steady_trim = 0
        if args.comb:
            ap.error("--require-parity requires a retained hardware build")
    try:
        if args.bottleneck_report:
            print(saved_bottleneck_report(args.bottleneck_report))
            return 0
        if args.selftest:
            return _selftest()
        if args.coverage_report:
            print(coverage_markdown(load_coverage_record(args.coverage_report)))
            return 0
        if args.coverage_diff:
            print(coverage_diff(*(load_coverage_record(path) for path in args.coverage_diff)))
            return 0
        if args.check_record or args.audit_mcps:
            report = (
                check_record(args.check_record)
                if args.check_record
                else audit_poly1305_hdl(
                    generated_out_dir(args.audit_mcps),
                    tuple(args.audit_directions.split(",")),
                    shared=sharing_from_args(args)["poly1305"],
                )
            )
            print(json.dumps(report, indent=2))
            return 0 if report["passed"] else 1
        if args.area_report:
            if os.path.isdir(args.area_report):
                report = parse_out_dir(
                    generated_out_dir(args.area_report), per_module=args.per_module
                )
                if args.json:
                    print(json.dumps(report, indent=2))
                else:
                    print(format_area(report["top"]) if report["top"] else "no top-level log found")
                    for name, module in sorted(report["per_module"].items()):
                        print(name + ": " + format_area(module))
            else:
                report = parse_log(args.area_report)
                print(json.dumps(report, indent=2) if args.json else format_area(report))
            return 0
    except (OSError, ValueError, KeyError) as exc:
        print("ERROR: " + str(exc), file=sys.stderr)
        return 1
    if args.coverage:
        return coverage_main(args, ap)
    if args.save_evidence and args.comb:
        ap.error("--save-evidence requires synthesized timing/area evidence")
    if args.jobs is not None and args.jobs < 1:
        ap.error("--jobs must be at least 1")
    try:
        if args.parse_only:
            # Resolve only neutral argument defaults; the saved record supplies
            # its own architecture/sharing/caps below, including legacy records.
            profile = resolve_profile(
                implementation=args.poly1305,
                target_mhz=args.target_mhz,
                multiplier=args.poly1305_mult,
                data_bitwidth=args.data_bitwidth,
                compute=args.poly1305_compute,
                prologue_cap=args.poly1305_prologue_cap,
                epilogue_cap=args.poly1305_epilogue_cap,
            )
            args.poly1305 = profile["implementation"]
            args.data_bitwidth = profile["data_bitwidth"]
            args.poly1305_mult = profile["multiplier"]
            args.poly1305_compute = profile["compute"]
            args.poly1305_prologue_cap = profile["prologue_cap"]
            args.poly1305_epilogue_cap = profile["epilogue_cap"]
            args.target_mhz = profile["target_mhz"]
            args.sharing = None
        else:
            profile = profile_from_args(args)
            args.sharing = profile["sharing"]
        args.poly1305_blocks_per_cycle = args.data_bitwidth // 128
    except ValueError as exc:
        ap.error(str(exc))

    label = args.label or (
        (
            "comb-smoke" + (f"-{args.target_mhz}mhz" if args.target_mhz != 80 else "")
            if args.comb
            else f"shared-{args.target_mhz}mhz"
        )
        + "-poly1305-"
        + args.poly1305
        + ("-share-" + sharing_name(args.sharing) if args.sharing is not None else "")
        + "-mult-"
        + args.poly1305_mult
        + ("-compute-" + args.poly1305_compute if args.poly1305 == "pipelined" else "")
    )
    if args.label is None and args.poly1305 == "pipelined" and args.poly1305_compute == "fsm":
        label = prologue_cap_out_dir(label, args.poly1305_prologue_cap)
        label = epilogue_cap_out_dir(label, args.poly1305_epilogue_cap)
    if args.label is None:
        label = blocks_out_dir(label, args.poly1305_blocks_per_cycle)
    meas_dir = os.path.join(HERE, GENERATED_FILES, "measurements", label)
    json_path = os.path.join(meas_dir, "perf_raw.json")
    log_path = os.path.join(meas_dir, "pypelinec.log")
    hardware_log_path = os.path.join(meas_dir, "pypelinec-hardware.log")
    if args.comb or args.parse_only:
        # A comb rig check builds nothing; parse-only reads the recorded directory below
        out_dir = out_dir_for(
            args.comb,
            args.poly1305,
            args.target_mhz,
            args.sharing,
            args.poly1305_mult,
            args.poly1305_compute if args.poly1305 == "pipelined" else None,
            args.poly1305_blocks_per_cycle,
        )
        if args.poly1305 == "pipelined" and args.poly1305_compute == "fsm":
            out_dir = prologue_cap_out_dir(out_dir, args.poly1305_prologue_cap)
            out_dir = epilogue_cap_out_dir(out_dir, args.poly1305_epilogue_cap)
    else:
        out_dir = os.path.normpath(
            os.path.join(
                HERE,
                hardware_out_dir(
                    "shared",
                    args.poly1305,
                    args.sharing,
                    args.poly1305_mult,
                    args.poly1305_compute,
                    args.target_mhz,
                    args.data_bitwidth,
                    args.poly1305_prologue_cap,
                    args.poly1305_epilogue_cap,
                ),
            )
        )
    if args.out_dir:
        out_dir = os.path.abspath(args.out_dir)
    if args.show_config:
        print(
            json.dumps(
                dict(
                    profile=profile,
                    measurement_dir=meas_dir,
                    out_dir=out_dir,
                    syn_cache=args.syn_cache or os.path.join(HERE, SYN_CACHE_DIR),
                ),
                indent=2,
            )
        )
        return 0
    os.makedirs(meas_dir, exist_ok=True)

    build_info = {"skipped": True}
    hardware_info = {"skipped": True}
    if not args.parse_only and not args.comb:
        if args.reuse_syn:
            # The simulation refuses hardware whose sources or compiler changed
            print(f"--> --reuse-syn: simulating the hardware already built in {out_dir}")
        else:
            # pypelinec does nothing when that hardware is already built from
            # these exact inputs (up to date), unless --rebuild
            hardware_info = run_hardware_build(args, hardware_log_path)
            if hardware_info["returncode"] != 0:
                print(
                    f"!! hardware build exited {hardware_info['returncode']} -- nothing to "
                    f"simulate (see {hardware_log_path})",
                    file=sys.stderr,
                )
                return hardware_info["returncode"]
    if not args.parse_only:
        build_info = run_build(args, json_path, log_path)
        if build_info["returncode"] != 0:
            print(
                f"!! build/sim exited {build_info['returncode']} -- merging whatever "
                f"was measured so far (see {log_path})",
                file=sys.stderr,
            )

    if not os.path.exists(json_path):
        print(f"ERROR: no perf JSON at {json_path}; nothing to merge", file=sys.stderr)
        return 1
    with open(json_path) as f:
        perf_raw = json.load(f)

    # Historical records predate the selector and used unsuffixed output dirs.
    # For parse-only runs the recorded design, not today's default, wins.
    config = perf_raw.get("config", {})
    mac_config = config.get("poly1305")
    previous = {}
    if args.parse_only:
        previous, out_dir = _restore_run_config(args, perf_raw, mac_config, meas_dir)

    stdout_info = parse_stdout(log_path)
    # Timing comes from the hardware build's log; a historical record's perf
    # build synthesized the testbench itself, so its own log has it
    timing_log = (
        hardware_log_path
        if os.path.exists(hardware_log_path) and not hardware_info.get("up_to_date")
        else log_path
    )
    hardware_scope = os.path.exists(os.path.join(out_dir, BUILT_HARDWARE_FILE)) or (
        previous.get("area", {}).get("scope") == "hardware_top"
    )
    fmax = parse_fmax(out_dir, parse_stdout(timing_log))
    area = parse_area(
        out_dir,
        per_module=not args.no_per_module_area,
        scope="hardware_top" if hardware_scope else "perf_tb_top",
    )
    # Saved records remain reformatable after local synthesis caches are
    # removed. Never replace their accepted evidence with "unavailable".
    if args.parse_only and previous:
        if not os.path.isdir(out_dir):
            fmax = previous.get("fmax", fmax)
            area = previous.get("area", area)
    target_mhz = fmax.get("target_mhz") or args.target_mhz
    phases = derive_throughput(perf_raw, fmax.get("design_mhz"), target_mhz, args.steady_trim or 0)
    # Internal taps -> per-block throughput/ceiling, a bottleneck verdict and the
    # model cross-check. A run with no taps leaves the phases untouched.
    aad_len = config.get("aad_len") or 0
    analyze(phases, aad_len=aad_len, mac_config=mac_config)
    emitted = build_metadata(out_dir) if not args.parse_only else {}

    results = {
        "schema_version": 1,
        "label": label,
        "generated_utc": datetime.datetime.now(datetime.timezone.utc).isoformat(timespec="seconds"),
        "config": dict(
            config,
            comb=args.comb,
            poly1305_impl=args.poly1305,
            poly1305_mult_impl=config.get("poly1305_mult_impl", "inferred"),
            requested_poly1305_mult_impl=None if args.parse_only else args.poly1305_mult,
            poly1305_blocks_per_cycle=config.get(
                "poly1305_blocks_per_cycle", recorded_data_bitwidth(config) // 128
            ),
            requested_poly1305_blocks_per_cycle=None
            if args.parse_only
            else args.poly1305_blocks_per_cycle,
            data_bitwidth=recorded_data_bitwidth(config),
            requested_data_bitwidth=None if args.parse_only else args.data_bitwidth,
            poly1305_compute_impl=config.get("poly1305_compute_impl", "mcp"),
            requested_poly1305_compute_impl=None if args.parse_only else args.poly1305_compute,
            poly1305_prologue_max_latency=(
                args.poly1305_prologue_cap if args.parse_only else emitted["prologue_cap"]
            ),
            requested_poly1305_prologue_max_latency=None
            if args.parse_only
            else args.poly1305_prologue_cap,
            poly1305_epilogue_max_latency=(
                args.poly1305_epilogue_cap if args.parse_only else emitted["epilogue_cap"]
            ),
            requested_poly1305_epilogue_max_latency=None
            if args.parse_only
            else args.poly1305_epilogue_cap,
            simulated_poly1305_prologue_max_latency=config.get("poly1305_prologue_max_latency"),
            simulated_poly1305_epilogue_max_latency=config.get("poly1305_epilogue_max_latency"),
            # Preserve the capacity override in records that predate automatic sizing.
            requested_poly1305_compute_capacity=previous.get("config", {}).get(
                "requested_poly1305_compute_capacity"
            ),
            sharing=args.sharing,
            out_dir=os.path.relpath(out_dir, HERE),
            target_mhz=target_mhz,
            requested_target_mhz=(
                previous.get("config", {}).get("requested_target_mhz")
                if args.parse_only
                else args.target_mhz
            ),
            build_cmd=build_info.get("cmd"),
            reuse_syn=bool(args.reuse_syn),
            steady_trim_packets=args.steady_trim or 0,
            require_throughput_parity=args.require_parity,
        ),
        "provenance": {
            "wireguard_fpga_git": git_describe(os.path.join(HERE, "..", "..")),
            # Recorded at build launch when there was a build (see run_build).
            "pipelinec_git": build_info.get("pipelinec_git")
            or compiler_revision(
                os.path.dirname(
                    os.path.dirname(os.environ.get("PYPELINEC", DEFAULT_PIPELINEC_REPO + "/src/x"))
                )
            ),
            "vivado_version": area.get("vivado_version") if area.get("available") else None,
            "host": socket.gethostname(),
            "build_wall_s": build_info.get("wall_s"),
            "build_returncode": build_info.get("returncode"),
            "cycles_run": stdout_info["sim_cycles"] or build_info.get("clock_lines"),
            "sim_wall_s": stdout_info["sim_wall_s"],
            # With --reuse-syn the hardware (hence fmax/area) was built by an
            # EARLIER run, so it can predate pipelinec_git above, which is the
            # revision that ran this sim.
            "synthesis_reused": bool(args.reuse_syn),
            "hardware_build": hardware_info,
            "log": os.path.relpath(log_path, HERE),
            "perf_raw": os.path.relpath(json_path, HERE),
        },
        "fmax": fmax,
        "area": area,
        "phases": phases,
        "summary": summarize(phases),
        "checks": perf_raw.get("checks", {}),
        "sim": perf_raw.get("sim", {}),
    }
    # Reformatting a saved run must not replace its build provenance with the
    # checkout doing the formatting, or silently drop its DUT-only area.
    if args.parse_only and previous:
        results["provenance"] = previous.get("provenance", results["provenance"])
        correct_frozen_compiler_revision(results["provenance"], log_path)
        for key in ("build_cmd", "reuse_syn"):
            if key in previous.get("config", {}):
                results["config"][key] = previous["config"][key]
        for key in (
            "area_hw_build",
            "fmax_hw_build",
            "build_mult_impls",
            "build_compute_impls",
            "build_block_rates",
        ):
            if key in previous:
                results[key] = previous[key]
        for key in (
            "requested_poly1305_blocks_per_cycle",
            "requested_data_bitwidth",
            "requested_poly1305_compute_impl",
            "requested_poly1305_mult_impl",
            "requested_poly1305_prologue_max_latency",
            "requested_poly1305_epilogue_max_latency",
        ):
            results["config"][key] = previous.get("config", {}).get(key)
    elif not args.parse_only:
        # The comb rig check builds nothing; otherwise the hardware build's own selections
        scope = "perf" if args.comb else "hardware"
        results["build_mult_impls"] = {scope: emitted["multiplier"]}
        results["build_compute_impls"] = {scope: emitted["compute"]}
        results["build_block_rates"] = {scope: emitted["blocks_per_cycle"]}

    if (
        not args.parse_only
        and not args.comb
        and args.poly1305 == "pipelined"
        and args.poly1305_compute == "mcp"
    ):
        try:
            audit = audit_poly1305_hdl(out_dir, shared=args.sharing["poly1305"])
        except (OSError, ValueError) as exc:
            audit = {"passed": False, "errors": [str(exc)]}
        results["mcp_hdl_audits"] = {"hardware": audit}
    elif args.parse_only and "mcp_hdl_audits" in previous:
        results["mcp_hdl_audits"] = previous["mcp_hdl_audits"]
    errors = measurement_errors(results)
    results["validation"] = {"passed": not errors, "errors": errors}
    results_path = os.path.join(meas_dir, "results.json")
    with open(results_path, "w") as f:
        json.dump(results, f, indent=1)
    write_csv(os.path.join(meas_dir, "summary.csv"), label, phases)
    table = markdown_table(results)
    with open(os.path.join(meas_dir, "summary.md"), "w") as f:
        f.write(table + "\n")
    extra_csvs = write_tap_csvs(meas_dir, label, phases)
    block_table = None
    blocks_path = os.path.join(meas_dir, "blocks.md")
    if any(phase.get("blocks") for phase in phases):
        block_table = markdown_blocks(phases)
        with open(blocks_path, "w") as f:
            f.write(block_table + "\n")
    # Keep the README at top-level QoR; component detail stays in blocks.md.
    block_summary = (
        "Detailed per-block service/stall, shared arbitration and lifecycle measurements\n"
        "are generated locally as `blocks.md` in the measurement directory.\n"
        "Raw measurement artifacts are not included in the repository."
        if block_table
        else "No internal taps were recorded for this run."
    )

    if args.save_evidence and not errors:
        try:
            save_evidence(meas_dir, results)
        except (OSError, ValueError, KeyError) as exc:
            errors.append("Evidence packaging failed: " + str(exc))
            results["validation"] = {"passed": False, "errors": errors}
            with open(results_path, "w") as destination:
                json.dump(results, destination, indent=1)
    run_returncode = results["provenance"].get("build_returncode") or 0
    measurement_ok = not errors
    if args.update_readme and measurement_ok:
        update_readme(readme_table(results), results, block_summary)
    elif args.update_readme:
        print("!! Incomplete or failing measurement; README results not replaced", file=sys.stderr)

    print()
    print(table)
    if block_table:
        print()
        print(block_table)
    print()
    print(f"--> {results_path}")
    print(f"--> {os.path.join(meas_dir, 'summary.csv')}")
    for path in extra_csvs:
        print(f"--> {path}")
    if block_table:
        print(f"--> {os.path.join(meas_dir, 'blocks.md')}")
    elif config.get("taps"):
        print(
            "!! taps were requested but none fired -- check the names against "
            "the design's stream_perf_probe call sites",
            file=sys.stderr,
        )
    for phase in phases:
        check = phase.get("taps_check")
        if check and not check["consistent"]:
            print(
                f"!! phase {phase['name']}: taps disagree on cycle count "
                f"{check['cycles_seen']} -- a probe fired more than once per "
                f"cycle ({', '.join(check['disagreeing_taps'][:4])}), so its "
                f"per-cycle rates are inflated",
                file=sys.stderr,
            )
    for error in errors:
        print(f"!! {error}", file=sys.stderr)
    return run_returncode or (1 if errors else 0)


if __name__ == "__main__":
    sys.exit(main())
