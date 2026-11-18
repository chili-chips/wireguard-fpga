# SPDX-FileCopyrightText: 2026 Julian Kemmerer
# SPDX-FileCopyrightText: 2026 Chili.CHIPS
#
# SPDX-License-Identifier: BSD-3-Clause

"""Functional-coverage goals for the ChaCha20-Poly1305 random testbenches.

A random run reports only pass or fail, so a repeat on an improved design, or on
the same design built another way, can pass while reaching other corners. This
file says which corners count, measure.py --coverage runs the testbenches and
judges the result against it, and ../../README.md#functional-coverage explains
the workflow. Pure Python without pypeline, so the testbench plans its packet
lengths here (closure_lengths) and measure.py bins the run's raw facts here.

A run records its packets (length, timing, verdict) and every probe tap
(PipelineC stream_perf_probe). collect() turns them into bins:

  functional  stimulus classes (lengths, framing paths, verdicts), design
              paths (cover.* probes), FSM states, and whether each edge
              transferred. A bin that stays empty is a lost corner unless
              HOLES or PERMANENT waive it.
  timing      packet timing (start, input gaps, output stalls), edge stalls,
              FIFO levels, arbitration and races. They depend on the design's
              timing as well as the stimulus, so comb and pipelined runs can
              differ; they are reported, and only MUST_HIT bins gate.

A bin the stimulus predicts and a cover.* probe observes carries both counts,
and a mismatch means the model or the probe is stale. Bin ids are
"<direction>/<coverpoint>:<bin>" for stimulus and "<tap name>:<bin>" for taps.
"""

from collections import Counter

from tb_constants import AAD_LEN, AAD_MAX_LEN

TAG_BYTES = 16
POLY_WORD_BYTES = 16
CHACHA_BLOCK_BYTES = 64
MAX_PACKET_BYTES = 2032
DIRECTIONS = ("encrypt", "decrypt")

# Run modes: -D parameters on top of the default random run. SUITE lists the
# modes whose union is judged against PERMANENT when all of them run.
MODES = {
    "default": {},
    "stress": {"TB_STRESS": 1},
    "closure": {"TB_CLOSURE": 1},
}
SUITE = ("default", "stress", "closure")

# The testbenches send one fixed AAD, so only one of these classes can be hit.
# They stay bins so that the gap shows in every report (see PERMANENT).
AAD_CLASSES = ("0", "1-15", "16", "17-31", str(AAD_MAX_LEN))

# Per-packet context, from the run's timing and verdicts; no length can add it.
CONTEXT_BINS = {
    "start": ("cold", "back_to_back", "gap", "drained"),
    "in_gap": ("none", "some"),
    "out_stall": ("none", "some"),
    "verdict": ("pass", "fail"),
    "verdict_seq": ("pass_to_fail", "fail_to_pass"),
    "in_stall": ("none", "some"),
}
DECRYPT_ONLY = ("verdict", "verdict_seq")
# When a packet starts, and whether it meets an input gap, an output stall or a
# held-back input, depends on the design's timing too: a pipelined build differs
# from a comb one. These are timing bins; the verdicts follow the stimulus alone.
TIMING_CONTEXT = ("start", "in_gap", "out_stall", "in_stall")

# The paired MAC takes two authentication blocks per beat at 256 bits only, and
# only its probes (framing around it, the lanes, tail_in) exist there. The
# chacha20 and the 128-bit append/strip probes serve both widths.
PAIRED_BEATS = (32,)

# Probes that count one event per packet, as <label>/<name>, and the stimulus
# bin each must match (cover.* are the probes added for this model).
EVENTS = {
    "cover.append.tag_only": ("encrypt", "append_path", "tag_only"),
    "cover.append.one_beat": ("encrypt", "append_path", "one_beat"),
    "cover.append.two_beat": ("encrypt", "append_path", "two_beat"),
    "cover.strip.single_beat": ("decrypt", "strip_path", "single_beat"),
    "cover.strip.straddle": ("decrypt", "strip_path", "straddle"),
    "cover.strip.exact": ("decrypt", "strip_path", "exact"),
    "cover.strip.two_tail": ("decrypt", "strip_path", "two_tail"),
    "cover.prep.final_single": (None, "prep_final", "single"),
    "cover.chacha.last_aligned": (None, "chacha_last", "aligned"),
    "cover.chacha.last_partial": (None, "chacha_last", "partial"),
    "poly1305.tail_in": (None, "poly_final", "tail"),
}
# One probe per accumulator lane counts the packets whose final authentication
# pair used that lane: cover.poly.final_lane<N> for the bin poly_final:lane<N>.
LANE_TAP = "cover.poly.final_"

# Races between independent stages: counted, but not a corner to hit every run.
TIMING_EDGES = (
    "poly1305.setup_body_overlap",
    "poly1305.epilogue_body_overlap",
    "poly1305.body_drain_overlap",
)


# ---------------------------------------------------------------------------
# Stimulus model
# ---------------------------------------------------------------------------
def _length_class(length, beat_bytes, max_bytes):
    points = sorted({1, 16, beat_bytes, 64, 128, 1024, max_bytes})
    low = 1
    for point in points:
        if length < point:
            return f"{low}-{point - 1}" if point - 1 > low else str(low)
        if length == point:
            return str(point)
        low = point + 1
    return f"{low}-"  # above the last point: not a legal packet


def _append_path(length, beat_bytes):
    """How append_auth_tag places the tag after a final beat of `fill` bytes."""
    fill = length % beat_bytes or beat_bytes
    if fill == beat_bytes:
        return "tag_only"
    return "one_beat" if fill + TAG_BYTES <= beat_bytes else "two_beat"


def _strip_path(length, beat_bytes):
    """How strip_auth_tag finds the tag in the final input beat of `fill` bytes."""
    total = length + TAG_BYTES
    if total <= beat_bytes:
        return "single_beat"
    fill = total % beat_bytes or beat_bytes
    if fill < TAG_BYTES:
        return "straddle"
    return "exact" if fill == TAG_BYTES else "two_tail"


def _ceil_div(value, unit):
    return -(-value // unit)


def packet_bins(direction, length, beat_bytes, aad_len, lanes, max_bytes=MAX_PACKET_BYTES):
    """The (coverpoint, bin) pairs a packet of `length` bytes falls into."""
    chacha_tail = length % CHACHA_BLOCK_BYTES or CHACHA_BLOCK_BYTES
    bins = [
        ("len_class", _length_class(length, beat_bytes, max_bytes)),
        ("len_tail16", str(length % POLY_WORD_BYTES or POLY_WORD_BYTES)),
        ("len_tail_beat", str(length % beat_bytes or beat_bytes)),
        ("chacha_final_beats", str(_ceil_div(chacha_tail, beat_bytes))),
        ("chacha_last", "partial" if length % CHACHA_BLOCK_BYTES else "aligned"),
        (
            ("append_path", _append_path(length, beat_bytes))
            if direction == "encrypt"
            else ("strip_path", _strip_path(length, beat_bytes))
        ),
    ]
    if beat_bytes in PAIRED_BEATS:
        # The paired MAC takes two 16-byte authentication blocks per beat: AAD,
        # ciphertext and the lengths block. An even count ends in a pair, issued
        # to the lane after the packet's earlier pairs; an odd count ends in a
        # single tail block.
        blocks = _ceil_div(aad_len, POLY_WORD_BYTES) + _ceil_div(length, POLY_WORD_BYTES) + 1
        pairs = blocks // 2
        if pairs == 1:
            pairs_class = "one"
        elif pairs < lanes:
            pairs_class = "lt_lanes"
        else:
            pairs_class = "eq_lanes" if pairs == lanes else "gt_lanes"
        bins += [
            ("prep_final", "single" if blocks % 2 else "pair"),
            ("poly_final", "tail" if blocks % 2 else f"lane{(pairs - 1) % lanes}"),
            ("pairs_class", pairs_class),
        ]
    return bins


def aad_class(aad_len):
    if aad_len in (0, 16, AAD_MAX_LEN):
        return str(aad_len)
    return "1-15" if aad_len < 16 else "17-31"


def _bin_order(coverpoint, name):
    """Sort key: numbers ascending, lanes by index, a single tail last."""
    if name == "tail":
        return (2, 0, name)
    digits = "".join(c for c in name.split("-")[0] if c.isdigit())
    return (0 if coverpoint == "poly_final" else 1, int(digits) if digits else 0, name)


def stimulus_universe(direction, beat_bytes, lanes, max_bytes=MAX_PACKET_BYTES):
    """{coverpoint: [bin, ...]}: every length-dependent bin some legal packet reaches.

    The AAD length is free here (none, one block, two blocks), because the
    bins describe the design's input space, not the one AAD the testbenches send.
    """
    universe = {"aad_class": list(AAD_CLASSES)}
    for aad_len in (0, 16, AAD_MAX_LEN):
        for length in range(1, max_bytes + 1):
            for coverpoint, name in packet_bins(
                direction, length, beat_bytes, aad_len, lanes, max_bytes
            ):
                bins = universe.setdefault(coverpoint, [])
                if name not in bins:
                    bins.append(name)
    for coverpoint, bins in universe.items():
        if coverpoint in ("poly_final", "chacha_final_beats", "len_tail16", "len_tail_beat"):
            bins.sort(key=lambda name: _bin_order(coverpoint, name))
    return universe


def context_bins(direction, packets):
    """One list of (coverpoint, bin) per packet, from its timing and verdict.

    A packet starts `cold` (first), `back_to_back` (offered the cycle after the
    previous packet's last beat), after a `gap`, or `drained` (the previous
    packet's output was complete before this one's first beat).
    """
    result = []
    for i, packet in enumerate(packets):
        previous = packets[i - 1] if i else None
        if previous is None:
            start = "cold"
        elif previous["done"] <= packet["first"]:
            start = "drained"
        elif packet["first"] - previous["last"] == 1:
            start = "back_to_back"
        else:
            start = "gap"
        bins = [
            ("start", start),
            ("in_gap", "some" if packet["gap"] else "none"),
            ("in_stall", "some" if packet["stall"] else "none"),
            ("out_stall", "some" if packet["out_stall"] else "none"),
        ]
        if direction == "decrypt":
            passed = packet["expected_verified"]
            bins.append(("verdict", "pass" if passed else "fail"))
            if previous is not None and previous["expected_verified"] != passed:
                bins.append(("verdict_seq", "fail_to_pass" if passed else "pass_to_fail"))
        result.append(bins)
    return result


# ---------------------------------------------------------------------------
# Run -> bins
# ---------------------------------------------------------------------------
def _bin(bin_id, kind, hits, predicted=None, modeled=False, observed=False):
    """One bin. `modeled` bins have a probe that should observe them (`observed`
    says whether this run has it); `predicted` is then the stimulus's count."""
    return {
        "id": bin_id,
        "cp": bin_id.rsplit(":", 1)[0],
        "bin": bin_id.rsplit(":", 1)[1],
        "kind": kind,
        "hits": hits,
        "predicted": predicted,
        "modeled": modeled,
        "observed": observed,
    }


def _lanes(metadata, direction):
    directions = metadata["poly1305"].get("directions", {})
    return directions.get(direction, {}).get("accumulator_count", 1)


def _split_label(name):
    label, _, rest = name.partition("/")
    return label, rest


def _probed(event, beat_bytes):
    """Whether the design at this width carries this event's probe."""
    if event.startswith(("cover.chacha.", "cover.append.", "cover.strip.")):
        return True
    return beat_bytes in PAIRED_BEATS


def collect(raw):
    """Every bin of one run, in report order, from its raw facts.

    Stimulus bins count the checked packets. Where a probe observes the same
    corner (EVENTS, LANE_TAP), `hits` is what the design did, `predicted` what
    the stimulus implies, and `observed` says whether the probe exists.
    """
    metadata, taps = raw["metadata"], raw["taps"]
    beat_bytes, aad_len = metadata["beat_bytes"], metadata["aad_len"]
    max_bytes = metadata.get("max_packet_bytes", MAX_PACKET_BYTES)
    bins, consumed = [], set()
    for direction, packets in raw["packets"].items():
        lanes = _lanes(metadata, direction)
        universe = stimulus_universe(direction, beat_bytes, lanes, max_bytes)
        counts = Counter()
        counts[("aad_class", aad_class(aad_len))] = len(packets)
        for packet, context in zip(packets, context_bins(direction, packets)):
            for item in packet_bins(direction, packet["length"], beat_bytes, aad_len, lanes, max_bytes):
                counts[item] += 1
            for item in context:
                counts[item] += 1
        for coverpoint, names in CONTEXT_BINS.items():
            if direction == "encrypt" and coverpoint in DECRYPT_ONLY:
                continue
            universe[coverpoint] = list(names)
        # (coverpoint, bin) -> design event count, or None where the run has no probe.
        observed = {}
        for event, (only, coverpoint, name) in EVENTS.items():
            if only in (None, direction) and _probed(event, beat_bytes):
                snapshot = taps.get(f"{direction}/{event}")
                observed[(coverpoint, name)] = None if snapshot is None else snapshot["xfer_cycles"]
                consumed.add(f"{direction}/{event}")
        if beat_bytes in PAIRED_BEATS:
            for name in universe["poly_final"]:
                if name != "tail":
                    snapshot = taps.get(f"{direction}/{LANE_TAP}{name}")
                    observed[("poly_final", name)] = (
                        None if snapshot is None else snapshot["xfer_cycles"]
                    )
                    consumed.add(f"{direction}/{LANE_TAP}{name}")
        for coverpoint, names in universe.items():
            kind = "timing" if coverpoint in TIMING_CONTEXT else "functional"
            for name in names:
                predicted = counts[(coverpoint, name)]
                modeled = (coverpoint, name) in observed
                seen = observed.get((coverpoint, name))
                bins.append(
                    _bin(
                        f"{direction}/{coverpoint}:{name}",
                        kind,
                        predicted if seen is None else seen,
                        predicted if modeled else None,
                        modeled,
                        seen is not None,
                    )
                )
    for name, snapshot in sorted(taps.items()):
        if name not in consumed:
            bins.extend(_tap_bins(name, snapshot, metadata.get("buffering", {})))
    return bins


def _tap_bins(name, snapshot, buffering):
    kind = snapshot["kind"]
    suffix = name.partition("/")[2]
    if kind == "state":
        declared = snapshot.get("declared") or list(snapshot["states"])
        return [
            _bin(f"{name}:{state}", "functional", snapshot["states"].get(state, {}).get("cycles", 0))
            for state in declared
        ]
    if kind == "handshake":
        timing = suffix in TIMING_EDGES or suffix.startswith("cover.")
        return [
            _bin(f"{name}:xfer", "timing" if timing else "functional", snapshot["xfer_cycles"]),
            _bin(f"{name}:stall", "timing", snapshot["stall_cycles"]),
        ]
    if kind == "buffer":
        capacity, high = snapshot["capacity_beats"], snapshot["high_water_beats"]
        bins = [
            _bin(f"{name}:nonempty", "timing", int(high >= 1)),
            _bin(f"{name}:half", "timing", int(2 * high >= capacity)),
            _bin(f"{name}:full", "timing", int(high >= capacity)),
        ]
        # A buffer sized to hold a maximum-size packet while its verdict is pending.
        sizing = buffering.get(name.rpartition(".")[0], {}).get("sizing") or {}
        held = sizing.get("terms_beats", {}).get("held_maximum_packet")
        if held:
            bins.append(_bin(f"{name}:held_packet", "timing", int(high >= held)))
        return bins
    if kind == "arb":
        bins = []
        for label, stats in snapshot["per_requester"].items():
            bins.append(_bin(f"{name}:{label}.xfer", "functional", stats["xfer_cycles"]))
            bins.append(_bin(f"{name}:{label}.blocked", "timing", stats["blocked_cycles"]))
            bins.append(_bin(f"{name}:{label}.contention", "timing", stats["contention_cycles"]))
        return bins
    return []


def fixed_vector_bins(geometry):
    """Bin ids the fixed-vector testbenches reach, from their lengths alone.

    Their ten plaintexts run through both directions, and decrypt replays the
    first with a corrupted tag. They are not simulated here, so these bins
    only extend the suite view; nothing gates on them. `geometry` holds
    beat_bytes, aad_len, max_packet_bytes and the MAC lanes per direction.
    None means tb_common did not import (its reference model needs the
    cryptography package), so the report can say the view is missing.
    """
    try:
        from tb_common import PLAINTEXT_LENS
    except ImportError:
        return None
    ids = {"decrypt/verdict:pass", "decrypt/verdict:fail"}
    for direction in DIRECTIONS:
        for length in PLAINTEXT_LENS:
            for coverpoint, name in packet_bins(
                direction,
                length,
                geometry["beat_bytes"],
                geometry["aad_len"],
                geometry["lanes"].get(direction) or 1,
                geometry["max_packet_bytes"],
            ):
                ids.add(f"{direction}/{coverpoint}:{name}")
    return ids


def model_errors(bins):
    """Stale model or probe: a modeled bin whose probe is absent or disagrees."""
    errors = []
    for b in bins:
        if not b["modeled"]:
            continue
        if not b["observed"]:
            errors.append(f"{b['id']}: no probe observed this corner")
        elif b["hits"] != b["predicted"]:
            errors.append(f"{b['id']}: stimulus predicts {b['predicted']}, probe saw {b['hits']}")
    return errors


# ---------------------------------------------------------------------------
# Baseline: gated profile, waived holes, required timing bins
# ---------------------------------------------------------------------------
# A waiver is an exact empty bin plus its reason, so the lists are the baseline:
# a corner a re-run loses is an unwaived hole, and a waived corner that gets
# hit is a stale waiver to delete. Only the default 256-bit shared build has
# lists; other profiles are reported, not gated. Bins that do not exist in a
# run (lane4 with two lanes) never match, so one list serves comb and hardware.
GATED_PROFILE = {
    "design": "shared",
    "data_bitwidth": 256,
    "implementation": "pipelined",
    "sharing": {"chacha20": True, "poly1305": False},
}


def gated(metadata):
    profile = {
        "design": metadata["design"],
        "data_bitwidth": metadata["data_bitwidth"],
        "implementation": metadata["poly1305"]["implementation"],
        "sharing": metadata["sharing"],
    }
    return profile == GATED_PROFILE


def _expand(names):
    """'1 3..5 lane2' -> ['1', '3', '4', '5', 'lane2']; class names keep their hyphen."""
    result = []
    for token in names.split():
        low, dots, high = token.partition("..")
        if dots:
            result.extend(str(n) for n in range(int(low), int(high) + 1))
        else:
            result.append(token)
    return result


def _waive(table, reason, spec, directions=DIRECTIONS):
    """Add {coverpoint: names} for each direction to {bin id: reason}."""
    for coverpoint, names in spec.items():
        for direction in directions:
            for name in _expand(names):
                table[f"{direction}/{coverpoint}:{name}"] = reason


_R_AAD = "out of scope: every packet carries the same 29-byte AAD"
_R_LENGTHS = "the random lengths miss it; closure mode reaches it"
_R_TAMPER = "needs a valid packet after a tampered one, which only stress mode sends"

# Holes no mode can close (judged on the suite, and part of every mode's list).
PERMANENT = {}
_waive(PERMANENT, _R_AAD, {"aad_class": "0 1-15 16 32", "pairs_class": "one"})

# Holes of each mode on its own (the permanent ones are added by waivers()).
HOLES = {"default": {}, "stress": {}, "closure": {}}
# Default: 12 random-ish lengths. 5 lanes (the built hardware) also miss two final lanes.
_waive(HOLES["default"], _R_LENGTHS, {
    "len_class": "1 32 33-63 1024 1025-2031 2032",
    "len_tail16": "2 3 6 8..13",
    "len_tail_beat": "1..4 6..13 18 19 21 22 24..30",
    "poly_final": "lane2 lane4",
})
_waive(HOLES["default"], _R_TAMPER, {"verdict_seq": "fail_to_pass"}, ("decrypt",))
# Stress: directed lengths, but few residues.
_waive(HOLES["stress"], _R_LENGTHS, {
    "len_tail16": "2..11 13 14",
    "len_tail_beat": "2..11 13 14 18..30",
}, ("encrypt",))
_waive(HOLES["stress"], _R_LENGTHS, {
    "len_tail16": "2..6 8..11 13 14",
    "len_tail_beat": "2..11 13 14 18..22 24..30",
}, ("decrypt",))
# Closure: the length plan, ending in the one tampered packet.
_waive(HOLES["closure"], _R_TAMPER, {"verdict_seq": "fail_to_pass"}, ("decrypt",))

# Timing bins a mode must reach, because its stimulus guarantees them. Each
# stress direction sends packets longer than its 37-cycle input-gap period and
# meets its 300-cycle output stall window. When a packet starts (after a gap or
# back to back) depends on the design, so it is reported only.
MUST_HIT = {
    "stress": [
        f"{direction}/{coverpoint}:some"
        for direction in DIRECTIONS
        for coverpoint in ("in_gap", "out_stall")
    ]
    + ["encrypt/append.axis_out:stall", "decrypt/wtv.axis_out:stall"],
}


def waivers(mode, metadata):
    """{bin id: reason} that may stay empty in this mode of a gated profile."""
    return {**HOLES[mode], **PERMANENT}


def must_hit(mode, metadata):
    return MUST_HIT.get(mode, [])


# ---------------------------------------------------------------------------
# Closure plan
# ---------------------------------------------------------------------------
# Widths and lane counts the plan must serve at once, so one list closes every
# profile: the testbench cannot know them when it plans (the design imports after).
_CLOSURE_BEATS = (16, 32)
_CLOSURE_LANES = tuple(range(1, 9))
# A packet costs this many cycles of fixed work plus its beats: short packets win.
_PACKET_OVERHEAD_CYCLES = 40


def closure_lengths(aad_len=AAD_LEN, max_bytes=MAX_PACKET_BYTES):
    """Short, deterministic packet lengths that reach every length-dependent bin.

    Greedy set cover over every legal length, preferring the most new bins per
    simulated cycle (ties go to the shorter packet), for every beat width and
    lane count in _CLOSURE_*. Both directions use the same plan.
    """
    reach = {}
    for length in range(1, max_bytes + 1):
        items = set()
        for beat_bytes in _CLOSURE_BEATS:
            for lanes in _CLOSURE_LANES:
                for direction in DIRECTIONS:
                    for coverpoint, name in packet_bins(
                        direction, length, beat_bytes, aad_len, lanes, max_bytes
                    ):
                        items.add((beat_bytes, lanes, direction, coverpoint, name))
        reach[length] = items
    missing = set().union(*reach.values())
    plan = []
    while missing:
        best = max(
            reach,
            key=lambda n: (
                len(reach[n] & missing) / (_PACKET_OVERHEAD_CYCLES + _ceil_div(n, 32)),
                -n,
            ),
        )
        plan.append(best)
        missing -= reach[best]
    return sorted(plan)
