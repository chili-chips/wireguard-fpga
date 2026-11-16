# pyright: reportInvalidTypeForm=none
"""Shared AEAD types, latency-derived buffer sizes, and probed buffer factories."""
import wireguard_env  # noqa: F401

from copy import deepcopy

from pypeline import uint1_t, uint8_t, make_uint_t
from kept_data_bus import make_kept_data_bus_t
from ndarray import make_ndarray_fragment_t
from stream import make_stream_interface
from axi.axis import make_keep_count, make_count_to_keep, make_axis_broadcast_interlock
from stream.stream_perf_probe import make_probed_stream_fifo, make_probed_skid_buffer

# ChaCha20 sizes in bytes, except the state word count.
CHACHA20_STATE_NWORDS = 16
CHACHA20_KEY_SIZE = 32
CHACHA20_NONCE_SIZE = 12
CHACHA20_BLOCK_SIZE = 64

# Poly1305 sizes in bytes.
POLY1305_BLOCK_SIZE = 16
POLY1305_KEY_SIZE = 32
POLY1305_AUTH_TAG_SIZE = 16

# Maximum additional authenticated data, in bytes.
AAD_MAX_LEN = 32

# Fixed-width stream used by the single-block Poly1305 and framing modules.
AXIS128_BEAT_BYTES = 16

# Supported plaintext payload limit, independent of verification FIFO rounding.
AEAD_MAX_PLAINTEXT_BYTES = 2032

# Packed scalar types, derived from the corresponding byte sizes.
key_uint_t = make_uint_t(8 * CHACHA20_KEY_SIZE)
nonce_uint_t = make_uint_t(8 * CHACHA20_NONCE_SIZE)
aad_uint_t = make_uint_t(8 * AAD_MAX_LEN)
poly1305_key_uint_t = make_uint_t(8 * POLY1305_KEY_SIZE)
poly1305_auth_tag_uint_t = make_uint_t(8 * POLY1305_AUTH_TAG_SIZE)

# 128-bit stream: one Poly1305 block per beat.
axis128_bus_t = make_kept_data_bus_t(uint8_t, AXIS128_BEAT_BYTES)
axis128_frag_t = make_ndarray_fragment_t(axis128_bus_t, 1)
axis128_if_t = make_stream_interface(axis128_frag_t)
axis128_keep_count = make_keep_count(axis128_bus_t, AXIS128_BEAT_BYTES)
axis128_keep_count_t = make_uint_t(AXIS128_BEAT_BYTES.bit_length())
axis128_count_to_keep = make_count_to_keep(AXIS128_BEAT_BYTES)

# Selected packet width. Explicit axis128_* names stay genuinely 128 bits.
AEAD_BEAT_BYTES = wireguard_env.DATA_BITWIDTH // 8
aead_data_uint_t = make_uint_t(8 * AEAD_BEAT_BYTES)
aead_keep_uint_t = make_uint_t(AEAD_BEAT_BYTES)
aead_axis_bus_t = make_kept_data_bus_t(uint8_t, AEAD_BEAT_BYTES)
aead_axis_frag_t = make_ndarray_fragment_t(aead_axis_bus_t, 1)
aead_axis_if_t = make_stream_interface(aead_axis_frag_t)
aead_keep_count = make_keep_count(aead_axis_bus_t, AEAD_BEAT_BYTES)
aead_count_to_keep = make_count_to_keep(AEAD_BEAT_BYTES)
aead_2broadcast = make_axis_broadcast_interlock(aead_axis_if_t, 2)

# 512-bit stream: one ChaCha20 block per beat.
axis512_bus_t = make_kept_data_bus_t(uint8_t, CHACHA20_BLOCK_SIZE)
axis512_frag_t = make_ndarray_fragment_t(axis512_bus_t, 1)
axis512_if_t = make_stream_interface(axis512_frag_t)

# Scalar streams.
poly1305_key_stream_if_t = make_stream_interface(poly1305_key_uint_t)
poly1305_auth_tag_stream_if_t = make_stream_interface(poly1305_auth_tag_uint_t)
uint1_stream_if_t = make_stream_interface(uint1_t)

# Reporting only: factories record allocations by direction/tap during elaboration.
# perf_tb_common snapshots these after importing the selected dataflows.
_fifo_metadata = {}
_output_slice_metadata = {}


def _fifo_budget(terms):
    """Keep the complete beat budget alongside its power-of-two allocation."""
    required = sum(terms.values())
    return {
        "required_beats": required,
        "memory_depth_beats": 1 << (max(2, required) - 1).bit_length(),
    }


def decrypt_auth_fifo_sizing(chacha_func, mac_func):
    """Size the decrypt authentication fork for either pipelined MAC width."""
    return overlap_fifo_sizing("decrypt/auth_fifo", chacha_func, mac_func)


def overlap_fifo_sizing(name, chacha_func, mac_func, *, auth_capacity_beats=None):
    """Size fork FIFOs in AEAD beats from the selected pipeline and compute-unit latencies.

    One ingress beat can arrive per clock. A single-flight shared compute unit
    can serve one preceding peer request; requesters reserve response storage before
    launching, so a peer's downstream consumer cannot prolong that compute unit.
    External stalls use ordinary backpressure rather than an unbounded budget.

    The authentication FIFO provides initialization lookahead. The append FIFO also
    covers the entire authentication queue plus initialization and completion, allowing
    both fork copies to advance while the old tag is pending. Decrypt retains
    the ChaCha credit floor needed to reach a key response without deadlock,
    adding the two-bank controller's bounded completion interval.
    """
    pipeline = getattr(chacha_func, "pipeline_func", None)
    if pipeline is None:
        raise ValueError("Overlap FIFO sizing requires chacha_func.pipeline_func")
    if name not in ("encrypt/auth_fifo", "encrypt/append_fifo", "decrypt/auth_fifo"):
        raise ValueError("Unknown overlap FIFO")
    block_beats = CHACHA20_BLOCK_SIZE // AEAD_BEAT_BYTES
    aad_beats = (AAD_MAX_LEN + AEAD_BEAT_BYTES - 1) // AEAD_BEAT_BYTES
    shared = bool(mac_func.shared_compute)
    peer_requests = int(shared)
    init_latency = mac_func.init_unit.compute_tag.latency
    finish_latency = mac_func.finish_unit.compute_tag.latency
    init_budget = (1 + peer_requests) * (init_latency + 1) + mac_func.init_handoff_cycles
    # A partial ciphertext beat plus the 16-byte tag occupies at most two
    # beats at either supported width (128 or 256 bits).
    tag_words = 2
    body_latency = getattr(
        mac_func, "total_body_latency", mac_func.body_auto_pipeline.latency + 2
    )
    completion = (
        body_latency + mac_func.body_commit_cycles
        + (1 + peer_requests) * (finish_latency + 1)
        + mac_func.finish_handoff_cycles + tag_words
    )
    terms = {
        "setup_service_and_handoffs": init_budget,
        "aad_framing": aad_beats,
        "framing_idle": 1,  # prep_auth_data's registered IDLE transition
        "length_framing": 1,  # its single 128-bit lengths block
        "fifo_startup": 2,  # memory read plus FWFT output register
        "fork_copy_lead": 1,
    }
    if name == "encrypt/auth_fifo":
        terms["narrowing_storage"] = block_beats + 1
    elif name == "encrypt/append_fifo":
        if type(auth_capacity_beats) is not int or auth_capacity_beats < 1:
            raise ValueError("Append sizing requires actual authentication FIFO capacity")
        terms["authentication_queue"] = auth_capacity_beats
        terms["completion_service_and_handoffs"] = completion
    else:
        terms["pipeline_credits"] = block_beats * pipeline.max_in_flight
        terms["widening_storage"] = block_beats + 1
        terms["completion_service_and_handoffs"] = completion
    if wireguard_env.POLY1305_BLOCKS_PER_CYCLE == 2:
        terms["formatter_storage"] = 2  # four complete authentication blocks
    return {
        "method": "poly1305-overlap-fork-v2",
        "axis_beat_bytes": AEAD_BEAT_BYTES,
        "buffer": name,
        "chacha20_core_latency": pipeline.auto_pipeline.latency,
        "chacha20_max_in_flight_blocks": pipeline.max_in_flight,
        "chacha20_block_beats": block_beats,
        "prologue_mcp_latency": init_latency,
        "epilogue_mcp_latency": finish_latency,
        "body_latency": body_latency,
        "prologue_handoff_cycles": mac_func.init_handoff_cycles,
        "body_commit_cycles": mac_func.body_commit_cycles,
        "epilogue_handoff_cycles": mac_func.finish_handoff_cycles,
        "shared_mcps": shared,
        "preceding_peer_requests": peer_requests,
        "max_aad_beats": aad_beats,
        "max_packed_tag_beats": tag_words,
        "authentication_capacity_beats": auth_capacity_beats,
        "terms_beats": terms,
        **_fifo_budget(terms),
    }


def decrypt_verify_fifo_sizing(chacha_func, mac_func, *, verify_handoff_cycles):
    """Hold a maximum plaintext packet without choking shared ChaCha results.

    Reuse the authentication-fork bound for work admitted ahead of the MAC: selected ChaCha credits, input conversion, framing, initialization and
    completion (including one preceding shared-unit request). Add the held
    packet, ChaCha's output converter and the comparator/release handoffs.
    At most one narrow beat arrives per clock. This deliberately
    overcounts overlapping phases and key blocks, rather than depending on
    the measured packet length or occupancy. External sink stalls still
    propagate by ordinary ready/valid backpressure.
    """
    if type(verify_handoff_cycles) is not int or verify_handoff_cycles < 1:
        raise ValueError("Verification sizing requires a positive handoff bound")
    sizing = decrypt_auth_fifo_sizing(chacha_func, mac_func)
    terms = sizing["terms_beats"]
    terms["held_maximum_packet"] = (
        AEAD_MAX_PLAINTEXT_BYTES + AEAD_BEAT_BYTES - 1
    ) // AEAD_BEAT_BYTES
    terms["narrowing_storage"] = sizing["chacha20_block_beats"] + 1
    terms["verification_handoffs"] = verify_handoff_cycles
    terms["release_handoff"] = 1  # wait-to-verdict -> output-plaintext
    sizing.update(
        method="plaintext-verdict-credit-bound-v1",
        buffer="decrypt/verify_fifo",
        authentication_sizing_method=sizing["method"],
        max_plaintext_bytes=AEAD_MAX_PLAINTEXT_BYTES,
        axis_beat_bytes=AEAD_BEAT_BYTES,
        verify_handoff_cycles=verify_handoff_cycles,
        **_fifo_budget(terms),
    )
    return sizing


def make_aead_fifo(data_t, depth, tap_name, direction, *, sizing=None):
    """Stream FIFO with simulation-only handshake/occupancy probes."""
    fifo = make_probed_stream_fifo(data_t, depth, tap_name)
    metadata = {
        "requested_memory_depth_beats": depth,
        "memory_depth_beats": fifo.capacity_beats - 1,
        "capacity_beats": fifo.capacity_beats,
        "output_register_beats": 1,
    }
    if sizing is not None:
        metadata["sizing"] = deepcopy(sizing)
    _fifo_metadata[direction + "/" + tap_name] = metadata
    return fifo


def buffering_metadata():
    """Snapshot FIFO allocations and sizing inputs for performance reports/checks."""
    return deepcopy(_fifo_metadata)


def make_aead_output_slice(stream_if_t, tap_name, direction):
    """Two-slot output register slice; II=1 and stable valid under stalls."""
    skid = make_probed_skid_buffer(stream_if_t, tap_name, mode="full")
    _output_slice_metadata[direction + "/" + tap_name] = {
        "mode": skid.mode,
        "capacity_beats": skid.capacity_beats,
        "latency_cycles": skid.latency,
    }
    return skid


def stream_slice_metadata():
    """Snapshot output register-slice allocations for performance reports/checks."""
    return {name: dict(values) for name, values in _output_slice_metadata.items()}


# Zero-valued initializers for elaboration and simulation.
def axis128_frag_null():
    return axis128_frag_t(
        frag=axis128_bus_t(data=[0] * AXIS128_BEAT_BYTES, keep=[0] * AXIS128_BEAT_BYTES),
        eod=[0],
    )


def axis128_stream_null():
    return axis128_if_t.stream_t(data=axis128_frag_null(), valid=0)


def axis512_frag_null():
    return axis512_frag_t(
        frag=axis512_bus_t(data=[0] * CHACHA20_BLOCK_SIZE, keep=[0] * CHACHA20_BLOCK_SIZE),
        eod=[0],
    )


def axis512_stream_null():
    return axis512_if_t.stream_t(data=axis512_frag_null(), valid=0)


def poly1305_key_stream_null():
    return poly1305_key_stream_if_t.stream_t(data=0, valid=0)


def poly1305_auth_tag_stream_null():
    return poly1305_auth_tag_stream_if_t.stream_t(data=0, valid=0)


def uint1_stream_null():
    return uint1_stream_if_t.stream_t(data=0, valid=0)


def aead_frag_null():
    return aead_axis_frag_t(
        frag=aead_axis_bus_t(data=[0] * AEAD_BEAT_BYTES, keep=[0] * AEAD_BEAT_BYTES),
        eod=[0],
    )


def aead_stream_null():
    return aead_axis_if_t.stream_t(data=aead_frag_null(), valid=0)
