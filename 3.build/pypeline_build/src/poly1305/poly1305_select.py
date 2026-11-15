"""Import only the selected MAC (-D POLY1305_IMPL); selection creates no hardware mux."""
import wireguard_env  # noqa: F401

IMPLEMENTATION = wireguard_env.POLY1305_IMPL
# Interface-function definitions selected for this elaboration, keyed by direction.
# Reuse them for hardware construction, sharing checks, and metadata reporting.
_mac_definitions = {}

if IMPLEMENTATION == "pipelined":
    if wireguard_env.POLY1305_BLOCKS_PER_CYCLE == 2:
        from poly1305_mac_paired import make_poly1305_mac_paired as _make_pipelined_mac
    else:
        from poly1305_mac_pipelined import make_poly1305_mac_pipelined as _make_pipelined_mac
else:
    import poly1305_legacy


def make_poly1305_mac(direction, share_compute=False):
    """Return the selected MAC interface-function definition for one direction."""
    if direction not in ("encrypt", "decrypt"):
        raise ValueError("Invalid Poly1305 direction")
    if share_compute and IMPLEMENTATION != "pipelined":
        raise ValueError("Only pipelined Poly1305 has shareable initialization/finalization units")
    if (direction in _mac_definitions
            and bool(share_compute) != getattr(_mac_definitions[direction], "shared_compute", False)):
        raise ValueError("Cannot mix private and shared MACs for one direction in a top")
    if direction not in _mac_definitions:
        if IMPLEMENTATION == "pipelined":
            _mac_definitions[direction] = _make_pipelined_mac(direction, share_compute=share_compute)
        else:
            _mac_definitions[direction] = poly1305_legacy.poly1305_mac_if_func
    return _mac_definitions[direction]


def implementation_metadata():
    """Snapshot selected MACs for performance reports and measurement validation.

    Hardware buffer sizing reads the MAC definitions' attributes directly.
    """
    result = {
        "implementation": IMPLEMENTATION,
        "directions": {},
        "arithmetic": "residue130" if IMPLEMENTATION == "pipelined" else "limb320-corrected",
    }
    if IMPLEMENTATION == "pipelined":
        result["compute_impl"] = wireguard_env.POLY1305_COMPUTE_IMPL
        result["blocks_per_cycle"] = wireguard_env.POLY1305_BLOCKS_PER_CYCLE
        result["body_architecture"] = (
            "paired" if wireguard_env.POLY1305_BLOCKS_PER_CYCLE == 2 else "interleaved"
        )
    # The report schema uses MCP names for both AUTO_MCP and AUTO_FSM compute units.
    # *_mcp_latency excludes the wrapper's one result/handshake cycle.
    if any(getattr(mac, "shared_compute", False) for mac in _mac_definitions.values()):
        from poly1305_compute_shared import CAPACITY, init_arbiter, finish_arbiter
        result["shared_mcps"] = {
            "capacity_lanes": CAPACITY,
            "prologue_mcp_latency": init_arbiter.compute_tag.latency,
            "epilogue_mcp_latency": finish_arbiter.compute_tag.latency,
        }
    for direction, mac in _mac_definitions.items():
        if IMPLEMENTATION == "pipelined":
            result["directions"][direction] = {
                "body_core_latency": mac.body_auto_pipeline.latency,
                "body_latency": mac.body_auto_pipeline.latency + 2,
                "accumulator_count": mac.accumulator_count,
                "body_ii": 1,
                "blocks_per_cycle": wireguard_env.POLY1305_BLOCKS_PER_CYCLE,
                "coefficient_latency": getattr(mac, "coefficient_latency", 0),
                "coefficient_core_latency": (
                    mac.coefficient_auto_pipeline.latency
                    if wireguard_env.POLY1305_BLOCKS_PER_CYCLE == 2 else 0
                ),
                "axis_beat_bytes": wireguard_env.DATA_BITWIDTH // 8,
                "total_body_latency": getattr(
                    mac, "total_body_latency", mac.body_auto_pipeline.latency + 2
                ),
                "shared_mcps": mac.shared_compute,
                "packet_architecture": mac.packet_architecture,
                "packet_buffers": dict(mac.packet_buffers),
                "prologue_handoff_cycles": mac.init_handoff_cycles,
                "body_commit_cycles": mac.body_commit_cycles,
                "epilogue_handoff_cycles": mac.finish_handoff_cycles,
                "prologue_mcp_latency": mac.init_unit.compute_tag.latency,
                "epilogue_mcp_latency": mac.finish_unit.compute_tag.latency,
                "prologue_response_cycles": mac.init_unit.compute_tag.latency + 1,
                "epilogue_response_cycles": mac.finish_unit.compute_tag.latency + 1,
            }
        else:
            result["directions"][direction] = {
                "body_ii": poly1305_legacy.compute_mcp.mcp.latency + 1,
                "body_mcp_latency": poly1305_legacy.compute_mcp.mcp.latency,
                "accumulator_count": 1,
            }
    return result
