# pyright: reportInvalidTypeForm=none
"""Shared Poly1305 initialization/finalization for either compute mode.

Each phase has an independent arbiter; adapters own no compute or packet state.
See poly1305_design.md#shared-versus-private-compute-units for wiring and handshake rules.
"""
import wireguard_env  # noqa: F401

from types import SimpleNamespace
from pypeline import (
    MAIN, NamedTuple, Reg, Feedback, Wire, struct, hw_func, uint1_t, uint2_t,
)
from stream import stream_perf_probe as perf_taps
from stream import make_stream_interface
from poly1305_compute import make_compute_unit, make_shared_compute
from poly1305_math import (
    uint128_t, uint130_t,
)

if wireguard_env.POLY1305_BLOCKS_PER_CYCLE == 2:
    from poly1305_mac_paired import get_body_auto_pipeline
else:
    from poly1305_mac_pipelined import get_body_auto_pipeline

# Both directions share one body latency group, so one lane count.
CAPACITY = get_body_auto_pipeline().latency + 2


# The paired path reuses its kernels for both private and shared compute units.
if wireguard_env.POLY1305_BLOCKS_PER_CYCLE == 2:
    from poly1305_compute import make_paired_compute as make_shared_compute
compute = make_shared_compute(CAPACITY)
init_in_if_t = make_stream_interface(uint130_t)
init_out_if_t = make_stream_interface(compute.powers_t)
finish_in_if_t = make_stream_interface(compute.finish_in_t)
finish_out_if_t = make_stream_interface(uint128_t)


def make_compute_arbiter(func, input_t, output_t, phase):
    """Arbitrate two requesters for one AUTO_FSM/AUTO_MCP compute unit per phase."""
    in_if_t = make_stream_interface(input_t)
    out_if_t = make_stream_interface(output_t)

    @struct
    class tagged_in_t(NamedTuple):
        data: input_t
        is_encrypt: uint1_t

    @struct
    class tagged_out_t(NamedTuple):
        data: output_t
        is_encrypt: uint1_t

    @hw_func
    def tagged_compute(x: tagged_in_t) -> tagged_out_t:
        o: tagged_out_t
        o.data = func(x.data)
        o.is_encrypt = x.is_encrypt
        return o

    unit = make_compute_unit(tagged_compute, phase=phase)

    @struct
    class result_t(NamedTuple):
        encrypt_in_if: in_if_t.fb_t
        decrypt_in_if: in_if_t.fb_t
        encrypt_out_if: out_if_t.fwd_t
        decrypt_out_if: out_if_t.fwd_t

    # Probe names are part of the saved measurement format.
    probe_phase = {"init": "prologue", "finish": "epilogue"}[phase]
    arb_tap = f"poly1305.{probe_phase}.arb"
    enc_in_tap, dec_in_tap = f"poly1305.{probe_phase}.enc_in", f"poly1305.{probe_phase}.dec_in"
    enc_out_tap, dec_out_tap = f"poly1305.{probe_phase}.enc_out", f"poly1305.{probe_phase}.dec_out"
    unit_in_tap, unit_out_tap = f"poly1305.{probe_phase}.service_in", f"poly1305.{probe_phase}.service_out"
    unit_state_tap = f"poly1305.{probe_phase}.service"

    @hw_func
    def arbiter(
        encrypt_in_if: in_if_t.fwd_t,
        decrypt_in_if: in_if_t.fwd_t,
        encrypt_out_if: out_if_t.fb_t,
        decrypt_out_if: out_if_t.fb_t,
    ) -> result_t:
        result: Feedback[unit.return_t]
        priority_encrypt: Reg[uint1_t]  # Initial priority is decrypt.
        grant_stalled: Reg[uint1_t]
        stalled_is_encrypt: Reg[uint1_t]
        busy: Reg[uint1_t]
        enc_valid: uint1_t = encrypt_in_if.stream.valid
        dec_valid: uint1_t = decrypt_in_if.stream.valid
        is_encrypt: uint1_t = priority_encrypt
        o: result_t
        o.encrypt_in_if.ready = 0
        o.decrypt_in_if.ready = 0
        # Hold the selected requester until acceptance, even if its peer arrives.
        # The requester must keep valid and payload stable while stalled.
        if grant_stalled:
            is_encrypt = stalled_is_encrypt
            if is_encrypt:
                o.encrypt_in_if.ready = result.stream_in_if.ready
            else:
                o.decrypt_in_if.ready = result.stream_in_if.ready
        else:
            if enc_valid & ~dec_valid:
                is_encrypt = 1
            elif dec_valid & ~enc_valid:
                is_encrypt = 0
            o.encrypt_in_if.ready = result.stream_in_if.ready & (priority_encrypt | ~dec_valid)
            o.decrypt_in_if.ready = result.stream_in_if.ready & (~priority_encrypt | ~enc_valid)

        request: unit.in_if_t.stream_t
        request.data.is_encrypt = is_encrypt
        if is_encrypt:
            request.data.data = encrypt_in_if.stream.data
            request.valid = enc_valid
        else:
            request.data.data = decrypt_in_if.stream.data
            request.valid = dec_valid

        # Rotate priority only on acceptance, not while waiting for the compute unit.
        if request.valid & result.stream_in_if.ready:
            priority_encrypt = ~is_encrypt
            grant_stalled = 0
        elif request.valid:
            grant_stalled = 1
            stalled_is_encrypt = is_encrypt

        # Only the tagged owner sees valid and supplies response backpressure.
        o.encrypt_out_if.stream.data = result.stream_out_if.stream.data.data
        o.decrypt_out_if.stream.data = result.stream_out_if.stream.data.data
        o.encrypt_out_if.stream.valid = 0
        o.decrypt_out_if.stream.valid = 0
        response_ready: uint1_t = 0
        if result.stream_out_if.stream.valid:
            if result.stream_out_if.stream.data.is_encrypt:
                o.encrypt_out_if.stream.valid = 1
                response_ready = encrypt_out_if.ready
            else:
                o.decrypt_out_if.stream.valid = 1
                response_ready = decrypt_out_if.ready

        # Probe-only occupancy; the compute unit wrapper controls readiness.
        unit_state: uint2_t = busy
        if result.stream_out_if.stream.valid:
            unit_state = 2
        perf_taps.state(unit_state_tap, unit_state, ("IDLE", "COMPUTE", "OUTPUT"))
        if result.stream_out_if.stream.valid & response_ready:
            busy = 0
        if request.valid & result.stream_in_if.ready:
            busy = 1

        result = unit(unit.in_fwd_t(stream=request), unit.out_fb_t(ready=response_ready))
        perf_taps.arb(
            arb_tap, is_encrypt, enc_valid, dec_valid,
            result.stream_in_if.ready, "encrypt", "decrypt",
        )
        perf_taps.hs(enc_in_tap, enc_valid, o.encrypt_in_if.ready)
        perf_taps.hs(dec_in_tap, dec_valid, o.decrypt_in_if.ready)
        perf_taps.hs(enc_out_tap, o.encrypt_out_if.stream.valid, encrypt_out_if.ready)
        perf_taps.hs(dec_out_tap, o.decrypt_out_if.stream.valid, decrypt_out_if.ready)
        perf_taps.hs(unit_in_tap, request.valid, result.stream_in_if.ready)
        perf_taps.hs(unit_out_tap, result.stream_out_if.stream.valid, response_ready)
        return o

    arbiter.compute_tag = unit.compute_tag
    return arbiter


init_arbiter = make_compute_arbiter(
    compute.init, uint130_t, compute.powers_t, "init"
)
finish_arbiter = make_compute_arbiter(
    compute.finish, compute.finish_in_t, uint128_t, "finish"
)

# Each compound Wire has exactly one forward and one reverse writer.
encrypt_init_in_if: Wire[init_in_if_t]
decrypt_init_in_if: Wire[init_in_if_t]
encrypt_init_out_if: Wire[init_out_if_t]
decrypt_init_out_if: Wire[init_out_if_t]
encrypt_finish_in_if: Wire[finish_in_if_t]
decrypt_finish_in_if: Wire[finish_in_if_t]
encrypt_finish_out_if: Wire[finish_out_if_t]
decrypt_finish_out_if: Wire[finish_out_if_t]


@MAIN(wireguard_env.TARGET_MHZ)
def poly1305_init_shared():
    o = init_arbiter(
        init_in_if_t.fwd_t(encrypt_init_in_if.stream),
        init_in_if_t.fwd_t(decrypt_init_in_if.stream),
        init_out_if_t.fb_t(encrypt_init_out_if.ready),
        init_out_if_t.fb_t(decrypt_init_out_if.ready),
    )
    encrypt_init_in_if.ready = o.encrypt_in_if.ready
    decrypt_init_in_if.ready = o.decrypt_in_if.ready
    encrypt_init_out_if.stream = o.encrypt_out_if.stream
    decrypt_init_out_if.stream = o.decrypt_out_if.stream


@MAIN(wireguard_env.TARGET_MHZ)
def poly1305_finish_shared():
    o = finish_arbiter(
        finish_in_if_t.fwd_t(encrypt_finish_in_if.stream),
        finish_in_if_t.fwd_t(decrypt_finish_in_if.stream),
        finish_out_if_t.fb_t(encrypt_finish_out_if.ready),
        finish_out_if_t.fb_t(decrypt_finish_out_if.ready),
    )
    encrypt_finish_in_if.ready = o.encrypt_in_if.ready
    decrypt_finish_in_if.ready = o.decrypt_in_if.ready
    encrypt_finish_out_if.stream = o.encrypt_out_if.stream
    decrypt_finish_out_if.stream = o.decrypt_out_if.stream


@struct
class init_result_t(NamedTuple):
    stream_in_if: init_in_if_t.fb_t
    stream_out_if: init_out_if_t.fwd_t


@struct
class finish_result_t(NamedTuple):
    stream_in_if: finish_in_if_t.fb_t
    stream_out_if: finish_out_if_t.fwd_t


@hw_func
def encrypt_init_shared_adapter(
    stream_in_if: init_in_if_t.fwd_t,
    stream_out_if: init_out_if_t.fb_t,
) -> init_result_t:
    encrypt_init_in_if.stream = stream_in_if.stream
    encrypt_init_out_if.ready = stream_out_if.ready
    return init_result_t(
        init_in_if_t.fb_t(encrypt_init_in_if.ready),
        init_out_if_t.fwd_t(encrypt_init_out_if.stream),
    )


@hw_func
def decrypt_init_shared_adapter(
    stream_in_if: init_in_if_t.fwd_t,
    stream_out_if: init_out_if_t.fb_t,
) -> init_result_t:
    decrypt_init_in_if.stream = stream_in_if.stream
    decrypt_init_out_if.ready = stream_out_if.ready
    return init_result_t(
        init_in_if_t.fb_t(decrypt_init_in_if.ready),
        init_out_if_t.fwd_t(decrypt_init_out_if.stream),
    )


@hw_func
def encrypt_finish_shared_adapter(
    stream_in_if: finish_in_if_t.fwd_t,
    stream_out_if: finish_out_if_t.fb_t,
) -> finish_result_t:
    encrypt_finish_in_if.stream = stream_in_if.stream
    encrypt_finish_out_if.ready = stream_out_if.ready
    return finish_result_t(
        finish_in_if_t.fb_t(encrypt_finish_in_if.ready),
        finish_out_if_t.fwd_t(encrypt_finish_out_if.stream),
    )


@hw_func
def decrypt_finish_shared_adapter(
    stream_in_if: finish_in_if_t.fwd_t,
    stream_out_if: finish_out_if_t.fb_t,
) -> finish_result_t:
    decrypt_finish_in_if.stream = stream_in_if.stream
    decrypt_finish_out_if.ready = stream_out_if.ready
    return finish_result_t(
        finish_in_if_t.fb_t(decrypt_finish_in_if.ready),
        finish_out_if_t.fwd_t(decrypt_finish_out_if.stream),
    )


def _stream_attrs(func, in_if_t, out_if_t, compute_tag):
    func.in_if_t, func.out_if_t = in_if_t, out_if_t
    func.in_fwd_t, func.out_fb_t = in_if_t.fwd_t, out_if_t.fb_t
    func.compute_tag = compute_tag


def make_shared_compute_adapters(direction, lanes, local_powers_t, local_finish_in_t):
    """Bridge one MAC's local payload types to the shared-capacity compute units.

    Adapters expose the same stream interface and compute_tag metadata as
    private compute units, without adding buffering.
    """
    if lanes > CAPACITY:
        raise ValueError("Shared compute capacity differs from consumed body latency")
    init_shared_adapter = encrypt_init_shared_adapter if direction == "encrypt" else decrypt_init_shared_adapter
    finish_shared_adapter = encrypt_finish_shared_adapter if direction == "encrypt" else decrypt_finish_shared_adapter
    init_out = make_stream_interface(local_powers_t)
    finish_in = make_stream_interface(local_finish_in_t)

    @struct
    class local_init_result_t(NamedTuple):
        stream_in_if: init_in_if_t.fb_t
        stream_out_if: init_out.fwd_t

    @hw_func
    def init_payload_adapter(
        stream_in_if: init_in_if_t.fwd_t,
        stream_out_if: init_out.fb_t,
    ) -> local_init_result_t:
        response = init_shared_adapter(stream_in_if, init_out_if_t.fb_t(stream_out_if.ready))
        o: local_init_result_t
        o.stream_in_if = response.stream_in_if
        o.stream_out_if.stream.valid = response.stream_out_if.stream.valid
        for j in range(lanes):
            o.stream_out_if.stream.data.values[j] = response.stream_out_if.stream.data.values[j]
        return o

    @struct
    class local_finish_result_t(NamedTuple):
        stream_in_if: finish_in.fb_t
        stream_out_if: finish_out_if_t.fwd_t

    @hw_func
    def finish_payload_adapter(
        stream_in_if: finish_in.fwd_t,
        stream_out_if: finish_out_if_t.fb_t,
    ) -> local_finish_result_t:
        request: finish_in_if_t.stream_t
        request.valid = stream_in_if.stream.valid
        request.data.lane_count = lanes
        request.data.next_lane = stream_in_if.stream.data.next_lane
        request.data.s = stream_in_if.stream.data.s
        if wireguard_env.POLY1305_BLOCKS_PER_CYCLE == 2:
            request.data.r = stream_in_if.stream.data.r
            request.data.tail = stream_in_if.stream.data.tail
            request.data.has_tail = stream_in_if.stream.data.has_tail
        # Pad to shared capacity; lane_count keeps rotation local to this MAC.
        for j in range(CAPACITY):
            request.data.accumulators[j] = 0
            request.data.powers.values[j] = 0
        for j in range(lanes):
            request.data.accumulators[j] = stream_in_if.stream.data.accumulators[j]
            request.data.powers.values[j] = stream_in_if.stream.data.powers.values[j]
        response = finish_shared_adapter(finish_in_if_t.fwd_t(request), stream_out_if)
        o: local_finish_result_t
        o.stream_in_if.ready = response.stream_in_if.ready
        o.stream_out_if = response.stream_out_if
        return o

    _stream_attrs(init_payload_adapter, init_in_if_t, init_out, init_arbiter.compute_tag)
    _stream_attrs(finish_payload_adapter, finish_in, finish_out_if_t, finish_arbiter.compute_tag)
    return SimpleNamespace(init=init_payload_adapter, finish=finish_payload_adapter)
