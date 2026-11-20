# pyright: reportInvalidTypeForm=none
# SPDX-FileCopyrightText: 2026 Chili.CHIPS*ba
# SPDX-License-Identifier: BSD-3-Clause

"""Native encrypt driver for correctness and performance simulation.

Queue each packet's reference ciphertext and tag before sending its plaintext.
Shared AXI helpers check transfers and stalled-beat stability; final assertions
reject mismatches and incomplete runs. tb_common_sim.py selects packet lengths
and stress patterns; PERF selects perf_tb_common.py's coordinated phases.
See ../../README.md#simulation for run instructions and encrypt_syn_tb.py for
the fixed-vector testbench.
"""
import wireguard_env  # noqa: F401

import random

from pypeline import (
    MAIN,
    final,
    initial,
    sim_input,
    sim_output,
    sim_print,
    uint1_t,
)

import chacha20poly1305_encrypt_ports

from aead_types import (
    aead_axis_if_t,
    AEAD_BEAT_BYTES,
)
from axi.axis_sim import AxisSimSink, Scoreboard
import tb_common_sim as common

# Callbacks use detached copies of module globals: mutate this dictionary in
# place so they and chacha20poly1305_tb.py's completion checker share updates.
enc_state = {
    "rng": None,  # created by start()
    "errors": 0,
    "in_packet_idx": 0,
    "gen_log": [],  # plaintext lengths in generation order, for reporting
    "printed_gen_count": 0,
    "out_packet_idx": 0,  # packets checked; also used by the completion checker
    "cycle": 0,
    "last_move": 0,  # cycle of the last accepted input or output beat
}

_scoreboard = Scoreboard()
# Per-packet coverage facts; chacha20poly1305_tb.py writes them out.
packet_log = common.PacketLog("encrypt")
_src = common.ConvergedAxisSource(aead_axis_if_t, AEAD_BEAT_BYTES)
if common.PERF:
    import perf_tb_common as perf

    _snk = AxisSimSink(aead_axis_if_t, AEAD_BEAT_BYTES, scoreboard=_scoreboard)
    _runner = perf.make_runner("encrypt", _src, _snk, _scoreboard, perf.encrypt_frame_builder)
else:
    _snk = common.ConvergedAxisSink(aead_axis_if_t, AEAD_BEAT_BYTES, scoreboard=_scoreboard)


@sim_input
def drive_in_word() -> aead_axis_if_t.stream_t:
    if common.PERF:
        _runner.prepare_input()
        return _src.drive().stream

    if enc_state["in_packet_idx"] < common.NUM_RANDOM_PACKETS and _src.idle():
        # Generate one packet and its independent reference when the source is idle.
        idx = enc_state["in_packet_idx"]
        length = common.next_packet_length(enc_state["rng"], idx)
        plaintext, ciphertext, tag = common.generate_packet(enc_state["rng"], length)
        enc_state["gen_log"].append(length)
        _scoreboard.expect(ciphertext + tag, idx=idx, length=length)
        _src.send(plaintext)
        enc_state["in_packet_idx"] += 1

    return _src.drive(common.input_paused("encrypt", enc_state["cycle"])).stream


@sim_input
def drive_out_ready() -> uint1_t:
    return common.output_ready("encrypt", enc_state["cycle"])


@initial(sim=True)
def start():
    if common.PERF:
        sim_print("=== ChaCha20-Poly1305 PERFORMANCE measurement (encrypt side) ===")
        sim_print(f"Encrypt: phases = {[p['name'] for p in perf.PHASES]}")
        sim_print(f"Encrypt: seed = {perf.SEED}, json = {perf.JSON_PATH or '(none)'}")
        return
    enc_state["rng"] = random.Random(common.SEED)
    sim_print(
        "=== ChaCha20-Poly1305 Encryption Test (non-synthesizable, on-the-fly random vectors) ==="
    )
    sim_print(f"Encrypt: RNG seed = {common.SEED}")
    sim_print(f"Encrypt Key: {bytes(common.KEY).hex()}")
    sim_print(f"Encrypt Nonce: {bytes(common.NONCE).hex()}")


@sim_output
def report_new_packets():
    # Report from @sim_output, after this cycle's input generation.
    while enc_state["printed_gen_count"] < len(enc_state["gen_log"]):
        idx = enc_state["printed_gen_count"]
        length = enc_state["gen_log"][idx]
        sim_print(f"Encrypt: Generated packet {idx} ({length} bytes)")
        enc_state["printed_gen_count"] += 1


@sim_output
def check_out():
    # Commit input acceptance and sample output after ready/valid have settled.
    ready = int(chacha20poly1305_encrypt_ports.axis_in_if.ready)
    incoming = chacha20poly1305_encrypt_ports.axis_in_if.stream
    if common.PERF:
        valid = int(incoming.valid)
        _runner.note_in(
            valid=valid,
            ready=ready,
            keep_count=perf.keep_count(incoming) if valid else 0,
            eod=int(incoming.data.eod[0]),
        )
    else:
        enc_state["cycle"] += 1
        packet_log.note_input(
            enc_state["cycle"], int(incoming.valid), ready, int(incoming.data.eod[0])
        )
    accepted_in = _src.commit(ready)
    out = chacha20poly1305_encrypt_ports.axis_out_if.stream
    if common.PERF:
        _runner.note_out(
            valid=int(out.valid),
            keep_count=perf.keep_count(out) if out.valid else 0,
            eod=int(out.data.eod[0]),
        )
        _snk.step(aead_axis_if_t.fwd_t(out))
    else:
        _snk.step(
            aead_axis_if_t.fwd_t(out),
            ready=chacha20poly1305_encrypt_ports.axis_out_if.ready,
        )
        if accepted_in or (
            int(out.valid) and int(chacha20poly1305_encrypt_ports.axis_out_if.ready)
        ):
            enc_state["last_move"] = enc_state["cycle"]
    result = _snk.check_nowait()
    if result is not None:
        if common.PERF:
            _runner.note_checked(
                result["passed"], perf.packet_mismatch_message(result, "Ciphertext/Tag")
            )
        else:
            idx = result.get("idx", "?")
            common.check_packet_result("Encrypt", "Ciphertext/Tag", enc_state, result)
            packet_log.note_output(enc_state["cycle"], result, _snk.stalled_cycles)
            sim_print(f"Encrypt: Test {idx} DONE!")
            enc_state["out_packet_idx"] += 1
    if common.PERF:
        for line in _runner.drain_log():
            sim_print(line)
        _runner.tick()


@final(sim=True)
def finish_checks():
    if not common.PERF:
        common.check_completion("Encrypt", enc_state, common.NUM_RANDOM_PACKETS, _scoreboard)


# Simulation-only MAINs: this testbench has no hardware. The driver runs once per cycle,
# before the cycle converges; the checker after it, on the converged wires.
@MAIN
@sim_input
def encrypt_tb_drive():
    chacha20poly1305_encrypt_ports.key = common.KEY
    chacha20poly1305_encrypt_ports.nonce = common.NONCE
    chacha20poly1305_encrypt_ports.aad = common.AAD
    chacha20poly1305_encrypt_ports.aad_len = common.AAD_LEN

    chacha20poly1305_encrypt_ports.axis_in_if.stream = drive_in_word()
    chacha20poly1305_encrypt_ports.axis_out_if.ready = 1
    if not common.PERF and common.STRESS:
        chacha20poly1305_encrypt_ports.axis_out_if.ready = drive_out_ready()


@MAIN
@sim_output
def encrypt_tb_check():
    if not common.PERF:
        report_new_packets()
    check_out()
