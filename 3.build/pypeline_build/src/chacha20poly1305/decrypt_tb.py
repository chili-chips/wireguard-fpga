# pyright: reportInvalidTypeForm=none
# SPDX-FileCopyrightText: 2026 Chili.CHIPS*ba
# SPDX-License-Identifier: BSD-3-Clause

"""Native decrypt driver for correctness and performance simulation.

Send reference ciphertext and tags; check the returned plaintext and verdict.
Tampered tags must still return plaintext with a false verdict. Shared AXI
helpers check transfers and stalled-beat stability; final assertions reject
mismatches and incomplete runs. tb_common_sim.py selects packet lengths and
stress patterns; PERF selects valid packets in perf_tb_common.py's phases.
See ../../README.md#simulation for run instructions and
decrypt_syn_tb.py for the fixed-vector testbench.
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

import chacha20poly1305_decrypt_ports

from aead_types import (
    aead_axis_if_t,
    AEAD_BEAT_BYTES,
)
from axi.axis_sim import AxisSimSink, Scoreboard
import tb_common_sim as common

NUM_TOTAL_PACKETS = common.NUM_RANDOM_PACKETS + 1  # final packet has a tampered tag

# Callbacks use detached copies of module globals: mutate this dictionary in
# place so they and chacha20poly1305_tb.py's completion checker share updates.
dec_state = {
    "rng": None,  # created by start()
    "errors": 0,
    "in_packet_idx": 0,
    "gen_log": [],  # (plaintext length, expected verdict) entries for reporting
    "printed_gen_count": 0,
    "out_packet_idx": 0,  # packets checked; also used by the completion checker
    "cycle": 0,
    "last_move": 0,  # cycle of the last accepted input or output beat
    "verdict_beats": 0,  # accepted output beats whose verdict was checked
}

_scoreboard = Scoreboard()
# Per-packet coverage facts; chacha20poly1305_tb.py writes them out.
packet_log = common.PacketLog("decrypt")
_src = common.ConvergedAxisSource(aead_axis_if_t, AEAD_BEAT_BYTES)
if common.PERF:
    import perf_tb_common as perf

    _snk = AxisSimSink(aead_axis_if_t, AEAD_BEAT_BYTES, scoreboard=_scoreboard)
    _runner = perf.make_runner("decrypt", _src, _snk, _scoreboard, perf.decrypt_frame_builder)
else:
    _snk = common.ConvergedAxisSink(aead_axis_if_t, AEAD_BEAT_BYTES, scoreboard=_scoreboard)


def _generate_packet(rng: random.Random, packet_idx: int) -> dict:
    """Generate a reference packet, corrupting its tag for negative cases."""
    if packet_idx < common.NUM_RANDOM_PACKETS:
        length = common.next_packet_length(rng, packet_idx)
    else:
        length = rng.randint(common.PACKET_LEN_MIN, common.PACKET_LEN_MAX)

    plaintext, ciphertext, tag = common.generate_packet(rng, length)

    # Always end with a bad tag. Stress also rejects a middle packet to check
    # tag/verdict alignment when valid packets follow it.
    tamper = packet_idx >= common.NUM_RANDOM_PACKETS or (
        common.STRESS and packet_idx == common.NUM_RANDOM_PACKETS // 2
    )
    if tamper:
        tag = bytes([tag[0] ^ 1]) + tag[1:]

    return {
        "plaintext": plaintext,
        "ciphertext": ciphertext,
        "tag": tag,
        "expected_verified": int(not tamper),
    }


@sim_input
def drive_in_word() -> aead_axis_if_t.stream_t:
    if common.PERF:
        _runner.prepare_input()
        return _src.drive().stream

    if dec_state["in_packet_idx"] < NUM_TOTAL_PACKETS and _src.idle():
        idx = dec_state["in_packet_idx"]
        pkt = _generate_packet(dec_state["rng"], idx)
        dec_state["gen_log"].append((len(pkt["plaintext"]), pkt["expected_verified"]))
        _scoreboard.expect(
            pkt["plaintext"],
            idx=idx,
            length=len(pkt["plaintext"]),
            expected_verified=pkt["expected_verified"],
        )
        # The tag follows ciphertext without padding; the source derives keep.
        _src.send(pkt["ciphertext"] + pkt["tag"])
        dec_state["in_packet_idx"] += 1

    return _src.drive(common.input_paused("decrypt", dec_state["cycle"])).stream


@sim_input
def drive_out_ready() -> uint1_t:
    return common.output_ready("decrypt", dec_state["cycle"])


@initial(sim=True)
def start():
    if common.PERF:
        sim_print("=== ChaCha20-Poly1305 PERFORMANCE measurement (decrypt side) ===")
        sim_print(f"Decrypt: phases = {[p['name'] for p in perf.PHASES]}")
        sim_print(f"Decrypt: seed = {perf.SEED}, json = {perf.JSON_PATH or '(none)'}")
        return
    dec_state["rng"] = random.Random(common.SEED)
    sim_print(
        "=== ChaCha20-Poly1305 Decryption Test (non-synthesizable, on-the-fly random vectors) ==="
    )
    sim_print(f"Decrypt: RNG seed = {common.SEED}")
    sim_print(f"Decrypt Key: {bytes(common.KEY).hex()}")
    sim_print(f"Decrypt Nonce: {bytes(common.NONCE).hex()}")


@sim_output
def report_new_packets():
    # Report from @sim_output, after this cycle's input generation.
    while dec_state["printed_gen_count"] < len(dec_state["gen_log"]):
        idx = dec_state["printed_gen_count"]
        length, expected_verified = dec_state["gen_log"][idx]
        tamper_note = "" if expected_verified else " [tampered tag, expect reject]"
        sim_print(f"Decrypt: Generated packet {idx} ({length} bytes){tamper_note}")
        dec_state["printed_gen_count"] += 1


@sim_output
def check_out():
    # Commit input acceptance and sample output after ready/valid have settled.
    ready = int(chacha20poly1305_decrypt_ports.axis_in_if.ready)
    incoming = chacha20poly1305_decrypt_ports.axis_in_if.stream
    if common.PERF:
        valid = int(incoming.valid)
        _runner.note_in(
            valid=valid,
            ready=ready,
            keep_count=perf.keep_count(incoming) if valid else 0,
            eod=int(incoming.data.eod[0]),
        )
    else:
        dec_state["cycle"] += 1
        packet_log.note_input(
            dec_state["cycle"], int(incoming.valid), ready, int(incoming.data.eod[0])
        )
    accepted_in = _src.commit(ready)
    out = chacha20poly1305_decrypt_ports.axis_out_if.stream
    # Include the verdict in stalled-beat checks. PERF compares its expected
    # value when the packet completes; otherwise every accepted beat must carry it.
    got_verified = chacha20poly1305_decrypt_ports.is_verified_out
    accepted_out = int(out.valid) and int(chacha20poly1305_decrypt_ports.axis_out_if.ready)
    if not common.PERF and accepted_out:
        idx = dec_state["out_packet_idx"]
        # An output beat with no packet in flight is reported by the scoreboard
        # once its frame ends; here it has no verdict to compare.
        if idx < len(dec_state["gen_log"]):
            dec_state["verdict_beats"] += 1
            expected_verified = dec_state["gen_log"][idx][1]
            if int(got_verified) != expected_verified:
                dec_state["errors"] += 1
                sim_print(
                    f"ERROR: Decrypt: is_verified mismatch packet {idx} on accepted "
                    f"output beat {dec_state['verdict_beats']}. "
                    f"expected {expected_verified} got {got_verified}"
                )
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
            ready=chacha20poly1305_decrypt_ports.axis_out_if.ready,
            sideband=got_verified,
        )
        if accepted_in or accepted_out:
            dec_state["last_move"] = dec_state["cycle"]
    result = _snk.check_nowait()
    if result is not None:
        idx = result.get("idx", "?")
        if common.PERF:
            expected_verified = result.get("expected_verified")
            verdict_mismatch = expected_verified is not None and got_verified != expected_verified
            message = perf.packet_mismatch_message(result, "Plaintext")
            if verdict_mismatch:
                message = (
                    f"is_verified mismatch packet {idx}: expected "
                    f"{expected_verified} got {got_verified}"
                )
            _runner.note_checked(result["passed"] and not verdict_mismatch, message)
        else:
            common.check_packet_result("Decrypt", "Plaintext", dec_state, result)
            packet_log.note_output(dec_state["cycle"], result, _snk.stalled_cycles, got_verified)
            sim_print(f"Decrypt: Test {idx} DONE!")
            dec_state["out_packet_idx"] += 1
    if common.PERF:
        for line in _runner.drain_log():
            sim_print(line)
        _runner.tick()


@final(sim=True)
def finish_checks():
    if not common.PERF:
        common.check_completion("Decrypt", dec_state, NUM_TOTAL_PACKETS, _scoreboard)


# Simulation-only MAINs: this testbench has no hardware. The driver runs once per cycle,
# before the cycle converges; the checker after it, on the converged wires.
@MAIN
@sim_input
def decrypt_tb_drive():
    chacha20poly1305_decrypt_ports.key = common.KEY
    chacha20poly1305_decrypt_ports.nonce = common.NONCE
    chacha20poly1305_decrypt_ports.aad = common.AAD
    chacha20poly1305_decrypt_ports.aad_len = common.AAD_LEN

    chacha20poly1305_decrypt_ports.axis_in_if.stream = drive_in_word()
    chacha20poly1305_decrypt_ports.axis_out_if.ready = 1
    if not common.PERF and common.STRESS:
        chacha20poly1305_decrypt_ports.axis_out_if.ready = drive_out_ready()


@MAIN
@sim_output
def decrypt_tb_check():
    if not common.PERF:
        report_new_packets()
    check_out()
