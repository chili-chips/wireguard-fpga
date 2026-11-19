# pyright: reportInvalidTypeForm=none
# SPDX-FileCopyrightText: 2026 Chili.CHIPS*ba
# SPDX-License-Identifier: BSD-3-Clause

"""Native correctness/performance top for the selected design and sharing configuration.

Both enabled directions run concurrently using @sim_input/@sim_output. PERF
selects coordinated packet-size phases and JSON recording instead of random
or stress traffic. TB_COVERAGE_JSON makes a random run write the facts that
measure.py --coverage bins. See ../README.md#simulation, #functional-coverage and
#throughput-measurement for commands, or chacha20poly1305_syn_tb.py for the
fixed-vector top.
"""

import wireguard_env

from pypeline import MAIN, PART, DesignParamError, final, sim_finish, sim_output, sim_print

import tb_common_sim as common

if common.PERF and wireguard_env.DESIGN != "shared":
    raise DesignParamError(
        "The performance testbench measures the combined design: build it with "
        "DESIGN=shared (./build.py --perf); measure.py --dirs selects "
        "the measured directions"
    )

PART("xc7a200tffg1156-2")  # Artix 7 200T

# Import all selected dataflows before perf_tb_common snapshots their metadata.
if wireguard_env.ENCRYPT:
    import encrypt_dataflow  # noqa: F401
if wireguard_env.DECRYPT:
    import decrypt_dataflow  # noqa: F401

# Both performance runners register even when PERF_DIRS leaves one idle.
if wireguard_env.ENCRYPT:
    import encrypt_tb
    from chacha20poly1305_encrypt_ports import encrypt_port_waves
if wireguard_env.DECRYPT:
    import decrypt_tb
    from chacha20poly1305_decrypt_ports import decrypt_port_waves

if common.PERF:
    import perf_tb_common as perf

    @final(sim=True)
    def write_results():
        # Retain partial phase results without marking an interrupted run complete.
        if not perf.all_done():
            sim_print(
                "PERF: simulation ended before every phase finished -- "
                f"{perf.JSON_PATH or '(no PERF_JSON set)'} left unfinalized"
            )
            return
        perf.finalize()
        for line in perf.summary_lines():
            sim_print("PERF: " + line)
        sim_print(f"PERF: wrote {perf.JSON_PATH or '(no PERF_JSON set)'}")


if common.COVERAGE_JSON and not common.PERF:
    from aead_types import AEAD_BEAT_BYTES, AEAD_MAX_PLAINTEXT_BYTES, buffering_metadata
    from poly1305_select import implementation_metadata

    @final(sim=True)
    def write_coverage():
        # Runs even when a checker failed, so a failing run still leaves its facts.
        runs = []
        if wireguard_env.ENCRYPT:
            runs.append((encrypt_tb.packet_log, encrypt_tb.enc_state))
        if wireguard_env.DECRYPT:
            runs.append((decrypt_tb.packet_log, decrypt_tb.dec_state))
        metadata = {
            "design": wireguard_env.DESIGN,
            "sharing": wireguard_env.SHARING,
            "data_bitwidth": wireguard_env.DATA_BITWIDTH,
            "beat_bytes": AEAD_BEAT_BYTES,
            "max_packet_bytes": AEAD_MAX_PLAINTEXT_BYTES,
            "aad_len": common.AAD_LEN,
            "poly1305": implementation_metadata(),
            "buffering": buffering_metadata(),
            "cycles": {log.direction: state["cycle"] for log, state in runs},
            "params": {
                "TB_STRESS": bool(common.STRESS),
                "TB_CLOSURE": bool(common.CLOSURE),
                "TB_SEED": common.SEED,
                "TB_PACKETS": common.PACKETS,
                "random_packets": common.NUM_RANDOM_PACKETS,
            },
        }
        common.write_coverage(common.COVERAGE_JSON, metadata, [log for log, _ in runs])


# Read the host-side packet counts and wait for every enabled direction.
@sim_output
def check_done():
    if common.PERF:
        if perf.all_done():
            sim_finish()
        return
    if wireguard_env.ENCRYPT:
        common.check_progress("Encrypt", encrypt_tb.enc_state, common.NUM_RANDOM_PACKETS)
    if wireguard_env.DECRYPT:
        common.check_progress("Decrypt", decrypt_tb.dec_state, decrypt_tb.NUM_TOTAL_PACKETS)
    if (
        wireguard_env.ENCRYPT
        and encrypt_tb.enc_state["out_packet_idx"] < common.NUM_RANDOM_PACKETS
    ):
        return
    if (
        wireguard_env.DECRYPT
        and decrypt_tb.dec_state["out_packet_idx"] < decrypt_tb.NUM_TOTAL_PACKETS
    ):
        return
    sim_finish()


# A simulation-only MAIN, registered after both directions' so their last checks run first.
# A waveform (--wave) gets the flat ports first, so a finishing cycle has them too.
@MAIN
@sim_output
def tb_finish_checker():
    if wireguard_env.ENCRYPT:
        encrypt_port_waves()
    if wireguard_env.DECRYPT:
        decrypt_port_waves()
    check_done()
