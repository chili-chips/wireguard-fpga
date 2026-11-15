# pyright: reportInvalidTypeForm=none
# SPDX-FileCopyrightText: 2026 Chili.CHIPS*ba
# SPDX-License-Identifier: BSD-3-Clause

"""Native correctness/performance top for the selected design and sharing configuration.

Both enabled directions run concurrently using @sim_input/@sim_output. PERF
selects coordinated packet-size phases and JSON recording instead of random
or stress traffic. See ../README.md#simulation and #throughput-measurement for
commands, or chacha20poly1305_syn_tb.py for the fixed-vector top.
"""

import wireguard_env

from pypeline import MAIN, PART, DesignParamError, final, sim_finish, sim_output, sim_print, wires

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
if wireguard_env.DECRYPT:
    import decrypt_tb

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


# Read the host-side packet counts and wait for every enabled direction.
@sim_output
def check_done():
    if common.PERF:
        if perf.all_done():
            sim_finish()
        return
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


# @wires lets native simulation run this control MAIN without saved hardware latency.
@MAIN(wireguard_env.TARGET_MHZ)
@wires
def tb_finish_checker():
    check_done()
