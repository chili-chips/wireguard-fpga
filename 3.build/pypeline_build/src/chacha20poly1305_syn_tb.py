# SPDX-FileCopyrightText: 2026 Julian Kemmerer
# SPDX-FileCopyrightText: 2026 Chili.CHIPS
#
# SPDX-License-Identifier: BSD-3-Clause

# pyright: reportInvalidTypeForm=none
"""Fixed-vector simulation top for the selected design and sharing configuration.

Both enabled directions run concurrently; decryption includes a tampered-tag
packet. See ../README.md#simulation for commands and simulator choices, or
chacha20poly1305_tb.py for the random-vector top.

Pypeline port of ../pipelinec_build/src/chacha20poly1305_{encrypt,decrypt,
encrypt_decrypt_shared}_tb.c.
"""

import wireguard_env

from pypeline import MAIN, PART, sim_finish, uint1_t, wires

PART("xc7a200tffg1156-2")  # Artix 7 200T

ENCRYPT = wireguard_env.ENCRYPT
DECRYPT = wireguard_env.DECRYPT

# Imports expose the selected MAINs; testbenches drive the structured ports directly.
if ENCRYPT:
    import encrypt_dataflow  # noqa: F401
    import encrypt_syn_tb
    from chacha20poly1305_encrypt_ports import encrypt_port_waves
if DECRYPT:
    import decrypt_dataflow  # noqa: F401
    import decrypt_syn_tb
    from chacha20poly1305_decrypt_ports import decrypt_port_waves


# Wait for every enabled direction's completion Wire so neither run is cut short.
# This MAIN is built into the simulated HDL, where sim_finish() is a VHDL finish. It only
# reads wires, so @wires keeps it out of timing characterization.
# A waveform (--wave) gets the flat ports first, so the finishing cycle has them too.
@MAIN(wireguard_env.TARGET_MHZ)
@wires
def syn_tb_finish_checker():
    done: uint1_t = 1
    if ENCRYPT:
        encrypt_port_waves()
        done = done & encrypt_syn_tb.encrypt_all_done
    if DECRYPT:
        decrypt_port_waves()
        done = done & decrypt_syn_tb.decrypt_all_done
    if done:
        sim_finish()
