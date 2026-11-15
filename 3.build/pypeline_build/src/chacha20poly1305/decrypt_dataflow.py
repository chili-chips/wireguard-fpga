# pyright: reportInvalidTypeForm=none
"""Select decrypt resources and connect the dataflow core to the port wires.

Pypeline port of ../pipelinec_build/src/chacha20poly1305/decrypt_dataflow.c.
"""
import wireguard_env

from pypeline import MAIN

import chacha20poly1305_decrypt_ports
from poly1305_select import make_poly1305_mac

if wireguard_env.SHARING["chacha20"]:
    import chacha20_pipeline_shared

    chacha_func = chacha20_pipeline_shared.chacha20_decrypt_shared_adapter
else:
    import chacha20

    chacha_func = chacha20.chacha20_if_func
if wireguard_env.SHARING["poly1305"]:
    # Expose the shared compute units' MAINs and wires for discovery.
    import poly1305_compute_shared  # noqa: F401

from aead_types import aead_axis_intrf
from decrypt_dataflow_core import make_decrypt_dataflow_core

decrypt_dataflow_core = make_decrypt_dataflow_core(
    chacha_func, make_poly1305_mac("decrypt", share_compute=wireguard_env.SHARING["poly1305"])
)


@MAIN(wireguard_env.TARGET_MHZ)
def decrypt_dataflow():
    # Connect the core's forward and feedback halves explicitly at the port boundary.
    r = decrypt_dataflow_core(
        axis_in_if=aead_axis_intrf.fwd_t(chacha20poly1305_decrypt_ports.axis_in_if.stream),
        key=chacha20poly1305_decrypt_ports.key,
        nonce=chacha20poly1305_decrypt_ports.nonce,
        aad=chacha20poly1305_decrypt_ports.aad,
        aad_len=chacha20poly1305_decrypt_ports.aad_len,
        axis_out_if=aead_axis_intrf.fb_t(chacha20poly1305_decrypt_ports.axis_out_if.ready),
    )
    chacha20poly1305_decrypt_ports.axis_in_if.ready = r.axis_in_if.ready
    chacha20poly1305_decrypt_ports.axis_out_if.stream = r.axis_out_if.stream
    chacha20poly1305_decrypt_ports.is_verified_out = r.is_verified_out
