# pyright: reportInvalidTypeForm=none
"""Shared ChaCha20 compute pipeline for the encrypt+decrypt shared design.

One MAIN arbitrates requests and routes results by direction. Each direction
keeps its own ChaCha20 FSM, with the same interface as chacha20_if_func.

Pypeline port of ../pipelinec_build/src/chacha20/chacha20_pipeline_shared.c
"""
import wireguard_env  # noqa: F401

from pypeline import (
    MAIN,
    NamedTuple,
    struct,
    hw_func,
    Wire,
    Reg,
    Feedback,
    uint1_t,
    uint8_t,
)
from stream import make_stream_interface
from stream.stream_auto_pipeline import make_stream_auto_pipeline

from stream import stream_perf_probe as perf_taps

import chacha20
from chacha20 import (
    chacha20_loop_body_in_t,
    chacha20_loop_body_stream_if_t,
    chacha20_loop_body_in_null,
)

from aead_types import (
    CHACHA20_KEY_SIZE,
    CHACHA20_NONCE_SIZE,
    aead_axis_if_t,
    axis512_frag_t,
    axis512_if_t,
    axis512_stream_null,
    poly1305_key_stream_if_t,
)


# Carry the requesting direction through the pipeline with each block.
@struct
class chacha_shared_pipeline_in_t(NamedTuple):
    data: chacha20_loop_body_in_t
    is_encrypt: uint1_t


@struct
class chacha_shared_pipeline_out_t(NamedTuple):
    data: axis512_frag_t
    is_encrypt: uint1_t


chacha_shared_pipeline_in_stream_if_t = make_stream_interface(chacha_shared_pipeline_in_t)
chacha_shared_pipeline_out_stream_if_t = make_stream_interface(chacha_shared_pipeline_out_t)


def chacha_shared_pipeline_in_stream_null():
    return chacha_shared_pipeline_in_stream_if_t.stream_t(
        data=chacha_shared_pipeline_in_t(data=chacha20_loop_body_in_null(), is_encrypt=0),
        valid=0,
    )


@hw_func
def chacha_shared_pipeline(
    inputs: chacha_shared_pipeline_in_t,
) -> chacha_shared_pipeline_out_t:
    outputs: chacha_shared_pipeline_out_t
    outputs.data = chacha20.chacha20_loop_body(inputs.data)
    outputs.is_encrypt = inputs.is_encrypt
    return outputs


pipeline_func = make_stream_auto_pipeline(chacha_shared_pipeline, name="chacha20_shared")


# Each direction connects its FSM to the shared MAIN through these interfaces.
# Stream data and ready travel in opposite directions.
encrypt_pipeline_in_if: Wire[chacha20_loop_body_stream_if_t]
decrypt_pipeline_in_if: Wire[chacha20_loop_body_stream_if_t]
encrypt_pipeline_out_if: Wire[axis512_if_t]
decrypt_pipeline_out_if: Wire[axis512_if_t]


# Round-robin request arbitration and result routing around one shared pipeline.
@MAIN(wireguard_env.TARGET_MHZ)
def chacha20_pipeline_shared():
    pipeline_in_ready: Feedback[uint1_t]
    pipeline_out: Feedback[chacha_shared_pipeline_out_stream_if_t.stream_t]

    # Default to idle; drive the interfaces after arbitration and result routing.
    pipeline_in_s: chacha_shared_pipeline_in_stream_if_t.stream_t = (
        chacha_shared_pipeline_in_stream_null()
    )
    pipeline_out_ready_s: uint1_t = 0
    encrypt_pipeline_out_s: axis512_if_t.stream_t = axis512_stream_null()
    encrypt_pipeline_in_ready_s: uint1_t = 0
    decrypt_pipeline_out_s: axis512_if_t.stream_t = axis512_stream_null()
    decrypt_pipeline_in_ready_s: uint1_t = 0

    # Decrypt has initial priority. Advance only on an accepted launch, and
    # hold the selected direction while its valid input is stalled.
    priority_encrypt: Reg[uint1_t]
    grant_stalled: Reg[uint1_t]
    stalled_is_encrypt: Reg[uint1_t]
    encrypt_valid: uint1_t = encrypt_pipeline_in_if.stream.valid
    decrypt_valid: uint1_t = decrypt_pipeline_in_if.stream.valid
    is_encrypt: uint1_t = priority_encrypt
    if grant_stalled:
        is_encrypt = stalled_is_encrypt
        if is_encrypt:
            encrypt_pipeline_in_ready_s = pipeline_in_ready
        else:
            decrypt_pipeline_in_ready_s = pipeline_in_ready
    else:
        if encrypt_valid & ~decrypt_valid:
            is_encrypt = 1
        elif decrypt_valid & ~encrypt_valid:
            is_encrypt = 0
        # Each ready depends on priority and the OTHER requester's valid.
        # With neither requesting, both see the pipeline's readiness.
        encrypt_pipeline_in_ready_s = pipeline_in_ready & (
            priority_encrypt | ~decrypt_valid
        )
        decrypt_pipeline_in_ready_s = pipeline_in_ready & (
            ~priority_encrypt | ~encrypt_valid
        )

    pipeline_in_s.data.is_encrypt = is_encrypt
    if is_encrypt:
        pipeline_in_s.data.data = encrypt_pipeline_in_if.stream.data
        pipeline_in_s.valid = encrypt_valid
    else:
        pipeline_in_s.data.data = decrypt_pipeline_in_if.stream.data
        pipeline_in_s.valid = decrypt_valid

    # Simulation probes sample the actual grant, including a held grant.
    perf_taps.arb(
        "pipe.arb",
        is_encrypt,
        encrypt_pipeline_in_if.stream.valid,
        decrypt_pipeline_in_if.stream.valid,
        pipeline_in_ready,
        "encrypt",
        "decrypt",
    )
    perf_taps.hs(
        "pipe.enc_in",
        encrypt_pipeline_in_if.stream.valid,
        encrypt_pipeline_in_ready_s,
    )
    perf_taps.hs(
        "pipe.dec_in",
        decrypt_pipeline_in_if.stream.valid,
        decrypt_pipeline_in_ready_s,
    )

    if pipeline_in_s.valid & pipeline_in_ready:
        priority_encrypt = ~is_encrypt
        grant_stalled = 0
    elif pipeline_in_s.valid:
        grant_stalled = 1
        stalled_is_encrypt = is_encrypt

    # Route each result and its receiver's ready signal by the direction tag.
    if pipeline_out.valid:
        if pipeline_out.data.is_encrypt:
            encrypt_pipeline_out_s.data = pipeline_out.data.data
            encrypt_pipeline_out_s.valid = pipeline_out.valid
            pipeline_out_ready_s = encrypt_pipeline_out_if.ready
        else:
            decrypt_pipeline_out_s.data = pipeline_out.data.data
            decrypt_pipeline_out_s.valid = pipeline_out.valid
            pipeline_out_ready_s = decrypt_pipeline_out_if.ready

    # Drive output wires
    encrypt_pipeline_out_if.stream = encrypt_pipeline_out_s
    encrypt_pipeline_in_if.ready = encrypt_pipeline_in_ready_s
    decrypt_pipeline_out_if.stream = decrypt_pipeline_out_s
    decrypt_pipeline_in_if.ready = decrypt_pipeline_in_ready_s

    # Output side, after the demux has driven both directions' streams.
    perf_taps.hs(
        "pipe.enc_out", encrypt_pipeline_out_s.valid, encrypt_pipeline_out_if.ready
    )
    perf_taps.hs(
        "pipe.dec_out", decrypt_pipeline_out_s.valid, decrypt_pipeline_out_if.ready
    )

    result = pipeline_func(
        stream_in_if=chacha_shared_pipeline_in_stream_if_t.fwd_t(pipeline_in_s),
        stream_out_if=chacha_shared_pipeline_out_stream_if_t.fb_t(pipeline_out_ready_s),
    )
    pipeline_out = result.stream_out_if.stream
    pipeline_in_ready = result.stream_in_if.ready


# Per-direction adapters retain chacha20_if_func's interface and connect the
# same ChaCha20 FSM to the shared pipeline.
@hw_func
def chacha20_encrypt_shared_adapter(
    key: uint8_t[CHACHA20_KEY_SIZE],
    nonce: uint8_t[CHACHA20_NONCE_SIZE],
    axis_in_if: aead_axis_if_t.fwd_t,
    key_if: poly1305_key_stream_if_t.fb_t,
    axis_out_if: aead_axis_if_t.fb_t,
) -> chacha20.chacha20_if_func.return_t:
    o: chacha20.chacha20_if_func.return_t
    from_pipe_fwd: axis512_if_t.stream_t = encrypt_pipeline_out_if.stream
    fsm_out = chacha20.chacha20_fsm(
        key=key,
        nonce=nonce,
        axis_in_if=axis_in_if,
        key_if=key_if,
        axis_out_if=axis_out_if,
        to_pipeline_if=chacha20.chacha20_loop_body_stream_if_t.fb_t(
            encrypt_pipeline_in_if.ready
        ),
        from_pipeline_if=axis512_if_t.fwd_t(from_pipe_fwd),
    )
    o.axis_in_if = fsm_out.axis_in_if
    o.key_if = fsm_out.key_if
    o.axis_out_if = fsm_out.axis_out_if
    encrypt_pipeline_in_if.stream = fsm_out.to_pipeline_if.stream
    encrypt_pipeline_out_if.ready = fsm_out.from_pipeline_if.ready
    return o


@hw_func
def chacha20_decrypt_shared_adapter(
    key: uint8_t[CHACHA20_KEY_SIZE],
    nonce: uint8_t[CHACHA20_NONCE_SIZE],
    axis_in_if: aead_axis_if_t.fwd_t,
    key_if: poly1305_key_stream_if_t.fb_t,
    axis_out_if: aead_axis_if_t.fb_t,
) -> chacha20.chacha20_if_func.return_t:
    o: chacha20.chacha20_if_func.return_t
    from_pipe_fwd: axis512_if_t.stream_t = decrypt_pipeline_out_if.stream
    fsm_out = chacha20.chacha20_fsm(
        key=key,
        nonce=nonce,
        axis_in_if=axis_in_if,
        key_if=key_if,
        axis_out_if=axis_out_if,
        to_pipeline_if=chacha20.chacha20_loop_body_stream_if_t.fb_t(
            decrypt_pipeline_in_if.ready
        ),
        from_pipeline_if=axis512_if_t.fwd_t(from_pipe_fwd),
    )
    o.axis_in_if = fsm_out.axis_in_if
    o.key_if = fsm_out.key_if
    o.axis_out_if = fsm_out.axis_out_if
    decrypt_pipeline_in_if.stream = fsm_out.to_pipeline_if.stream
    decrypt_pipeline_out_if.ready = fsm_out.from_pipeline_if.ready
    return o


# Plain elaboration metadata: size consumers from this selected shared wrapper.
chacha20_encrypt_shared_adapter.pipeline_func = pipeline_func
chacha20_decrypt_shared_adapter.pipeline_func = pipeline_func
