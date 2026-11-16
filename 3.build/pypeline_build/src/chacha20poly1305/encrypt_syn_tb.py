# pyright: reportInvalidTypeForm=none
"""Fixed-vector encrypt testbench with hardware stream drivers and checkers.

Pypeline port of ../../../pipelinec_build/src/chacha20poly1305/encrypt_tb.c.
tb_common.py supplies plaintexts and independent reference ciphertext/tags;
shared AXI helpers stream and collect packets. See ../../README.md#simulation
for run instructions, or encrypt_tb.py for the native random-vector testbench.
"""
import wireguard_env  # noqa: F401

from pypeline import (
    MAIN,
    Wire,
    Feedback,
    Reg,
    uint1_t,
    uint8_t,
    uint32_t,
    initial,
    sim_assert,
    sim_print,
    hex,
)

import chacha20poly1305_encrypt_ports

from aead_types import (
    CHACHA20_KEY_SIZE,
    CHACHA20_NONCE_SIZE,
    AAD_MAX_LEN,
    aead_axis_if_t,
    AEAD_BEAT_BYTES,
)
from axi.axis import make_axis_byte_source, make_axis_byte_sink
from tb_common import (
    KEY,
    NONCE,
    AAD,
    AAD_LEN,
    NUM_PLAINTEXT_TEST_STRS,
    PLAINTEXT_TEST_STR_MAX_SIZE,
    PLAINTEXTS,
    PLAINTEXT_LENS,
    POLY1305_AUTH_TAG_SIZE,
    CIPHERTEXT_MAX_SIZE,
    EXPECTED_CIPHERTEXTS,
    EXPECTED_TAGS,
    CIPHERTEXT_LENS,
    pack_ciphertext_frames,
)

# Pack each ciphertext and tag without a gap. Trim the padded ciphertext
# using CIPHERTEXT_LENS, then pad the combined frame for the fixed-size array.
OUT_FRAME_MAX_SIZE = CIPHERTEXT_MAX_SIZE + POLY1305_AUTH_TAG_SIZE
EXPECTED_OUT_FRAMES, EXPECTED_OUT_FRAME_LENS = pack_ciphertext_frames(
    EXPECTED_CIPHERTEXTS, EXPECTED_TAGS, CIPHERTEXT_LENS, OUT_FRAME_MAX_SIZE
)

byte_source = make_axis_byte_source(
    aead_axis_if_t, AEAD_BEAT_BYTES, PLAINTEXT_TEST_STR_MAX_SIZE
)
# The sink writes every lane, including unused final-beat lanes, so round its
# storage up to a whole beat (144 bytes becomes 160 on the 256-bit interface).
OUT_SINK_CAPACITY = (
    (OUT_FRAME_MAX_SIZE + AEAD_BEAT_BYTES - 1) // AEAD_BEAT_BYTES
) * AEAD_BEAT_BYTES
byte_sink = make_axis_byte_sink(aead_axis_if_t, AEAD_BEAT_BYTES, OUT_SINK_CAPACITY)


# Stay asserted so chacha20poly1305_syn_tb.py can wait for both directions.
# Delay completion by one clock to let the final DONE print finish before
# the top-level checker ends the simulation.
encrypt_all_done: Wire[uint1_t]


# Print once before the first clock in either simulator.
@initial(sim=True)
def announce():
    sim_print("=== ChaCha20-Poly1305 Encryption Test ===")
    sim_print(f"Encrypt Key: {bytes(KEY).hex()}")
    sim_print(f"Encrypt Nonce: {bytes(NONCE).hex()}")
    sim_print("AAD (29 bytes): Additional authenticated data")


# Registers, counters and stream logic require a timed MAIN.
@MAIN(wireguard_env.TARGET_MHZ)
def encrypt_syn_tb() -> aead_axis_if_t.fwd_t:
    # Test vectors
    key: uint8_t[CHACHA20_KEY_SIZE] = KEY
    nonce: uint8_t[CHACHA20_NONCE_SIZE] = NONCE
    aad: uint8_t[AAD_MAX_LEN] = AAD
    plaintexts: uint8_t[NUM_PLAINTEXT_TEST_STRS][PLAINTEXT_TEST_STR_MAX_SIZE] = PLAINTEXTS
    plaintext_lens: uint32_t[NUM_PLAINTEXT_TEST_STRS] = PLAINTEXT_LENS
    expected_out_frames: uint8_t[NUM_PLAINTEXT_TEST_STRS][OUT_FRAME_MAX_SIZE] = (
        EXPECTED_OUT_FRAMES
    )
    expected_out_frame_lens: uint32_t[NUM_PLAINTEXT_TEST_STRS] = EXPECTED_OUT_FRAME_LENS

    # Hold the key, nonce and AAD constant for every packet.
    chacha20poly1305_encrypt_ports.key = key
    chacha20poly1305_encrypt_ports.nonce = nonce
    chacha20poly1305_encrypt_ports.aad = aad
    chacha20poly1305_encrypt_ports.aad_len = AAD_LEN

    encrypt_all_done_reg: Reg[uint1_t]

    # Expose the previous-cycle value before completion can set the register below.
    encrypt_all_done = encrypt_all_done_reg

    # Load each plaintext once; advance when its final beat has been accepted.
    input_packet_count: Reg[uint32_t]
    input_loaded: Reg[uint1_t]

    dut_in_ready: Feedback[uint1_t]
    src = byte_source(
        load=~input_loaded,
        load_data=plaintexts[input_packet_count],
        load_len=plaintext_lens[input_packet_count],
        stream_out_if=aead_axis_if_t.fb_t(dut_in_ready),
    )
    if ~input_loaded:
        sim_print(f"Encrypting test string {input_packet_count}...")
        input_loaded = 1
    if src.idle & input_loaded & (input_packet_count < NUM_PLAINTEXT_TEST_STRS - 1):
        input_packet_count = input_packet_count + 1
        input_loaded = 0
    chacha20poly1305_encrypt_ports.axis_in_if.stream = src.stream_out_if.stream
    dut_in_ready = chacha20poly1305_encrypt_ports.axis_in_if.ready

    # Collect ciphertext and tag, then check the complete frame's length and bytes.
    output_packet_count: Reg[uint32_t]

    chacha20poly1305_encrypt_ports.axis_out_if.ready = 1
    snk = byte_sink(
        stream_in_if=aead_axis_if_t.fwd_t(
            chacha20poly1305_encrypt_ports.axis_out_if.stream
        )
    )

    if snk.frame_valid:
        expected_len: uint32_t = expected_out_frame_lens[output_packet_count]
        sim_assert(
            snk.frame_len == expected_len,
            f"Encrypt: Test {output_packet_count} output length mismatch. "
            f"expected {expected_len} got {snk.frame_len}",
        )
        for i in range(OUT_FRAME_MAX_SIZE):
            byte_idx: uint32_t = i
            if byte_idx < expected_len:
                sim_assert(
                    snk.frame_data[i] == expected_out_frames[output_packet_count][i],
                    f"Encrypt: Test {output_packet_count} mismatch at byte[{byte_idx}]. "
                    f"expected {hex(expected_out_frames[output_packet_count][i])} "
                    f"got {hex(snk.frame_data[i])}",
                )
        sim_print(f"Encrypt: Test {output_packet_count} DONE!")
        output_packet_count = output_packet_count + 1
        if output_packet_count >= NUM_PLAINTEXT_TEST_STRS:
            encrypt_all_done_reg = 1

    # Keep the observed output visible to the compiler.
    return aead_axis_if_t.fwd_t(chacha20poly1305_encrypt_ports.axis_out_if.stream)
