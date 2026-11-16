# SPDX-FileCopyrightText: 2026 Julian Kemmerer
# SPDX-FileCopyrightText: 2026 Chili.CHIPS
#
# SPDX-License-Identifier: BSD-3-Clause

# pyright: reportInvalidTypeForm=none
"""Fixed-vector decrypt testbench with hardware stream drivers and checkers.

Pypeline port of ../../../pipelinec_build/src/chacha20poly1305/decrypt_tb.c.
Check plaintext and verdict against tb_common.py's independent reference
vectors. The final packet replays test 0 with a corrupted tag: plaintext must
still be returned with a false verdict. See ../../README.md#simulation for
run instructions, or decrypt_tb.py for the native random-vector testbench.
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

import chacha20poly1305_decrypt_ports

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
    TAMPERED_TAG,
    pack_ciphertext_frames,
)

# Append test 0 with a tampered tag to the reference encryption vectors.
NUM_PACKETS = NUM_PLAINTEXT_TEST_STRS + 1
PLAINTEXT_MAX_SIZE = PLAINTEXT_TEST_STR_MAX_SIZE

# Pack ciphertext and tag without a gap; the source derives keep from length.
LANE_WIDTH = AEAD_BEAT_BYTES
IN_FRAME_MAX_SIZE = CIPHERTEXT_MAX_SIZE + POLY1305_AUTH_TAG_SIZE
_INPUT_CIPHERTEXTS = EXPECTED_CIPHERTEXTS + [EXPECTED_CIPHERTEXTS[0]]
_INPUT_TAGS = EXPECTED_TAGS + [TAMPERED_TAG]
_INPUT_CIPHERTEXT_LENS = CIPHERTEXT_LENS + [CIPHERTEXT_LENS[0]]

INPUT_FRAMES, INPUT_FRAME_LENS = pack_ciphertext_frames(
    _INPUT_CIPHERTEXTS, _INPUT_TAGS, _INPUT_CIPHERTEXT_LENS, IN_FRAME_MAX_SIZE
)

EXPECTED_PLAINTEXTS = PLAINTEXTS + [PLAINTEXTS[0]]
EXPECTED_PLAINTEXT_LENS = PLAINTEXT_LENS + [PLAINTEXT_LENS[0]]
EXPECTED_VERIFIED = [1] * NUM_PLAINTEXT_TEST_STRS + [0]

byte_source = make_axis_byte_source(aead_axis_if_t, LANE_WIDTH, IN_FRAME_MAX_SIZE)
byte_sink = make_axis_byte_sink(aead_axis_if_t, AEAD_BEAT_BYTES, PLAINTEXT_MAX_SIZE)


# Stay asserted so chacha20poly1305_syn_tb.py can wait for both directions.
# Delay completion by one clock to let the final DONE print finish before
# the top-level checker ends the simulation.
decrypt_all_done: Wire[uint1_t]


# Print once before the first clock in either simulator.
@initial(sim=True)
def announce():
    sim_print("=== ChaCha20-Poly1305 Decryption Test ===")
    sim_print(f"Decrypt Key: {bytes(KEY).hex()}")
    sim_print(f"Decrypt Nonce: {bytes(NONCE).hex()}")
    sim_print("AAD (29 bytes): Additional authenticated data")


# Registers, counters and stream logic require a timed MAIN.
@MAIN(wireguard_env.TARGET_MHZ)
def decrypt_syn_tb() -> aead_axis_if_t.fwd_t:
    # Test vectors
    key: uint8_t[CHACHA20_KEY_SIZE] = KEY
    nonce: uint8_t[CHACHA20_NONCE_SIZE] = NONCE
    aad: uint8_t[AAD_MAX_LEN] = AAD
    input_frames: uint8_t[NUM_PACKETS][IN_FRAME_MAX_SIZE] = INPUT_FRAMES
    input_frame_lens: uint32_t[NUM_PACKETS] = INPUT_FRAME_LENS
    expected_plaintexts: uint8_t[NUM_PACKETS][PLAINTEXT_MAX_SIZE] = EXPECTED_PLAINTEXTS
    expected_plaintext_lens: uint32_t[NUM_PACKETS] = EXPECTED_PLAINTEXT_LENS
    expected_verified_flags: uint1_t[NUM_PACKETS] = EXPECTED_VERIFIED

    # Hold the key, nonce and AAD constant for every packet.
    chacha20poly1305_decrypt_ports.key = key
    chacha20poly1305_decrypt_ports.nonce = nonce
    chacha20poly1305_decrypt_ports.aad = aad
    chacha20poly1305_decrypt_ports.aad_len = AAD_LEN

    decrypt_all_done_reg: Reg[uint1_t]

    # Expose the previous-cycle value before completion can set the register below.
    decrypt_all_done = decrypt_all_done_reg

    # Load each ciphertext/tag frame once; advance after its final accepted beat.
    input_packet_count: Reg[uint32_t]
    input_loaded: Reg[uint1_t]

    dut_in_ready: Feedback[uint1_t]
    src = byte_source(
        load=~input_loaded,
        load_data=input_frames[input_packet_count],
        load_len=input_frame_lens[input_packet_count],
        stream_out_if=aead_axis_if_t.fb_t(dut_in_ready),
    )
    if ~input_loaded:
        sim_print(f"Decrypting test string {input_packet_count}...")
        input_loaded = 1
    if src.idle & input_loaded & (input_packet_count < NUM_PACKETS - 1):
        input_packet_count = input_packet_count + 1
        input_loaded = 0
    chacha20poly1305_decrypt_ports.axis_in_if.stream = src.stream_out_if.stream
    dut_in_ready = chacha20poly1305_decrypt_ports.axis_in_if.ready

    # Collect plaintext, then check its verdict, length and bytes at frame completion.
    output_packet_count: Reg[uint32_t]

    chacha20poly1305_decrypt_ports.axis_out_if.ready = 1
    snk = byte_sink(
        stream_in_if=aead_axis_if_t.fwd_t(
            chacha20poly1305_decrypt_ports.axis_out_if.stream
        )
    )

    if snk.frame_valid:
        expected_verified: uint1_t = expected_verified_flags[output_packet_count]
        sim_assert(
            chacha20poly1305_decrypt_ports.is_verified_out == expected_verified,
            f"Decrypt: Test {output_packet_count} is_verified mismatch. "
            f"expected {expected_verified} "
            f"got {chacha20poly1305_decrypt_ports.is_verified_out}",
        )
        expected_len: uint32_t = expected_plaintext_lens[output_packet_count]
        sim_assert(
            snk.frame_len == expected_len,
            f"Decrypt: Test {output_packet_count} output length mismatch. "
            f"expected {expected_len} got {snk.frame_len}",
        )
        for i in range(PLAINTEXT_MAX_SIZE):
            byte_idx: uint32_t = i
            if byte_idx < expected_len:
                sim_assert(
                    snk.frame_data[i] == expected_plaintexts[output_packet_count][i],
                    f"Decrypt: Test {output_packet_count} mismatch at byte[{byte_idx}]. "
                    f"expected {hex(expected_plaintexts[output_packet_count][i])} "
                    f"got {hex(snk.frame_data[i])}",
                )
        sim_print(f"Decrypt: Test {output_packet_count} DONE!")
        output_packet_count = output_packet_count + 1
        if output_packet_count >= NUM_PACKETS:
            decrypt_all_done_reg = 1

    # Keep the observed output visible to the compiler.
    return aead_axis_if_t.fwd_t(chacha20poly1305_decrypt_ports.axis_out_if.stream)
