"""Fixed plaintexts, reference vectors and frame packing for the testbenches.

Reference ciphertext and tags are generated at import by aead_ref_model.py.
tb_constants.py also supplies the native random and performance testbenches.
"""

from aead_ref_model import generate_encrypt_vector
from tb_constants import AAD, AAD_LEN, AAD_MAX_LEN, AAD_TEST_STR, KEY, NONCE

PLAINTEXT_TEST_STR_MAX_SIZE = 128
# Cover partial/full 16-byte Poly1305 words, 64-byte ChaCha20 blocks and the
# maximum fixed-vector length. On the 128-bit interface, the 15- and 79-byte
# cases leave room for only one tag byte in the final ciphertext beat.
PLAINTEXT_TEST_STRS = [
    "Hello CHILIChips - Wireguard team, let's test this aead!",
    "PipelineC is the best HDL around :) Let's go CHILIChips Wireguard team!",
    "Thanks Claude for helping CHILIChips Wireguard + Pypeline!",
    "Hi!",
    "Exactly 16 bytes",
    "Seventeen bytes!!",
    "One full sixty four byte ChaCha20 block exactly, nothing more!!!",
    "This one hundred twenty eight byte maximum size test string covers"
    " exactly two full sixty four byte ChaCha20 blocks of data!!!!!",
    "Fifteen bytes!!",
    "Seventy nine byte string spanning past one ChaCha20 block boundary exactly!!!!!",
]
NUM_PLAINTEXT_TEST_STRS = len(PLAINTEXT_TEST_STRS)
PLAINTEXT_LENS = [len(s) for s in PLAINTEXT_TEST_STRS]
assert PLAINTEXT_LENS == [56, 71, 58, 3, 16, 17, 64, 128, 15, 79]
assert all(0 < n <= PLAINTEXT_TEST_STR_MAX_SIZE for n in PLAINTEXT_LENS)
PLAINTEXTS = [
    list(s.encode()) + [0] * (PLAINTEXT_TEST_STR_MAX_SIZE - len(s))
    for s in PLAINTEXT_TEST_STRS
]

# Reference ciphertext has the same length as plaintext. The fixed-vector
# testbenches use pack_ciphertext_frames() to append tags without padding gaps.
POLY1305_AUTH_TAG_SIZE = 16
CIPHERTEXT_MAX_SIZE = PLAINTEXT_TEST_STR_MAX_SIZE

_AAD_BYTES = AAD_TEST_STR.encode()
_GENERATED = [
    generate_encrypt_vector(bytes(KEY), bytes(NONCE), _AAD_BYTES, s.encode())
    for s in PLAINTEXT_TEST_STRS
]
CIPHERTEXT_LENS = [len(ct) for ct, _ in _GENERATED]
assert CIPHERTEXT_LENS == PLAINTEXT_LENS  # stream cipher: same length
EXPECTED_CIPHERTEXTS = [
    list(ct) + [0] * (CIPHERTEXT_MAX_SIZE - len(ct)) for ct, _ in _GENERATED
]
EXPECTED_TAGS = [list(tag) for _, tag in _GENERATED]

# decrypt_syn_tb.py replays test 0 with this tag, expecting a false verdict.
TAMPERED_TAG = list(EXPECTED_TAGS[0])
TAMPERED_TAG[0] ^= 0x01


def pack_ciphertext_frames(ciphertexts, tags, ciphertext_lens, max_size):
    """Return padded ciphertext/tag arrays and their unpadded byte lengths."""
    frames = []
    lengths = []
    for ciphertext, tag, ciphertext_len in zip(ciphertexts, tags, ciphertext_lens):
        length = ciphertext_len + len(tag)
        frames.append(ciphertext[:ciphertext_len] + tag + [0] * (max_size - length))
        lengths.append(length)
    return frames, lengths
