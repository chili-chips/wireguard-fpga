# pyright: reportInvalidTypeForm=none
"""Hardware top for ChaCha20-Poly1305, with flattened I/O ports.

See ../README.md#setup-and-options for design and sharing choices.

Pypeline port of ../pipelinec_build/src/chacha20poly1305_{encrypt,decrypt,
encrypt_decrypt_shared}.c.
"""

import wireguard_env

from pypeline import PART

PART("xc7a200tffg1156-2")  # Artix 7 200T

# Imports expose the selected ports and MAINs; dependencies are discovered transitively.
if wireguard_env.ENCRYPT:
    import chacha20poly1305_encrypt_hw_io  # noqa: F401
    import encrypt_dataflow  # noqa: F401
if wireguard_env.DECRYPT:
    import chacha20poly1305_decrypt_hw_io  # noqa: F401
    import decrypt_dataflow  # noqa: F401
