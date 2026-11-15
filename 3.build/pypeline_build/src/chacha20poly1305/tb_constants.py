"""Fixed key, nonce and AAD shared by all AEAD testbenches.

Importing these constants does not generate reference packets or load PypelineC.
"""

KEY = list(range(0x80, 0xA0))
NONCE = [0x07, 0x00, 0x00, 0x00, 0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47]

AAD_TEST_STR = "Additional authenticated data"
AAD_MAX_LEN = 32
AAD_LEN = len(AAD_TEST_STR)  # 29
AAD = list(AAD_TEST_STR.encode()) + [0] * (AAD_MAX_LEN - AAD_LEN)
