# SPDX-FileCopyrightText: 2026 Chili.CHIPS
#
# SPDX-License-Identifier: BSD-3-Clause

"""pcap_same.py [--replay] A.pcap B.pcap: exit 0 when both hold the same
packets, in the same order, byte for byte. Timestamps are ignored (stalls in a
bench move them). Prints the first difference otherwise.

--replay: B is A replayed onto a bus (pcapreader.sv): a packet captured
shorter than it was on the wire comes out at its wire length, so B's packet
must have A's original length and begin with A's captured bytes."""
import struct
import sys


def packets(path):  # [(captured bytes, original length)]
    with open(path, 'rb') as f:
        data = f.read()
    magic = data[:4]
    order = '<' if magic in (b'\xd4\xc3\xb2\xa1', b'\x4d\x3c\xb2\xa1') else '>'
    pos, out = 24, []
    while pos + 16 <= len(data):
        incl, orig = struct.unpack(order + 'II', data[pos + 8:pos + 16])
        out.append((data[pos + 16:pos + 16 + incl], orig))
        pos += 16 + incl
    return out


args = sys.argv[1:]
replay = args[0] == '--replay'
if replay:
    args = args[1:]
a, b = packets(args[0]), packets(args[1])
for i, ((pa, oa), (pb, _)) in enumerate(zip(a, b)):
    want_len = oa if replay else len(pa)
    if len(pb) != want_len or pb[:len(pa)] != pa:
        n = next((k for k in range(min(len(pa), len(pb))) if pa[k] != pb[k]), min(len(pa), len(pb)))
        print(f'packet {i}: differs at byte {n} (length {len(pb)}, want {want_len})')
        sys.exit(1)
if len(a) != len(b):
    print(f'{len(a)} packets vs {len(b)}')
    sys.exit(1)
print(f'{len(a)} packets, the same')

# -----------------------------------------------------------------------------
# Project:     WireGuard-FPGA
# Description: NLnet-funded open-source implementation
# Funding:     https://nlnet.nl/project/KlusterLab-Wireguard (2023-12 to 2025-12)
# -----------------------------------------------------------------------------
