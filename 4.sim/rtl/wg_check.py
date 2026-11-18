# SPDX-FileCopyrightText: 2026 Chili.CHIPS
#
# SPDX-License-Identifier: BSD-3-Clause

"""WireGuard block benches: reference frames, built here from the plaintext,
independent of the RTL.

  wg_check.py enc PLAIN.pcap OUT.pcap   encryptor output: headers,
      ciphertext and tag (RFC 8439 ChaCha20-Poly1305), byte for byte
  wg_check.py dec PLAIN.pcap OUT.pcap [N...]   decryptor output: the outer
      Ethernet header, then the IPv4 packet; frames N (counted from 0) must
      be missing: the bench corrupts them, so their tag must fail
  wg_check.py mix OUT.pcap IN.pcap...   one pcap of all their frames, plus a
      60-byte frame whose IPv4 packet is shorter (junk in the padding)
  wg_check.py wg OUT.pcap PLAIN.pcap   the WireGuard frames of PLAIN, as
      the encryptor must make them: the decryptor bench's input without the
      encryptor (LOOPBACK=0)

PEER is the benches' routing-table entry (tb.sv: PEER), as wire bytes.
Exit 0 when all frames match; prints the first difference otherwise."""
import struct
import sys

PEER = dict(
    local_mac=bytes.fromhex('FFEEDDCCBBAA'),  # tb: 48'hAABBCCDDEEFF, bus order
    local_ip=bytes([192, 168, 0, 1]),
    local_port=bytes.fromhex('CA6D'),  # 51821
    remote_mac=bytes.fromhex('AABBCCDDEEFF'),  # tb: 48'hFFEEDDCCBBAA
    remote_ip=bytes([192, 168, 0, 2]),
    remote_port=bytes.fromhex('CA6C'),
    remote_id=0xAABBCCDD,
    # tb: 256'h0123...EF; the core takes byte 0 from [7:0]
    key=bytes.fromhex('0123456789ABCDEF' * 4)[::-1],
    send_cnt=1,
)


def rotl(v, c):
    return ((v << c) & 0xffffffff) | (v >> (32 - c))


def chacha_block(key, ctr, nonce):
    st = [0x61707865, 0x3320646e, 0x79622d32, 0x6b206574,
          *struct.unpack('<8I', key), ctr, *struct.unpack('<3I', nonce)]
    w = st[:]

    def qr(a, b, c, d):
        w[a] = (w[a] + w[b]) & 0xffffffff
        w[d] = rotl(w[d] ^ w[a], 16)
        w[c] = (w[c] + w[d]) & 0xffffffff
        w[b] = rotl(w[b] ^ w[c], 12)
        w[a] = (w[a] + w[b]) & 0xffffffff
        w[d] = rotl(w[d] ^ w[a], 8)
        w[c] = (w[c] + w[d]) & 0xffffffff
        w[b] = rotl(w[b] ^ w[c], 7)
    for _ in range(10):
        qr(0, 4, 8, 12), qr(1, 5, 9, 13), qr(2, 6, 10, 14), qr(3, 7, 11, 15)
        qr(0, 5, 10, 15), qr(1, 6, 11, 12), qr(2, 7, 8, 13), qr(3, 4, 9, 14)
    return struct.pack('<16I', *[(a + b) & 0xffffffff for a, b in zip(w, st)])


def chacha20(key, nonce, data):  # RFC 8439 encryption: block counter from 1
    out = b''
    for i in range(0, len(data), 64):
        ks = chacha_block(key, 1 + i // 64, nonce)
        out += bytes(x ^ y for x, y in zip(data[i:i + 64], ks))
    return out


def poly1305(key, msg):  # RFC 8439 2.5
    r = int.from_bytes(key[:16], 'little') & 0x0ffffffc0ffffffc0ffffffc0fffffff
    s, a, p = int.from_bytes(key[16:], 'little'), 0, (1 << 130) - 5
    for i in range(0, len(msg), 16):
        a = (a + int.from_bytes(msg[i:i + 16] + b'\x01', 'little')) * r % p
    return ((a + s) & ((1 << 128) - 1)).to_bytes(16, 'little')


def aead_tag(key, nonce, ct):  # RFC 8439 2.8, no AAD
    mac_data = ct + bytes(-len(ct) % 16) + struct.pack('<QQ', 0, len(ct))
    return poly1305(chacha_block(key, 0, nonce)[:32], mac_data)


def packets(path):
    with open(path, 'rb') as f:
        data = f.read()
    order = '<' if data[:4] in (b'\xd4\xc3\xb2\xa1', b'\x4d\x3c\xb2\xa1') else '>'
    pos, out = 24, []
    while pos + 16 <= len(data):
        incl = struct.unpack(order + 'I', data[pos + 8:pos + 12])[0]
        out.append(data[pos + 16:pos + 16 + incl])
        pos += 16 + incl
    return out


def ip_packet(frame):
    return frame[14:14 + int.from_bytes(frame[16:18], 'big')]


def padded_len(n):  # net_pkg wg_padded_len()
    return (n | 15) + 1


def wg_frame(frame, p=PEER):
    ip = ip_packet(frame)
    plen = padded_len(len(ip))
    nonce = bytes(4) + p['send_cnt'].to_bytes(8, 'little')
    ct = chacha20(p['key'], nonce, ip + bytes(plen - len(ip)))
    ipv4 = (bytes([0x45, 0]) + (plen + 60).to_bytes(2, 'big') + bytes(4) +
            bytes([64, 17, 0, 0]) + p['local_ip'] + p['remote_ip'])
    udp = p['local_port'] + p['remote_port'] + (plen + 40).to_bytes(2, 'big') + bytes(2)
    wg = (struct.pack('<II', 4, p['remote_id']) + p['send_cnt'].to_bytes(8, 'little'))
    eth = p['remote_mac'] + p['local_mac'] + b'\x08\x00'
    return eth + ipv4 + udp + wg + ct + aead_tag(p['key'], nonce, ct)


def compare(want, got, tag_len):
    if len(want) != len(got):
        print(f'{len(got)} frames, want {len(want)}')
        return 1
    for i, (w, g) in enumerate(zip(want, got)):
        if len(g) != len(w) + tag_len or g[:len(w)] != w:
            n = next((k for k in range(min(len(w), len(g))) if w[k] != g[k]), min(len(w), len(g)))
            print(f'frame {i}: differs at byte {n} (length {len(g)}, want {len(w) + tag_len})')
            return 1
    print(f'{len(got)} frames, as they should be')
    return 0


def write_pcap(path, frames):
    with open(path, 'wb') as f:
        f.write(struct.pack('<IHHiIII', 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1))
        for fr in frames:
            f.write(struct.pack('<IIII', 0, 0, len(fr), len(fr)) + fr)  # back to back


def main(mode, *paths):
    if mode == 'mix':
        frames = [fr for p in paths[1:] for fr in packets(p)]
        short = bytearray(frames[0][:60])  # 60 bytes on the wire, IPv4 30
        short[16:18] = (30).to_bytes(2, 'big')
        short[44:] = b'\xee' * 16
        write_pcap(paths[0], frames + [bytes(short)])
        return 0
    if mode == 'wg':
        write_pcap(paths[0], [wg_frame(f) for f in packets(paths[1])])
        return 0
    plain, out = packets(paths[0]), packets(paths[1])
    if mode == 'enc':
        return compare([wg_frame(f) for f in plain], out, 0)
    eth = PEER['remote_mac'] + PEER['local_mac'] + b'\x08\x00'
    dropped = {int(n) for n in paths[2:]}  # frames the bench corrupts
    return compare([eth + ip_packet(f) for i, f in enumerate(plain) if i not in dropped], out, 0)


if __name__ == '__main__':
    sys.exit(main(*sys.argv[1:]))

# -----------------------------------------------------------------------------
# Project:     WireGuard-FPGA
# Description: NLnet-funded open-source implementation
# Funding:     https://nlnet.nl/project/KlusterLab-Wireguard (2023-12 to 2025-12)
# -----------------------------------------------------------------------------
