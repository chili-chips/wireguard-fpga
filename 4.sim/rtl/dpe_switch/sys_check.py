# SPDX-FileCopyrightText: 2026 Chili.CHIPS
#
# SPDX-License-Identifier: BSD-3-Clause

"""dpe_switch system bench: its input frames and the output it must give,
built here from the plaintext (../wg_check.py's RFC 8439 reference),
independent of the RTL.

  sys_check.py gen PLAIN.pcap IN.pcap   the bench's input
  sys_check.py check PLAIN.pcap OUT.pcap META.txt   the output: each frame
      byte for byte, in order, and its tuser (dst, bypass_all) from META

The tables and addresses are tb.sv's. Two peers; each case a frame in:
  enc    LAN plaintext to a peer's network: WireGuard to that peer, its
         send_cnt counting up (peer 1 from 2^32 - 2: across the word)
  plain  LAN to LAN: out as it came
  dec    WireGuard from a peer, inner source its own: the outer Ethernet
         header, then the inner IPv4 packet, routed by the inner destination
  hairpin  from peer 1 to peer 2's network: decrypted, then encrypted again
  hairmax  the same with a 2032-byte IPv4 packet, the most the core takes
  spoof  from peer 2, inner source peer 1's: dropped
  index  a receiver index whose upper bits do not match: dropped
  tag    a corrupted tag: dropped
  hs     a handshake: to the CPU as it came (bypass_all)
  transit  WireGuard to another host: routed as it came
  port   WireGuard to this device's address, another port: routed as it came
  arp    a WireGuard frame to us, but EtherType ARP: to the CPU as it came
Exit 0 when the output is as it should be."""
import importlib.util
import os
import sys

sys.dont_write_bytecode = True  # no __pycache__ next to wg_check.py
_spec = importlib.util.spec_from_file_location(
    'wg_check', os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'wg_check.py'))
wg = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(wg)

ETH_1, ETH_2, ETH_3, ETH_4, CPU = 1, 2, 3, 4, 0
MAX_PT = 2032  # net_pkg AEAD_MAX_PT_BYTES: the longest IPv4 packet the core takes


def ip(a, b, c, d):
    return bytes([a, b, c, d])


def key(hex64):  # tb.sv's 256-bit key: the core takes byte 0 from [7:0]
    return int(hex64, 16).to_bytes(32, 'little')


US = dict(mac=bytes.fromhex('CCBACACA0001'), ip=ip(192, 168, 1, 98), port=51820)
PEERS = {  # the cryptokey table entries (tb.sv)
    1: dict(mac=bytes.fromhex('020000000099'), ip=ip(192, 168, 1, 99), port=51821,
            local_id=0x5EED0041, remote_id=0xAABBCCDD, send_cnt=0xFFFFFFFE,
            enc=key('0123456789ABCDEF' * 4), dec=key('FEDCBA9876543210' * 4)),
    2: dict(mac=bytes.fromhex('020000000077'), ip=ip(192, 168, 1, 77), port=51822,
            local_id=0x7A110042, remote_id=0x11223344, send_cnt=5,
            enc=key('00112233445566778899AABBCCDDEEFF' * 2),
            dec=key('A5A5A5A55A5A5A5A0F0F0F0FF0F0F0F0' * 2)),
}
LAN = ip(172, 16, 0, 10)  # a host behind this device (172.16.0.0/12, ETH_3)
NET = {1: ip(10, 1, 0, 5), 2: ip(10, 2, 0, 7)}  # in each peer's network


def readdr(frame, src, dst):  # the frame with another IPv4 source, destination
    f = bytearray(frame)
    f[26:30], f[30:34] = src, dst
    return bytes(f)


def to_peer(n, cnt):  # wg_check's peer dict: this device to peer n
    p = PEERS[n]
    return dict(local_mac=US['mac'], local_ip=US['ip'], local_port=US['port'].to_bytes(2, 'big'),
                remote_mac=p['mac'], remote_ip=p['ip'], remote_port=p['port'].to_bytes(2, 'big'),
                remote_id=p['remote_id'], key=p['enc'], send_cnt=cnt)


def from_peer(n, rcv=None, dst_ip=None, port=None):  # peer n to this device
    p = PEERS[n]
    return dict(local_mac=p['mac'], local_ip=p['ip'], local_port=p['port'].to_bytes(2, 'big'),
                remote_mac=US['mac'], remote_ip=dst_ip or US['ip'],
                remote_port=(port or US['port']).to_bytes(2, 'big'),
                remote_id=p['local_id'] if rcv is None else rcv, key=p['dec'], send_cnt=9)


def wg_in(inner, p):  # a WireGuard data frame around an IPv4 packet
    pkt = wg.ip_packet(inner)
    return wg.wg_from_pt(pkt + bytes(wg.padded_len(len(pkt)) - len(pkt)), p)


def scenario(plain_path):
    """[(frame in, frame out or None (dropped), dst, bypass_all)]"""
    plain = [f for f in wg.packets(plain_path) if wg.plausible(f)]
    cnt = {n: p['send_cnt'] for n, p in PEERS.items()}
    k = 0

    def pick():  # the next plaintext frame, round robin
        nonlocal k
        k += 1
        return plain[(k - 1) % len(plain)]

    def enc(n, frame):  # its WireGuard frame to peer n, at n's next count
        out = wg.wg_frame(frame, to_peer(n, cnt[n]))
        cnt[n] += 1
        return out

    cases = []
    # back to back to one peer (enc1 enc1, hairpin enc2): the next packet
    # must read the count the last one wrote back. The plaintext's 1506-byte
    # frame (round robin, every 11th) lands on dec1 and on enc1
    # Then the largest hairpin (hairmax: IPv4 2032, AEAD_MAX_PT_BYTES), twice,
    # while tb.sv holds outp long: decryption waits on the encryptor, both
    # on the one core
    for kind in ('enc1', 'dec1', 'enc1', 'enc1', 'plain', 'hs', 'spoof', 'enc2', 'dec1',
                 'hairpin', 'enc2', 'index', 'transit', 'tag', 'arp', 'port', 'enc1', 'dec2',
                 'enc2', 'enc1', 'enc1', 'hairmax', 'enc1', 'hairmax', 'dec2', 'enc2'):
        f = pick()
        if kind == 'hairmax':
            big = bytearray(plain[0][:34] + bytes(range(256)) * 8)[:14 + MAX_PT]
            big[16:18] = MAX_PT.to_bytes(2, 'big')
            inner = readdr(bytes(big), NET[1], NET[2])
            cases.append((wg_in(inner, from_peer(1)), enc(2, inner), ETH_4, 0))
        elif kind in ('enc1', 'enc2'):
            n = int(kind[-1])
            fi = readdr(f, LAN, NET[n])
            cases.append((fi, enc(n, fi), ETH_1 if n == 1 else ETH_4, 0))
        elif kind == 'plain':
            fi = readdr(f, LAN, ip(172, 16, 5, 5))
            cases.append((fi, fi, ETH_3, 0))
        elif kind in ('dec1', 'dec2'):
            n = int(kind[-1])
            fi = wg_in(readdr(f, NET[n], LAN), from_peer(n))
            cases.append((fi, fi[:14] + wg.ip_packet(readdr(f, NET[n], LAN)), ETH_3, 0))
        elif kind == 'hairpin':
            inner = readdr(f, NET[1], NET[2])
            cases.append((wg_in(inner, from_peer(1)), enc(2, inner), ETH_4, 0))
        elif kind == 'spoof':
            cases.append((wg_in(readdr(f, NET[1], LAN), from_peer(2)), None, 0, 0))
        elif kind == 'index':
            rcv = PEERS[1]['local_id'] ^ 0x100  # entry 1, other upper bits
            cases.append((wg_in(readdr(f, NET[1], LAN), from_peer(1, rcv)), None, 0, 0))
        elif kind == 'tag':
            fi = bytearray(wg_in(readdr(f, NET[1], LAN), from_peer(1)))
            fi[-1] ^= 0x80
            cases.append((bytes(fi), None, 0, 0))
        elif kind == 'hs':  # a handshake initiation: type 1
            fi = bytearray(wg_in(readdr(f, NET[1], LAN), from_peer(1)))
            fi[42:46] = (1).to_bytes(4, 'little')
            cases.append((bytes(fi), bytes(fi), CPU, 1))
        elif kind == 'transit':  # to peer 2's address, through this device
            fi = wg_in(readdr(f, NET[1], LAN), from_peer(1, dst_ip=PEERS[2]['ip']))
            cases.append((fi, fi, ETH_2, 0))
        elif kind == 'arp':  # WireGuard to us but for its EtherType: to the CPU
            fi = bytearray(wg_in(readdr(f, NET[1], LAN), from_peer(1)))
            fi[12:14] = b'\x08\x06'
            cases.append((bytes(fi), bytes(fi), CPU, 0))
        elif kind == 'port':  # to wg_ip, another port: not WireGuard, routed
            fi = wg_in(readdr(f, NET[1], LAN), from_peer(1, port=US['port'] + 1))
            cases.append((fi, fi, ETH_2, 0))
    return cases


def main(mode, plain_path, *paths):
    cases = scenario(plain_path)
    if mode == 'gen':
        wg.write_pcap(paths[0], [c[0] for c in cases])
        return 0
    want = [c for c in cases if c[1] is not None]
    got = wg.packets(paths[0])
    with open(paths[1]) as f:
        meta = [tuple(int(x) for x in line.split()) for line in f if line.strip()]
    if len(got) != len(want) or len(meta) != len(want):
        print(f'{len(got)} frames ({len(meta)} in META), want {len(want)}')
        return 1
    for i, ((_, w, dst, ba), g, m) in enumerate(zip(want, got, meta)):
        if g != w:
            n = next((j for j in range(min(len(w), len(g))) if w[j] != g[j]), min(len(w), len(g)))
            print(f'frame {i}: differs at byte {n} (length {len(g)}, want {len(w)})')
            return 1
        if m != (dst, ba):
            print(f'frame {i}: dst {m[0]} bypass_all {m[1]}, want {dst} {ba}')
            return 1
    print(f'{len(got)} frames, as they should be ({len(cases) - len(want)} dropped)')
    return 0


if __name__ == '__main__':
    sys.exit(main(*sys.argv[1:]))

# -----------------------------------------------------------------------------
# Project:     WireGuard-FPGA
# Description: NLnet-funded open-source implementation
# Funding:     https://nlnet.nl/project/KlusterLab-Wireguard (2023-12 to 2025-12)
# -----------------------------------------------------------------------------
