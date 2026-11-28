# SPDX-FileCopyrightText: 2026 Chili.CHIPS
#
# SPDX-License-Identifier: BSD-3-Clause

"""dpe_switch system bench: its input frames and the output it must give,
built here from the plaintext (../wg_check.py's RFC 8439 reference),
independent of the RTL.

  sys_check.py gen PLAIN.pcap IN.pcap   the bench's input
  sys_check.py check PLAIN.pcap OUT.pcap META.txt   the output: each frame
      byte for byte, in order, and its tuser (dst, bypass_all) from META
  sys_check.py perf PLAIN.pcap CASE N IN.pcap WANT.pcap   throughput input
      (make perf): N frames of CASE (enc1420, dec1420, mix1420, enc20, ...)
  sys_check.py same OUT.pcap WANT.pcap   the output, byte for byte

The tables and addresses are tb.sv's. Two peers (entries 1, 2; 4 and 5 their
next sessions, #85); each case a frame in:
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
  The replay window (#79): each frame from a peer has its own counter,
  counting up from 9, except in these, at the end:
  replay   a dec1 frame twice: the second dropped
  ooo      counters out of order inside the window (c+2, c, c+1): all
           through; then c once more: dropped
  old      a jump of 70 (X), then X-63 (the window's last bit): through;
           X-64, older than the window: dropped
  badtag   a bad tag at a new counter k, then a good frame at k: through
           (a failed tag marks nothing); the same at k-1, inside the window
  limit    peer 2 at REJECT_AFTER_MESSAGES (2^64 - 2^13 - 1): dropped; one
           below: through
  nokey    LAN plaintext routed to entry 3, which has no session (all-zero
           keys): dropped, twice back to back, then enc1, then once more;
           tb.sv checks entry 3's send_cnt counted all 3 (NOKEY_FRAMES)
  zerokey  on entry 6 (a local_id, all-zero keys), encrypted under the zero key,
           inner source peer 1's (tag 1): dropped, twice; tb.sv checks entry
           6's window did not move
  The rekey overlap (#85): entry 4 is peer 1's next session, entry 5 peer
  2's; each entry's peer tag is the entry its peer's routes point at (1, 2):
  next     on entry 4, inner source peer 1's: through (tag 1 = the route's)
  nexthair on entry 4, to peer 2's network: decrypted, encrypted to peer 2
  nextspoof  on entry 5 (tag 2), inner source peer 1's: dropped
  next2    on entry 5, inner source peer 2's: through
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
REJECT = 2**64 - 2**13 - 1  # net_pkg REJECT_AFTER_MESSAGES: no counter from it on
RCV_CNT = 9  # the first counter of each peer's frames to us


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
    # the next sessions (#85): entry 4 of peer 1, entry 5 of peer 2
    4: dict(mac=bytes.fromhex('020000000099'), ip=ip(192, 168, 1, 99), port=51821,
            local_id=0x5EED0084, remote_id=0xAABB0004, send_cnt=0,
            enc=key('11112222333344445555666677778888' * 2), dec=key('13579BDF2468ACE0' * 4)),
    5: dict(mac=bytes.fromhex('020000000077'), ip=ip(192, 168, 1, 77), port=51822,
            local_id=0x7A110085, remote_id=0x11220005, send_cnt=0,
            enc=key('99990000AAAABBBBCCCCDDDDEEEEFFFF' * 2), dec=key('0F1E2D3C4B5A6978' * 4)),
    # entry 6: a local_id but no keys (written by hand, no session): peer 1's
    # address, tagged with peer 1's routed entry (tb.sv ZEROKEY_E)
    6: dict(mac=bytes.fromhex('020000000099'), ip=ip(192, 168, 1, 99), port=51821,
            local_id=0x5EED0086, remote_id=0xAABB0006, send_cnt=0,
            enc=bytes(32), dec=bytes(32)),
}
LAN = ip(172, 16, 0, 10)  # a host behind this device (172.16.0.0/12, ETH_3)
NET = {1: ip(10, 1, 0, 5), 2: ip(10, 2, 0, 7)}  # in each peer's network
NOKEY_NET = ip(10, 3, 0, 9)  # routed to entry 3, no session (tb.sv NOKEY_E)


def readdr(frame, src, dst):  # the frame with another IPv4 source, destination
    f = bytearray(frame)
    f[26:30], f[30:34] = src, dst
    return bytes(f)


def to_peer(n, cnt):  # wg_check's peer dict: this device to peer n
    p = PEERS[n]
    return dict(local_mac=US['mac'], local_ip=US['ip'], local_port=US['port'].to_bytes(2, 'big'),
                remote_mac=p['mac'], remote_ip=p['ip'], remote_port=p['port'].to_bytes(2, 'big'),
                remote_id=p['remote_id'], key=p['enc'], send_cnt=cnt)


def from_peer(n, rcv=None, dst_ip=None, port=None, ctr=RCV_CNT):  # peer n to this device
    p = PEERS[n]
    return dict(local_mac=p['mac'], local_ip=p['ip'], local_port=p['port'].to_bytes(2, 'big'),
                remote_mac=US['mac'], remote_ip=dst_ip or US['ip'],
                remote_port=(port or US['port']).to_bytes(2, 'big'),
                remote_id=p['local_id'] if rcv is None else rcv, key=p['dec'], send_cnt=ctr)


def wg_in(inner, p):  # a WireGuard data frame around an IPv4 packet
    pkt = wg.ip_packet(inner)
    return wg.wg_from_pt(pkt + bytes(wg.padded_len(len(pkt)) - len(pkt)), p)


def scenario(plain_path):
    """[(frame in, frame out or None (dropped), dst, bypass_all)]"""
    plain = [f for f in wg.packets(plain_path) if wg.plausible(f)]
    cnt = {n: p['send_cnt'] for n, p in PEERS.items()}
    rcnt = {n: RCV_CNT for n in PEERS}  # the counter of each peer's next frame to us
    k = 0

    def pick():  # the next plaintext frame, round robin
        nonlocal k
        k += 1
        return plain[(k - 1) % len(plain)]

    def enc(n, frame):  # its WireGuard frame to peer n, at n's next count
        out = wg.wg_frame(frame, to_peer(n, cnt[n]))
        cnt[n] += 1
        return out

    def rcv(n):  # the counter of peer n's next frame to us
        rcnt[n] += 1
        return rcnt[n] - 1

    def dec(n, ctr, bad=False):  # a frame from peer n at counter ctr; bad: its tag
        f = readdr(pick(), NET[n], LAN)
        fi = bytearray(wg_in(f, from_peer(n, ctr=ctr)))
        if bad:
            fi[-1] ^= 0x80
            return (bytes(fi), None, 0, 0)
        return (bytes(fi), bytes(fi[:14]) + wg.ip_packet(f), ETH_3, 0)

    def dec_on(e, ctr):  # dec() on entry e, inner source peer 1's
        f = readdr(pick(), NET[1], LAN)
        fi = wg_in(f, from_peer(e, ctr=ctr))
        return (fi, fi[:14] + wg.ip_packet(f), ETH_3, 0)

    def dropped(c):  # the same frame in, nothing out
        return (c[0], None, 0, 0)

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
            cases.append((wg_in(inner, from_peer(1, ctr=rcv(1))), enc(2, inner), ETH_4, 0))
        elif kind in ('enc1', 'enc2'):
            n = int(kind[-1])
            fi = readdr(f, LAN, NET[n])
            cases.append((fi, enc(n, fi), ETH_1 if n == 1 else ETH_4, 0))
        elif kind == 'plain':
            fi = readdr(f, LAN, ip(172, 16, 5, 5))
            cases.append((fi, fi, ETH_3, 0))
        elif kind in ('dec1', 'dec2'):
            n = int(kind[-1])
            fi = wg_in(readdr(f, NET[n], LAN), from_peer(n, ctr=rcv(n)))
            cases.append((fi, fi[:14] + wg.ip_packet(readdr(f, NET[n], LAN)), ETH_3, 0))
        elif kind == 'hairpin':
            inner = readdr(f, NET[1], NET[2])
            cases.append((wg_in(inner, from_peer(1, ctr=rcv(1))), enc(2, inner), ETH_4, 0))
        elif kind == 'spoof':
            cases.append((wg_in(readdr(f, NET[1], LAN), from_peer(2, ctr=rcv(2))), None, 0, 0))
        elif kind == 'index':
            other = PEERS[1]['local_id'] ^ 0x100  # entry 1, other upper bits
            cases.append((wg_in(readdr(f, NET[1], LAN), from_peer(1, other, ctr=rcv(1))), None,
                          0, 0))
        elif kind == 'tag':
            fi = bytearray(wg_in(readdr(f, NET[1], LAN), from_peer(1, ctr=rcv(1))))
            fi[-1] ^= 0x80
            cases.append((bytes(fi), None, 0, 0))
        elif kind == 'hs':  # a handshake initiation: type 1
            fi = bytearray(wg_in(readdr(f, NET[1], LAN), from_peer(1, ctr=rcv(1))))
            fi[42:46] = (1).to_bytes(4, 'little')
            cases.append((bytes(fi), bytes(fi), CPU, 1))
        elif kind == 'transit':  # to peer 2's address, through this device
            fi = wg_in(readdr(f, NET[1], LAN), from_peer(1, dst_ip=PEERS[2]['ip'], ctr=rcv(1)))
            cases.append((fi, fi, ETH_2, 0))
        elif kind == 'arp':  # WireGuard to us but for its EtherType: to the CPU
            fi = bytearray(wg_in(readdr(f, NET[1], LAN), from_peer(1, ctr=rcv(1))))
            fi[12:14] = b'\x08\x06'
            cases.append((bytes(fi), bytes(fi), CPU, 0))
        elif kind == 'port':  # to wg_ip, another port: not WireGuard, routed
            fi = wg_in(readdr(f, NET[1], LAN), from_peer(1, port=US['port'] + 1, ctr=rcv(1)))
            cases.append((fi, fi, ETH_2, 0))

    # The replay window (#79), after the others (their frames stay the same)
    for kind in ('replay', 'ooo', 'old', 'badtag', 'limit'):
        if kind == 'replay':  # a dec1 frame twice
            c = dec(1, rcv(1))
            cases += [c, dropped(c)]
        elif kind == 'ooo':  # c+2, c, c+1: all through; then c again
            c = rcv(1)
            rcnt[1] += 2
            first = dec(1, c)
            cases += [dec(1, c + 2), first, dec(1, c + 1), dropped(first)]
        elif kind == 'old':  # X, X-63: through; X-64: dropped
            x = rcnt[1] + 70
            rcnt[1] = x + 1
            cases += [dec(1, x), dec(1, x - 63), dropped(dec(1, x - 64))]
        elif kind == 'badtag':  # k bad then good; k-1 (in the window) the same
            k = rcnt[1] + 1
            rcnt[1] = k + 1
            cases += [dec(1, k, bad=True), dec(1, k), dec(1, k - 1, bad=True), dec(1, k - 1)]
        elif kind == 'limit':  # peer 2: REJECT dropped, REJECT - 1 through
            cases += [dropped(dec(2, REJECT)), dec(2, REJECT - 1)]

    # No session (entry 3, all-zero keys): dropped, but counted (tb.sv)
    for kind in ('nokey', 'nokey', 'enc1', 'nokey'):
        if kind == 'nokey':
            cases.append((readdr(pick(), LAN, NOKEY_NET), None, 0, 0))
        else:
            fi = readdr(pick(), LAN, NET[1])
            cases.append((fi, enc(1, fi), ETH_1, 0))

    # No decrypt key (entry 6): a frame forged under the public zero key, its
    # inner source passing the AllowedIPs check, is dropped before the core
    for _ in range(2):
        cases.append(dropped(dec_on(6, rcv(6))))

    # The rekey overlap (#85): decrypted on a next entry, tagged with the
    # peer's routed entry, so the AllowedIPs check passes it
    for kind in ('next', 'nexthair', 'nextspoof', 'next2', 'next'):
        f = pick()
        if kind == 'next':
            inner = readdr(f, NET[1], LAN)
            fi = wg_in(inner, from_peer(4, ctr=rcv(4)))
            cases.append((fi, fi[:14] + wg.ip_packet(inner), ETH_3, 0))
        elif kind == 'nexthair':
            inner = readdr(f, NET[1], NET[2])
            cases.append((wg_in(inner, from_peer(4, ctr=rcv(4))), enc(2, inner), ETH_4, 0))
        elif kind == 'nextspoof':
            cases.append((wg_in(readdr(f, NET[1], LAN), from_peer(5, ctr=rcv(5))), None, 0, 0))
        elif kind == 'next2':
            inner = readdr(f, NET[2], LAN)
            fi = wg_in(inner, from_peer(5, ctr=rcv(5)))
            cases.append((fi, fi[:14] + wg.ip_packet(inner), ETH_3, 0))
    return cases


def perf_frames(plain_path, case, n):
    """Throughput (make perf): n frames of one case, [(in, out)]. CASE is
    enc|dec|mix and the inner IPv4 length, e.g. dec1420; mix alternates
    encrypt and decrypt. All to or from peer 1."""
    kind, size, n = case[:3], int(case[3:]), int(n)
    base = wg.packets(plain_path)[0][:34]  # Ethernet and IPv4 headers

    def inner(src, dst):
        f = bytearray(base + bytes((i * 7 + 3) & 0xff for i in range(size - 20)))
        f[16:18] = size.to_bytes(2, 'big')
        f = readdr(bytes(f), src, dst)
        return f + bytes(max(0, 60 - len(f)))  # Ethernet padding

    cnt, rcnt, frames = PEERS[1]['send_cnt'], RCV_CNT, []
    for k in range(n):
        if kind == 'dec' or (kind == 'mix' and k % 2 == 1):
            pkt = inner(NET[1], LAN)
            f = wg_in(pkt, from_peer(1, ctr=rcnt))  # each its own counter: no replay
            rcnt += 1
            frames.append((f, f[:14] + wg.ip_packet(pkt)))  # outer Ethernet, inner IPv4
        else:
            pkt = inner(LAN, NET[1])
            frames.append((pkt, wg.wg_frame(pkt, to_peer(1, cnt))))
            cnt += 1
    return frames


def main(mode, plain_path, *paths):
    if mode == 'perf':  # perf PLAIN.pcap CASE N IN.pcap WANT.pcap
        frames = perf_frames(plain_path, paths[0], paths[1])
        wg.write_pcap(paths[2], [f[0] for f in frames])
        wg.write_pcap(paths[3], [f[1] for f in frames])
        return 0
    if mode == 'same':  # same OUT.pcap WANT.pcap: byte for byte
        got, want = wg.packets(plain_path), wg.packets(paths[0])
        if got != want:
            print(f'{len(got)} frames out, want {len(want)}: the output differs')
            return 1
        print(f'{len(got)} frames, as they should be')
        return 0
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
