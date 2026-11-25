#!/bin/bash
# SPDX-FileCopyrightText: 2026 Chili.CHIPS
#
# SPDX-License-Identifier: BSD-3-Clause

# Runs inside "unshare -rn": the kernel's wg0 (10.0.0.1, UDP 51820) against
# wg_interop (10.0.0.2, UDP 40000) on the namespace's loopback.
set -u
cd "${1:-build}"  # where make put wg_interop
read OURPUB PSK < <(./wg_interop pub)
KPRIV=$(wg genkey); KPUB=$(echo "$KPRIV" | wg pubkey)
fails=0

setup() {
  ip link del wg0 2>/dev/null
  ip link add wg0 type wireguard
  wg set wg0 listen-port 51820 private-key <(echo "$KPRIV") \
     peer "$OURPUB" preshared-key <(echo "$PSK") endpoint 127.0.0.1:40000 allowed-ips 10.0.0.2/32
  ip addr add 10.0.0.1/24 dev wg0
  ip link set wg0 up
}

ip link set lo up

echo "== A: the kernel initiates, we respond"
setup
./wg_interop respond "$KPUB" & P=$!
sleep 0.3; ping -c1 -W2 10.0.0.2 >/dev/null 2>&1
wait $P || fails=$((fails + 1))

echo "== B: we initiate"
setup
./wg_interop initiate "$KPUB" || fails=$((fails + 1))
wg show wg0 latest-handshakes | awk '{print "  kernel latest handshake:", ($2 > 0 ? "yes" : "none")}'
wg show wg0 transfer | awk '{print "  kernel rx/tx bytes:", $2, $3}'

echo "== $([ $fails -eq 0 ] && echo ALL PASS || echo "$fails part(s) FAILED")"
exit $fails

# -----------------------------------------------------------------------------
# Project:     WireGuard-FPGA
# Description: NLnet-funded open-source implementation
# Funding:     https://nlnet.nl/project/KlusterLab-Wireguard (2023-12 to 2025-12)
# -----------------------------------------------------------------------------
