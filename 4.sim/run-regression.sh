#!/bin/bash
# SPDX-FileCopyrightText: 2026 Chili.CHIPS
#
# SPDX-License-Identifier: BSD-3-Clause
#
# Regression, before a push (about 50 min): run-sanity.sh, then the other
# block benches, the DPE throughput (perf: clocks per frame, a ceiling),
# other simulators, and the co-simulation with the VProc CPU and under UART
# bus stress (#61), and the end-to-end WireGuard test. Prints one line per
# run, logs in logs/regression/; exits 1 if any run fails.
#
# REGRESS_RINGS=1 also runs the TRNG bench on its ring-oscillator model
# (+trng_rings=1, about 30 min more).
#
# Usage: bash run-regression.sh

set -u
cd "$(dirname "$0")"
LOG=$PWD/logs/regression  # not obj/: the co-simulation's make clean removes it
mkdir -p "$LOG"
fails=0

report() {  # name, ok (1/0), seconds, what, result
  [ "$2" = 1 ] || fails=$((fails + 1))
  printf '%-22s %4d s  %-4s %-40s %s\n' "$1" "$3" "$([ "$2" = 1 ] && echo PASS || echo FAIL)" "$4" "$5"
}

bench() {  # name, bench folder, make variables
  local n=$1 b=$2 t0=$SECONDS ok=0 r
  shift 2
  make -C rtl/"$b" all "$@" > "$LOG/$n.log" 2>&1 && ok=1
  r=$(grep -a 'RESULT:' "$LOG/$n.log" | tail -1)
  report "$n" $ok $((SECONDS - t0)) "rtl/$b $*" "${r:-exit $([ $ok = 1 ] && echo 0 || echo 1)}"
}

cosim() {  # name, the line that must appear, make variables
  local n=$1 want=$2 t0=$SECONDS ok=0 r
  shift 2
  make -f MakefileVProc.mk clean > /dev/null 2>&1
  make -f MakefileVProc.mk run "$@" > "$LOG/$n.log" 2>&1 && ok=1
  grep -a -q "All frames received" "$LOG/$n.log" || ok=0
  [ -z "$want" ] || grep -a -q "$want" "$LOG/$n.log" || ok=0
  ! grep -a -q -E "(UART_SOP_TEST|CHK_UART_BUS).*FAIL" "$LOG/$n.log" || ok=0
  r=$(grep -a -E "All frames received|UART_SOP_TEST|UART_BUS_STRESS:|time limit" "$LOG/$n.log" | tail -1)
  report "$n" $ok $((SECONDS - t0)) "$*" "${r:-no result, see $LOG/$n.log}"
}

# the end-to-end WireGuard test (README.md "End-to-end WireGuard test"):
# every check must print its PASS line
E2E_CHECKS="0-config 1-handshake 4a-confirm-wait 2a-peer-to-lan 4b-confirmed 2b-lan-to-peer
  3-replay 5a-keepalive 4c-rekey-peer 4d-retire 5c-reject 4e-initiator 5b-rekey-time 6-cookie"
e2e() {  # name, make variables
  local n=$1 t0=$SECONDS ok=0 r c
  shift
  make -f MakefileVProc.mk clean > /dev/null 2>&1
  make -f MakefileVProc.mk run WG_E2E=1 "$@" > "$LOG/$n.log" 2>&1 && ok=1
  for c in $E2E_CHECKS; do grep -a -q "E2E: PASS $c " "$LOG/$n.log" || ok=0; done
  grep -a -q "E2E: ALL PASS" "$LOG/$n.log" || ok=0
  ! grep -a -q "E2E: FAIL" "$LOG/$n.log" || ok=0
  r=$(grep -a -E "E2E: (ALL PASS|FAILED)|time limit" "$LOG/$n.log" | tail -1)
  report "$n" $ok $((SECONDS - t0)) "WG_E2E=1 $*" "${r:-no result, see $LOG/$n.log}"
}

perf() {  # name, CASE, the most clocks per frame (out): the DPE's throughput
  local n=$1 c=$2 max=$3 t0=$SECONDS ok=0 r clk
  make -C rtl/dpe_switch perf CASE="$c" > "$LOG/$n.log" 2>&1 && ok=1
  r=$(grep -a '^PERF: out' "$LOG/$n.log" | tail -1)
  clk=$(echo "$r" | sed -n 's/.* frames, \([0-9.]*\) clocks per frame.*/\1/p')
  [ -n "$clk" ] && awk -v c="$clk" -v m="$max" 'BEGIN { exit !(c <= m) }' || ok=0
  report "$n" $ok $((SECONDS - t0)) "rtl/dpe_switch perf $c (<= $max)" "${r:-no PERF line}"
}

t0=$SECONDS
if bash ./run-sanity.sh > "$LOG/sanity.log" 2>&1; then ok=1; else ok=0; fi
cat "$LOG/sanity.log"
report sanity $ok $((SECONDS - t0)) "run-sanity.sh" "$(tail -1 "$LOG/sanity.log")"

bench chacha20poly1305 chacha20poly1305_encrypt
bench dpe              dpe
bench dpe-mux          dpe_mux
bench dpe-demux        dpe_demux
bench dpe-switch       dpe_switch
# throughput, 1420-byte packets back to back (3.build/pypeline_build/README.md,
# "Throughput in the SoC"): fail when a change makes the DPE slower
perf  perf-enc         enc1420 217
perf  perf-dec         dec1420 316
perf  perf-mix         mix1420 207
bench gmii2gmii        gmii2gmii_test
bench pcap-rw          pcap_reader_writer
bench trng-icarus      trng SIM=icarus
bench trng-janushdl    trng SIM=janushdl
bench flash-janushdl   flash_spi SIM=janushdl
bench peer-janushdl    lkup_peer_table SIM=janushdl
[ "${REGRESS_RINGS:-0}" = 1 ] && bench trng-rings trng PLUSARGS="+trng_rings=1 +notrace"

cosim cosim-vproc  "" CPU=vproc
# the UART takes the bus while the firmware stores (#61): every write lands
cosim cosim-stress "UART_BUS_STRESS: 4 bus writes, 0 data errors" CPU=rtl \
  USRSIMOPTS="-GUART_BUS_STRESS_N=4"
# the firmware on VProc against the real data plane: handshakes, data both
# ways, replay, the session pool, the timers (scaled), a cookie reply
e2e   cosim-e2e    CPU=vproc

echo "regression: $fails failed"
[ $fails = 0 ]

# -----------------------------------------------------------------------------
# Project:     WireGuard-FPGA
# Description: NLnet-funded open-source implementation
# Funding:     https://nlnet.nl/project/KlusterLab-Wireguard (2023-12 to 2025-12)
# -----------------------------------------------------------------------------
