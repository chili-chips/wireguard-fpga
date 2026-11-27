#!/bin/bash
# SPDX-FileCopyrightText: 2026 Chili.CHIPS
#
# SPDX-License-Identifier: BSD-3-Clause
#
# Sanity, after every change (about 8 min): the firmware's host tests, the
# block benches of the data path, and the full co-simulation with the RTL
# CPU. Each run must exit 0 (a bench fails on "RESULT: FAIL", sim.mk) and show
# its result line. Prints one line per run, logs in logs/sanity/; exits 1 if
# any run fails. run-regression.sh runs this, then the rest.
#
# The tests of the fixes found by the 2026-11-26 review run here:
#   dpe_wg_decryptor LOOPBACK=0  a frame longer than its IPv4 length says
#                                must not overfill the core (wg_check.py wgx)
#   lkup_peer_table              receiver index 0 never matches (an unwritten
#                                entry holds local_id 0 and a zero key)
#   cosim-rtl-sop                a stray UART SOP must time out and give the
#                                CPU the bus back, with no CSR access meanwhile;
#                                a UART read of a CSR must read it once
#                                (tb.sv UART_SOP_TEST, set with -G)
#
# Needs Verilator, python3, gcc and the RISC-V gcc (as the benches and
# MakefileVProc.mk do). Run it in a local copy of the repo: the co-simulation
# writes its build into 4.sim.
#
# Usage: bash run-sanity.sh

set -u
cd "$(dirname "$0")"
LOG=$PWD/logs/sanity  # not obj/: the co-simulation's make clean removes it
mkdir -p "$LOG"
fails=0

report() {  # name, ok (1/0), seconds, what, result
  [ "$2" = 1 ] || fails=$((fails + 1))
  printf '%-22s %4d s  %-4s %-40s %s\n' "$1" "$3" "$([ "$2" = 1 ] && echo PASS || echo FAIL)" "$4" "$5"
}

host() {  # name: 2.sw/tests/<name>, make test
  local t0=$SECONDS ok=0 r
  make -C ../2.sw/tests/"$1" test > "$LOG/t-$1.log" 2>&1 && ok=1
  r=$(grep -a -E 'PASS|FAIL|checks' "$LOG/t-$1.log" | tail -1)
  report "t-$1" $ok $((SECONDS - t0)) "2.sw/tests/$1" "${r:-see $LOG/t-$1.log}"
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

for t in noise cookie wg_session rng rtc; do host $t; done

bench dec-hostile   dpe_wg_decryptor LOOPBACK=0
bench dec-loopback  dpe_wg_decryptor LOOPBACK=1
bench encryptor     dpe_wg_encryptor
bench disassembler  dpe_wg_disassembler
bench peer-table    lkup_peer_table
bench egress        lkup_egress
bench trng          trng
bench flash-spi     flash_spi

cosim cosim-rtl-sop "UART_SOP_TEST: CSR read PASS" CPU=rtl \
  USRSIMOPTS="-GUART_SOP_TEST=1 -GUART_TIMEOUT_LOG2=10"

echo "sanity: $fails failed"
[ $fails = 0 ]

# -----------------------------------------------------------------------------
# Project:     WireGuard-FPGA
# Description: NLnet-funded open-source implementation
# Funding:     https://nlnet.nl/project/KlusterLab-Wireguard (2023-12 to 2025-12)
# -----------------------------------------------------------------------------
