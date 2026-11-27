#!/bin/bash
# SPDX-FileCopyrightText: 2026 Chili.CHIPS
#
# SPDX-License-Identifier: BSD-3-Clause
#
# Formal equivalence check of the design between two versions of the RTL, with
# EQY (YosysHQ's equivalence checker), chip view (SYNTHESIS defined): the
# same job as run-leq.sh, the same command line and the same tops. Use it to
# prove that a cleanup does not change behaviour.
#
# EQY splits gold and gate into partitions at the signals they share by name,
# and proves each partition with the strategies below, in order: SAT
# (Yosys sat, cheap), then SBY with an SMT solver (Bitwuzla). Memories stay
# memory cells: EQY ends a partition at a memory's write and read ports, so a
# FIFO of any size is compared by its port signals, never as flops (run-leq.sh
# cannot prove a memory whose inputs differ: Yosys equiv has no SAT model for
# it). Only "DONE (PASS" for every top is a pass.
#
# usage:  bash run-eqy.sh <gold 1.hw> <gate 1.hw>
#   <gold 1.hw>, <gate 1.hw>  copies of 1.hw, e.g. before the change:
#                             mkdir -p /tmp/gold && git archive HEAD 1.hw | tar -x -C /tmp/gold
#                             bash run-eqy.sh /tmp/gold/1.hw ../../1.hw
#   EQY_TOPS="top ..."        the tops (default: top and BLOCK_TOPS, as run-leq.sh)
#   EQY_EXTRA=<file>          EQY sections added to each config, e.g. [match] or
#                             [collect] for registers that were renamed:
#                               [match top]
#                               gold-match old_name new_name
#   EQY_DEPTH=<n>             induction depth of both strategies (default 3)
#   EQY_JOBS=<n>              partitions proven at once (default: CPU count)
#   GOLD_SOURCES=<sources.sh> the gold tree's sources.sh, as for run-leq.sh
#
# Both versions use the same generated CSR (3.build/csr_build/generated-files)
# and the same imem.INIT.vh (3.build/sw_build). The Xilinx primitives and the
# generated ChaCha20-Poly1305 core are black boxes (gen_xilinx_bb.py,
# gen_core_bb.py): their inputs are compared, their outputs are shared.
#
# Needs eqy, sby, yosys-smtbmc and bitwuzla (OSS CAD Suite) and Yosys with
# read_slang (a plugin in the OSS CAD Suite: "-m slang" unless YOSYS_ARGS is
# set, as run-lint.sh). EQY, YOSYS, YOSYS_CONFIG and PYTHON override the commands.
set -e
HERE=$(cd "$(dirname "$0")" && pwd)
. "$HERE/sources.sh"
[ $# -eq 2 ] || { sed -n '19,30p' "$0"; exit 2; }
GOLD=$(cd "$1" && pwd); GATE=$(cd "$2" && pwd)
BLD=$(cd "$HERE/.." && pwd)
EQY=${EQY:-eqy}
YOSYS=${YOSYS:-yosys}
YOSYS_CONFIG=${YOSYS_CONFIG:-yosys-config}
PYTHON=${PYTHON:-python3}
DEPTH=${EQY_DEPTH:-3}
JOBS=${EQY_JOBS:-$(nproc)}
command -v "$EQY" >/dev/null || { echo "eqy not found (OSS CAD Suite bin on PATH, or EQY=)"; exit 2; }
PLUGIN=""
if [ -z "${YOSYS_ARGS+set}" ]; then  # as run-lint.sh: read_slang built in, or the plugin
  "$YOSYS" -p 'help read_slang' 2>/dev/null | grep -q 'read_slang \[' || PLUGIN="plugin -i slang"
elif [ "$YOSYS_ARGS" = "-m slang" ]; then
  PLUGIN="plugin -i slang"
fi
PRIMS="PLLE2_BASE BUFG IBUFGDS BUFGMUX ODDR DSP48E1 STARTUPE2 LUT1 LUT2"
GEN=$BLD/pypeline_build/soc  # the core the DPE uses, gzip'd
CORES="chacha20poly1305_encrypt_decrypt_shared"
TOPS=${EQY_TOPS:-top $BLOCK_TOPS}
W=$(mktemp -d); cd "$W"

"$PYTHON" "$HERE/gen_xilinx_bb.py" "$("$YOSYS_CONFIG" --datdir)/xilinx" bb.sv $PRIMS >/dev/null
for c in $CORES; do "$PYTHON" "$HERE/gen_core_bb.py" "$GEN/$c.v.gz" $c >> bb.sv; done

files() {  # $1 = 1.hw dir, $2 = gold|gate; the design, and what $TOP adds to it (as run-leq.sh)
  local s=$HERE/sources.sh
  [ "$2" = gold ] && s=${GOLD_SOURCES:-$s}
  ( . "$s"
    x=""
    [ "$TOP" = top ] || x="$(block_rtl "$TOP" "$1")"
    echo "$W/bb.sv" $(design_rtl "$1" "$BLD" | grep -v /pypeline_build/soc/ | tr '\n' ' ') $x )
}

prove() {  # the EQY run of one top ($TOP), in its own directory
  mkdir -p "$W/$TOP"; cd "$W/$TOP"
  local READ="read_slang --allow-toplevel-iface-ports -D SYNTHESIS -D SYN_YOSYS_BUG --top $TOP -I $BLD/sw_build"
  # memory_collect: one $mem_v2 cell per memory; EQY's partitioner asserts on
  # the separate $memrd/$memwr cells of a flattened design (rtlil.cc MEMID)
  local PREP="hierarchy -top $TOP; proc; flatten; memory_collect; async2sync; opt_clean"
  {
    echo "[gold]"; [ -n "$PLUGIN" ] && echo "$PLUGIN"
    echo "$READ $(files "$GOLD" gold)"; echo "$PREP"; echo
    echo "[gate]"; [ -n "$PLUGIN" ] && echo "$PLUGIN"
    echo "$READ $(files "$GATE" gate)"; echo "$PREP"; echo
    [ -n "${EQY_EXTRA:-}" ] && { cat "$EQY_EXTRA"; echo; }
    echo "[strategy sat]"; echo "use sat"; echo "depth $DEPTH"; echo
    echo "[strategy sby]"; echo "use sby"; echo "depth $DEPTH"; echo "engine smtbmc bitwuzla"
  } > "$TOP.eqy"
  local rc=0
  "$EQY" -f -j "$JOBS" "$TOP.eqy" > eqy.log 2>&1 || rc=$?
  grep -E "Failed to prove|Warning: Failed|ERROR|DONE \(" eqy.log | sed 's/^EQY [0-9:]* //' | tail -8
  echo "log: $PWD/eqy.log"
  RESULT="$RESULT
  $TOP: $([ $rc -eq 0 ] && grep -q 'DONE (PASS' eqy.log && echo PASS || echo FAILED)"
  [ $rc -eq 0 ] && grep -q 'DONE (PASS' eqy.log
}

RESULT=""; fail=0
for TOP in $TOPS; do
  echo "== $TOP"
  prove || fail=1
done
echo "EQY:$RESULT"
if [ $fail -ne 0 ]; then
  echo "EQY: FAILED"
  exit 1
fi
echo "EQY: PASS"

# -----------------------------------------------------------------------------
# Project:     WireGuard-FPGA
# Description: NLnet-funded open-source implementation
# Funding:     https://nlnet.nl/project/KlusterLab-Wireguard (2023-12 to 2025-12)
# -----------------------------------------------------------------------------
