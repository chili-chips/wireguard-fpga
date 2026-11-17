#!/bin/bash
# SPDX-FileCopyrightText: 2026 Chili.CHIPS*ba
#
# SPDX-License-Identifier: BSD-3-Clause
#
# Formal equivalence check of the whole design (top: Ethernet MACs and PHY
# interfaces, DPE, SOC, CPU, CSR) between two versions of the RTL, with Yosys
# (read_slang), chip view (SYNTHESIS defined). Use it to prove that a cleanup
# does not change behaviour. The DPE blocks top does not instantiate yet are
# tops of their own (leq_tops.sv): dpe_wg_encryptor, dpe_wg_decryptor,
# dpe_egress_ip_lookup, dpe_wg_disassembler; the encryptor's and the decryptor's
# generated ChaCha20-Poly1305 cores are black boxes (gen_core_bb.py).
# LEQ_TOPS="top leq_dpe_wg_encryptor ..." picks the tops (default: all).
#
# usage:  bash run-leq.sh <gold 1.hw> <gate 1.hw> [sed script]
#         LEQ_EXTRA=<file> bash run-leq.sh ... Yosys commands run after equiv_make,
#                                              e.g. equiv_add for registers that
#                                              were regrouped into a struct
#                                              (gold: name_gold, gate: name_gate):
#           cd eq
#           equiv_add -try \u_x.ng_cur_state_gold \u_x.ng_q_gate[12]
#           cd ..
#   <gold 1.hw>, <gate 1.hw>  copies of 1.hw, e.g. before the change:
#                             mkdir -p /tmp/gold && git archive HEAD 1.hw | tar -x -C /tmp/gold
#                             bash run-leq.sh /tmp/gold/1.hw ../../1.hw
#   [sed script]              renames gold objects to their gate names, for a
#                             change that moves logic between modules, e.g.
#                             's|^u_soc\.u_x\.|u_soc.|'
#
# Both versions use the same generated CSR (3.build/csr_build/generated-files)
# and the same imem.INIT.vh (3.build/sw_build) for the IMEM contents.
#
# The Xilinx primitives (PLLE2_BASE, BUFG, IBUFGDS, ODDR, ...) are black boxes
# turned into ports (expose -evert): their inputs are compared, their outputs
# are shared free inputs. equiv_induct starts from any state, so logic that is
# only constant after reset shows up as unproven and needs a look by hand.
#
# Memories stay memory cells (memory -nomap): the FIFOs hold over 1M bits,
# too many to prove as flops. A small one (64 words at most, a buffer of a
# few beats) is mapped to flops (memory_map), so it can be compared with the
# same buffer written as registers. equiv_struct merges the memories whose inputs
# match; a memory whose inputs differ ends the run with "No SAT model
# available for cell ... ($mem_v2)". Only "Equivalence successfully proven"
# is a pass.
#
# LEQ_MODE (default auto):
#   flat  the whole design flattened, as above: one proof, end to end
#   hier  module by module (read_slang --keep-hierarchy): every submodule
#         instance becomes ports of its parent (its inputs are compared, its
#         outputs are shared free inputs), so each module is proven on its
#         own and an unchanged FIFO never needs SAT. Needs the same modules
#         (the same hierarchy) in gold and gate; a change that moves logic
#         between modules needs flat, with a [sed script]
#   auto  flat; when that ends on a memory ("No SAT model ... $mem"), which
#         happens for any change upstream of a FIFO, hier decides
#
# Needs Yosys with read_slang: built into the openXC7 Yosys; with the OSS CAD
# Suite, YOSYS_ARGS="-m slang". YOSYS, YOSYS_CONFIG and PYTHON override the
# commands.
set -e
HERE=$(cd "$(dirname "$0")" && pwd)
. "$HERE/sources.sh"
GOLD=$(cd "$1" && pwd); GATE=$(cd "$2" && pwd); MAP=${3:-}
BLD=$(cd "$HERE/.." && pwd)
YOSYS=${YOSYS:-yosys}
YOSYS_CONFIG=${YOSYS_CONFIG:-yosys-config}
YOSYS_ARGS=${YOSYS_ARGS:-}
PYTHON=${PYTHON:-python3}
PRIMS="PLLE2_BASE BUFG IBUFGDS BUFGMUX BUFIO BUFIO2 BUFR ODDR ODDR2"
# The generated ChaCha20-Poly1305 cores are black boxes too (the same files
# on both sides; their proof against the Python source is PipelineC#398)
GEN=$BLD/pipelinec_build/generated-files
CORES="chacha20poly1305_encrypt chacha20poly1305_decrypt"
# The tops: the design, and the DPE blocks it does not instantiate yet
# (leq_tops.sv wraps each, a top cannot have interface ports)
# A change to a wrapped block's ports: LEQ_TOPS_GOLD names the gold side's
# wrappers, with the same top ports as the gate's (adapting the old ports)
WRAP_GOLD=$HERE/leq_tops.sv
[ -n "${LEQ_TOPS_GOLD:-}" ] && WRAP_GOLD=$(cd "$(dirname "$LEQ_TOPS_GOLD")" && pwd)/$(basename "$LEQ_TOPS_GOLD")
TOPS=${LEQ_TOPS:-top $BLOCK_TOPS}
W=$(mktemp -d); cd "$W"

"$PYTHON" "$HERE/gen_xilinx_bb.py" "$("$YOSYS_CONFIG" --datdir)/xilinx" bb.sv $PRIMS >/dev/null
for c in $CORES; do "$PYTHON" "$HERE/gen_core_bb.py" "$GEN/$c.v" $c >> bb.sv; done
PRIMS="$PRIMS $CORES"

files() {  # $1 = 1.hw dir, $2 = gold|gate; the design, and what $TOP adds to it
  local x="" wrap=$HERE/leq_tops.sv
  [ "$2" = gold ] && wrap=$WRAP_GOLD
  [ "$TOP" = top ] || x="$(block_rtl "$TOP" "$1") $wrap"
  echo bb.sv $(design_rtl "$1" "$BLD" | tr '\n' ' ') $x
}
BB=$(for p in $PRIMS; do printf 't:%s ' $p; done)

prove() {  # the LEQ of one top ($TOP), in its own directory
mkdir -p "$W/$TOP"; cd "$W/$TOP"; cp "$W/bb.sv" .
READ="read_slang -D SYNTHESIS -D SYN_YOSYS_BUG -D LEQ_TOP_$TOP --top $TOP -I $BLD/sw_build"
PREP="hierarchy -top $TOP; proc; flatten; memory -nomap; memory_map t:\$mem_v2 r:SIZE<=64 %i; async2sync"

REN=""
if [ -n "$MAP" ]; then   # rename gold objects to their gate names (skip names the gold already has)
  cat > names.ys <<EOF
$READ $(files $GOLD gold)
$PREP
tee -q -o names.txt select -list $TOP/w:* $TOP/c:*
EOF
  "$YOSYS" $YOSYS_ARGS -q names.ys >/dev/null
  sed "s|^$TOP/||" names.txt | sed -n "h; $MAP; G; s/\n/ /; p" |
    awk 'NR==FNR {have[$1]=1; next} $1!=$2 && substr($2,1,1)!="$" && !($1 in have) {print "rename \\" $2 " \\" $1}' \
        <(sed "s|^$TOP/||" names.txt) - > ren.ys
  echo "renamed: $(wc -l < ren.ys)"
  REN="cd $TOP; script ren.ys; cd .."
fi

EXTRA=""
[ -n "${LEQ_EXTRA:-}" ] && EXTRA="script $(cd "$(dirname "$LEQ_EXTRA")" && pwd)/$(basename "$LEQ_EXTRA")"

flat() {
  cat > eq.ys <<EOF
$READ $(files $GOLD gold)
$PREP
$REN
expose -evert $BB; opt_clean; rename $TOP gold; design -stash gold
$READ $(files $GATE gate)
$PREP
expose -evert $BB; opt_clean; rename $TOP gate; design -stash gate
design -copy-from gold -as gold gold
design -copy-from gate -as gate gate
equiv_make gold gate eq
hierarchy -top eq
$EXTRA
equiv_struct
equiv_simple -seq 3
equiv_induct -seq 3
equiv_status
EOF
  rc=0
  "$YOSYS" $YOSYS_ARGS -q -l eq.log eq.ys >/dev/null || rc=$?
  grep -E "Found [0-9]+ .equiv|Of those cells|successfully proven|^ERROR" eq.log | tail -3
  grep "Unproven" eq.log | sed -E 's/.*: .([^ ]*)_gold.*/\1/; s/\[[0-9]+\]//g' | sort | uniq -c
  echo "log: $PWD/eq.log"
  # Pass only if Yosys got through equiv_status and proved every $equiv cell
  unproven=$(sed -nE 's/.*Of those cells [0-9]+ are proven and ([0-9]+) are unproven.*/\1/p' eq.log | tail -1)
  [ $rc -eq 0 ] && [ -n "$unproven" ] && [ "$unproven" -eq 0 ]
}

hier() {
  local HREAD="${READ/read_slang /read_slang --keep-hierarchy }"
  local HPREP="hierarchy -top $TOP; proc; memory -nomap; memory_map t:\$mem_v2 r:SIZE<=64 %i; async2sync; opt_clean"
  local EVERT='expose -evert c:* t:$* %d; opt_clean'
  local m mods
  for v in gold gate; do  # the modules, by their instance path names
    local d=$GOLD; [ $v = gate ] && d=$GATE
    "$YOSYS" $YOSYS_ARGS -q -p "$HREAD $(files $d $v); $HPREP; tee -q -o mods_$v.txt ls" >/dev/null
    sed -n 's/^  //p' mods_$v.txt | sort > mods_$v.lst
  done
  if ! cmp -s mods_gold.lst mods_gate.lst; then
    echo "modules only in gold or only in gate (the hierarchy changed; use LEQ_MODE=flat):"
    comm -3 mods_gold.lst mods_gate.lst | head -20
    return 1
  fi
  mods=$(grep -v -x -F -f <(printf '%s\n' $PRIMS) mods_gold.lst)
  {
    echo "$HREAD $(files $GOLD gold)"; echo "$HPREP"; echo "$EVERT"; echo "design -stash gold"
    echo "$HREAD $(files $GATE gate)"; echo "$HPREP"; echo "$EVERT"; echo "design -stash gate"
    for m in $mods; do
      echo "log LEQ-MODULE $m"
      echo "design -reset"
      echo "design -copy-from gold -as gold \\$m"
      echo "design -copy-from gate -as gate \\$m"
      echo "equiv_make gold gate eq"
      echo "hierarchy -top eq"
      echo "equiv_struct"
      echo "equiv_simple -seq 3"
      echo "equiv_induct -seq 3"
      echo "equiv_status"
    done
  } > hier.ys
  rc=0
  "$YOSYS" $YOSYS_ARGS -q -l hier.log hier.ys >/dev/null || rc=$?
  # per module: proven, or its unproven signals
  awk '/LEQ-MODULE/ {m=$NF} /are unproven/ && !/ 0 are unproven/ {print "  " m ": " $0}
       /Unproven \$equiv/ {sub(/.*: /, ""); print "    " $0}' hier.log
  local n proven
  n=$(echo "$mods" | wc -l)
  proven=$(grep -c "Equivalence successfully proven" hier.log)
  echo "modules proven: $proven of $n"
  grep -m3 "^ERROR" hier.log || true
  echo "log: $PWD/hier.log"
  [ $rc -eq 0 ] && [ "$proven" -eq "$n" ]
}

MODE=${LEQ_MODE:-auto}
case $MODE in
  flat) flat && ok=1 || ok=0 ;;
  hier) hier && ok=1 || ok=0 ;;
  auto)
    if flat; then
      MODE=flat
      ok=1
    elif grep -q "No SAT model available for cell .*\$mem" eq.log; then
      echo "flat: stopped on a memory (a change upstream of a FIFO): module by module"
      MODE=hier
      hier && ok=1 || ok=0
    else
      ok=0
    fi ;;
  *) echo "LEQ_MODE must be auto, flat or hier (got \"$MODE\")"; exit 2 ;;
esac
RESULT="$RESULT
  $TOP: $([ $ok -eq 1 ] && echo PASS || echo FAILED) ($MODE)"
[ $ok -eq 1 ]
}

RESULT=""; fail=0
for TOP in $TOPS; do
  echo "== $TOP"
  prove || fail=1
done
echo "LEQ:$RESULT"
if [ $fail -ne 0 ]; then
  echo "LEQ: FAILED"
  exit 1
fi
echo "LEQ: PASS"

# -----------------------------------------------------------------------------
# Project:     WireGuard-FPGA
# Description: NLnet-funded open-source implementation
# Funding:     https://nlnet.nl/project/KlusterLab-Wireguard (2023-12 to 2025-12)
# Ported from: openPCIE / openCologne-PCIE (4.build)
# -----------------------------------------------------------------------------
