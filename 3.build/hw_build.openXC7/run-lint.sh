#!/bin/bash
# SPDX-FileCopyrightText: 2026 Chili.CHIPS*ba
#
# SPDX-License-Identifier: BSD-3-Clause
#
# Lint of the RTL of top (1.hw/top.filelist, via sources.sh) and of the DPE
# blocks top does not instantiate yet (BLOCK_TOPS in sources.sh, each a top of
# its own through its wrapper in leq_tops.sv): syntax and limited semantic
# checks with a set of opensource tools, run in this order:
#
#   tags       every /*LINT:OK*/ sits on an output port (no tool needed)
#   verilator  Verilator --lint-only -Wall: unused/undriven signals, widths,
#              implicit nets, multiple drivers, blocking vs non-blocking, case
#   yosys      Yosys check on the read_slang netlist: combinational loops,
#              conflicting drivers, used-but-undriven wires, latches
#   slang      read_slang -Wextra: strict IEEE parse, second opinion
#   verible    Verible style rules (run-lint.verible) on our own RTL: our case
#              rule -- signals and ports lower case, constants UPPER case --
#              and Verible's defaults
#   ghdl       GHDL analysis and elaboration (VHDL-2008) of the Pypeline
#              ChaCha20-Poly1305 core, 3.build/pypeline_build, as VHDL that
#              pypelinec --no_synth generates (combinational, no Vivado)
#   ghdl-verilator
#              the same VHDL converted to Verilog by Yosys' GHDL plugin, then
#              Verilator --lint-only with its default warnings (widths, drivers,
#              latches); -Wall's style and unused-signal warnings say nothing
#              about a GHDL netlist
#
# There is no opensource CDC checker mature enough for a cdc phase.
#
# usage:  bash run-lint.sh [phase ...]    default: all phases
#         VIEW=sim bash run-lint.sh        lint the simulation view (SIM_ONLY
#                                          defined, # delays ignored by read_slang;
#                                          default chip: SYNTHESIS)
#         CPU=edubos5 bash run-lint.sh     lint with the other CPU (picorv32 or edubos5;
#                                          default: the one top.filelist lists)
#         LINT_TOPS="top ..." bash run-lint.sh   the tops the verilator, yosys
#                                          and slang phases elaborate (default:
#                                          top and BLOCK_TOPS)
#
# The generated ChaCha20-Poly1305 cores of the encryptor and the decryptor are
# black boxes (gen_core_bb.py), as in run-leq.sh.
#
# A phase whose tool is not found is skipped. The tool commands can be
# overridden: VERILATOR, YOSYS (+ YOSYS_ARGS), YOSYS_CONFIG, PYTHON, VERIBLE,
# GHDL, GHDL_YOSYS (+ GHDL_YOSYS_ARGS, default "-m ghdl"; default YOSYS) and
# PYPELINEC (PipelineC's src/pypelinec, as for pypeline_build/build.py).
# PYPELINE_TOP selects the Pypeline top (default: the shared encrypt/decrypt one).
# read_slang is built into the openXC7 Yosys; with the OSS CAD Suite it is a
# plugin: YOSYS_ARGS="-m slang". The Xilinx primitives come from the Yosys
# library (yosys-config --datdir), as blackboxes (gen_xilinx_bb.py).
#
# Our forks of third-party code, formatted like ours but linted as theirs:
# external_lib (Alex Forencich's verilog-ethernet and verilog-axis) and
# PicoRV32. Their
# Verilator and slang findings are not shown; the Yosys check findings, which
# can be bugs (latches, undriven wires), stay. The PeakRDL CSR is linted, with
# waivers for its generated constructs.
#
# Sources are copied into a work directory (LINT_WORK, default mktemp -d) and
# every tool gets relative paths. Logs stay there: <phase>.log is the tool
# output, <phase>.findings the findings left after the waivers.
#
# Accepted findings are waived in two ways, each one reviewed:
#   - inline, on an unused output of an instance:  .PIN (/*LINT:OK*/)
#     waives the findings about that pin, from any phase; the tags phase flags
#     a /*LINT:OK*/ on an input, so it cannot hide a floating input
#   - run-lint-waivers.txt (or LINT_WAIVERS=<file>), for findings without a
#     source line of ours (generated code, ...)
# Exit status is non-zero when any phase has findings that are not waived, or
# when its tool fails or stops before the step it reports on (FAILED in the
# summary): "0 finding(s)" always means the phase really ran.

set -u
HERE=$(cd "$(dirname "$0")" && pwd)
REPO=$HERE/../..
. "$HERE/sources.sh"
TOPS=${LINT_TOPS:-top $BLOCK_TOPS}
CORES="chacha20poly1305_encrypt chacha20poly1305_decrypt"
VERILATOR=${VERILATOR:-verilator}
YOSYS=${YOSYS:-yosys}
YOSYS_CONFIG=${YOSYS_CONFIG:-yosys-config}
PYTHON=${PYTHON:-python3}
YOSYS_ARGS=${YOSYS_ARGS:-}
VERIBLE=${VERIBLE:-verible-verilog-lint}
GHDL=${GHDL:-ghdl}
GHDL_YOSYS=${GHDL_YOSYS:-$YOSYS}
GHDL_YOSYS_ARGS=${GHDL_YOSYS_ARGS:--m ghdl}
GHDL_FLAGS="--std=08 -frelaxed"
PYPELINEC=${PYPELINEC:-pypelinec}
PYP_TOP=${PYPELINE_TOP:-chacha20poly1305_encrypt_decrypt_shared}
VIEW=${VIEW:-chip}
case $VIEW in
  chip) VL_DEFS="-DSYNTHESIS -DSYN_YOSYS_BUG"; SL_DEFS="-D SYNTHESIS -D SYN_YOSYS_BUG" ;;
  sim)  VL_DEFS="-DSIM_ONLY -DSYN_YOSYS_BUG"; SL_DEFS="-D SIM_ONLY -D SYN_YOSYS_BUG --ignore-timing" ;;
  *) echo "VIEW must be chip or sim, got \"$VIEW\""; exit 1 ;;
esac

WAIVERS=${LINT_WAIVERS:-$HERE/run-lint-waivers.txt}
PHASES=${*:-tags verilator yosys slang verible ghdl ghdl-verilator}
W=${LINT_WORK:-$(mktemp -d)}
mkdir -p "$W"
W=$(cd "$W" && pwd)

# ---- work copy ----------------------------------------------------------------
(cd "$REPO" && cp -r --parents 1.hw/top.filelist 1.hw/top.sv 1.hw/fpgatech_lib 1.hw/external_lib \
   1.hw/ip.* "$W/")
mkdir -p "$W/bld/csr_build/generated-files" "$W/bld/sw_build"
cp "$REPO"/3.build/csr_build/generated-files/{csr_pkg,csr}.sv "$W/bld/csr_build/generated-files/"
cp "$REPO/3.build/sw_build/imem.INIT.vh" "$W/bld/sw_build/"
cp "$HERE/leq_tops.sv" "$W/"
[ -n "${CPU:-}" ] && { cpu_select "$W/1.hw/top.filelist" "$CPU" || exit 1; }
cd "$W"
SV=$(design_rtl 1.hw bld | tr '\n' ' ')
# the files of one top: the design, and for a block top its files and wrapper
top_sv() {
  if [ "$1" = top ]; then echo "$SV"; else echo "$SV $(block_rtl "$1" 1.hw) leq_tops.sv"; fi
}
# every file one of the tops reads, once
ALL=$(for t in $TOPS; do top_sv $t; done | tr ' ' '\n' | awk 'NF && !seen[$0]++' | tr '\n' ' ')
OWN=$(own_rtl 1.hw bld | tr '\n' ' ')
INC="bld/sw_build"
PRIMS="PLLE2_BASE BUFG IBUFGDS BUFGMUX BUFIO BUFIO2 BUFR ODDR ODDR2"

have() { command -v "$1" >/dev/null 2>&1; }
declare -A RESULT
skip() { RESULT[$1]="skipped ($2)"; echo "-- $1: skipped, $2"; }

# waiver regexes of one phase: the lines "<phase> <regex>" of the waivers file
waivers() {
  [ -f "$WAIVERS" ] || return 0
  awk -v ph="$1" '{ sub(/\r$/, "") } $1 == ph { sub(/^[ \t]*[^ \t]+[ \t]+/, ""); print }' "$WAIVERS"
}

# inline waivers .PIN (/*LINT:OK*/), as file:line:PIN (the first line keeps
# awk's NR==FNR test working when there is none)
{ echo "#"
  grep -n -o -E '\.[A-Za-z_][A-Za-z0-9_]*[[:space:]]*\([[:space:]]*/\*LINT:OK\*/[[:space:]]*\)' $ALL |
    sed -E 's/^([^:]*:[0-9]+):\.([A-Za-z0-9_]*).*/\1:\2/'
} > lint_ok.txt

found() {  # $1 phase; one finding per line on stdin (not a pipe: RESULT must stay in this shell)
  awk '!seen[$0]++' > $1.all  # a finding in a module that several tops share, once
  # drop findings about a pin waived inline: file:line plus the 'PIN' the tools
  # quote (Windows tools print \ in paths)
  awk 'NR == FNR { ok[$0] = 1; next }
       { l = $0; gsub(/\\/, "/", l)
         if (match(l, /[A-Za-z0-9_.\/-]+\.s?v:[0-9]+/)) {
           k = substr(l, RSTART, RLENGTH)
           if (match(l, /\047[A-Za-z_][A-Za-z0-9_]*\047/) && (k ":" substr(l, RSTART + 1, RLENGTH - 2)) in ok) next
         }
         print }' lint_ok.txt $1.all > $1.inline
  grep -E -v -f <(waivers $1) $1.inline > $1.findings
  local n=$(wc -l < $1.findings) t=$(wc -l < $1.all) i=$(wc -l < $1.inline)
  RESULT[$1]="$n finding(s), $((t - n)) waived ($((t - i)) inline), see $W/$1.findings"
  echo "-- $1: $n finding(s), $((t - n)) waived ($((t - i)) inline)"
}

# Xilinx primitive stubs and the generated cores as black boxes, for the
# tags, Verilator, Yosys and slang phases
bb() {
  [ -s bb.sv ] && return 0
  have "$YOSYS_CONFIG" || return 1
  "$PYTHON" "$HERE/gen_xilinx_bb.py" "$("$YOSYS_CONFIG" --datdir)/xilinx" bb.tmp $PRIMS >/dev/null &&
    for c in $CORES; do
      "$PYTHON" "$HERE/gen_core_bb.py" "$REPO/3.build/pipelinec_build/generated-files/$c.v" $c >> bb.tmp ||
        return 1
    done && mv bb.tmp bb.sv
}

# /*LINT:OK*/ on anything but an output port; the port directions come from the
# module headers of the design and the primitive stubs
# A tool that fails, or stops before the step its findings come from, fails its
# phase: "0 finding(s)" must not stand for "not checked"
failed() {  # $1 phase, $2 reason
  RESULT[$1]="FAILED ($2), see $W/$1.log"
  echo "-- $1: FAILED, $2"
}

# after found: a tool that exits non-zero must have reported something (waived
# or not); a non-zero exit with nothing to show is the tool failing
exit_check() {  # $1 phase, $2 exit status
  if [ "$2" -ne 0 ] && [ ! -s "$1.all" ]; then failed "$1" "exit $2, nothing reported"; fi
}

run_tags() {
  bb || { skip tags "no Xilinx stubs (yosys-config)"; return; }
  "$PYTHON" - -- bb.sv $ALL > tags.log <<'EOF'
import re, sys
files = sys.argv[sys.argv.index('--') + 1:]
text = {f: open(f).read() for f in files}
types = {'logic', 'wire', 'reg', 'signed', 'unsigned', 'var', 'bit', 'integer', 'tri'}
dirs = {}
for t in text.values():
    t = re.sub(r'//[^\n]*|/\*.*?\*/', '', t, flags=re.S)
    for m in re.finditer(r'\bmodule\s+(\w+)(.*?)\bendmodule', t, flags=re.S):
        d = dirs.setdefault(m.group(1), {})
        # ranges first: they can hold ( ), e.g. [$clog2(DEPTH):0]
        for p in re.finditer(r'\b(input|output|inout)\b(.*?)(?=\b(?:input|output|inout)\b|[;()]|$)',
                             re.sub(r'\[[^\]]*\]', ' ', m.group(2)), flags=re.S):
            for part in p.group(2).split(','):
                w = [x for x in re.findall(r'[A-Za-z_]\w*', part) if x not in types]
                if w:
                    d.setdefault(w[-1], p.group(1))
tag  = re.compile(r'\.(\w+)\s*\(\s*/\*LINT:OK\*/\s*\)')
inst = re.compile(r'\s*([A-Za-z_]\w*)\s*(#|\s\w+\s*\()')
kw   = {'if', 'else', 'for', 'begin', 'end', 'case', 'assign', 'module', 'always', 'always_ff',
        'always_comb', 'initial', 'function', 'task', 'return', 'generate'}
for f in files:
    lines = text[f].split('\n')
    for n, line in enumerate(lines, 1):
        for m in tag.finditer(line):
            typ = next((t.group(1) for i in range(n - 1, -1, -1)
                        for t in [inst.match(lines[i])] if t and t.group(1) not in kw), None)
            d = dirs.get(typ, {}).get(m.group(1))
            if d != 'output':
                print(f'{f}:{n}: LINT:OK on {d or "unknown"} port {typ}.{m.group(1)}')
EOF
  local rc=$?
  [ $rc -eq 0 ] || { failed tags "exit $rc"; return; }
  found tags < tags.log
}

run_verilator() {
  have "$VERILATOR" || { skip verilator "$VERILATOR not found"; return; }
  bb || { skip verilator "no Xilinx stubs (yosys-config)"; return; }
  cat > waive.vlt <<'VLT'
`verilator_config
lint_off -file "*bb.sv"
lint_off -file "*/external_lib/*"
lint_off -file "*/cpu.PICORV32/*"
// one file of wrappers, a module per block top
lint_off -rule DECLFILENAME -file "*leq_tops.sv"
VLT
  # --timescale: none of the RTL sets one (no delays)
  local t rc=0
  for t in $TOPS; do
    "$VERILATOR" --lint-only -Wall -Wno-fatal --timing --timescale 1ns/1ns --top-module $t $VL_DEFS \
      -DLEQ_TOP_$t -I$INC waive.vlt bb.sv $(top_sv $t) > verilator.$t.log 2>&1 || rc=$?
  done
  for t in $TOPS; do echo "-- top $t"; cat verilator.$t.log; done > verilator.log
  # A package is compiled whole by every top that reads it, and each top
  # reports the package parameters it does not use: one is unused only when
  # every top that reads the package reports it
  for t in $TOPS; do top_sv $t | tr ' ' '\n'; done |
    awk 'NF { n[$0]++ } END { for (f in n) print n[f], f }' > tops_per_file.txt
  found verilator < <(for t in $TOPS; do grep -E '^%(Warning|Error)' verilator.$t.log; done |
    awk 'NR == FNR { n[$2] = $1; next }
         /^%Warning-UNUSED[A-Z]*: [^ :]*_pkg\.sv:/ {
           f = $2; sub(/:.*/, "", f)
           if (++seen[$0] == n[f]) print
           next
         }
         { print }' tops_per_file.txt -)
  exit_check verilator $rc
}

run_yosys() {
  have "$YOSYS" || { skip yosys "$YOSYS not found"; return; }
  # the SIM_ONLY models (PLL clocks) are behavioural: check the netlist of the chip view only
  [ $VIEW = sim ] && { skip yosys "chip view only"; return; }
  bb || { skip yosys "no Xilinx stubs"; return; }
  local t rc
  : > yosys.log
  for t in $TOPS; do
    "$YOSYS" $YOSYS_ARGS -q -l yosys.$t.log -p "read_slang $SL_DEFS -D LEQ_TOP_$t --top $t -I $INC \
        bb.sv $(top_sv $t); hierarchy -check -top $t; proc; check -nolatches -initdrv" >/dev/null 2>&1
    rc=$?
    cat yosys.$t.log >> yosys.log
    if [ $rc -ne 0 ] || ! grep -q 'Executing CHECK pass' yosys.$t.log; then
      failed yosys "top $t: exit $rc, CHECK pass not reached"; return
    fi
  done
  # read_slang's own warnings are the slang phase's business; take check's
  found yosys < <(for t in $TOPS; do awk '/Executing CHECK pass/ { c = 1 } c && /^Warning:/' yosys.$t.log; done)
}

run_slang() {
  have "$YOSYS" || { skip slang "$YOSYS not found"; return; }
  bb || { skip slang "no Xilinx stubs"; return; }
  local t rc=0
  : > slang.log
  for t in $TOPS; do
    "$YOSYS" $YOSYS_ARGS -q -l slang.$t.log -p "read_slang $SL_DEFS -D LEQ_TOP_$t --top $t -I $INC \
        -Wextra bb.sv $(top_sv $t)" >/dev/null 2>&1 || rc=$?
    cat slang.$t.log >> slang.log
  done
  # the yosys-slang plugin prints "file:line: Warning:", the built-in read_slang
  # "file:line:col: warning:"; bring both to the second form so the waivers
  # match either. Paths come relative to the work directory, after any ../
  found slang < <(sed -E 's#^(\.\./)+[^ ]*/(1\.hw|bld)/#\2/#;
                          s/^([^ :]+:[0-9]+): Warning:/\1:0: warning:/;
                          s/^([^ :]+:[0-9]+): Error:/\1:0: error:/' slang.log |
                  grep -E 'warning:|error:' | grep -v -E '^(bb\.sv|1\.hw/external_lib/|1\.hw/ip\.cpu/cpu\.PICORV32/)')
  exit_check slang $rc
}

run_verible() {
  have "$VERIBLE" || { skip verible "$VERIBLE not found"; return; }
  cp "$HERE/run-lint.verible" .
  "$VERIBLE" --rules_config=run-lint.verible $OWN > verible.log 2>&1
  local rc=$?
  [ $rc -le 1 ] || { failed verible "exit $rc"; return; }
  found verible < <(grep -E ':[0-9]+:[0-9]+' verible.log)
  exit_check verible $rc
}

# Pypeline VHDL, generated once into $W/pypeline for both ghdl phases
pypeline_vhdl() {
  [ -s pypeline/vhdl_files.txt ] && return 0
  [ -e pypeline.failed ] && return 1
  # no __pycache__ in the source tree
  (cd "$REPO/3.build/pypeline_build" && PYTHONDONTWRITEBYTECODE=1 \
     "$PYPELINEC" ./src/chacha20poly1305.py --out_dir "$W/pypeline" --top $PYP_TOP --no_synth) \
     > pypeline.log 2>&1 && [ -s pypeline/vhdl_files.txt ] && return 0
  touch pypeline.failed; return 1
}

run_ghdl() {
  have "$GHDL" || { skip ghdl "$GHDL not found"; return; }
  have "$PYPELINEC" || { skip ghdl "$PYPELINEC not found (set PYPELINEC)"; return; }
  pypeline_vhdl || { cp pypeline.log ghdl.log; failed ghdl "pypelinec --no_synth"; return; }
  mkdir -p ghdl.work
  # -Wno-hide: every generated function declares a variable named after its
  # return port (return_output)
  { "$GHDL" -i $GHDL_FLAGS --workdir=ghdl.work $(cat pypeline/vhdl_files.txt) &&
    "$GHDL" -m $GHDL_FLAGS -Wno-hide --workdir=ghdl.work -o ghdl.work/top $PYP_TOP; } > ghdl.log 2>&1
  local rc=$?
  found ghdl < <(sed "s#$W/##" ghdl.log | grep -E ':[0-9]+:[0-9]+:(warning|error)' | sort -u)
  exit_check ghdl $rc
}

run_ghdl_verilator() {
  local ph=ghdl-verilator
  have "$VERILATOR" || { skip $ph "$VERILATOR not found"; return; }
  have "$PYPELINEC" || { skip $ph "$PYPELINEC not found (set PYPELINEC)"; return; }
  "$GHDL_YOSYS" $GHDL_YOSYS_ARGS -q -p "help ghdl" >/dev/null 2>&1 ||
    { skip $ph "no GHDL plugin in $GHDL_YOSYS (set GHDL_YOSYS)"; return; }
  pypeline_vhdl || { cp pypeline.log $ph.log; failed $ph "pypelinec --no_synth"; return; }
  "$GHDL_YOSYS" $GHDL_YOSYS_ARGS -q -l $ph.log -p "ghdl $GHDL_FLAGS --no-formal \
      $(cat pypeline/vhdl_files.txt) -e $PYP_TOP; write_verilog -noattr pypeline_top.v" >/dev/null 2>&1 ||
    { failed $ph "GHDL to Verilog conversion"; return; }
  "$VERILATOR" --lint-only -Wno-fatal --top-module $PYP_TOP pypeline_top.v >> $ph.log 2>&1
  local rc=$?
  found $ph < <(grep -E '^%(Warning|Error)' $ph.log)
  exit_check $ph $rc
}

for ph in $PHASES; do
  case $ph in
    tags|verilator|yosys|slang|verible|ghdl|ghdl-verilator) echo "== $ph"; run_${ph//-/_} ;;
    *) echo "unknown phase: $ph (tags verilator yosys slang verible ghdl ghdl-verilator)"; exit 2 ;;
  esac
done

echo; echo "== summary  ($VIEW view, $W)"
FAIL=0
for ph in $PHASES; do
  printf '  %-14s %s\n' "$ph" "${RESULT[$ph]}"
  case ${RESULT[$ph]} in skipped*|"0 finding"*) ;; *) FAIL=1 ;; esac
done
exit $FAIL

# -----------------------------------------------------------------------------
# Project:     WireGuard-FPGA
# Description: NLnet-funded open-source implementation
# Funding:     https://nlnet.nl/project/KlusterLab-Wireguard (2023-12 to 2025-12)
# Ported from: openPCIE / openCologne-PCIE (4.build)
# -----------------------------------------------------------------------------
