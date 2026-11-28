#!/bin/bash
# SPDX-FileCopyrightText: 2026 Chili.CHIPS*ba
#
# SPDX-License-Identifier: BSD-3-Clause
#
# Lint of the RTL of top (1.hw/top.filelist, via sources.sh) and of the DPE
# blocks inside dpe_switch (BLOCK_TOPS in sources.sh, each also a top of
# its own, interface ports and all): syntax and limited semantic
# checks with a set of opensource tools, run in this order:
#
#   tags       every /*LINT:OK*/ sits on an output port, every unique and
#              priority case of our RTL has a default, and our RTL has no
#              `timescale, timeunit or timeprecision (no tool needed)
#   verilator  Verilator --lint-only -Wall: unused/undriven signals, widths,
#              implicit nets, multiple drivers, blocking vs non-blocking, case
#   yosys      Yosys check on the read_slang netlist: combinational loops,
#              conflicting drivers, used-but-undriven wires, latches
#   reset      Yosys netlist and run-lint-reset.py: a control flop or flag with
#              no reset (data and address flops need none: waived by name);
#              the tops, then eduBOS5 alone with RV32M and the counters
#   ram        Yosys memory_libmap (synth_xilinx's) and run-lint-ram.py: a
#              memory mapped to block or LUT RAM with read-first or
#              transparency logic built in fabric; the tops
#   iob        the same netlist and run-lint-iob.py: every data pin of top
#              reaches its flop directly (input: pin to D; output: Q to pin
#              and nothing else), so the flop can sit in the I/O tile
#   slang     read_slang -Wextra: strict IEEE parse, second opinion
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
#   cdc        Vivado report_cdc on top: clock-domain crossings and their
#              synchronizers (there is no mature opensource CDC checker; the
#              generated core is a black box)
#   check-timing
#              Vivado check_timing on the same synthesis: clocks and
#              constraints (a register with no clock, unconstrained
#              endpoints, ports with no I/O delay, loops); HIGH and MEDIUM
#   methodology
#              Vivado report_methodology on the same synthesis: the XDC and
#              timing rules (TIMING-*, XDC*, ...); Critical Warning and Warning;
#              plus every Vivado CRITICAL WARNING on an XDC line (a constraint
#              that matches nothing)
#
#              cdc, check-timing and methodology share one Vivado run
#              (about 3 min); skipped without Vivado, so not in CI
#
# The phase names and helpers are those of openPCIE and openCologne-PCIE
# (run-lint-ram.py, run-lint-iob.py, run-lint-reset.py: the same files).
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
# VIVADO, GHDL, GHDL_YOSYS (+ GHDL_YOSYS_ARGS, default "-m ghdl"; default YOSYS) and
# PYPELINEC (PipelineC's src/pypelinec, as for pypeline_build/build.py).
# PYPELINE_TOP selects the Pypeline top (default: the shared encrypt/decrypt one).
# read_slang is built into the openXC7 Yosys, a plugin in the OSS CAD Suite:
# when YOSYS_ARGS is not set, it is "" if the Yosys has read_slang, else
# "-m slang". The Xilinx primitives come from the Yosys
# library (yosys-config --datdir), as blackboxes (gen_xilinx_bb.py).
#
# external_lib (our fork of Alex Forencich's verilog-ethernet and
# verilog-axis) is linted like our own RTL. PicoRV32, formatted like ours, is
# linted as third party: its Verilator and slang findings are not shown; the Yosys check findings, which
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
CORES="chacha20poly1305_encrypt_decrypt_shared"
VERILATOR=${VERILATOR:-verilator}
YOSYS=${YOSYS:-yosys}
YOSYS_CONFIG=${YOSYS_CONFIG:-yosys-config}
PYTHON=${PYTHON:-python3}
if [ -z "${YOSYS_ARGS+set}" ]; then
  if "$YOSYS" -p 'help read_slang' 2>/dev/null | grep -q 'read_slang \['; then
    YOSYS_ARGS=""
  else
    YOSYS_ARGS="-m slang"
  fi
fi
VERIBLE=${VERIBLE:-verible-verilog-lint}
VIVADO=${VIVADO:-vivado}
PART=xc7a200tfbg484-2
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
PHASES=${*:-tags verilator yosys reset ram iob slang verible ghdl ghdl-verilator cdc check-timing methodology}
W=${LINT_WORK:-$(mktemp -d)}
mkdir -p "$W"
W=$(cd "$W" && pwd)
PHASE_NAMES="tags verilator yosys reset ram iob slang verible ghdl ghdl-verilator cdc check-timing methodology"
for ph in $PHASES; do  # every name first, before minutes of Vivado
  case " $PHASE_NAMES " in *" $ph "*) ;; *) echo "unknown phase: $ph ($PHASE_NAMES)"; exit 2 ;; esac
done

# ---- work copy ----------------------------------------------------------------
# a reused LINT_WORK keeps no stale sources, stubs, generated VHDL or netlists
# (iob reads reset's netlist when both run)
rm -rf "$W/1.hw" "$W/bld" "$W/bb.sv" "$W/pypeline" "$W/pypeline.failed" "$W/ghdl.work" \
  "$W"/reset*.json "$W"/ram*.json
(cd "$REPO" && cp -r --parents 1.hw/top.filelist 1.hw/top.sv 1.hw/fpgatech_lib 1.hw/external_lib \
   1.hw/ip.* 1.hw/constraints "$W/")
mkdir -p "$W/bld/csr_build/generated-files" "$W/bld/sw_build"
cp "$REPO"/3.build/csr_build/generated-files/{csr_pkg,csr}.sv "$W/bld/csr_build/generated-files/"
cp "$REPO/3.build/sw_build/imem.INIT.vh" "$W/bld/sw_build/"
[ -n "${CPU:-}" ] && { cpu_select "$W/1.hw/top.filelist" "$CPU" || exit 1; }
cd "$W"
SV=$(design_rtl 1.hw bld | grep -v /pypeline_build/soc/ | tr '\n' ' ')
# the files of one top: the design, and for a block top its own files
top_sv() {
  if [ "$1" = top ]; then echo "$SV"; else echo "$SV $(block_rtl "$1" 1.hw)"; fi
}
# every file one of the tops reads, once
ALL=$(for t in $TOPS; do top_sv $t; done | tr ' ' '\n' | awk 'NF && !seen[$0]++' | tr '\n' ' ')
OWN=$(own_rtl 1.hw bld | grep -v /pypeline_build/soc/ | tr '\n' ' ')
INC="bld/sw_build"
PRIMS="PLLE2_BASE BUFG IBUFGDS BUFGMUX ODDR DSP48E1 STARTUPE2 LUT1 LUT2"

have() { command -v "$1" >/dev/null 2>&1; }
declare -A RESULT
skip() { RESULT[$1]="skipped ($2)"; echo "-- $1: skipped, $2"; }

# waiver regexes of one phase: the lines "<phase> <regex>" of the waivers file;
# a regex that never matches keeps grep -v -f from dropping every line when
# the phase has no waiver
waivers() {
  echo '^$'
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
      "$PYTHON" "$HERE/gen_core_bb.py" "$REPO/3.build/pypeline_build/soc/$c.v.gz" $c >> bb.tmp ||
        return 1
    done && mv bb.tmp bb.sv
}

# /*LINT:OK*/ on anything but an output port; the port directions come from the
# module headers of the design and the primitive stubs
# A tool that fails, or stops before the step its findings come from, fails its
# phase: "0 finding(s)" must not stand for "not checked"
failed() {  # $1 phase, $2 reason, $3 its log (default $W/<phase>.log)
  RESULT[$1]="FAILED ($2), see ${3:-$W/$1.log}"
  echo "-- $1: FAILED, $2"
}

# after found: a tool that exits non-zero must have reported something (waived
# or not); a non-zero exit with nothing to show is the tool failing
exit_check() {  # $1 phase, $2 exit status
  if [ "$2" -ne 0 ] && [ ! -s "$1.all" ]; then failed "$1" "exit $2, nothing reported"; fi
}

run_tags() {
  bb || { skip tags "no Xilinx stubs (yosys-config)"; return; }
  # every external_lib file too: one a generate branch instantiates is tagged
  # even when no file list names it
  CASE_RTL="$OWN" "$PYTHON" - -- bb.sv $ALL $(ls 1.hw/external_lib/*/*.sv) > tags.log <<'EOF'
import os, re, sys
files = list(dict.fromkeys(sys.argv[sys.argv.index('--') + 1:]))
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
# our RTL rule: every unique and priority case has a default, also a full one
# (no tool checks it: Verible's case-missing-default skips unique, Verilator
# and slang only flag values no item covers); unique0 has none
# (CASE_RTL: our own RTL, also the files no top reads)
third_party = re.compile(r'cpu\.PICORV32/|csr_build/')
tok = re.compile(r'\b(?:(unique0|unique|priority)\s+)?(case[zx]?|endcase|default)\b|([{}])')
blank = re.compile(r'"(?:\\.|[^"\\\n])*"|//[^\n]*|/\*.*?\*/', re.S)
for f in dict.fromkeys(files + os.environ.get('CASE_RTL', '').split()):
    if f == 'bb.sv' or third_party.search(f):
        continue
    # strings and comments blanked, newlines kept, so line numbers stay
    t = blank.sub(lambda m: re.sub(r'[^\n]', ' ', m.group(0)), text.get(f) or open(f).read())
    stack, braces = [], 0  # one [qualifier, line, brace depth, has default] per open case
    for m in tok.finditer(t):
        if m.group(3):
            braces += 1 if m.group(3) == '{' else -1
        elif m.group(2).startswith('case'):
            stack.append([m.group(1), t.count('\n', 0, m.start()) + 1, braces, False])
        elif m.group(2) == 'default':
            # a case label, not '{default: ...} in an assignment pattern
            if stack and stack[-1][2] == braces:
                stack[-1][3] = True
        elif stack:
            q, n, _, has = stack.pop()
            if q in ('unique', 'priority') and not has:
                print(f'{f}:{n}: {q} case without default')
    for q, n, _, _ in stack:
        print(f'{f}:{n}: case without endcase (an `ifdef around case or endcase?)')
    # our RTL rule: no `timescale, timeunit or timeprecision, also not under
    # SIM_ONLY: the simulator command line gives the timescale (1.hw/README.md)
    for m in re.finditer(r'`timescale\b|\btime(?:unit|precision)\b', t):
        print(f'{f}:{t.count(chr(10), 0, m.start()) + 1}: {m.group(0)}: no timescale in our RTL')
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
lint_off -file "*/cpu.PICORV32/*"
VLT
  # --timescale: none of the RTL sets one (no delays)
  local t rc=0
  for t in $TOPS; do
    "$VERILATOR" --lint-only -Wall -Wno-fatal --timing --timescale 1ns/1ns --top-module $t $VL_DEFS \
      -I$INC waive.vlt bb.sv $(top_sv $t) > verilator.$t.log 2>&1 || rc=$?
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
    "$YOSYS" $YOSYS_ARGS -q -l yosys.$t.log -p "read_slang --allow-toplevel-iface-ports $SL_DEFS --top $t -I $INC \
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

# Our rule: every control flop and flag has a reset; data and address flops
# need none. A flop with no reset that reaches an enable, a select or a reset
# starts at X in a 4-state simulator and can lock the design up (eduBOS5
# dmem_vld). One finding per flop, at its source line; the rules are in
# run-lint-reset.py.
run_reset() {
  have "$YOSYS" || { skip reset "$YOSYS not found"; return; }
  [ $VIEW = sim ] && { skip reset "chip view only"; return; }
  bb || { skip reset "no Xilinx stubs"; return; }
  local t rc
  : > reset.log; : > reset.out
  for t in $TOPS; do
    "$YOSYS" $YOSYS_ARGS -q -l reset.$t.log -p "read_slang --allow-toplevel-iface-ports $SL_DEFS --top $t -I $INC \
        bb.sv $(top_sv $t); hierarchy -check -top $t; proc; flatten; opt_expr; opt_clean; opt_dff; opt_clean; \
        write_json reset.$t.json" >/dev/null 2>&1
    rc=$?
    cat reset.$t.log >> reset.log
    [ $rc -eq 0 ] && [ -s reset.$t.json ] || { failed reset "top $t: exit $rc, no netlist"; return; }
    "$PYTHON" "$HERE/run-lint-reset.py" reset.$t.json >> reset.out 2>> reset.log
    rc=$?
    [ $rc -eq 0 ] || { failed reset "top $t: netlist check exit $rc"; return; }
  done
  # eduBOS5 alone with the options no SoC build sets: the counters (RV32M is
  # on in the SoC too)
  local E=1.hw/ip.cpu/cpu.EDUBOS5
  "$YOSYS" $YOSYS_ARGS -q -l reset.cpu.log -p "read_slang --top edubos5 -G USE_HW_MUL=1 -G EN_COUNTERS=1 \
      $E/edubos5_pkg.sv $E/edubos5_rf.sv $E/edubos5_alu.sv $E/edubos5.sv; hierarchy -check -top edubos5; \
      proc; flatten; opt_expr; opt_clean; opt_dff; opt_clean; write_json reset.cpu.json" >/dev/null 2>&1
  rc=$?
  cat reset.cpu.log >> reset.log
  [ $rc -eq 0 ] && [ -s reset.cpu.json ] || { failed reset "eduBOS5 alone: exit $rc, no netlist"; return; }
  "$PYTHON" "$HERE/run-lint-reset.py" reset.cpu.json >> reset.out 2>> reset.log ||
    { failed reset "eduBOS5 alone: netlist check failed"; return; }
  # paths relative to the work directory, as in the slang phase
  found reset < <(sed -E 's#^(\.\./)+[^ ]*/(1\.hw|bld)/#\2/#' reset.out | sort -u)
}

# A memory mapped to block or LUT RAM must need no read-first or transparency
# logic in fabric: Yosys builds it there, saying so only in its debug log.
# synth_xilinx up to its memory mapping, then that step under debug, so the
# libraries and options are synth_xilinx's own. The memories' source lines
# come from a netlist written before it (after it, the simulation models it
# reads stop write_json). One finding per memory, at its source line; the
# rules are in run-lint-ram.py.
run_ram() {
  have "$YOSYS" || { skip ram "$YOSYS not found"; return; }
  [ $VIEW = sim ] && { skip ram "chip view only"; return; }
  bb || { skip ram "no Xilinx stubs"; return; }
  local t rc syn
  : > ram.log; : > ram.out
  for t in $TOPS; do
    syn="synth_xilinx -family xc7 -top $t"
    "$YOSYS" $YOSYS_ARGS -q -l ram.$t.log -p "read_slang --allow-toplevel-iface-ports $SL_DEFS --top $t -I $INC \
        bb.sv $(top_sv $t); hierarchy -check -top $t; proc; write_json ram.$t.json; \
        $syn -run begin:map_memory; debug $syn -run map_memory:map_ffram" \
        >/dev/null 2>&1
    rc=$?
    cat ram.$t.log >> ram.log
    [ $rc -eq 0 ] && [ -s ram.$t.json ] && grep -q 'Executing MEMORY_LIBMAP' ram.$t.log ||
      { failed ram "top $t: exit $rc, memory_libmap not reached"; return; }
    "$PYTHON" "$HERE/run-lint-ram.py" ram.$t.log ram.$t.json >> ram.out 2>> ram.log ||
      { failed ram "top $t: log check failed"; return; }
  done
  found ram < <(sed -E 's#^(\.\./)+[^ ]*/(1\.hw|bld)/#\2/#' ram.out | sort -u)
}

# IOB flops: every data pin of top reaches its flop directly, so Vivado and
# nextpnr can put the flop in the I/O tile (run-lint-iob.py). Uses the reset
# phase's netlist of top when this run made one
run_iob() {
  have "$YOSYS" || { skip iob "$YOSYS not found"; return; }
  [ $VIEW = sim ] && { skip iob "chip view only"; return; }
  bb || { skip iob "no Xilinx stubs"; return; }
  local rc
  if [[ " $PHASES " != *" reset "* ]] || [ ! -s reset.top.json ]; then
    "$YOSYS" $YOSYS_ARGS -q -l iob.log -p "read_slang --allow-toplevel-iface-ports $SL_DEFS --top top -I $INC \
        bb.sv $(top_sv top); hierarchy -check -top top; proc; flatten; opt_expr; opt_clean; opt_dff; \
        opt_clean; write_json reset.top.json" >/dev/null 2>&1
    rc=$?
    [ $rc -eq 0 ] && [ -s reset.top.json ] || { failed iob "exit $rc, no netlist"; return; }
  fi
  "$PYTHON" "$HERE/run-lint-iob.py" reset.top.json > iob.out 2>> iob.log ||
    { failed iob "netlist check failed"; return; }
  found iob < <(sed -E 's#^(\.\./)+[^ ]*/(1\.hw|bld)/#\2/#' iob.out | sort -u)
}

run_slang() {
  have "$YOSYS" || { skip slang "$YOSYS not found"; return; }
  bb || { skip slang "no Xilinx stubs"; return; }
  local t rc=0
  : > slang.log
  for t in $TOPS; do
    "$YOSYS" $YOSYS_ARGS -q -l slang.$t.log -p "read_slang --allow-toplevel-iface-ports $SL_DEFS --top $t -I $INC \
        -Wextra bb.sv $(top_sv $t)" >/dev/null 2>&1 || rc=$?
    cat slang.$t.log >> slang.log
  done
  # the yosys-slang plugin prints "file:line: Warning:", the built-in read_slang
  # "file:line:col: warning:"; bring both to the second form so the waivers
  # match either. Paths come relative to the work directory, after any ../
  found slang < <(sed -E 's#^(\.\./)+[^ ]*/(1\.hw|bld)/#\2/#;
                          s/^([^ :]+:[0-9]+): Warning:/\1:0: warning:/;
                          s/^([^ :]+:[0-9]+): Error:/\1:0: error:/' slang.log |
                  grep -E 'warning:|error:' | grep -v -E '^(bb\.sv|1\.hw/ip\.cpu/cpu\.PICORV32/)')
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
  # no __pycache__ in the source tree. --comb with --no_synth: with Vivado
  # found, a plain --no_synth build writes no vhdl_files.txt (without a
  # synthesis tool pypelinec switches to --comb itself)
  (cd "$REPO/3.build/pypeline_build" && PYTHONDONTWRITEBYTECODE=1 \
     "$PYPELINEC" ./src/chacha20poly1305.py --out_dir "$W/pypeline" --top $PYP_TOP --comb --no_synth) \
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

# Vivado has its own primitives, so no stubs here; the generated core is a
# black box (Vivado's attribute). One synthesis serves the cdc, check-timing
# and methodology phases (about 3 min); VIVADO_RC keeps its outcome
VIVADO_RC=
vivado_run() {
  [ -n "$VIVADO_RC" ] && return $VIVADO_RC
  local c
  : > core_bb.tmp
  for c in $CORES; do
    "$PYTHON" "$HERE/gen_core_bb.py" "$REPO/3.build/pypeline_build/soc/$c.v.gz" $c >> core_bb.tmp ||
      { VIVADO_RC=2; echo "core black box" > vivado.err; return 2; }
  done
  sed 's/(\* blackbox \*)/(* black_box *)/' core_bb.tmp > core_bb.sv
  cat > vivado.tcl <<EOT
read_verilog -sv {core_bb.sv $SV}
read_xdc 1.hw/constraints/top.xdc
synth_design -top top -part $PART -flatten_hierarchy rebuilt -include_dirs $INC
report_cdc -details -file cdc.rpt
report_clock_interaction -file clock_interaction.rpt
check_timing -verbose -file check_timing.rpt
report_methodology -file methodology.rpt
EOT
  rm -f cdc.rpt check_timing.rpt methodology.rpt
  "$VIVADO" -mode batch -nojournal -log vivado.log -source vivado.tcl >/dev/null 2>&1
  VIVADO_RC=$?
  echo "exit $VIVADO_RC" > vivado.err
  [ $VIVADO_RC -eq 0 ] && [ -s cdc.rpt ] && [ -s check_timing.rpt ] && [ -s methodology.rpt ] ||
    { [ $VIVADO_RC -eq 0 ] && VIVADO_RC=3; echo "exit $VIVADO_RC, a report is missing" > vivado.err; }
  return $VIVADO_RC
}

vivado_phase() {  # $1 phase: skip without Vivado or in the sim view, else run it once
  have "$VIVADO" || { skip $1 "$VIVADO not found"; return 1; }
  [ $VIEW = sim ] && { skip $1 "chip view only"; return 1; }
  vivado_run || { failed $1 "Vivado: $(cat vivado.err)" "$W/vivado.log"; return 1; }
}

run_cdc() {
  vivado_phase cdc || return
  # detail rows: <row> CDC-<n> <severity> <description> ... <from> <to>
  found cdc < <(grep -E '^ +[0-9]+ +CDC-[0-9]+ +(Critical|Warning) ' cdc.rpt)
}

# check_timing: every HIGH or MEDIUM line, as "<check>: <line>" (no_clock,
# unconstrained_internal_endpoints, no_input_delay, multiple_clock, loops, ...)
run_check_timing() {
  vivado_phase check-timing || return
  found check-timing < <(awk '/^[0-9]+\. checking / { chk = $3 }
      /\((HIGH|MEDIUM)\) *$/ { l = $0; sub(/^ +/, "", l); print chk ": " l }' check_timing.rpt)
}

# report_methodology: every Critical Warning and Warning, as
# "<rule> <severity>: <message>" (TIMING-17 Critical Warning: The clock pin ...);
# and every CRITICAL WARNING of the Vivado run that points at an XDC line
# (a constraint on nothing: "'set_property' expects at least one object"), as
# "XDC <file>:<line>: <message>"
run_methodology() {
  vivado_phase methodology || return
  found methodology < <(awk '/^[A-Z]+-[0-9]+#[0-9]+ (Critical Warning|Warning) *$/ {
      r = $1; sub(/#.*/, "", r); s = $0; sub(/^[^ ]+ /, "", s); sub(/ +$/, "", s)
      getline; getline m; sub(/ +$/, "", m); print r " " s ": " m }' methodology.rpt
    sed -n -E 's#^CRITICAL WARNING: (.*) \[([^]]*/)?([^]/]+\.xdc):([0-9]+)\]$#XDC \3:\4: \1#p' vivado.log)
}

for ph in $PHASES; do
  echo "== $ph"; run_${ph//-/_}  # names checked at start-up
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
