#!/bin/bash
# SPDX-FileCopyrightText: 2026 Chili.CHIPS
#
# SPDX-License-Identifier: BSD-3-Clause
#
# LintCrux (https://lintcrux.app) over our RTL: five engines in one run, their
# findings in one table, gated by a committed baseline.
#
#   ghdl       GHDL analysis (VHDL-2008) of the Pypeline ChaCha20-Poly1305
#              core, as the VHDL that pypelinec --no_synth generates
#   verilator  Verilator --lint-only -Wall, with the waivers of run-lint.sh
#              (lintcrux.vlt)
#   verible    Verible with our rules (run-lint.verible, copied to
#              1.hw/.rules.verible_lint, which Verible finds)
#   slang      slang elaboration: strict IEEE 1800
#   svlint     the functional rules in .svlint.toml, no style rules
#
# What is linted: the project wireguard-fpga.lintcrux at the repository root,
# the chip view of top with eduBOS5 plus the DPE block tops (BLOCK_TOPS in
# hw_build.openXC7/sources.sh), the Xilinx primitives and the generated
# ChaCha20-Poly1305 cores as black boxes, as in run-lint.sh. The baseline,
# .lintcrux-baseline.json (the root too), is empty: the design has no
# findings, so with --fail-on-new-violations any finding fails the run
# (exit 2). Fix it, or waive it with its reason in lintcrux.vlt or
# .svlint.toml; do not baseline it. (Writing a baseline takes LintCrux Pro,
# which CI cannot run, lintcrux#57; the free lintcrux only reads one.)
#
# usage:  bash run-lintcrux.sh [lintcrux options]
#           (no options)                      the table, exit 0
#           --fail-on-new-violations          the CI gate
#           --sarif lint.sarif                SARIF 2.1.0 for code scanning
#           --engine slang                    one engine only (repeatable)
#
# Exit status is lintcrux's: 0 clean or no gate failed, 1 findings with
# --exit-code, 2 new findings with --fail-on-new-violations, 3 the run failed
# (an engine missing or broken, or the sourceFiles of wireguard-fpga.lintcrux
# not those of top.filelist: never a clean result), 64 a usage error.
#
# Tools: LINTCRUX (default lintcrux, the free open-core CLI), VERILATOR,
# VERIBLE (verible-verilog-lint), SLANG, SVLINT, GHDL, YOSYS_CONFIG (for the
# Xilinx primitive stubs), PYTHON and PYPELINEC (PipelineC's src/pypelinec,
# as for run-lint.sh). CI pins the versions (.github/workflows/lintcrux.yml):
# the baseline matches messages, so a different engine release can word a
# finding differently and make it new. Run with the same versions.
#
# Generated inputs go to 3.build/lintcrux_build/generated (not tracked).

set -eu
HERE=$(cd "$(dirname "$0")" && pwd)
REPO=$(cd "$HERE/../.." && pwd)
GEN=$HERE/generated
PROJECT=$REPO/wireguard-fpga.lintcrux

LINTCRUX=${LINTCRUX:-lintcrux}
VERILATOR=${VERILATOR:-verilator}
VERIBLE=${VERIBLE:-verible-verilog-lint}
SLANG=${SLANG:-slang}
SVLINT=${SVLINT:-svlint}
GHDL=${GHDL:-ghdl}
YOSYS_CONFIG=${YOSYS_CONFIG:-yosys-config}
PYTHON=${PYTHON:-python3}
PYPELINEC=${PYPELINEC:-pypelinec}
PYP_TOP=chacha20poly1305_encrypt_decrypt_shared
PRIMS="PLLE2_BASE BUFG IBUFGDS BUFGMUX ODDR DSP48E1"
CORES="chacha20poly1305_encrypt_decrypt_shared"

# LintCrux starts an engine by path: resolve each tool to an absolute one
abs() {
  local p
  p=$(command -v "$1" 2>/dev/null) || { echo "run-lintcrux.sh: $1 not found (set $2)" >&2; exit 3; }
  (cd "$(dirname "$p")" && echo "$(pwd -P)/$(basename "$p")")
}
LINTCRUX=$(abs "$LINTCRUX" LINTCRUX)
VERILATOR=$(abs "$VERILATOR" VERILATOR)
VERIBLE=$(abs "$VERIBLE" VERIBLE)
SLANG=$(abs "$SLANG" SLANG)
SVLINT=$(abs "$SVLINT" SVLINT)
GHDL=$(abs "$GHDL" GHDL)

# ---- the project's sources are the design's -----------------------------------
# wireguard-fpga.lintcrux lists the RTL files by hand: they must be those of
# top.filelist and the block tops (sources.sh, as for run-lint.sh), or a new
# file would go unlinted
. "$REPO/3.build/hw_build.openXC7/sources.sh"
want=$(cd "$REPO" && { design_rtl 1.hw 3.build | grep -v /pypeline_build/soc/
  for t in $BLOCK_TOPS; do block_rtl $t 1.hw 3.build | tr ' ' '\n'; done; } | grep . | sort -u)
have=$("$PYTHON" -c 'import json, sys
for f in json.load(open(sys.argv[1]))["sourceFiles"]:
    if not f.startswith("3.build/lintcrux_build/generated/"):
        print(f)' "$PROJECT" | sort -u)
if [ "$want" != "$have" ]; then
  echo "run-lintcrux.sh: the sourceFiles of wireguard-fpga.lintcrux differ from top.filelist" \
    "and BLOCK_TOPS (< missing, > extra):" >&2
  diff <(echo "$want") <(echo "$have") | grep '^[<>]' >&2
  exit 3
fi

rm -rf "$GEN"
mkdir -p "$GEN/bin"
# Verible finds the .rules.verible_lint nearest to each file: our rules for
# 1.hw, copied rather than linked (a Windows checkout turns a link into a
# text file); not tracked
cp "$REPO/3.build/hw_build.openXC7/run-lint.verible" "$REPO/1.hw/.rules.verible_lint"

# ---- black boxes: the Xilinx primitives and the generated cores -------------
"$PYTHON" "$REPO/3.build/hw_build.openXC7/gen_xilinx_bb.py" \
  "$("$YOSYS_CONFIG" --datdir)/xilinx" "$GEN/bb.tmp" $PRIMS >/dev/null
for c in $CORES; do
  "$PYTHON" "$REPO/3.build/hw_build.openXC7/gen_core_bb.py" \
    "$REPO/3.build/pypeline_build/soc/$c.v.gz" $c >> "$GEN/bb.tmp"
done
mv "$GEN/bb.tmp" "$GEN/bb.sv"
# generated stubs: Verible's style rules do not apply (it reads the
# .rules.verible_lint nearest to each file)
printf '%s\n' -explicit-parameter-storage-type -line-length -module-filename \
  -no-trailing-spaces > "$GEN/.rules.verible_lint"

# ---- the Pypeline VHDL, in one file -------------------------------------------
# pypelinec names each file after a hash of its contents, so the names change
# with the design; one file keeps the project and the baseline stable. GHDL
# analyses the units in file order, so they go in dependency order.
# --comb with --no_synth: pypelinec switches to that mode itself when no
# synthesis tool is installed (CI), but with Vivado found a plain --no_synth
# build writes no vhdl_files.txt; --comb makes both write the same files
echo "-- pypelinec --comb --no_synth --top $PYP_TOP"
(cd "$REPO/3.build/pypeline_build" && PYTHONDONTWRITEBYTECODE=1 \
   "$PYPELINEC" ./src/chacha20poly1305.py --out_dir "$GEN/pypeline" --top $PYP_TOP --comb --no_synth) \
   > "$GEN/pypelinec.log" 2>&1 || { tail -20 "$GEN/pypelinec.log"; echo "run-lintcrux.sh: pypelinec failed" >&2; exit 3; }
"$PYTHON" - "$GEN/pypeline" "$GEN/pypeline.vhd" <<'EOF'
import os, re, sys
out_dir, dest = sys.argv[1:3]
files = open(os.path.join(out_dir, 'vhdl_files.txt')).read().split()
defines, uses, text = {}, {}, {}
for f in files:
    t = text[f] = open(f).read()
    for u in re.findall(r'^\s*(?:entity|package)\s+(\w+)\s+is\b', t, re.M | re.I):
        defines[u.lower()] = f
    uses[f] = {u.lower() for u in re.findall(r'\b(?:entity|use)\s+work\.(\w+)', t, re.I)}
order, state = [], {}
def visit(f):
    if state.get(f) == 2:
        return
    if state.get(f) == 1:
        sys.exit('run-lintcrux.sh: circular VHDL dependency at ' + f)
    state[f] = 1
    for u in sorted(uses[f]):
        if u in defines and defines[u] != f:
            visit(defines[u])
    state[f] = 2
    order.append(f)
for f in files:
    visit(f)
with open(dest, 'w') as o:
    o.write('-- Generated by run-lintcrux.sh from pypelinec --no_synth. Do not edit.\n')
    for f in order:
        o.write('\n-- %s\n' % os.path.relpath(f, out_dir))
        o.write(text[f])
EOF

# ---- what LintCrux 1.2 cannot take from the project file yet ------------------
# (https://github.com/Ferrite-Engineering/lintcrux/issues/55 and
# https://github.com/Ferrite-Engineering/lintcrux/issues/56)
# slang: block tops with interface ports, as read_slang in run-lint.sh, and
# absolute paths in its findings: slang runs in the folder of the first
# source, and a finding it reports as ../<file> would be dropped
cat > "$GEN/bin/slang" <<EOF
#!/bin/sh
[ "\$1" = --version ] && exec "$SLANG" "\$@"
exec "$SLANG" --allow-toplevel-iface-ports --diag-abs-paths "\$@"
EOF
# ghdl: VHDL-2008, as run-lint.sh's ghdl phase; -s checks without generating
# code (-a with GHDL's LLVM backend compiles all of the 300k generated lines)
cat > "$GEN/bin/ghdl" <<EOF
#!/bin/sh
[ "\$1" = -a ] || exec "$GHDL" "\$@"
shift
exec "$GHDL" -s --std=08 -frelaxed "\$@"
EOF
# svlint: the project's include path (3.build/sw_build, imem.INIT.vh) by its
# absolute path: svlint too runs in the folder of the first source, where the
# relative one does not resolve
cat > "$GEN/bin/svlint" <<EOF
#!/bin/sh
[ "\$1" = --version ] && exec "$SVLINT" "\$@"
exec "$SVLINT" -i "$REPO/3.build/sw_build" "\$@"
EOF
chmod +x "$GEN/bin/slang" "$GEN/bin/ghdl" "$GEN/bin/svlint"
# Verilator's waiver file by its absolute path: a relative one is looked up
# from the folder of the first source, not from the project's
"$PYTHON" - "$PROJECT" "$GEN/paths.lintcrux" <<'EOF'
import json, os, sys
project, dest = sys.argv[1:3]
opts = json.load(open(project))['perEngineOptions']
root = os.path.dirname(os.path.abspath(project))
vl = opts['verilator']
vl['waiverFiles'] = [os.path.join(root, f) for f in vl.get('waiverFiles', [])]
json.dump({'perEngineOptions': opts}, open(dest, 'w'), indent=2)
EOF

ENGINES="--verilator-path=$VERILATOR --verible-path=$VERIBLE --slang-path=$GEN/bin/slang
  --svlint-path=$GEN/bin/svlint --ghdl-path=$GEN/bin/ghdl --config=$GEN/paths.lintcrux"

cd "$REPO"
if [ "${1:-}" = baseline ]; then
  shift
  exec "$LINTCRUX" baseline "$@" $ENGINES "$PROJECT"
fi
exec "$LINTCRUX" $ENGINES "$@" "$PROJECT"

# -----------------------------------------------------------------------------
# Project:     WireGuard-FPGA
# Description: NLnet-funded open-source implementation
# Funding:     https://nlnet.nl/project/KlusterLab-Wireguard (2023-12 to 2025-12)
# -----------------------------------------------------------------------------
