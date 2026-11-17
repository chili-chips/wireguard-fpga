#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Chili.CHIPS
#
# SPDX-License-Identifier: BSD-3-Clause
#
# A black box of a generated module, for run-leq.sh: its port list and port
# declarations only, so the LEQ compares what goes into the module and
# shares what comes out, without reading the module itself (the PipelineC
# ChaCha20-Poly1305 cores: 2.8 MB of generated Verilog each, the same on
# both sides; proving them against their source is PipelineC#398).
#   usage: gen_core_bb.py <generated .v> <module> >> bb.sv
import re
import sys

src, name = sys.argv[1:3]
text = open(src).read()
m = re.search(r'^module\s+' + re.escape(name) + r'\s*\((.*?)\);', text, re.M | re.S)
if not m:
    sys.exit('gen_core_bb.py: no module %s in %s' % (name, src))
ports = [p.strip() for p in m.group(1).split(',') if p.strip()]
body = text[m.end():text.index('endmodule', m.end())]
decl = re.findall(r'^\s*((?:input|output|inout)\b[^;]*;)', body, re.M)
print('(* blackbox *)')
print('module %s(%s);' % (name, ', '.join(ports)))
for d in decl:
    print('  ' + ' '.join(d.split()))
print('endmodule')

# -----------------------------------------------------------------------------
# Project:     WireGuard-FPGA
# Description: NLnet-funded open-source implementation
# Funding:     https://nlnet.nl/project/KlusterLab-Wireguard (2023-12 to 2025-12)
# -----------------------------------------------------------------------------
