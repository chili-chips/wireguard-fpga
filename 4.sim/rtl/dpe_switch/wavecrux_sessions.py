# SPDX-FileCopyrightText: 2026 Chili.CHIPS
#
# SPDX-License-Identifier: BSD-3-Clause

"""WaveCrux sessions for the dpe_switch bench, one per side of the shared
ChaCha20-Poly1305 core (u_aead):
its key, nonce, aad_len and stream handshakes, with WaveCrux Pro 1.2's
ChaCha20-Poly1305 decoder (the plaintext in, every tag checked) and the
AXI-Stream decoder (VALID/READY rules) on its ports.

  python3 wavecrux_sessions.py      after `make`: writes wave.encrypt.wavecrux
                                    and wave.decrypt.wavecrux next to it

A session names each signal by its FST handle, which changes with the design:
run this again after an RTL change, or the decoders come up empty. Needs
fst2vcd (OSS CAD Suite; FST2VCD=<path> to override).
"""

import json
import os
import subprocess
import sys

sys.dont_write_bytecode = True
HERE = os.path.dirname(os.path.abspath(__file__))
FST = 'output/wave.fst'  # as the session names it: relative to the session
CLK = 'TOP.tb.dut.u_aead.clk_80p0'  # the core's own clock input
WHITE = 0xFFE0E0E0
CORES = (  # port prefix, colour (TX orange, RX light blue), first view
    ('encrypt', 0xFFFF9100, (9300, 9.0)),
    ('decrypt', 0xFF40C4FF, (9300, 13.0)),
)


def fst_ids(fst):
    """hierarchical path -> fst2vcd identifier, from the FST header"""
    vcd = subprocess.run([os.environ.get('FST2VCD', 'fst2vcd'), '-f', fst],
                         capture_output=True, text=True, check=True).stdout
    ids, stack = {}, []
    for line in vcd.split('\n'):
        t = line.split()
        if not t:
            continue
        if t[0] == '$enddefinitions':
            break
        if t[0] == '$scope':
            stack.append(t[2])
        elif t[0] == '$upscope':
            stack.pop()
        elif t[0] == '$var':
            ids.setdefault('.'.join(stack + [t[4]]), t[3])
    return ids


def session(ids, s, colour, view):
    def ref(path):  # fst2vcd identifier -> WaveCrux ref: the 0-based FST handle (bijective base 94)
        return str(sum((ord(c) - 33 + (k > 0)) * 94 ** k for k, c in enumerate(ids[path])))

    p = f'TOP.tb.dut.u_aead.{s}_'
    sigs = []

    def sig(path, col, name):
        sigs.append({'kind': 'signal', 'id': f'wg-{s}-{len(sigs)}', 'ref': ref(path), 'path': path,
                     'name': name, 'color': col, 'format': 'hexadecimal', 'height': 24.0})

    clk = CLK
    sig(clk, WHITE, 'clk_80p0')
    for x in ('key', 'nonce', 'aad_len', 's_axis_tvalid', 's_axis_tready', 's_axis_tlast',
              'm_axis_tvalid', 'm_axis_tready', 'm_axis_tlast') + (('m_verified',) if s == 'decrypt' else ()):
        sig(p + x, colour, f'{s}_{x}')

    def axis(side):
        return {'aclk': clk, 'tvalid': f'{p}{side}_axis_tvalid', 'tready': f'{p}{side}_axis_tready',
                'tdata': f'{p}{side}_axis_tdata', 'tlast': f'{p}{side}_axis_tlast',
                'tkeep': f'{p}{side}_axis_tkeep'}

    decs = []

    def dec(did, b, params):
        decs.append({'decoderId': did, 'instanceNumber': len(decs) + 1, 'config': {
            'bindings': {k: ref(v) for k, v in b.items()}, 'bindingPaths': b, 'parameters': params}})

    # key, nonce and AAD are read at each packet's first beat
    crypto = {'key': p + 'key', 'nonce': p + 'nonce', 'aad': p + 'aad', 'aad_len': p + 'aad_len'}
    modes = [('s', 'plaintext'), ('m', 'encrypt_output')] if s == 'encrypt' else [('s', 'decrypt')]
    for side, mode in modes:
        dec('chacha20_poly1305', axis(side) | crypto, {'mode': mode, 'data_width': 128})
    for side in ('s', 'm'):
        dec('axi_stream', axis(side), {'data_width': 128, 'check_handshake': True})
    return {'version': 4, 'sourceFilePath': FST, 'signals': sigs,
            'cursor': {'primary': view[0], 'secondary': None}, 'markers': {},
            'view': {'ticksPerPixel': view[1], 'panOffsetTicks': float(view[0]), 'scrollOffset': 0.0},
            'panels': {'signalTree': False, 'valueColumn': False, 'transactionView': True,
                       'stageView': False, 'statisticsStrip': False, 'cocotbLogPanel': False,
                       'rtlSource': False, 'bottomDockTab': 'transactions',
                       'sizes': {'left': 230.0, 'right': 150.0, 'bottom': 300.0}},
            'translateFilters': {}, 'stage': {'panels': []}, 'activeTheme': 'wavecrux-dark',
            'decoders': decs}


def main():
    ids = fst_ids(os.path.join(HERE, FST))
    for s, colour, view in CORES:
        out = os.path.join(HERE, f'wave.{s}.wavecrux')
        with open(out, 'w', newline='\n') as f:
            json.dump(session(ids, s, colour, view), f, indent=2)
            f.write('\n')
        print(out)


if __name__ == '__main__':
    main()

# -----------------------------------------------------------------------------
# Project:     WireGuard-FPGA
# Description: NLnet-funded open-source implementation
# Funding:     https://nlnet.nl/project/KlusterLab-Wireguard (2023-12 to 2025-12)
# -----------------------------------------------------------------------------
