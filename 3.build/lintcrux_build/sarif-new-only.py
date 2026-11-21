#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Chili.CHIPS*ba
#
# SPDX-License-Identifier: BSD-3-Clause
#
# The SARIF of run-lintcrux.sh, cut down to the findings the baseline does not
# have, for GitHub code scanning. LintCrux writes every finding into the SARIF,
# the 303 baselined ones too; uploaded as they are, they would all be open
# alerts. Code scanning gets only the new ones, the findings the gate fails on,
# and the full SARIF stays a build artifact.
#
# "New" is decided as the gate decides it: a finding is in the baseline when
# its fingerprint is, the FNV-1a 64 of "<engine>/<rule>|<file>|<message>"
# (file relative to the project root, which is the repository root where the
# SARIF paths start; whitespace in the message collapsed),
# LintCrux's crux-fnv1a64/1. Findings suppressed in the source are dropped too.
# Every run is kept, also an empty one, so that code scanning closes an alert
# whose finding is gone.
#
#   usage: sarif-new-only.py <lintcrux.sarif> <.lintcrux-baseline.json> <out.sarif>
import json
import re
import sys


def fnv1a64(text):
    h = 0xcbf29ce484222325
    data = text.encode('utf-16-le')  # LintCrux hashes UTF-16 code units
    for i in range(0, len(data), 2):
        h ^= data[i] | (data[i + 1] << 8)
        h = (h * 0x100000001b3) & 0xffffffffffffffff
    return '%016x' % h


def fingerprint(rule, path, message):
    return fnv1a64('%s|%s|%s' % (rule, path, re.sub(r'\s+', ' ', message).strip()))


sarif_in, baseline_in, sarif_out = sys.argv[1:4]
sarif = json.load(open(sarif_in))
frozen = {v['fingerprint'] for v in json.load(open(baseline_in))['frozenViolations']}

kept = total = 0
for run in sarif['runs']:
    engine = run['tool']['driver']['name']
    new = []
    for r in run.get('results', []):
        total += 1
        if r.get('suppressions'):
            continue
        uri = r['locations'][0]['physicalLocation']['artifactLocation']['uri']
        if fingerprint('%s/%s' % (engine, r['ruleId']), uri, r['message']['text']) not in frozen:
            new.append(r)
    run['results'] = new
    kept += len(new)

json.dump(sarif, open(sarif_out, 'w'), indent=2)
print('sarif-new-only.py: %d of %d findings are new' % (kept, total))

# -----------------------------------------------------------------------------
# Project:     WireGuard-FPGA
# Description: NLnet-funded open-source implementation
# Funding:     https://nlnet.nl/project/KlusterLab-Wireguard (2023-12 to 2025-12)
# -----------------------------------------------------------------------------
