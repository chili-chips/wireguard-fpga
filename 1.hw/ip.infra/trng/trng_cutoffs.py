# SPDX-FileCopyrightText: 2026 Chili.CHIPS
#
# SPDX-License-Identifier: BSD-3-Clause
#
# The SP 800-90B section 4.4 health-test cutoffs of trng_pkg.sv, for binary
# samples (one bit per sample):
#   RCT  C = 1 + ceil(-log2(alpha) / H)
#   APT  W = 1024, C = 1 + CRITBINOM(W, 2^-H, 1 - alpha), the spec formula:
#        the smallest C with P(X >= C) <= alpha, X ~ Binomial(W, 2^-H)
# H is the claimed min-entropy per sample, alpha the false-alarm probability
# per sample (RCT) and per window (APT) for a source exactly at the claim.
#
# usage:  python3 trng_cutoffs.py [H [log2(1/alpha)]]   default: 0.5 40

import math
import sys


def upper_tail(n, p, k):
    """P(X >= k), X ~ Binomial(n, p), summed in log space"""
    lp, lq = math.log(p), math.log1p(-p)
    terms = [math.lgamma(n + 1) - math.lgamma(i + 1) - math.lgamma(n - i + 1) + i * lp + (n - i) * lq
             for i in range(k, n + 1)]
    if not terms:
        return 0.0
    m = max(terms)
    return math.exp(m) * sum(math.exp(t - m) for t in terms)


def cutoffs(h, a_bits, w=1024):
    rct = 1 + math.ceil(a_bits / h)
    alpha = 2.0 ** -a_bits
    p = 2.0 ** -h
    apt = next(c for c in range(1, w + 2) if upper_tail(w, p, c) <= alpha)
    return rct, apt


if __name__ == '__main__':
    h = float(sys.argv[1]) if len(sys.argv) > 1 else 0.5
    a = float(sys.argv[2]) if len(sys.argv) > 2 else 40
    rct, apt = cutoffs(h, a)
    print(f'H = {h} bit/sample, alpha = 2^-{a:g}: TRNG_RCT_CUTOFF = {rct}, '
          f'TRNG_APT_CUTOFF = {apt} (W = 1024)')

# -----------------------------------------------------------------------------
# Project:     WireGuard-FPGA
# Description: NLnet-funded open-source implementation
# Funding:     https://nlnet.nl/project/KlusterLab-Wireguard (2023-12 to 2025-12)
# -----------------------------------------------------------------------------
