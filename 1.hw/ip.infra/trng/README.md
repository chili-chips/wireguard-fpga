<!--
SPDX-FileCopyrightText: 2026 Chili.CHIPS

SPDX-License-Identifier: BSD-3-Clause
-->

# TRNG: hardware entropy source (#2)

Raw entropy for the firmware's random numbers ([`2.sw/app/random.c`](../../../2.sw/app/random.c)). The hardware only produces and tests raw samples; conditioning (BLAKE2s) and the DRBG (ChaCha20) are in firmware. What it touches outside this folder: [INTEGRATION.md](INTEGRATION.md).

| File | |
|---|---|
| `trng_pkg.sv` | ring lengths, sample rate, health-test cutoffs, types |
| `trng_bank.sv` | one bank: 8 ring oscillators, sampled, XORed; `SIM_ONLY`: a seeded xorshift32, or the rings with stage delays (`+trng_rings=1`) |
| `trng_health.sv` | SP 800-90B Repetition Count and Adaptive Proportion tests, one bank |
| `trng_core.sv` | two banks, sample tick, startup test, data word |
| `trng.sv` | the CSR client: `csr.trng` to `trng_core` |
| `trng_cutoffs.py` | the cutoff math |

Bench: [`4.sim/rtl/trng`](../../../4.sim/rtl/trng) (`make`, `make SIM=icarus`, `make SIM=janushdl`).

## Sources

Two banks, A and B. Each is 8 free-running ring oscillators (a LUT2 NAND for enable plus LUT1 inverters, `KEEP`/`DONT_TOUCH`), every ring sampled by its own flop on the 80 MHz system clock, the 8 samples XORed and registered again. Every ring length is a different odd prime (A: 3, 7, 13, 19, 29, 37, 43, 53; B: 5, 11, 17, 23, 31, 41, 47, 59), so no two rings lock to each other. The entropy is the rings' phase jitter against the system clock, accumulated over the 200 ns between samples.

Why a second ring bank and not the Ethernet RX clocks: an RX clock is recovered from the link partner's signal, so the far end (an attacker on the wire) sets its phase, and there is none without a link. The two banks are separate rings with separate flops and separate health tests; they share the supply, the die temperature and the sampling clock (common-mode, see below).

Samples: one per bank every `TRNG_SAMPLE_CLKS << rate` = 16 clocks at `rate` 0 (5 Msample/s per bank). A data word holds 16 samples of each bank, interleaved: bit 2i bank A, bit 2i+1 bank B, sample i before i+1. Deinterleave a raw dump on the host before assessment.

Cost (Vivado 2026.2, `trng_core` alone on xc7a200t): 505 LUTs, 438 of them the rings (422 LUT1, 16 LUT2), and 221 flops.

## Entropy claim

**H = 0.5 bit of min-entropy per raw sample, per bank, at rate 0.** This is a design assumption, not a measurement. A slower `rate` only adds jitter, so the claim holds there too. The firmware takes 1024 samples of each bank per 256-bit seed: 512 claimed bits from either bank alone, 2x the seed.

## Health tests (SP 800-90B 4.4)

Both tests run on every sample of each bank, in hardware. Cutoffs for H = 0.5 and a false-alarm probability alpha = 2^-40 (per sample for the RCT, per window for the APT):

| Test | Rule | Cutoff |
|---|---|---|
| Repetition Count (RCT) | C = 1 + ceil(-log2(alpha) / H) | 81 equal samples in a row |
| Adaptive Proportion (APT), W = 1024 | C = 1 + CRITBINOM(W, 2^-H, 1 - alpha) | 824 samples of a window equal to its first |

`python3 trng_cutoffs.py [H [log2(1/alpha)]]` gives other claims: H = 1: 41 / 625; H = 0.25: 161 / 938; H = 0.125: 321 / 995 (alpha 2^-40). Its APT value for alpha = 2^-20, H = 1 (589) matches the SP 800-90B table.

A failure is latched until `enable` = 0. After `enable`, the startup test (SP 800-90B 4.3): one full window, 1024 samples of each bank, with no failure, then `ready`. In normal mode words are offered only while `ready`. `rct_max` and `apt_max` (since enable) show the margin to the cutoffs.

The firmware runs the source only while it takes a seed (enable, startup test, 64 words, 6 more words so the RCT sees past the last one, status, disable). A false alarm can then only cost one seed attempt; the next request tries again. A lasting fault fails every attempt, and the firmware refuses.

Bench results: stuck-at-0 and -1 trip the RCT at sample 81 and the APT at sample 824 exactly; a window of 823 matches passes, 824 fails; P(1) = 0.9 trips the APT within 916 samples, P(1) = 0.8 within 1014; 300 windows of good random samples trip nothing (rct_max 17, apt_max 561).

## Raw mode, for offline assessment

`raw` = 1: words from `enable` on, also during the startup test and after a failure (never for keys). `ovf` = 1 means a word was lost, so the dump is not contiguous; raise `rate` until the reader keeps up (rate 8: 19.5 ksample/s per bank, within reach of the UART bus master). Dump at least 1,000,000 samples per bank, deinterleave, and run NIST's [SP800-90B_EntropyAssessment](https://github.com/usnistgov/SP800-90B_EntropyAssessment) `ea_non_iid` (and the restart test, `ea_restart`, 1000 restarts x 1000 samples).

## What still needs hardware

- The min-entropy per sample of each bank at rate 0, on several boards, at cold and hot. If it is below 0.5, lower the claim and set the cutoffs from `trng_cutoffs.py` (and `RANDOM_SEED_WORDS` in `random.c`).
- That every ring oscillates (no bank output stuck), and the ring frequencies (ChipScope/ILA on a ring tap or a counter).
- Independence of A and B: their cross-correlation, and both under supply noise (the DPE at full load) and with the Ethernet ports busy.
- The same with the openXC7 bitstream: its placement of the rings differs from Vivado's.
- The false-alarm rate in practice: `rct_max` and `apt_max` over long runs.

## Simulation

Two `SIM_ONLY` models, behind the same ports and timing. Neither is random, and `csr.trng.status.impl` reads 2 instead of 1, so firmware can tell.

- **Default: a seeded xorshift32** per bank (`TRNG_SIM_SEED`). Cheap: the co-simulation uses it.
- **`+trng_rings=1`: the rings themselves.** Each stage is a `#` delay of 350 ps, a fixed spread of ±10 ps and a seeded jitter of ±10 ps per edge, into the same sampling flops and XOR as on the chip. It checks the structure (enable, rings, sampling, the health tests on real ring output), not the entropy. It needs a 1 ps precision (the TRNG bench sets `TIMESCALE = 1ns/1ps`); at 1 ns it stops with a `$fatal`.

| TRNG bench, Verilator | xorshift32 | `+trng_rings=1` |
|---|---|---|
| no waveform (`PLUSARGS=+notrace`) | 13 s | 1,677 s |
| with `wave.fst` | 51 s, 14 MB | 2,103 s, 1.4 GB |

The rings run about 1 ms of the 4.9 ms; each stage is an event every 350 ps, about 2,000 per clock. In the co-simulation one seed would add about 11 minutes.

```
make -C 4.sim/rtl/trng PLUSARGS="+trng_rings=1 +notrace"
```

## Toolchains

- **Vivado 2026.2**: synthesis, implementation and bitstream of `trng_core` (on pins) pass. All 422 + 16 ring LUTs survive to routing. The `allow_combinatorial_loops` attribute in `trng_bank.sv` reaches the ring nets, so DRC reports LUTLP-2 (allowed loop, warning) for the 16 rings instead of the LUTLP-1 error. No XDC needed.
- **openXC7** (Yosys 0.70 + nextpnr-himbaechel): Yosys keeps the rings. nextpnr stops with "Timing analysis failed due to combinational loops" unless it gets `--ignore-loops`; with it, place, route and `fpga-as` pass, all ring cells present. `--ignore-loops` goes in `NEXTPNR_OPTS` (INTEGRATION.md). It only skips the loops in timing analysis; the lint's Yosys `check` still finds unwanted loops elsewhere.
- **Lint** (`run-lint.sh`, both views) and `run-format.sh --check`: clean, with `LUT1 LUT2` added to the black-boxed primitives.

<!--
-----------------------------------------------------------------------------
Project:     WireGuard-FPGA
Description: NLnet-funded open-source implementation
Funding:     https://nlnet.nl/project/KlusterLab-Wireguard (2023-12 to 2025-12)
-----------------------------------------------------------------------------
-->
