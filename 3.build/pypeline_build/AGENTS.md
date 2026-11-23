# Agent guidance

Applies to `3.build/pypeline_build/`. The [README](README.md) is the reference
for the current design, [source layout](README.md#source-layout), and
[setup and options](README.md#setup-and-options). Link there instead of
duplicating design descriptions, parameter tables, commands, or results here.

## Licensing new files

Create new source, script, configuration, and documentation files with
SPDX copyright and license notices at the top, except for Markdown (`.md`),
`.drawio` files, HTML diagrams, and plain-text README files. Copy this subtree's existing BSD-3-Clause
attribution, also recorded in the root `REUSE.toml`:

```python
# SPDX-FileCopyrightText: 2026 Julian Kemmerer
# SPDX-FileCopyrightText: 2026 Chili.CHIPS
#
# SPDX-License-Identifier: BSD-3-Clause
```

Use the appropriate year for future contributions. Preserve existing and
third-party notices. Use the file format's comment syntax (`#` for Python and
`.gitignore`), keeping shebangs and format declarations first.
Do not add license headers to Markdown, `.drawio` files, HTML diagrams, or plain-text README files;
the existing `REUSE.toml` annotation covers them. Binary assets are also covered by
`REUSE.toml` and do not need `.license` sidecars. For assets or formats that
cannot carry comments and need different attribution or licensing, preserve
that information in a specific `REUSE.toml` annotation or a `.license` sidecar.
Include headers when creating source and other commentable text files, with
the exceptions above, even though `REUSE.toml` also covers this directory.

## Editing the design

- Keep changes in this subproject unless the task requires otherwise. Do not
  backport fixes to `../pipelinec_build/` without a request; see the
  [earlier-design comparison](README.md#comparison-with-the-earlier-pipelinec-design).
- Keep `import wireguard_env  # noqa: F401` as the first import in hardware
  design and testbench files. It bootstraps this tree's flat module imports.
- [pipelinec.ref](pipelinec.ref) names the oldest PipelineC commit this design
  is known to work with. That commit or any newer one should work, and the
  latest is preferred; never require one exact PipelineC version. CI lints with
  that commit, and `build.py` warns when the local checkout predates it. A
  design change that needs a newer PipelineC moves `pipelinec.ref` forward in
  the same commit, after `run-lint.sh ghdl ghdl-verilator` passes with it.
- Reserve leading underscores in Python names for use within one file. APIs
  used across files should have public names; update their callers when renaming.
- Keep profile resolution and defaults in
  [src/wireguard_env.py](src/wireguard_env.py), shared by the build and
  measurement scripts. Hardware configuration uses parameters, not environment
  variables. Change `DEFAULT_PROFILE` only to promote a validated result.
- Identical encrypt/decrypt modules must retain matching pipeline depths and
  AUTO_FSM schedules; keep the build and measurement checks enforcing this.
- Follow the existing interface functions in the
  [dataflow cores](README.md#data-flow). Keep explicit `Wire` assignments at
  top-level and shared-resource boundaries. Interface ports use matching `_if`
  names across arguments and results; interface types use `_if_t`.
- Size buffers from the selected instances' resolved pipeline metadata, ex. using
  [aead_types.py](src/aead_types.py).
- Declare `wireguard_env.TARGET_MHZ` on every hardware MAIN. A testbench's
  stimulus and checker are simulation-only MAINs (`@MAIN` over `@sim_input` or
  `@sim_output`), a bare `@MAIN` with no clock; do not tag them `@wires`.
- Report PypelineC compiler or shared performance-library bugs to the user.

## Validation

Use the README's [simulation workflow](README.md#simulation) and
[HDL build instructions](README.md#building-vhdl-and-verilog).

- Native simulation is sufficient for functional acceptance during ordinary
  development. Do not automatically run generated-HDL/compiler rendering
  checks or final Verilog export. For an explicitly requested final export,
  run the selected design's pipelined GHDL/cocotb check once immediately before
  exporting, and require it to pass.
- Preserve independent reference checks in correctness and performance
  testbenches. Sinks count transfers and check that stalled data and sidebands stay stable. Keep assertions that make mismatches or incomplete runs exit nonzero.
- Obtain timing and area from the real external-port hardware top, never a
  synthesized testbench.
- When changing measurement or bottleneck tooling, run the corresponding
  existing `--selftest` described in [measurement controls](README.md#measurement-controls).
  Builds and self-tests must not depend on saved local measurement archives.
- A change to the random testbenches, their stimulus or the probes changes what a
  run reaches. Run `./measure.py --coverage default --comb` (about ten minutes;
  `stress` takes longer, so run it on request) and update the waiver lists in
  [func_coverage_goals.py](src/chacha20poly1305/func_coverage_goals.py) with the
  reason for each corner. Never waive a bin only to make a run pass.
- Lint the generated HDL before pushing. From the repo root, run
  `PYPELINEC=<PipelineC>/src/pypelinec bash 3.build/hw_build.openXC7/run-lint.sh ghdl ghdl-verilator`.
  It generates the VHDL with `pypelinec --comb --no_synth`, without Vivado. GHDL
  then analyzes it, and Verilator lints its GHDL-Yosys Verilog. CI job
  `pypeline-lint` in `.github/workflows/lint.yml` runs the same check with
  the oldest supported PipelineC (`pipelinec.ref`). Fix findings in the design
  or in PipelineC. A waiver
  goes in `3.build/hw_build.openXC7/run-lint-waivers.txt` only for a proven
  false positive.

## Performance work

Follow [throughput measurement](README.md#throughput-measurement) and
[bottleneck analysis](README.md#finding-a-bottleneck) for commands, sampling,
and interpretation.

- Start with the documented large-packet measurement; collect the full
  small-packet curve after meeting the throughput goals. Keep longer
  functional/stress/soak campaigns separate and run them when requested;
  they are not a reason to enlarge performance samples.
- Reuse compatible hardware and the shared synthesis store through the
  [build controls](README.md#build-and-simulation-controls). Investigate
  unexpected cache misses before repeating synthesis. Do not bypass
  compatibility checks or force guessed latencies. Cold-cache build-time
  comparisons are separate work, only when requested.
- Run each test campaign and long build from a fresh clone of the latest
  PipelineC ([setup](README.md#setup-and-options)), so changes to your own
  checkout cannot alter the generated VHDL midway and the campaign's later runs
  keep hitting the synthesis cache. Pass the same absolute `--syn-cache` path to
  every build and measurement. Outside CI, leave `PYPELINEC_CACHE_DIR` unset so
  builds use the clone's committed `cache/`; a runner that sets it first copies
  that `cache/` there, so it does not start empty.
- Preserve valid synthesis logs after interruption; rename only an identified
  incomplete or failed vendor log. Distinguish cache restoration from an actual
  Vivado launch, and report whether synthesis is characterizing blocks,
  searching schedules, or confirming the whole design.

## Adding performance probes

Use the compiler's `stream.stream_perf_probe` library and the existing probes
in the hardware as examples.

- Place probes in plain `@hw_func` or `@MAIN` bodies, not interface-function
  bodies or AUTO_PIPELINE arithmetic cores.
- Sample state before FSM assignments and handshakes after output assignments.
- Update `stream_perf_probe.MAIN_LABELS` in place in
  [tb_common_sim.py](src/chacha20poly1305/tb_common_sim.py), so encrypt and
  decrypt instances keep separate labels in performance and coverage runs.
- Add new blocks to `BLOCKS` in [measure.py](measure.py) for report rollups.
  Reuse the probed buffer factories in [aead_types.py](src/aead_types.py).
- A corner for [functional coverage](README.md#functional-coverage) is a
  `cover.<block>.<corner>` probe whose transfer marks the corner: an
  unconditional `perf_taps.hs(name, event, ready)` at body level. Pass the
  consumer's ready when the corner's beat can wait for it, else `1`. Build
  `event` from existing signals, adding no local signals, and sample registers
  before their assignments. An event that fires once per packet also needs its
  model in `EVENTS` of [func_coverage_goals.py](src/chacha20poly1305/func_coverage_goals.py).

## Maintaining documentation and results

- Keep the README focused on the current default, with non-default choices in
  its options tables and baseline results in the appendix. Preserve the opening
  image. Keep diagrams consistent with current wiring, including shared-unit
  request and return paths.
- Keep the current results independent of baseline comparisons. Publish through
  the [current-results workflow](README.md#current-results), preserving both
  `MEASURED-RESULTS` and `BLOCK-RESULTS` marker pairs and the compact formatter.
  When promoting a default, update `DEFAULT_PROFILE` and its descriptions
  together; retain validation and profile-agreement guards.
- Keep [raw measurements](README.md#measurement-outputs), diagnostic outputs,
  and scratch investigations local and ignored by Git. Publish concise
  provenance without local absolute paths; do not link to ignored artifacts.
- Keep [ChaCha20](src/chacha20/chacha20_design.md) and
  [Poly1305](src/poly1305/poly1305_design.md) design notes focused on the
  current architecture and implementation-specific tradeoffs; link to the
  README for shared commands, options, and results. Link to these notes instead
  of duplicating component details elsewhere. Preserve Poly1305's legacy and
  intermediate architectures and illustration link, with a short history
  timeline and a final baseline reference. Remove stale investigations,
  compiler internals, and debugging stories rather than keeping a running log.
- Check documented commands and flags against the scripts, and verify links
  and README anchors after documentation edits.

## Design write-ups: executive summary

Full documents:
[Exploring Pypeline native simulation with ChaCha20-Poly1305](https://github.com/JulianKemmerer/PipelineC/blob/master/examples/pypeline/chacha20poly1305/pypeline_sim_and_wireguard.md)
(PipelineC repo, 2026-09-14),
[Poly1305 design](src/poly1305/poly1305_design.md) and
[ChaCha20 design](src/chacha20/chacha20_design.md).

- **Verification:** testbenches check random packets against Python's
  `cryptography` ChaCha20-Poly1305 (RFC 8439). That is how three Poly1305
  math bugs were found in the old `pipelinec_build` core, whose testbench used
  the same buggy C code as its reference. The synthesizable fixed-vector
  testbench (`--syn_tb`) also runs under cocotb/GHDL and on an FPGA.
- **Pipelined native sim emulates latency:** each pipelined call runs as an
  instant Python call plus a delay line, so it is not a per-register model.
  Check against generated VHDL with PipelineC's `pypeline_sim_debug.py`.
- **Poly1305:** the serial `(a+c)·r` chain is regrouped into interleaved lanes
  (5 at 256 bits, lane stride `q^L` with `q = r²`). The body takes one 16-byte block per clock
  at 128 bits, or two at 256 bits, behind init and finalization AUTO_FSMs.
  Those FSMs are experimental placeholders, meant to be replaced by
  hand-designed units. A nearer-term option is to
  [derive the FSM latency caps from a small-packet throughput target](src/poly1305/poly1305_design.md#auto_fsm-versus-auto_mcp).
- **Packet rate, not width, limits short packets:** finalization costs a fixed
  48 clocks per packet (init 44), so packets up to about 1.4 KB run at
  80 MHz / 48 = 1.67 Mpacket/s per direction whatever the width. 64-byte
  packets get 0.85 Gb/s. Minimum-size frames on 4x 1GbE need about 6
  Mpacket/s. Faster init and finalization is the lever for small packets.
- **ChaCha20:** one 512-bit block pipeline shared by both directions, with
  per-block round-robin arbitration (decrypt first). It serves 30.8 B/clock at
  1920 bytes, so it is not a bottleneck.
- **Next steps the write-up lists:** waveform output for native sim, random
  backpressure (partly covered since by `-D TB_STRESS=1`), coverage-driven
  stimulus, and manually set pipeline depths.
- **Stale in the PipelineC write-up:** it predates the 256-bit, overlapped
  design (128-bit only, packets up to 1024 bytes). Its links and images point
  to the suspended `chili-chips-ba` org (now `chili-chips`). Its README anchor
  `#fixed-poly1305-320-bit-math-is-now-rfc-8439-correct` no longer exists;
  that content now lives in
  [Corrections from the earlier PipelineC implementation](src/poly1305/poly1305_design.md#corrections-from-the-earlier-pipelinec-implementation).

## Open review notes (PR #34)

Notes from the PR #34 review, merged 2026-11-16. Delete each item once it
is done.

- **Vivado 2026.2:** builds work with 2019.2 or 2026.x, and the published
  results used 2019.2. Re-measure timing and area on 2026.2.
- **Perf sim speed:** removing the native arithmetic models made the native
  perf sim about 24% slower (1.04 vs 0.84 s/cycle, same PipelineC). Restore
  the models or accept the cost.
- **Duplicated code:** `perf_tb_common.packet_mismatch_message` repeats
  `tb_common_sim.check_packet_result`. The `init` kernel is the same in
  `make_pipelined_compute` and `make_shared_compute`. Share one copy of each.
- **`tag_words = 2`** in `aead_types.py` holds only for 128- and 256-bit
  beats. Add an assert against `DATA_BITWIDTHS` so a new width fails loudly.

### SoC integration

Where it stands (2026-11-23). Chili.CHIPS works on the SoC side, on `main`
too: pull before you edit `1.hw/` or `4.sim/`.

- **Swapped in** ([#48](https://github.com/chili-chips/wireguard-fpga/issues/48), `98cc510`,
  2026-11-17): `1.hw/ip.dpe/dpe_wg_encryptor.sv` and `dpe_wg_decryptor.sv`
  now take this core: standalone `--enc --soc` and `--dec --soc` builds
  (PipelineC `97097a87`, Vivado 2026.1), Verilog gzip'd in `soc/*.v.gz`
  (`4.sim/rtl/sim.mk` unpacks it; lint and LEQ read it as is), their
  `latency_profile.json` in `latency_hints/`. With them our benches pass byte
  for byte, RFC 8439 tags included. The ports keep the old core's names, so
  the swap was an instance change. Keep the port names and their meaning
  stable; tell us (issue or note here) before changing them.
- **What the wrappers give the core** (rewritten 2026-11-17, `cedffc4`,
  `cc96f5d`): 128-bit beats at 80 MHz (`dpe_if`: `tdata[127:0]`,
  `tkeep[15:0]`, byte 0 in `[7:0]`); whole 16-byte blocks, the IPv4 packet
  zero-padded, `tkeep` all ones; `key` byte 0 in `[7:0]`; nonce
  `{counter, 32'd0}` (4 zero bytes, then the little-endian counter); no AAD.
  Key and nonce stay put while a packet is in the core: one packet at a time
  for now, so the core's throughput is not yet the limit.
- **Open for you: latch key, nonce, AAD and `aad_len` per packet in the core**
  ([#32](https://github.com/chili-chips/wireguard-fpga/issues/32), 2026-11-23).
  Take them at each packet's first beat (`tvalid && tready`) and carry them
  with the packet through the FIFOs. Then we stop holding them (one place,
  no duplication) and packets can overlap: one at a time costs about 290
  clocks for a 1420-byte packet, where 4 Gb/s at 80 MHz allows 227. The shared
  core needs it anyway. Keep AAD in the unit test (a different key, nonce,
  AAD and length per packet, overlapping, both directions) although our DPE
  sends `aad_len = 0`: `prep_auth_data_fsm` (`_wide` at 256 bits) takes AAD
  when a packet leaves the auth FIFO, and a handshake offload would need AAD.
- **WaveCrux checks the core** (Pro 1.2): its ChaCha20-Poly1305 decoder
  reads key, nonce and AAD at each packet's first beat, the same contract,
  and checks every tag (or computes the ciphertext a plaintext packet must
  give); its AXI-Stream decoder checks VALID/READY. Sessions on our bench:
  `4.sim/rtl/dpe_switch/wave.{encrypt,decrypt}.wavecrux` (regenerate with
  `wavecrux_sessions.py`; set `data_width` 128, the default 32 gives false tag
  mismatches). Snapshots in the top-level README. Use it on your own benches.
- **Open for you ([#58](https://github.com/chili-chips/wireguard-fpga/issues/58),
  2026-11-18):** `dpe_wg_encryptor` sends the outer IPv4 header checksum as
  0 (a real peer drops it), and `wg_padded_len()` adds a 16-byte block when
  the length already is a multiple of 16. `wg_check.py` mirrors both, so fix
  the reference with the RTL.
- **Failed authentication: handled.** The decryptor drops a packet whose
  plaintext comes with `is_verified_out` low; the loopback bench flips one
  ciphertext bit and checks the packet is dropped.
- **Benches that will check this core:** `4.sim/rtl/dpe_wg_encryptor` (10
  frames, 30 to 1492 IPv4 bytes, stalls on both sides) and
  `4.sim/rtl/dpe_wg_decryptor` (encryptor to decryptor loopback).
  `4.sim/rtl/wg_check.py` rebuilds every frame in Python, tag included
  (RFC 8439, checked against `cryptography`).
- **Two cores, one design:** separate PipelineC builds give their helper
  modules the same names (`bin_op_plus_uint128_t_uint128_t_0clk_de264c78_Barch`),
  so two netlists read into one design clash: Verilator `MODDUP` keeps one
  body, Yosys stops with "Re-definition of module", synthesis of both
  clashes. `build.py --enc` and `--dec` pass `--module_prefix enc_` and
  `dec_` ([PipelineC#400](https://github.com/JulianKemmerer/PipelineC/issues/400),
  [#59](https://github.com/chili-chips/wireguard-fpga/issues/59)), so every
  module of those netlists except the top has its own core's prefix. The
  tracked `soc/*.v.gz` predate the flag: they share 419 names (169 differ
  only in GHDL's net numbers, such as `\:3609.read_pipe`; with those
  normalized, none does), and their benches keep `-Wno-MODDUP` until the
  netlists are rebuilt with `build.py` (`pipelinec.ref` has the flag). The shared top (one ChaCha20 pipeline) avoids the clash
  too but needs one instance for both wrappers: our call at integration
  ([#27](https://github.com/chili-chips/wireguard-fpga/issues/27)).
- **`pipelinec.ref`** is `4e7a7ced` (includes the #394, #395 and #392 fixes,
  imports without distutils, so CI's Python 3.12 needs no setuptools, and has
  `--module_prefix`, which `build.py --enc` and `--dec` pass).
  The SoC builds above started on `97097a87` with the old workaround; the
  lint and the native random sim pass on `99e5e018`; on `0b710cca` the GHDL
  lints pass with no waiver (the #395 one is gone).
- **Fast rebuild, proposed for `build.py`:** with a warm synthesis cache and
  the tracked `latency_hints/` profile, `pypelinec ... --syn_cache <shared
  store> --latency_hints <profile>.json --no_sweep` rebuilt the `--enc --soc`
  Verilog in 14 min with no Vivado run, byte-identical to the 2.5 h build
  (2026-11-17, on `99e5e018`). Proposal: a `build.py --no-sweep` option, and
  a default `--syn-cache` shared across output directories (today each
  build's cache sits inside its own copy). Valid while the source is
  unchanged; a design change needs one full build to re-verify 80 MHz and
  refresh the hints. We also skip `--sim --syn_tb` for the SoC cores: our
  benches check the exported Verilog against RFC 8439.
- **Size the core to the board** ([#40](https://github.com/chili-chips/wireguard-fpga/issues/40)):
  the published default uses about 61% of the
  xc7a200t's LUTs and 45% of its DSPs (81,489 LUT, 332 DSP48) and gives
  19.2 Gb/s per direction. 4x 1GbE needs at most 4 Gb/s per direction, and the
  MACs, CPU and DPE must fit too. Measure `--data-bitwidth 128` at 80 MHz as
  the SoC profile.
  **Measured 2026-11-22** (Vivado 2026.2 out of context, `soc/*.v.gz`): the
  two standalone cores do not fit. Encrypt 71.7k LUT / 127k FF, decrypt
  77.3k LUT / 166k FF, 115 DSP48 each; with the SoC (17.7k LUT) and the DPE
  blocks (13.4k LUT) that is about 180k LUT, 134% of the xc7a200t. The
  shared 128-bit core (63.6k LUT / 56k FF) gives about 70%: the SoC will use
  one shared core for both directions.
- **Routed timing:** the published 81.32 MHz is synthesis only (1.6% margin).
  Check timing after place and route, in the SoC.
- **Reproducibility:** published results name the PipelineC commit they used,
  which must be `pipelinec.ref` or newer. A newer PipelineC should still build
  and pass, though its timing and area can differ.

### The core's I/O, as the SoC drives it

From `1.hw/ip.dpe/dpe_wg_encryptor.sv` and `dpe_wg_decryptor.sv` (the
wrappers), 2026-11-23. One clock, `clk_80p0` (80 MHz); the core has no reset.

**Streams.** AXI4-Stream, 128-bit beats, byte 0 in `tdata[7:0]`. Every
handshake is independent: either side can stall at any beat (our benches
throttle both at random).

| Port | What travels | Framing |
|---|---|---|
| `encrypt_s_axis` | the IPv4 packet, zero-padded to 16-byte blocks | whole blocks, `tkeep` all ones, `tlast` on the last block |
| `encrypt_m_axis` | the ciphertext blocks, then the 16-byte tag | the tag is the last beat (`tlast`) |
| `decrypt_s_axis` | the ciphertext blocks, then the 16-byte tag | whole blocks, `tkeep` all ones, `tlast` on the tag |
| `decrypt_m_axis` | the plaintext blocks, only after the tag is checked | `tlast` on the last block |

**Decrypt verdict.** The core holds a packet's plaintext until its tag is
checked (`wait_to_verify`; at most `AEAD_MAX_PT_BYTES` = 2032 bytes of
plaintext, the core's limit; the verify FIFO is sized for it). Then it sends
the plaintext with `decrypt_m_verified` valid on
every beat, the same value for the whole packet. A failed packet still comes
out, with `decrypt_m_verified` low: the wrapper drains and drops it. The
wrapper reads the verdict at the packet's first output beat.

**Key, nonce, AAD.**
- `key` 256 bits, byte 0 in `[7:0]`. `nonce` 96 bits: `{counter, 32'd0}`
  (4 zero bytes, then the little-endian 64-bit WireGuard counter). `aad`
  256 bits and `aad_len` 8 bits, today always 0.
- Encryptor: the peer table answers at `PEER_RSP`, before the packet's first
  beat; key and `send_cnt` stay put until the tag's last byte has left, then
  `send_cnt + 1` is written back.
- Decryptor: the key comes from the peer table, the counter from the
  WireGuard header (`FEED_WG`), both before the first ciphertext beat. They
  stay put until the packet's plaintext has left.
- So today one packet is in each core at a time. The target (#32): the core
  takes key, nonce, AAD and `aad_len` with each packet's first `s_axis`
  beat (`tvalid && tready`), and they may change on the next clock.

**Rates.** 4x 1GbE needs at most 4 Gb/s per direction, both directions at
once, so about 0.4 beats per clock each way at 80 MHz, and up to about
6 Mpacket/s for minimum-size frames on all four ports.

### Checking the core in WaveCrux

[WaveCrux](https://wavecrux.app) Pro 1.2 decodes ChaCha20-Poly1305 on an
AXI-Stream and checks every tag against RFC 8439. Start from our sessions,
then use the same setup on your own waves.

1. **Our bench, as is.** From the repository root:
   ```bash
   cd 4.sim/rtl/dpe_switch
   make                          # the system bench, writes output/wave.fst
   python3 wavecrux_sessions.py  # wave.encrypt.wavecrux, wave.decrypt.wavecrux
   ```
   Open a session with File > Open (or `wavecrux_pro <session>`). Each one
   shows one core's key, nonce, `aad_len` and stream handshakes, and its
   decoder rows (ChaCha20-Poly1305 and AXI-Stream). The Transactions table
   lists every packet: length, nonce, plaintext or ciphertext, and "tag OK"
   or a red, hatched tag mismatch (hover it for the reason). The bench sends
   one corrupted tag on purpose: that packet, and only that one, must be red.
2. **After an RTL change**, run `wavecrux_sessions.py` again: a session names
   signals by FST handle, and stale handles leave the decoders empty.
3. **Your own waves.** `./build.py --sim --comb --native --soc --wave enc.vcd
   --enc` writes the core's flat ports under the same names
   (`encrypt_s_axis_tdata`, `encrypt_key`, ...). Open it, add Protocol
   Decoder > ChaCha20-Poly1305 (AXI-Stream), bind `aclk`, `tvalid`, `tready`,
   `tdata`, `tlast`, `tkeep` to one stream and `key`, `nonce`, `aad`,
   `aad_len` to the core's ports, and set:
   - **Data width 128** (the default 32 reads `tdata[31:0]` only and gives
     false tag mismatches);
   - **Stream carries:** Plaintext on the encryptor's `s_axis`; Ciphertext +
     tag (encryptor output) on its `m_axis`; Ciphertext + tag (decryptor
     input) on the decryptor's `s_axis`.
   Add an AXI-Stream decoder (data width 128) on each stream for the
   VALID/READY checks. Save the session next to the wave; for scripts, copy
   `session()` from `wavecrux_sessions.py` and change the paths.
4. **The per-packet test (#32):** the decoder samples key, nonce and AAD at
   each packet's first beat, the contract we ask of the core. With a
   different key, nonce and AAD per packet and packets overlapping, every
   packet should still read "tag OK"; one that took the next packet's params
   shows red.
