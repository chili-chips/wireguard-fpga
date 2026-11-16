# Agent guidance

Applies to `3.build/pypeline_build/`. The [README](README.md) is the reference
for the current design, [source layout](README.md#source-layout), and
[setup and options](README.md#setup-and-options). Link there instead of
duplicating design descriptions, parameter tables, commands, or results here.

## Editing the design

- Keep changes in this subproject unless the task requires otherwise. Do not
  backport fixes to `../pipelinec_build/` without a request; see the
  [earlier-design comparison](README.md#comparison-with-the-earlier-pipelinec-design).
- Keep `import wireguard_env  # noqa: F401` as the first import in hardware
  design and testbench files. It bootstraps this tree's flat module imports.
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
- Declare `wireguard_env.TARGET_MHZ` on every MAIN, including simulation
  checkers.
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
- Lint the generated HDL before pushing. From the repo root, run
  `PYPELINEC=<PipelineC>/src/pypelinec bash 3.build/hw_build.openXC7/run-lint.sh ghdl ghdl-verilator`.
  It generates the VHDL with `pypelinec --no_synth`, without Vivado. GHDL
  then analyzes it, and Verilator lints its GHDL-Yosys Verilog. CI job
  `pypeline-lint` in `.github/workflows/lint.yml` runs the same check with
  a pinned PipelineC. Fix findings in the design or in PipelineC. A waiver
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
- Run long builds from a frozen compiler copy. Pass the same
  absolute `--syn-cache` path to build and measurement from frozen copies.
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
  [perf_tb_common.py](src/chacha20poly1305/perf_tb_common.py), so encrypt and
  decrypt instances keep separate labels.
- Add new blocks to `BLOCKS` in [measure.py](measure.py) for report rollups.
  Reuse the probed buffer factories in [aead_types.py](src/aead_types.py).

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
  hand-designed units.
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

- **PipelineC#395:** a package-declaration constant in `c_structs_pkg.pkg.vhd`
  calls `bank_state_t_..._to_slv` before its body is elaborated (GHDL
  `-Welaboration`). The lint waives it; drop the waiver and bump
  `PIPELINEC_REF` in `lint.yml` once it is fixed.
- **PipelineC#394:** an empty VHDL `LinearRegression` record breaks Vivado
  2026.1 and GHDL. CI applies the workaround; drop it from `lint.yml` and the
  [README tracker](README.md#issues-filed-upstream) once it is fixed.
- **Vivado 2026.1:** the project uses 2026.1, while the published results used
  2019.2. Re-measure timing and area on 2026.1.
- **Perf probes:** `prep.fsm` in `prep_auth_data_wide.py` and `append.fsm` in
  `auth_tag_wide.py` sample after the FSM assignments, so they record the next
  state. Move them before the assignments (see
  [Adding performance probes](#adding-performance-probes)).
- **Perf sim speed:** removing the native arithmetic models made the native
  perf sim about 24% slower (1.04 vs 0.84 s/cycle, same PipelineC). Restore
  the models or accept the cost.
- **Duplicated code:** `perf_tb_common.packet_mismatch_message` repeats
  `tb_common_sim.check_packet_result`. The `init` kernel is the same in
  `make_pipelined_compute` and `make_shared_compute`. Share one copy of each.
- **`tag_words = 2`** in `aead_types.py` holds only for 128- and 256-bit
  beats. Add an assert against `DATA_BITWIDTHS` so a new width fails loudly.

### SoC integration

- **The SoC still uses the old core:** `1.hw/ip.dpe/dpe_wg_encryptor.sv` and
  `dpe_wg_decryptor.sv` instantiate the `pipelinec_build` core, which has the
  known Poly1305 and ciphertext-length bugs. This core replaces it. The DPE
  stream (`1.hw/ip.infra/dpe_if.sv`) is 128-bit (`tdata[127:0]`,
  `tkeep[15:0]`), and the SoC clock is 80 MHz (`clk_80p0`).
- **Size the core to the board:** the published default uses about 61% of the
  xc7a200t's LUTs and 45% of its DSPs (81,489 LUT, 332 DSP48) and gives
  19.2 Gb/s per direction. 4x 1GbE needs at most 4 Gb/s per direction, and the
  MACs, CPU and DPE must fit too. Measure `--data-bitwidth 128` at 80 MHz as
  the SoC profile.
- **Failed authentication:** decrypt releases the plaintext of a failed packet
  with `is_verified_out` low. The DPE must drop such packets, never forward
  them.
- **Routed timing:** the published 81.32 MHz is synthesis only (1.6% margin).
  Check timing after place and route, in the SoC.
- **Reproducibility:** name the tested PipelineC commit in the README (CI
  pins `PIPELINEC_REF` in `.github/workflows/lint.yml`). Results from an
  unpinned `master` may not reproduce.
