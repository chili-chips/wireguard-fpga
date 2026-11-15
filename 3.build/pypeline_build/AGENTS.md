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
- Keep profile resolution and defaults in
  [src/wireguard_env.py](src/wireguard_env.py), shared by the build and
  measurement scripts. Hardware configuration uses parameters, not environment
  variables. Change `DEFAULT_PROFILE` only to promote a validated result.
- Identical encrypt/decrypt modules must retain matching pipeline depths and
  AUTO_FSM schedules; keep the build and measurement checks enforcing this.
- Follow the existing interface functions in the
  [dataflow cores](README.md#data-flow). Keep explicit `Wire` assignments at
  top-level and shared-resource boundaries. Interface ports use matching `_if`
  names across arguments and results; interface types use `_intrf`.
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
- Add new blocks to `BLOCKS` in [bottleneck.py](bottleneck.py) for report rollups.
  Reuse the probed buffer factories in [aead_types.py](src/aead_types.py).

## Maintaining documentation and results

- Keep the README focused on the current default, with non-default choices in
  its options tables and baseline results in the appendix. Preserve the opening
  image. Keep diagrams consistent with current wiring, including shared-service
  request and return paths.
- Keep the current results independent of baseline comparisons. Publish through
  the [current-results workflow](README.md#current-results), preserving both
  `MEASURED-RESULTS` and `BLOCK-RESULTS` marker pairs and the compact formatter.
  When promoting a default, update `DEFAULT_PROFILE` and its descriptions
  together; retain validation and profile-agreement guards.
- Keep [raw measurements](README.md#measurement-outputs), diagnostic outputs,
  and scratch investigations local and ignored by Git. Publish concise
  provenance without local absolute paths; do not link to ignored artifacts.
- Put useful component rationale in existing
  [component notes](src/poly1305/throughput.md). Remove stale investigations,
  dated progress notes, compiler internals, and debugging stories from the
  README and this file rather than preserving them as a running log.
- Check documented commands and flags against the scripts, and verify links
  and README anchors after documentation edits.
