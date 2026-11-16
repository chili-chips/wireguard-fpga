# ChaCha20-Poly1305 AEAD in Pypeline

This design implements concurrent ChaCha20-Poly1305 encryption and decryption
using **Pypeline HDL** to generate FPGA hardware and run native simulation. 

<div align="center">
  <img width="90%" src="0.doc/wireguard-pypeline-sim-light.png"
   alt="Pypeline native sim: Python HDL, cycle-exact sim engine, silicon-verified">
</div>

The default targets Artix-7 at **80 MHz**, with a **256-bit packet
datapath**, one shared ChaCha20 pipeline, and a private pipelined Poly1305 MAC
per direction. Poly1305 processes two 16-byte blocks per beat using
[paired, interleaved accumulators](src/poly1305/poly1305_design.md#breaking-the-serial-chain), and experimental Pypeline HDL
[AUTO_FSM based initialization/finalization state machines](src/poly1305/poly1305_design.md#auto_fsm-versus-auto_mcp).

Packet streams use valid/ready handshakes, 32 byte-enable bits, and a last-beat
flag. Encryption appends a 16-byte authentication tag; decryption buffers
plaintext until its authentication verdict is available. The supported payload
limit is 2032 bytes, with up to 32 bytes of associated data (AAD).

The default profile is defined in [src/wireguard_env.py](src/wireguard_env.py).
Its [published results](#current-results) appear below.

## Data flow

Each diagram below is one level of the design's hierarchy, as the build's
[`diagram.html`](0.doc/diagram.html) draws it ([Building VHDL and Verilog](#building-vhdl-and-verilog)):
the forward data between the blocks a function calls, each wire named as the
code names it. Stream ready signals travel in reverse and are not drawn, nor
are the key, nonce and AAD sideband inputs; operators and registers form logic
blocks, and a dashed edge passes through a `Feedback` variable. To refresh one,
open the page at that view and use **copy as Mermaid**.

### Top level

```mermaid
flowchart LR
    n0["chacha20_pipeline_shared<br>MAIN  80 MHz"]
    n1["decrypt_dataflow<br>MAIN  80 MHz"]
    n2["encrypt_dataflow<br>MAIN  80 MHz"]
    subgraph inputs[" "]
        n3["decrypt_s_axis<br>Input pins (4)  290b"]
        n4["encrypt_s_axis<br>Input pins (4)  290b"]
    end
    style inputs fill:none,stroke:none
    subgraph outputs[" "]
        n5["decrypt_m_axis<br>Output pins (4)  290b"]
        n6["encrypt_m_axis<br>Output pins (4)  290b"]
    end
    style outputs fill:none,stroke:none
    n0 -->|"encrypt_pipeline_out_if.stream"| n2
    n0 -->|"decrypt_pipeline_out_if.stream"| n1
    n1 -->|"decrypt_pipeline_in_if.stream: data,<br>valid"| n0
    n1 -->|"axis_out_if.stream"| n5
    n2 -->|"encrypt_pipeline_in_if.stream: data,<br>valid"| n0
    n2 -->|"axis_out_if.stream"| n6
    n3 -->|"axis_in_if.stream"| n1
    n4 -->|"axis_in_if.stream"| n2
    n0 ~~~ n5
```

`encrypt_dataflow` and `decrypt_dataflow` each handle one direction. Both send
ChaCha20 work to the one `chacha20_pipeline_shared` MAIN over global wires and
take its results back. Each direction's AXIS pins form one stream port in and
one out.

### Encrypt

```mermaid
flowchart LR
    n2["aead_2broadcast<br>axis_broadcast_interlock"]
    n3["append_func<br>buffered_append"]
    n4["chacha_func<br>chacha20_encrypt_shared_adapter"]
    n5["mac_func<br>poly1305_mac_paired"]
    n6["prep_func<br>buffered_prep_interface"]
    subgraph inputs[" "]
        n0["axis_in_if<br>input  aead_axis_intrf.fwd_t (290b)"]
    end
    style inputs fill:none,stroke:none
    subgraph outputs[" "]
        n1["axis_out_if<br>output  aead_axis_intrf.fwd_t (290b)"]
    end
    style outputs fill:none,stroke:none
    n0 -->|"axis_in_if"| n4
    n2 -->|"bcast.axis_out_if[1]"| n3
    n2 -->|"bcast.axis_out_if[0]"| n6
    n3 -->|"append.axis_out_if"| n1
    n4 -->|"chacha.key_if"| n5
    n4 -->|"chacha.axis_out_if"| n2
    n5 -->|"mac.auth_tag_if"| n3
    n6 -->|"prep.axis_if"| n5
    n3 ~~~ n1
```

In [encrypt_dataflow_core](src/chacha20poly1305/encrypt_dataflow_core.py),
[ChaCha](src/chacha20/chacha20_design.md#packet-streams-and-the-poly1305-key)
supplies ciphertext (`chacha.axis_out_if`) and a separate per-packet Poly1305 key
(`chacha.key_if`). `aead_2broadcast` forks the ciphertext: the first
fork is framed with the AAD, padding and lengths by `prep_func` and
authenticated by `mac_func`
([Poly1305 design](src/poly1305/poly1305_design.md#current-design)); the other
keeps the ciphertext unpadded, and `append_func` packs the tag (`mac.auth_tag_if`) after it. With pipelined MACs,
`append_func` also includes the append FIFO and output slice.

### Decrypt

```mermaid
flowchart LR
    n2["aead_2broadcast<br>axis_broadcast_interlock"]
    n3["chacha_func<br>chacha20_decrypt_shared_adapter"]
    n4["compare_func<br>buffered_compare"]
    n5["mac_func<br>poly1305_mac_paired"]
    n6["prep_func<br>buffered_prep"]
    n7["stripping_func<br>strip_auth_tag_wide"]
    n8["verify_func<br>wait_to_verify"]
    subgraph inputs[" "]
        n0["axis_in_if<br>input  aead_axis_intrf.fwd_t (290b)"]
    end
    style inputs fill:none,stroke:none
    subgraph outputs[" "]
        n1["axis_out_if<br>output  aead_axis_intrf.fwd_t (290b)"]
    end
    style outputs fill:none,stroke:none
    n0 -->|"axis_in_if"| n7
    n2 -->|"bcast.axis_out_if[1]"| n3
    n2 -->|"bcast.axis_out_if[0]"| n6
    n3 -->|"chacha.key_if"| n5
    n3 -->|"chacha.axis_out_if"| n8
    n4 -->|"compare.tags_match_if"| n8
    n5 -->|"mac.auth_tag_if"| n4
    n6 -->|"prep.axis_if"| n5
    n7 -->|"strip.auth_tag_out_if"| n4
    n7 -->|"strip.axis_out_if"| n2
    n8 -->|"verified.axis_out_if"| n1
    n8 ~~~ n1
```

In [decrypt_dataflow_core](src/chacha20poly1305/decrypt_dataflow_core.py),
`stripping_func` separates the received tag (`strip.auth_tag_out_if`) from the
ciphertext, which `aead_2broadcast` forks to authentication and decryption.
[ChaCha](src/chacha20/chacha20_design.md) supplies plaintext and the per-packet
Poly1305 key; `prep_func` and
`mac_func` calculate the tag. Both tag streams preserve packet order, and
`compare_func` compares one pair per verdict (`compare.tags_match_if`).
`verify_func` releases the plaintext after the verdict, holding it on
`is_verified_out` for every valid beat, including packets whose authentication
failed.

### One level down

The ChaCha20 and Poly1305 blocks continue in their design documents, each
section built around the same kind of diagram:

- [ChaCha20 design](src/chacha20/chacha20_design.md): the block function and
  its pipeline, the per-packet FSM inside `chacha_func` that sends the
  Poly1305 key, and the shared `chacha20_pipeline_shared` MAIN of the top
  level with its arbiter and result demux.
- [Poly1305 design](src/poly1305/poly1305_design.md): `mac_func`
  (`poly1305_mac_paired`) and its initialization, body and finalization
  stages, down to the two pipelines that process each pair of blocks.

## Source layout

| Location | Purpose |
| --- | --- |
| [build.py](build.py) | Hardware build, HDL export, and simulation entrypoint. |
| [measure.py](measure.py) | Throughput, latency, timing, area, and bottleneck analysis. |
| [src/wireguard_env.py](src/wireguard_env.py) | Build parameters, default profile, and source imports. |
| [src/aead_types.py](src/aead_types.py) | Stream types, limits, and buffer factories. |
| [src/chacha20/](src/chacha20/) | ChaCha20 arithmetic and stream processing; [pipeline and sharing design](src/chacha20/chacha20_design.md). |
| [src/poly1305/](src/poly1305/) | Poly1305 arithmetic, packet processing, and tag verification; [architecture and throughput](src/poly1305/poly1305_design.md). |
| [src/prep_auth_data/](src/prep_auth_data/) | Authentication framing. |
| [src/auth_tag/](src/auth_tag/) | Tag append/strip in [auth_tag.py](src/auth_tag/auth_tag.py) (128-bit) and [auth_tag_wide.py](src/auth_tag/auth_tag_wide.py) (256-bit); plaintext verification buffering. |
| [src/chacha20poly1305/](src/chacha20poly1305/) | Encrypt/decrypt wiring, external ports, and testbench support. |
| [src/chacha20poly1305.py](src/chacha20poly1305.py) | Hardware top. |
| [src/chacha20poly1305_tb.py](src/chacha20poly1305_tb.py) | Native testbench top for random/stress checks and performance measurement. |
| [src/chacha20poly1305_syn_tb.py](src/chacha20poly1305_syn_tb.py) | Fixed-vector testbench top. |
| [src/poly1305/mac_components_tb.py](src/poly1305/mac_components_tb.py), [src/poly1305/paired_path_tb.py](src/poly1305/paired_path_tb.py) | Poly1305 component and paired-path testbenches. |
| `generated-files/` | Ignored local build outputs, synthesis cache, and measurements. |

## Setup and options

Run commands from `3.build/pypeline_build`. Use Python 3 with `cryptography`
for reference checks, and a PypelineC checkout with its dependencies installed.
Vivado is needed for hardware synthesis; generated-VHDL simulation uses GHDL
and cocotb, and Verilog export additionally uses Yosys.

```bash
export PYPELINEC=/path/to/PipelineC/src/pypelinec
./build.py --show-config
./measure.py --show-config
```

`build.py` also accepts `pypelinec` on `PATH`. For measurement tooling, set
`PYPELINEC` as above or keep the compiler checkout at `../../../PipelineC`.
`--show-config` prints the resolved settings and output paths without building.

### Design parameters

The table gives defaults for the published profile. The named flags are shared
by `build.py` and `measure.py` unless noted. The parameter column names the
corresponding direct PypelineC `-D` parameter; use named flags in the scripts.

| Option | PypelineC parameter | Values and default |
| --- | --- | --- |
| No design flag; `--enc`, `--dec` (`build.py` only) | `DESIGN` | `shared` (default combined top), `encrypt`, `decrypt`. Standalone directions cannot take sharing flags. |
| `--shared`, `--share-chacha20`, `--share-poly1305`, `--share-none` | `SHARE` | `auto` (default: ChaCha20 only), `both`, `chacha20`, `poly1305`, `none`. `--shared` explicitly shares both resources; the two resource flags together do the same. An explicit selection replaces the default set. `--share-none` excludes other sharing flags. |
| `--poly1305` | `POLY1305_IMPL` | `pipelined` (default), `legacy`. Legacy requires 128 bits and inferred multiplication, defaults to ChaCha20 sharing, and cannot share Poly1305. |
| `--data-bitwidth` | `DATA_BITWIDTH` | `256` (default), `128`; selects packet data and byte-enable widths. Legacy defaults to `128`. |
| `--poly1305-mult` | `POLY1305_MULT_IMPL` | `inferred_body` (default: inferred feedback product, Karatsuba elsewhere), `inferred` (wide products), `hybrid` (Karatsuba), `hybrid_square` (Karatsuba plus explicit squares). Legacy defaults to `inferred`. |
| `--poly1305-compute` | `POLY1305_COMPUTE_IMPL` | `fsm` (default), `mcp`; selects pipelined initialization/finalization ([architecture comparison](src/poly1305/poly1305_design.md#auto_fsm-versus-auto_mcp)). MCP automatically shares both resources unless sharing is explicitly selected. |
| `--poly1305-prologue-cap`, `--poly1305-epilogue-cap` | `POLY1305_PROLOGUE_MAX_LATENCY`, `POLY1305_EPILOGUE_MAX_LATENCY` | Initialization/finalization FSM latency caps; defaults `44` / `45` at 256 bits, `64` / `64` at 128 bits. |
| `--target-mhz` | `TARGET_MHZ` | Positive integer MHz. Default `80` for 256-bit `inferred_body` and legacy; other profiles default to `85` when sharing both resources, otherwise `30`. |

Thanks to **FPGA-House-AG** for the
[Karatsuba DSP multiplier reference](https://github.com/FPGA-House-AG/ChaCha20Poly1305/blob/7e75c097af32429ff2c7979b976fe876efbdb9f3/src_dsp_opt/mul_136_kar.vhd)
that inspired the multiplication choices.

### Build and simulation controls

| Option | Purpose |
| --- | --- |
| `--show-config` | Print resolved profile and paths; available in both scripts. |
| `--sim` | Run a correctness testbench instead of building the hardware. |
| `--native` | Use native simulation; otherwise `--sim` selects cocotb/GHDL. |
| `--comb` | Simulate without automatic pipeline delays; also available in `measure.py` for a rig check without timing/area. |
| `--syn_tb` | Select fixed vectors; default correctness simulation uses random vectors and requires `--native`. |
| `-D NAME=VALUE` | Pass non-profile testbench parameters, such as `TB_STRESS=1`; profile parameters use the named flags above. |
| `--perf` | Set `PERF=1` on the native testbench; implies `--sim --native` and requires the combined design. Prefer `measure.py` for reports. |
| `--verilog` | Export the hardware top to Verilog; cannot combine with simulation. |
| `-j N`, `--jobs N` | Limit concurrent synthesis jobs; positive integer, available in both scripts. |
| `--continue` | Preserve the build output directory; required to reuse a nonempty custom directory. |
| `--rebuild` | Force a hardware build; available in both scripts. |
| `--out-dir DIR` | Select a hardware output directory; pass the same directory to measurement or pipelined native simulation. Available in both scripts. |
| `--syn-cache DIR` | Select the shared synthesis store; default `generated-files/syn_cache`, or `none` to disable. Available in both scripts. |

PypelineC reuses unchanged builds automatically. Its latency memory and shared
synthesis cache avoid repeating matching pipeline searches and syntheses.
Ordinary measurement therefore re-simulates existing hardware without synthesis
when its sources, compiler, and settings match; changed inputs may need a build.

### Measurement controls

| Option | Purpose / default |
| --- | --- |
| `--label NAME` | Local run under `generated-files/measurements/`; defaults to a profile-derived name. An absolute path selects another directory. |
| `--sizes N,N,...` | Payload sizes in bytes; default `1420,1920`, maximum `2032`. |
| `--packets N` | Back-to-back packets per size/direction; default `4`. |
| `--dirs {both,enc,dec}` | Traffic directions; default `both`. This changes stimulus, not the hardware profile. |
| `--peak-bytes N` | Add a long-packet phase; default `0` (disabled). |
| `--seed N` | Payload RNG seed; default `8439`. |
| `--taps FILTER` | Internal probes; default `all`. Accepts block/direction prefixes or exact names; `--taps ''` keeps boundary measurements only. |
| `--steady-trim N` | Exclude N warm-up and N drain packets from completion-rate measurement; default no trimming. |
| `--require-parity` | Check the 1420/1920-byte throughput goal, direction parity, and interval stability; needs at least four packets per size and a pipelined run. |
| `--reuse-syn` | Skip the hardware build step; requires matching, current hardware artifacts. Mutually exclusive with `--rebuild`. |
| `--bottleneck-report RESULTS_JSON` | Print block analysis of a saved record without building, simulating, or changing it. |
| `--parse-only` | Regenerate reports from the selected run's existing outputs without building or simulating. |
| `--update-readme` | Publish a validated result matching the default profile into this README. |
| `--save-evidence` | Package build evidence with the local measurement. |
| `--check-record DIR` | Check a saved record and its retained evidence without rewriting it. |
| `--area-report LOG_OR_DIR` | Print utilization; `--per-module` adds module reports and `--json` selects JSON. |
| `--no-per-module-area` | Skip per-module area parsing during measurement. |
| `--audit-mcps DIR` | Inspect emitted MCP arithmetic; `--audit-directions` selects `encrypt`, `decrypt`, or `encrypt,decrypt` (default). |
| `--selftest` | Check measurement/report tooling without synthesis; includes block analysis and saved-report checks. |

Use `./build.py --help` and `./measure.py --help` for the full CLI reference.

## Simulation

Both correctness testbenches check against an independent RFC 8439 reference
using Python's `cryptography` package. They cover packet boundaries and
partial words; decryption also checks a corrupted tag. A run passes only when
it exits zero. Random runs print their seed for reproducibility.

| Testbench / mode | Command | Prerequisite / use |
| --- | --- | --- |
| Random, native combinational | `./build.py --sim --comb --native` | Quick functional check; no synthesis. |
| Fixed vectors, native combinational | `./build.py --sim --syn_tb --comb --native` | Fixed-vector functional check; no synthesis. |
| Stress, native combinational | `./build.py --sim --comb --native -D TB_STRESS=1` | Directed lengths, input gaps, output stalls, and tampered-tag recovery. |
| Random, native pipelined | `./build.py --sim --native` | Build hardware first; simulates its actual latencies and schedules. |
| Fixed vectors, native pipelined | `./build.py --sim --syn_tb --native` | Build hardware first; fixed-vector check of that build. |
| Fixed vectors, generated VHDL | `./build.py --sim --syn_tb` | GHDL/cocotb check before final Verilog export; includes synthesis. |

Build the default hardware with `./build.py` before pipelined native simulation.
A missing or stale build is rejected. Add `-D TB_STRESS=1` to the native random
pipelined command to exercise backpressure with the built schedules.

The native testbench defaults to random/stress checks (`PERF=0`). Its performance
mode (`PERF=1`, selected by `--perf`) uses coordinated packet-size phases,
continuous input, and always-ready outputs, while still checking every packet.
[perf_tb_common.py](src/chacha20poly1305/perf_tb_common.py) handles phase
coordination and recording.

Fixed-vector testbenches support both simulators; adding `--comb` to their
generated-VHDL command skips automatic
pipelining. Native checks are the ordinary development workflow.

## Measuring QoR

### Throughput measurement

```bash
./measure.py --label throughput-check
./measure.py --label final-curve --sizes 16,64,256,1024,1420,1920
```

The first command measures four packets at each of 1420 and 1920 bytes, with
concurrent encrypt/decrypt traffic and internal probes enabled. The second
collects the full payload-size curve. Each command builds only what is needed,
then runs native performance simulation on the matching hardware. Every
packet is checked against the reference model.

Four completions give three packet-completion intervals. Increase packet count
only when those intervals are inconsistent; the parity check allows a 5%
spread. Cold first-packet latency is reported separately from throughput.
Changing payload sizes, packet counts, or seeds only requires simulation.

### What is measured

| Metric | Meaning |
| --- | --- |
| Synthesis fmax | Timing estimate from the real external-port hardware build; routed timing is not measured. |
| Area | Hardware-top LUT, FF, DSP48, and BRAM utilization from Vivado. |
| Sustained B/cycle | Payload bytes divided by mean packet-completion period, excluding cold first-packet latency. |
| Gb/s | Sustained B/cycle × clock MHz × 0.008; local reports include target-clock and fmax rates. |
| Packet period | Mean cycles between packet completions. |
| Cold first output | Cycles from the first packet's input start to its first output. |
| Median total latency | Median cycles from each packet's input start to its final output. |
| Block rates and stalls | Internal handshake, FSM, buffer, and arbitration measurements used to locate bottlenecks. |

### Finding a bottleneck

```bash
./measure.py --label bottleneck-check --sizes 1920 --packets 4 --dirs both --taps all
```

Normal measurement writes the bottleneck analysis to `blocks.md`. To print it
again from a saved record:

```bash
./measure.py --bottleneck-report generated-files/measurements/bottleneck-check/results.json
```

Read `summary.md` for payload throughput and periods, then `blocks.md` for block
processing rates, input starvation, downstream stalls, buffer occupancy, and
shared-resource arbitration. Use the Poly1305 lifecycle breakdown to separate
initialization, body, drain, and finalization costs. Check the ChaCha20-to-Poly1305 key
handoff as well as payload edges when investigating packet-boundary stalls.
Use pipelined simulation for performance conclusions; combinational checks
omit the hardware's pipeline delays.
[Where the time goes](src/poly1305/poly1305_design.md#where-the-time-goes)
reads the current results this way, stage by stage.

### Measurement outputs

Outputs live under `generated-files/measurements/<label>/` and are ignored by Git.

| File | Contents |
| --- | --- |
| `summary.md`, `summary.csv` | Detailed throughput and latency by payload size/direction. |
| `blocks.md`, `blocks.csv` | Block throughput, stalls, and bottleneck analysis. |
| `results.json` | Complete configuration, provenance, timing, area, and validation record. |
| `taps.csv`, `perf_raw.json` | Internal counters and raw simulation results. |
| `pypelinec.log` | Build/simulation progress and diagnostics. |

### Current results

These are the published measurements for the default profile. Timing and area
come from the external-port hardware top; routed timing has not been measured.
Finite-burst completion rates can retain some startup effects.

<!-- MEASURED-RESULTS:BEGIN -->

_Measured sources: wireguard-fpga `7283e9ffd0c5` (with local changes); PypelineC `dd212e9453ea` (frozen source snapshot `1e54c6517f5c`); Vivado 2019.2. Full provenance and raw artifacts are retained in local measurement outputs._

| Target clock | Synthesis fmax | LUT | FF | DSP48 | BRAM tiles |
| ---: | ---: | ---: | ---: | ---: | ---: |
| 80 MHz | 81.32 MHz | 81,489 | 67,232 | 332 | 26.5 |

Native pipelined simulation; directions: encrypt, decrypt; 4 packets per size/direction; seed 8439. Throughput uses packet-completion intervals.

| Payload bytes | Direction | Sustained B/cycle | Packet period (cycles) | Gb/s @80 MHz | Cold first output (cycles) | Median total latency (cycles) |
| ---: | --- | ---: | ---: | ---: | ---: | ---: |
| 16 | encrypt | 0.333 | 48.0 | 0.213 | 134 | 204.5 |
| 16 | decrypt | 0.333 | 48.0 | 0.213 | 139 | 206.0 |
| 64 | encrypt | 1.333 | 48.0 | 0.853 | 31 | 203.5 |
| 64 | decrypt | 1.032 | 62.0 | 0.661 | 140 | 225.5 |
| 256 | encrypt | 5.333 | 48.0 | 3.413 | 31 | 200.0 |
| 256 | decrypt | 5.333 | 48.0 | 3.413 | 146 | 207.0 |
| 1024 | encrypt | 21.333 | 48.0 | 13.653 | 31 | 183.0 |
| 1024 | decrypt | 21.333 | 48.0 | 13.653 | 170 | 214.0 |
| 1420 | encrypt | 28.784 | 49.3 | 18.422 | 31 | 183.5 |
| 1420 | decrypt | 28.400 | 50.0 | 18.176 | 183 | 229.0 |
| 1920 | encrypt | 30.000 | 64.0 | 19.200 | 31 | 198.0 |
| 1920 | decrypt | 29.845 | 64.3 | 19.101 | 198 | 258.0 |

<!-- MEASURED-RESULTS:END -->

<!-- BLOCK-RESULTS:BEGIN -->

Detailed per-block service/stall, shared arbitration and lifecycle measurements
are generated locally as `blocks.md` in the measurement directory.
Raw measurement artifacts are not included in the repository.

<!-- BLOCK-RESULTS:END -->

To refresh this table from a validated default-profile run:

```bash
./measure.py --label final-curve --sizes 16,64,256,1024,1420,1920 --update-readme
```

Publication rejects unvalidated or non-default measurements. Keep full evidence
locally; [Poly1305 component notes](src/poly1305/poly1305_design.md) explain the
architecture and throughput tradeoffs, and
[which stage limits each packet size](src/poly1305/poly1305_design.md#where-the-time-goes).

## Building VHDL and Verilog

Build the default hardware and inspect its output location:

```bash
./build.py
./build.py --show-config
```

PypelineC writes the generated VHDL and its `vhdl_files.txt` source list under
the reported output directory, with `diagram.html`, a page to browse the
design's hierarchy in (the [data flow](#data-flow) diagrams come from it; a
copy is kept at [`0.doc/diagram.html`](0.doc/diagram.html)). The
default top is `chacha20poly1305_encrypt_decrypt_shared`.

For final Verilog export, first run the fixed-vector generated-HDL check:

```bash
./build.py --sim --syn_tb
./build.py --verilog
```

Run the export only after the check succeeds. The Verilog conversion uses
GHDL and Yosys and retains the hardware top name.

## Comparison with the earlier PipelineC design

The [earlier PipelineC sources](../pipelinec_build/src/) implement the same
AEAD operation. See the Poly1305 notes for the
[legacy architecture](src/poly1305/poly1305_design.md#legacy-architecture) and
[arithmetic and framing corrections](src/poly1305/poly1305_design.md#corrections-from-the-earlier-pipelinec-implementation).

Pypeline uses function calls to instantiate hardware and interfaces to connect
forward data and reverse handshakes. Per-instance C macros become ordinary
function definitions; external hardware ports are kept separate from testbenches.

## Issues filed upstream

Issues filed upstream from this design, open and closed.

| Tool | Issue | What | Workaround | State |
| --- | --- | --- | --- | --- |
| PipelineC | [PipelineC#394](https://github.com/JulianKemmerer/PipelineC/issues/394) ([#35](https://github.com/chili-chips/wireguard-fpga/issues/35)) | `stream_perf.py` imports `statistics`; its untyped `LinearRegression` namedtuple becomes an empty VHDL record. Vivado 2026.1 and GHDL reject it; Vivado 2019.2 accepts it. | Move `import statistics` into `_median()` in PipelineC's `include/pypeline/stream/stream_perf.py`. | open |

## Appendix: baseline results

The recorded starting point used a 128-bit datapath, legacy Poly1305 with a
six-cycle body loop, and shared ChaCha20 at 80 MHz. Native pipelined simulation
ran concurrent encrypt/decrypt traffic, four packets per size/direction, with
seed 8439. All 48 reference checks passed.

| Payload bytes | Encrypt Gb/s @80 MHz | Decrypt Gb/s @80 MHz |
| ---: | ---: | ---: |
| 16 | 0.330 | 0.258 |
| 64 | 0.836 | 0.710 |
| 256 | 1.354 | 1.267 |
| 1024 | 1.567 | 1.167 |
| 1420 | 1.607 | 1.060 |
| 1920 | 1.620 | 1.181 |

Synthesis met the 80 MHz goal and reported 31,192 LUT, 16,049 FF, 420 DSP,
and 11 BRAM tiles. This area came from a synthesized performance testbench,
whose constant inputs can remove hardware, and is not directly comparable
with the current external-port hardware-top area.

Recorded sources: wireguard-fpga `db70c9753c44` with local changes,
PypelineC `32356330ec7c`, Vivado 2019.2. These are retained historical results,
not a new measurement of the baseline.
