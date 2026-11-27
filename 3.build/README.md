<!--
SPDX-FileCopyrightText: 2026 Chili.CHIPS*ba

SPDX-License-Identifier: BSD-3-Clause
-->

# Wireguard FPGA Build

The build process for the WireGuard project consists of three steps:
- Compilation of WireGuard control and status registers (CSR) from RDL specification into RTL for hardware design and harware abstraction layer (HAL) for software application
- Compilation of the software application for the RISC-V hardware target
- Compilation of SystemVerilog designs into bitstream for the hardware target

## Tool Versions

Build and lint tools as used locally (WSL, 2026-11-26). CI installs the latest OSS CAD Suite nightly instead ([`lint.yml`](../.github/workflows/lint.yml)). Simulation tools: [`4.sim` Tool Versions](../4.sim/README.md#tool-versions).

| Tool | In use | Use | Source |
|---|---|---|---|
| Vivado | 2026.2 (Artix-7) | reference flow, Pypeline core synthesis | [AMD](https://www.amd.com/en/products/software/adaptive-socs-and-fpgas/vivado.html) |
| openXC7 | main (2026-11-26): Yosys 0.71+134 (`f960e972`), nextpnr-himbaechel 1.0.0-396-g7077312a | open-source flow | [openXC7](https://github.com/openXC7) |
| yosys-slang | OSS CAD Suite 2026-11-26 | `read_slang` front end, lint | [povik/yosys-slang](https://github.com/povik/yosys-slang) |
| sv2v | 0.0.13 | `FRONTEND=sv2v` | [zachjs/sv2v](https://github.com/zachjs/sv2v) |
| Verible | v0.0-4296-g0f262651 | format, lint | [chipsalliance/verible](https://github.com/chipsalliance/verible) |
| Verilator | 5.055 devel (`v5.054-260-gb9f22851`) | lint | [verilator.org](https://verilator.org) |
| GHDL | 7.0.0-dev (`6.0.0.r793.g39bd39022`, OSS CAD Suite 2026-11-26; latest release v6.0.0) | Pypeline VHDL lint, cocotb sim | [ghdl/ghdl](https://github.com/ghdl/ghdl) |
| Yosys + GHDL plugin | 0.71+128 (OSS CAD Suite 2026-11-26) | Pypeline VHDL to Verilog | [YosysHQ/oss-cad-suite-build](https://github.com/YosysHQ/oss-cad-suite-build) |
| LintCrux | 1.2.0 (the free open-core CLI) | lint: GHDL, Verilator, Verible, slang and svlint in one run, baseline gate, SARIF ([`run-lintcrux.sh`](lintcrux_build/run-lintcrux.sh), CI: [`lintcrux.yml`](../.github/workflows/lintcrux.yml), which pins every engine, OSS CAD Suite 2026-11-12) | [lintcrux.app](https://lintcrux.app) |
| svlint | v0.9.5 | LintCrux lint, functional rules ([`.svlint.toml`](../.svlint.toml)) | [dalance/svlint](https://github.com/dalance/svlint) |
| PipelineC (Pypeline) | the commit in [`pipelinec.ref`](pypeline_build/pipelinec.ref) | crypto core | [JulianKemmerer/PipelineC](https://github.com/JulianKemmerer/PipelineC) |
| cocotb | 2.1.0 | Pypeline generated-VHDL sim | [cocotb.org](https://www.cocotb.org) |
| PeakRDL | 1.5.0 (systemrdl-compiler 1.33) | CSR HAL | [peakrdl.readthedocs.io](https://peakrdl.readthedocs.io) |
| RISC-V GCC | xPack riscv-none-elf-gcc 15.2.0-1 | firmware | [xPack](https://xpack-dev-tools.github.io/riscv-none-elf-gcc-xpack/) |
| Python | 3.12.3 | scripts, Pypeline | |

## CSR HAL Compilation

The CSR RTL and the firmware's register header come from one SystemRDL file, `csr_build/csr.rdl`, through `peakrdl`. `make -f MakefileCSR` writes, to `3.build/csr_build/generated-files`:

  * `csr.sv`        : the CSR RTL
  * `csr_pkg.sv`    : its structured RTL interface
  * `csr.h`         : the register layout, `peakrdl c-header` output
  * `csr_top.h`     : `CSR_TOP_T`, the address map's struct in `csr.h`
  * `wireguard.md`  : the register map
  * `html/`         : the same map as HTML pages, generated but not tracked

The firmware includes [`csr_regs.h`](csr_build/csr_regs.h), next to `csr.rdl` and the same file in openPCIE and openCologne-PCIE. It takes every address, the CSR base included, from `csr.h` and has four accessors:

| Macro | Does | Example |
|---|---|---|
| `CSR_REG32(member)` | the whole register, one 32-bit access | `CSR_REG32(cpu_fifo.rx.data_31_0) = d;` |
| `CSR_GET(member, FLD)` | one field, out of a 32-bit read | `CSR_GET(dpe.fcr, CSR__DPE__FCR__IDLE)` |
| `CSR_SET(member, FLD, v)` | one field that owns its bytes: a byte, half-word or word store | `CSR_SET(cpu_fifo.rx.control, CSR__CPU_FIFO__RX__CONTROL__TKEEP, 0xFFFF);` |
| `CSR_RMW(member, FLD, v)` | one field that shares a byte: read, then store only its bytes | `CSR_RMW(gpio, CSR__GPIO__LED1, 1);` |

`FLD` is the field prefix `csr.h` defines (`_bm`, `_bp`, `_bw`). On the RISC-V core these are plain loads and stores (`lw`, `sb`, `sh`, `sw`). In co-simulation the same firmware is compiled for the host, and each access becomes one *VProc* bus cycle with the same address and byte enables ([4.sim](../4.sim/README.md#hal)). One header, one source, for both.

## SW Compilation

To generate binaries (elf, bin, hex) and instruction memory (IMEM) Verilog configuration file (imem.INIT.vh) a make file is provided as `3.build/MakefileSW`. Running this make file (`make -f MakefileSW`) produces the following files in `3.build/sw_build`:

  * `main.lds`      : The compiled Linker/MemoryMapper script
  * `main.map`      : The memory map for debugging
  * `main.elf`      : The ELF file for RISC-V hardware target
  * `main.hex`      : The HEX programming file for RISC-V hardware target
  * `main.bin`      : The raw binary file
  * `main.dump`     : The disassembly of the ELF file
  * `imem.INIT.vh`  : The IMEM Verilog configuration file
  
Additionally, `MakefileSW` supports running a Python script `imem.UART.py` to program the IMEM on a hardware target that is already configured (using the bitstream resulting from the HW compilation) and running. This script uses UART to transfer the generated binary/hex file (as described in the [UART Data Flow](/1.hw/README.md#uart-data-flow)) and facilitates software testing without the need for resynthesis and FPGA reconfiguration. It is launched as follows:

```
make -f MakefileSW program
```

## HW Compilation - Vivado

The main hardware synthesis/PnR tool is Vivado Design Suite, using the prepared [project file](/3.build/hw_build.Vivado/wireguard.xpr) project located at `3.build/hw_build.Vivado`.

To run synthesis, place-and-route (PnR), and generate the FPGA bitfile, execute:

```
make -f MakefileHW
```

After the bitfile has been successfully generated, the FPGA device can be programmed using:

```
make -f MakefileHW program
```

## HW Compilation - openXC7

Ported to openXC7 v1.0.0 (Yosys 0.69 + nextpnr-himbaechel) on 2026-10-21; built from openXC7 main since 2026-11-26. The older nextpnr-xilinx flow follows below as the [legacy flow](#legacy-flow-pre-v100-nextpnr-xilinx-toolchainold).

### openXC7 main (default)

**Toolchain:** openXC7 at the tip of main, not a release (since 2026-11-26: Yosys `f960e972`, nextpnr `7077312a`), built with [`toolchain-installer`](https://github.com/openXC7/toolchain-installer) main's `toolchain-sources-builder.sh` with `YOSYS_HASH` and `NEXTPNR_HASH` set to those commits: Yosys with `read_slang`, nextpnr-himbaechel (called through openXC7's `nextpnr-xilinx` shim), prjxray-db and `fpga-as`. Point `NEXTPNR_XILINX_DIR` at its install prefix, or put its `bin` on `PATH`. The 1.0.0 release no longer builds this design: it has no `BUFGMUX` mapping (nextpnr#132), and our techmap for it is gone.

**Build:**
```bash
cd wireguard-fpga/3.build
make -f MakefileSW               # firmware first: hw_build needs sw_build/imem.INIT.vh
cd hw_build.openXC7
make check-env check-sources     # tools and sources present
make                             # -> build_artifacts.slang/top.bit
```

The default `1.hw/top.filelist` builds the real `dpe_switch`, which does not route on openXC7 yet ([#68](https://github.com/chili-chips/wireguard-fpga/issues/68)). For a bitstream today, select `dpe_switch.DUMMY.sv` there.

- The frontend is `read_slang`: Yosys reads the SystemVerilog directly. `make FRONTEND=sv2v` converts it with sv2v first.
- The sources come from `1.hw/top.filelist`, the list Vivado, `4.sim` and `run-lint.sh` use (`run-lint.sh` and `run-leq.sh` also take each DPE block inside `dpe_switch` as a top of its own: `BLOCK_TOPS` in `sources.sh`). The CPU is the one it lists: eduBOS5 by default, PicoRV32 as the alternative.
- The chipdb (`chipdb.new/xc7a200tfbg484-2.bin`) is generated on the first run. It is per die, so a chipdb built for another `xc7a200t` part can be copied under this name.
- nextpnr reads only the port constraints of `1.hw/constraints/top.xdc` (#6), plus `top.openxc7.xdc` with the `clk_n` pin (#7), minus the 25 MHz `eN_txc` clocks: nextpnr times a `BUFGMUX` output with one input clock only and would time 1000BASE-T TX at 25 MHz (nextpnr#241). nextpnr main maps each `BUFGMUX` onto a `BUFGCTRL` itself, as Vivado does (nextpnr#132); our techmap `bufgmux_map.v` (#5) is gone since 2026-11-26.
- Place and route uses `--tmg-ripup --placer-heap-timingweight 30` (`NEXTPNR_OPTS`). With nextpnr's defaults the Ethernet RX clocks land at 102-128 MHz, depending on the seed.
- `NEXTPNR_OPTS` also has `--ignore-loops` (the default `TOOLCHAIN=new`; the legacy flow is untested with the rings): the TRNG's ring oscillators (`1.hw/ip.infra/trng`, #2) are combinational loops on purpose, and without it nextpnr stops with "Timing analysis failed due to combinational loops". The flag only skips the loops in the timing analysis. The rings are `LUT1`/`LUT2` instances, black-boxed for Yosys like the other primitives (`XILINX_PRIMS`). The rings add about 440 LUTs: sweep the seeds again.

- The flash clock goes through `STARTUPE2` (`1.hw/fpgatech_lib/XILINX/fpga_startup.sv`, #30), black-boxed for Yosys and in `XILINX_PRIMS` like the others.

**Result (2026-11-23, openXC7 v1.0.0, DUMMY switch, eduBOS5, `SEED=2`, the Makefile default; before the TRNG, RTC and flash):** about 8 minutes, 3 GB RAM; every clock meets its constraint. Seed sweep ([#3](https://github.com/chili-chips/wireguard-fpga/issues/3)), max frequency in MHz:

| Seed | `sys_clk` (80) | RX 1-4 (125) | TX 1-4 (125) | `eth_gtx_clk` (125) | Result |
|---|---|---|---|---|---|
| 1 | 91.9 | 127.0, 126.6, 127.7, 141.3 | 177.1-220.6 | 190.1 | pass |
| **2** | **89.6** | **138.9, 145.3, 131.4, 128.0** | **179.5-222.4** | **170.0** | **pass, widest margin** |
| 3 | 84.8 | 146.4, 132.3, 127.6, 150.4 | 168.4-209.7 | 215.7 | pass |
| 4 | 78.8 | 147.9, 124.1, 126.4, 129.5 | 167.2-233.6 | 160.8 | misses `sys_clk`, RX 2 |
| 5 | 79.5 | 130.8, 130.4, 131.1, 127.9 | 165.5-200.0 | 211.2 | misses `sys_clk` |
| 6 | 92.5 | 146.5, 137.0, 126.1, 133.2 | 151.5-192.0 | 231.4 | pass |
| 7 | 87.1 | 125.6, 125.9, 105.0, 126.4 | 177.2-209.3 | 207.7 | misses RX 3 |
| 8 | - | - | - | - | stopped after 40 min in timing ripup, about 430 failing paths |

Seed 2 rebuilt from a clean tree gives the same numbers. The netlist changes with any RTL change, and with it the result of a seed: rerun the sweep then (`make -B SEED=N`; without `-B` a finished build is not redone), read the `Max frequency` lines at the end of `build_artifacts.slang/nextpnr.log`). Earlier sweeps, PicoRV32, 2026-10: one seed in four met timing.

Use: 18,021 LUTs (6% of nextpnr's 269,200 LUT bels; 13% of the 134,600 LUT6), 9,432 FFs (3%), 34 RAMB36 + 1 RAMB18, 10 of 32 BUFGCTRL, 2 PLLs. The RX margins are thin (2.4% at seed 2), and nextpnr's timing analysis is simpler than Vivado's (openXC7/nextpnr#42): not yet tried on the board.

### Legacy flow: pre-v1.0.0 nextpnr-xilinx (`TOOLCHAIN=old`)

The 2025-12 flow: nextpnr-xilinx, sv2v only, output `build_artifacts/top.bit`. Untested since v1.0.0.

- Install: openXC7 per the [openeye-CamSI guide](https://github.com/chili-chips/openeye-CamSI/blob/main/3.build/openXC7/README.md); sv2v with `make install-sv2v`.
- Run: `make TOOLCHAIN=old PREFIX=<that installation>` (default `PREFIX=/opt/openxc7`), after the firmware.
- Key difference: it had no `BUFGMUX`, so the clock select ran through LUTs, off the clock network (see the test below).

### openXC7 issues

Each open item has an issue here, labelled `openXC7`. Upstream numbers without a link were filed from an account that is no longer available.

| Issue | Toolchain | Status | Ours | Upstream | Workaround |
|---|---|---|---|---|---|
| No mapping for `BUFGMUX` | v1.0.0 | fixed in `main` ([nextpnr#132](https://github.com/openXC7/nextpnr/pull/132)), which we build since 2026-11-26 | [#5](https://github.com/chili-chips/wireguard-fpga/issues/5) | nextpnr#125 | none: `bufgmux_map.v` (a `BUFGCTRL` after synthesis) removed; nextpnr maps `BUFGMUX` as Vivado does |
| XDC targets other than `get_ports`/`get_cells` abort | v1.0.0 | fixed on main (nextpnr#193), not released | [#6](https://github.com/chili-chips/wireguard-fpga/issues/6) | [nextpnr#185](https://github.com/openXC7/nextpnr/issues/185) | the Makefile passes nextpnr only the `get_ports` lines of `top.xdc` |
| Differential input needs its N pin constrained | v1.0.0 | fixed on main (nextpnr#194), not released | [#7](https://github.com/chili-chips/wireguard-fpga/issues/7) | [nextpnr#184](https://github.com/openXC7/nextpnr/issues/184) | `hw_build.openXC7/top.openxc7.xdc`: `clk_n` on T4 |
| Timing closes on some seeds only (the sv2v failure is gone: `read_slang`) | v1.0.0 | swept 2026-11-23: seeds 1, 2, 3, 6 of 1-7 pass | [#3](https://github.com/chili-chips/wireguard-fpga/issues/3) (closed) | - | `SEED ?= 2`; sweep again after RTL changes |
| `BUFGMUX` not supported | legacy | closed | - | [nextpnr-xilinx#75](https://github.com/openXC7/nextpnr-xilinx/issues/75) | fixed upstream (nextpnr-xilinx#81) |
| `IBUFGDS` not supported | legacy | closed | - | [nextpnr-xilinx#74](https://github.com/openXC7/nextpnr-xilinx/issues/74) | `IBUFDS` + `BUFG` |
| `IOBUFGDS`, `PLLE2_BASE` not supported | legacy | closed | - | [nextpnr-xilinx#73](https://github.com/openXC7/nextpnr-xilinx/issues/73) | Yosys 0.38 -> 0.60 |

### Test example

The 2025-12 test, legacy toolchain, firmware answering only ICMP and ARP ([`main.cpp`](../2.sw/app/main.cpp)): Vivado built in 8 minutes and answered all 4 pings; the legacy openXC7 built in 1 minute and answered 4, 0 or 1 of 4 in three runs. The cause was the missing `BUFGMUX`: the clock select in LUTs added delay. Since v1.0.0, nextpnr keeps `BUFGMUX`, mapped to `BUFGCTRL` (nextpnr#132, #5).
