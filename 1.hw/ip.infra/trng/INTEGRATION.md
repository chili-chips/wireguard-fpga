<!--
SPDX-FileCopyrightText: 2026 Chili.CHIPS

SPDX-License-Identifier: BSD-3-Clause
-->

# What the TRNG touches outside this folder (#2)

Design notes: [README.md](README.md).

| File | What |
|---|---|
| `3.build/csr_build/csr.rdl` | regfile `trng` at 0x094 to 0x0A7: `ctrl`, `status`, `data`, `rct_max`, `apt_max` |
| `1.hw/top.sv` | `u_trng`, on `sys_clk`; drives `to_csr.trng` only |
| `1.hw/top.filelist` | the five `.sv` files, `trng_pkg.sv` first |
| `3.build/hw_build.openXC7/` | `LUT1 LUT2` in the black-boxed primitives (`run-lint.sh`, `run-leq.sh`, `Makefile` `XILINX_PRIMS`); `--ignore-loops` in `NEXTPNR_OPTS` |
| `3.build/lintcrux_build/run-lintcrux.sh` | `LUT1 LUT2` in `PRIMS` |
| `3.build/hw_build.Vivado/wireguard.xpr` | the five files in `sources_1`; no XDC: `allow_combinatorial_loops` turns DRC LUTLP-1 into LUTLP-2 |
| `2.sw/app/random.c` | uses `csr.trng` when `csr.h` has `CSR__TRNG__STATUS__READY_bm` |
| `4.sim/rtl/trng/` | the unit bench |

`run-lint.sh cdc` lists the ring taps as unclocked sources into `meta` (`ASYNC_REG`): intended.

**Raw dumps (to do):** a host script over the UART bus master. Write `ctrl` = `0x83` (enable, raw, rate 8), poll `status.valid`, read `data`, check `status.ovf` = 0 at the end. Then deinterleave even and odd bits and run `ea_non_iid -v <file> 1` per bank.

<!--
-----------------------------------------------------------------------------
Project:     WireGuard-FPGA
Description: NLnet-funded open-source implementation
Funding:     https://nlnet.nl/project/KlusterLab-Wireguard (2023-12 to 2025-12)
-----------------------------------------------------------------------------
-->
