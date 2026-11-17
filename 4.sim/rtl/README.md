<!--
SPDX-FileCopyrightText: 2026 Chili.CHIPS*ba

SPDX-License-Identifier: BSD-3-Clause
-->

# Block-level benches

One directory per block. In it:

```
make                  # Verilator (default)
make SIM=icarus       # Icarus Verilog
make SIM=janushdl     # JanusHDL 0.17 or later
make wave             # GTKWave on output/wave.fst
```

The rules are in [`sim.mk`](sim.mk): timescale `1ns/1ns`, `output/sim.log` and `output/wave.fst` with every simulator.

## Self-checking DPE benches

`dpe`, `dpe_multiplexer` and `dpe_demultiplexer` share [`dpe_tb_pkg.sv`](dpe_tb_pkg.sv), [`dpe_tb_src.sv`](dpe_tb_src.sv) and [`dpe_tb_sink.sv`](dpe_tb_sink.sv):

- A test packet (`test_pkt_t`) carries its destination, its length and its bytes. The bench keeps one per port in a struct with a field per port.
- `dpe_tb_src.send()` drives a packet: one byte per beat, `tkeep` `0x0001`, `tlast` on the last byte.
- `dpe_tb_sink` records what each output receives and checks it: every expected packet once, intact, with the right `tuser_src` and `tuser_dst`, nothing else, `tkeep` `0x0001` on every beat. Order is not checked.
- The bench prints `RESULT: PASS` or `RESULT: FAIL`. A FAIL fails `make`.

## Status

| Bench | Verilator | Icarus | JanusHDL |
|---|---|---|---|
| `dpe` | PASS | no: PeakRDL `csr_pkg.sv` uses unpacked structs | no: `tdp_ram.sv` written by two `always_ff` ([#1](https://github.com/chili-chips/wireguard-fpga/issues/1)) |
| `dpe_multiplexer` | PASS | PASS | PASS |
| `dpe_demultiplexer` | PASS | PASS | PASS |
| `pcap_reader_writer` | runs | runs | no: `$fread` into a memory |
| `gmii2gmii_test` | runs | no: compiles all of `top.filelist` (`csr_pkg.sv`) | runs |
| `chacha20poly1305_encrypt` | runs | no: nested unpacked array pattern (`tb.sv:62`) | runs |
| `dpe_wg_encryptor` | output differs from its reference `.pcap` | | |
| `dpe_wg_disassembler` | does not compile: RTL older than `dpe_if` | | |

"Runs" means the bench ends without error but has no self-check yet.
