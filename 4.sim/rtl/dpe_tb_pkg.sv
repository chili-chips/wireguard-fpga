// SPDX-FileCopyrightText: 2026 Chili.CHIPS
//
// SPDX-License-Identifier: BSD-3-Clause

//==========================================================================
// Block-level DPE benches: the test packet and the DPE port map, shared by
// dpe_tb_src (sends one) and dpe_tb_sink (receives and checks them).
// Packed throughout: Icarus has no unpacked structs.
//==========================================================================

package dpe_tb_pkg;
  import dpe_pkg::*;

  localparam int MAX_BYTES = 6;

  // One packet: one byte per beat, in tdata[7:0]
  typedef struct packed {
    logic [2:0]                    dst;   // tuser_dst: DPE_ADDR_*
    logic [3:0]                    len;   // bytes used, 1 to MAX_BYTES
    // verilator lint_off ASCRANGE
    logic [0:MAX_BYTES-1][7:0]     data;  // data[0] goes first
    // verilator lint_on ASCRANGE
  } test_pkt_t;

  // Output ports: bit 0 the CPU, bits 1 to 4 ETH 1 to 4
  typedef logic [4:0] ports_t;

  // The outputs a destination selects (dpe_demultiplexer.sv)
  function automatic ports_t ports_of(logic [2:0] dst);
    ports_of[0] = (dst == DPE_ADDR_CPU)   || (dst == DPE_ADDR_BCAST);
    ports_of[1] = (dst == DPE_ADDR_ETH_1) || (dst == DPE_ADDR_MCAST_13) || (dst == DPE_ADDR_BCAST);
    ports_of[2] = (dst == DPE_ADDR_ETH_2) || (dst == DPE_ADDR_MCAST_24) || (dst == DPE_ADDR_BCAST);
    ports_of[3] = (dst == DPE_ADDR_ETH_3) || (dst == DPE_ADDR_MCAST_13) || (dst == DPE_ADDR_BCAST);
    ports_of[4] = (dst == DPE_ADDR_ETH_4) || (dst == DPE_ADDR_MCAST_24) || (dst == DPE_ADDR_BCAST);
  endfunction
endpackage
