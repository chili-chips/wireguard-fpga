// SPDX-FileCopyrightText: 2026 Chili.CHIPS*ba
//
// SPDX-License-Identifier: BSD-3-Clause

//==========================================================================
// Wireguard-1GE FPGA * NLnet-sponsored open-source implementation
//--------------------------------------------------------------------------
//                   Copyright (C) 2026 Chili.CHIPS*ba
//
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions
// are met:
//
// 1. Redistributions of source code must retain the above copyright
// notice, this list of conditions and the following disclaimer.
//
// 2. Redistributions in binary form must reproduce the above copyright
// notice, this list of conditions and the following disclaimer in the
// documentation and/or other materials provided with the distribution.
//
// 3. Neither the name of the copyright holder nor the names of its
// contributors may be used to endorse or promote products derived
// from this software without specific prior written permission.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS
// IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED
// TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A
// PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
// HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
// SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
// LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
// DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
// THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
// (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
// OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
//
//              https://opensource.org/license/bsd-3-clause
//--------------------------------------------------------------------------
// Description:
//   DPE switch, DUMMY: a fixed crossbar, swapped for the IP lookup
//   (dpe_switch.sv) in top.filelist. The routing table is a RAM the CPU
//   writes and reads back over the CSR; the crossbar does not read it
//--------------------------------------------------------------------------
// Default configuration
// (can be overridden by assertion of tuser_bypass_all or tuser_bypass_stage)
//
//   .----------.                             .----------.
//   | From CPU |                 .---------->|  To CPU  |
//   |   FIFO   |------------.   /  .-------->|   FIFO   |
//   '----------'             \ /  /          '----------'
//                             X  /
//   .----------.             / \/            .----------.
//   |From ETH_1|------------'  /\            | To ETH_1 |
//   |   FIFO   |              /  '---------->|   FIFO   |
//   '----------'             /               '----------'
//                           /
//   .----------.           /                 .----------.
//   |From ETH_2|----------'             0--->| To ETH_2 |
//   |   FIFO   |                             |   FIFO   |
//   '----------'                             '----------'
//
//   .----------.                             .----------.
//   |From ETH_3|                             | To ETH_3 |
//   |   FIFO   |------------.   .----------->|   FIFO   |
//   '----------'             \ /             '----------'
//                             X
//   .----------.             / \             .----------.
//   |From ETH_4|------------'   '----------->| To ETH_4 |
//   |   FIFO   |                             |   FIFO   |
//   '----------'                             '----------'
//
//==========================================================================

module dpe_switch
  import dpe_pkg::*;
  import lkup_pkg::*;
(
    dpe_if.s_axis    inp,
    dpe_if.m_axis    out,
    output logic     idle,    // nothing to wait for: the crossbar decides at once

    // the CSR routing_table and cryptokey_table regfiles (csr.rdl)
    input  csr_cfg_t rt_cfg,
    output csr_sta_t rt_sta,
    input  ck_cfg_t  ck_cfg,
    output ck_sta_t  ck_sta
);

  dpe_if outp_sbuff (
      .clk (inp.clk),
      .rst (inp.rst)
  );

  // Backpressure
  assign inp.tready = outp_sbuff.tready;

  // Switch
  always_comb begin
    outp_sbuff.tvalid             = inp.tvalid;
    outp_sbuff.tdata              = inp.tdata;
    outp_sbuff.tkeep              = inp.tkeep;
    outp_sbuff.tlast              = inp.tlast;
    outp_sbuff.tid                = inp.tid;
    outp_sbuff.tuser.bypass_all   = inp.tuser.bypass_all;
    outp_sbuff.tuser.bypass_stage = 1'b0;
    outp_sbuff.tuser.src          = inp.tuser.src;
    outp_sbuff.tuser.dst          = inp.tuser.dst;  // unless the switch below swaps it
    if (inp.tuser.bypass_all == 1'b0 && inp.tuser.bypass_stage == 1'b0) begin
      unique case (inp.tuser.src)
        DPE_ADDR_CPU: begin
          outp_sbuff.tuser.dst = DPE_ADDR_ETH_1;
        end
        DPE_ADDR_ETH_1: begin
          outp_sbuff.tuser.dst = DPE_ADDR_CPU;
        end
        DPE_ADDR_ETH_2: begin
          outp_sbuff.tuser.dst = DPE_ADDR_CPU;
        end
        DPE_ADDR_ETH_3: begin
          outp_sbuff.tuser.dst = DPE_ADDR_ETH_4;
        end
        DPE_ADDR_ETH_4: begin
          outp_sbuff.tuser.dst = DPE_ADDR_ETH_3;
        end
        default: begin  // a multicast or broadcast source: dst as it is
        end
      endcase
    end
  end

  // Routing table: written and read back by the CPU only
  logic [31:0] rt_rd_data;
  logic        rt_rd_ack;

  tdp_ram #(
      .ADDR_WIDTH (8)
  ) u_routing_table (
      .clk    (inp.clk),
      .we_a   (rt_cfg.req & rt_cfg.req_is_wr),
      .addr_a (rt_cfg.addr[9:2]),
      .din_a  (rt_cfg.wr_data),
      .dout_a (rt_rd_data),
      .we_b   (1'b0),
      .addr_b ('0),
      .din_b  ('0),
      .dout_b (  /*LINT:OK*/)                   // port B: the crossbar does not read the table
  );
  always_ff @(posedge inp.clk) begin
    rt_rd_ack <= rt_cfg.req & ~rt_cfg.req_is_wr;
  end
  always_comb begin
    rt_sta.rd_data = rt_rd_data;
    rt_sta.rd_ack  = rt_rd_ack;
    rt_sta.wr_ack  = rt_cfg.req & rt_cfg.req_is_wr;
  end


  // Cryptokey table: written and read back by the CPU only
  logic [31:0] ck_rd_data;
  logic        ck_rd_ack;

  tdp_ram #(
      .ADDR_WIDTH (11)
  ) u_cryptokey_table (
      .clk    (inp.clk),
      .we_a   (ck_cfg.req & ck_cfg.req_is_wr),
      .addr_a (ck_cfg.addr[12:2]),
      .din_a  (ck_cfg.wr_data),
      .dout_a (ck_rd_data),
      .we_b   (1'b0),
      .addr_b ('0),
      .din_b  ('0),
      .dout_b (  /*LINT:OK*/)                   // port B: the crossbar does not read the table
  );
  always_ff @(posedge inp.clk) begin
    ck_rd_ack <= ck_cfg.req & ~ck_cfg.req_is_wr;
  end
  always_comb begin
    ck_sta.rd_data = ck_rd_data;
    ck_sta.rd_ack  = ck_rd_ack;
    ck_sta.wr_ack  = ck_cfg.req & ck_cfg.req_is_wr;
  end

  assign idle = 1'b1;

  // Skid buffers
  dpe_if_skid_buffer skid_buffer_outp (
      .inp  (outp_sbuff),
      .outp (out)
  );
endmodule

// -----------------------------------------------------------------------------
// Project:     WireGuard-FPGA
// Description: NLnet-funded open-source implementation
// Funding:     https://nlnet.nl/project/KlusterLab-Wireguard (2023-12 to 2025-12)
// -----------------------------------------------------------------------------
