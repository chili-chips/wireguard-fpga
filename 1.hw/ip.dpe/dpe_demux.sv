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
//   DPE demultiplexer with multicast and broadcast support: each beat goes
//   to the output ports (to_port, indexed by address: CPU, then Ethernet 1
//   to 4) its tuser.dst selects, and waits for all of them
//==========================================================================

module dpe_demux
  import dpe_pkg::*;
(
    dpe_if.s_axis from_dpe,
    dpe_if.m_axis to_port [DPE_PORTS]
);

  dpe_if from_dpe_sbuff (
      .clk (from_dpe.clk),
      .rst (from_dpe.rst)
  );

  // the ports a destination address selects: unicast, a multicast pair or
  // broadcast
  function automatic logic [DPE_PORTS-1:0] port_bit(dpe_addr_t a);
    return DPE_PORTS'(1) << a;
  endfunction

  function automatic logic [DPE_PORTS-1:0] dst_ports(dpe_addr_t dst);
    unique case (dst)
      DPE_ADDR_MCAST_13: return port_bit(DPE_ADDR_ETH_1) | port_bit(DPE_ADDR_ETH_3);
      DPE_ADDR_MCAST_24: return port_bit(DPE_ADDR_ETH_2) | port_bit(DPE_ADDR_ETH_4);
      DPE_ADDR_BCAST:    return '1;
      default:           return port_bit(dst);  // the CPU or one Ethernet port
    endcase
  endfunction

  logic [DPE_PORTS-1:0] sel, out_ready;
  assign                sel = dst_ports(from_dpe_sbuff.tuser.dst);

  // Backpressure: wait for every selected output
  assign from_dpe_sbuff.tready = &(~sel | out_ready);

  // each output: the beat when selected, through its skid buffer
  for (genvar p = 0; p < DPE_PORTS; p++) begin : g_out
    dpe_if to_sbuff (
        .clk (from_dpe.clk),
        .rst (from_dpe.rst)
    );

    assign to_sbuff.tvalid = sel[p] & from_dpe_sbuff.tvalid;
    assign to_sbuff.tdata  = sel[p] ? from_dpe_sbuff.tdata : '0;
    assign to_sbuff.tkeep  = sel[p] ? from_dpe_sbuff.tkeep : '0;
    assign to_sbuff.tlast  = sel[p] & from_dpe_sbuff.tlast;
    assign to_sbuff.tuser  = sel[p] ? from_dpe_sbuff.tuser : '0;
    assign to_sbuff.tid    = sel[p] ? from_dpe_sbuff.tid   : '0;
    assign out_ready[p]    = to_sbuff.tready;

    dpe_if_skid_buffer u_dpe_if_skid_buffer_to_port (
        .inp  (to_sbuff),
        .outp (to_port[p])
    );
  end

  // Skid buffer
  dpe_if_skid_buffer u_dpe_if_skid_buffer_from_dpe (
      .inp  (from_dpe),
      .outp (from_dpe_sbuff)
  );
endmodule

// -----------------------------------------------------------------------------
// Project:     WireGuard-FPGA
// Description: NLnet-funded open-source implementation
// Funding:     https://nlnet.nl/project/KlusterLab-Wireguard (2023-12 to 2025-12)
// -----------------------------------------------------------------------------
