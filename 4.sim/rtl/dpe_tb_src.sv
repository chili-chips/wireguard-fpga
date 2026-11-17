// SPDX-FileCopyrightText: 2026 Chili.CHIPS
//
// SPDX-License-Identifier: BSD-3-Clause

//==========================================================================
// Block-level DPE benches: one AXI-Stream source. send() drives a packet:
// one byte per beat in tdata[7:0] (tkeep 0x0001), tlast on its last byte,
// tuser_src = SRC and tuser_dst = the packet's dst. Inputs change on the
// falling edge; a beat moves on a rising edge with tready high.
//==========================================================================

module dpe_tb_src
  import dpe_pkg::*;
  import dpe_tb_pkg::*;
#(
    parameter dpe_addr_t SRC = DPE_ADDR_CPU
) (
    dpe_if.m_axis outp
);
  initial begin
    outp.tvalid             = 1'b0;
    outp.tlast              = 1'b0;
    outp.tkeep              = '0;
    outp.tdata              = '0;
    outp.tuser.bypass_all   = 1'b0;
    outp.tuser.bypass_stage = 1'b0;
    outp.tuser.src          = SRC;
    outp.tuser.dst          = DPE_ADDR_CPU;
    outp.tid                = '0;
  end

  task automatic send(input test_pkt_t p);
    // The bytes as one vector, byte i at [8*(MAX_BYTES-1-i) +: 8]: JanusHDL 0.17
    // cannot index p.data[i] at run time
    logic [8*MAX_BYTES-1:0] bytes;
    bytes          = p.data;
    outp.tvalid    = 1'b1;
    outp.tkeep     = 16'h0001;
    outp.tuser.dst = p.dst;
    for (int i = 0; i < int'(p.len); i++) begin
      outp.tdata      = {120'b0, bytes[8*(MAX_BYTES-1-i)+:8]};
      outp.tlast      = (i == int'(p.len) - 1);
      @(posedge outp.clk);
      while (!outp.tready) @(posedge outp.clk);
      @(negedge outp.clk);
    end
    outp.tvalid = 1'b0;
    outp.tlast  = 1'b0;
    outp.tkeep  = '0;
  endtask
endmodule
