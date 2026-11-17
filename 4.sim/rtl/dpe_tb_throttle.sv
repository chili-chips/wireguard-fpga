// SPDX-FileCopyrightText: 2026 Chili.CHIPS
//
// SPDX-License-Identifier: BSD-3-Clause

//==========================================================================
// Wireguard-1GE FPGA * NLnet-sponsored open-source implementation
//--------------------------------------------------------------------------
// Description:
//   Bench stage between two dpe_if: a beat passes only in a clock where a
//   free-running LFSR lets it, so the upstream sees backpressure and the
//   downstream sees bubbles. PASS_PCT of the clocks pass (0 to 100);
//   SEED picks the pattern.
//==========================================================================

module dpe_tb_throttle #(
    parameter int          PASS_PCT = 50,
    parameter logic [15:0] SEED     = 16'hACE1
) (
    dpe_if.s_axis inp,
    dpe_if.m_axis outp
);
  logic [15:0] lfsr;
  logic        go;  // this clock, a beat may pass

  always_ff @(posedge inp.clk) begin
    if (inp.rst) lfsr <= SEED;
    else lfsr <= {lfsr[14:0], lfsr[15] ^ lfsr[13] ^ lfsr[12] ^ lfsr[10]};
  end
  assign go = int'(lfsr[6:0]) < PASS_PCT * 128 / 100;

  assign outp.tvalid = inp.tvalid & go;
  assign inp.tready  = outp.tready & go;
  assign outp.tdata  = inp.tdata;
  assign outp.tkeep  = inp.tkeep;
  assign outp.tlast  = inp.tlast;
  assign outp.tuser  = inp.tuser;
  assign outp.tid    = inp.tid;
endmodule
