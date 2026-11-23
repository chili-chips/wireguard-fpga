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
//   Debouncer of board push-buttons and switches. Each input goes through a
//   2-flop synchronizer into the clk domain, then is sampled every
//   SAMPLE_CLKS clocks: the output takes a new value only after three
//   samples in a row agree on it. Polarity is kept: active-low in,
//   active-low out.
//==========================================================================

module debounce
  import soc_pkg::*;
#(
    parameter int           N           = 1,                // inputs
    parameter int           SAMPLE_CLKS = KEY_SAMPLE_CLKS,  // clocks between samples
    parameter logic [N-1:0] IDLE        = '0                // value at reset
) (
    input  logic         arst_n,
    input  logic         clk,

    input  logic [N-1:0] inp,     // asynchronous
    output logic [N-1:0] out      // synchronous to clk, debounced
);

  localparam int CNT_W = $clog2(SAMPLE_CLKS);

  (* ASYNC_REG = "TRUE" *) logic [N-1:0] sync[2];  // the synchronizer
  logic [N-1:0] smp[3];  // the last three samples, smp[0] the newest
  logic [CNT_W-1:0] cnt;  // clocks since the last sample

  always_ff @(negedge arst_n or posedge clk) begin
    if (arst_n == 1'b0) begin
      sync[0] <= IDLE;
      sync[1] <= IDLE;
      smp[0]  <= IDLE;
      smp[1]  <= IDLE;
      smp[2]  <= IDLE;
      out     <= IDLE;
      cnt     <= '0;
    end
    else begin
      sync[0] <= inp;
      sync[1] <= sync[0];
      if (cnt == CNT_W'(SAMPLE_CLKS - 1)) begin
        cnt    <= '0;
        smp[0] <= sync[1];
        smp[1] <= smp[0];
        smp[2] <= smp[1];
      end
      else begin
        cnt <= cnt + 1'b1;
      end
      // a bit changes when its three samples agree
      out <= (smp[0] & smp[1] & smp[2]) | (out & (smp[0] | smp[1] | smp[2]));
    end
  end

endmodule : debounce

/*
-----------------------------------------------------------------------------
Version History:
-----------------------------------------------------------------------------
 2024/1/3  JI: initial creation
 2024/2/12 JI: improved so that it works for both Active1 and Active0  input
 2026/11/23  : 2-flop synchronizer, own sample counter, N inputs, symmetric
               filter; the coding rules of 1.hw/README.md
*/

// -----------------------------------------------------------------------------
// Project:     WireGuard-FPGA
// Description: NLnet-funded open-source implementation
// Funding:     https://nlnet.nl/project/KlusterLab-Wireguard (2023-12 to 2025-12)
// -----------------------------------------------------------------------------
