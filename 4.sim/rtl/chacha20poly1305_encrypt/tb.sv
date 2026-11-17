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
//   ChaCha20Poly1305 encryption core testbench
//==========================================================================


module tb;
   import dpe_pkg::*;

   // Constants

   // Clock and reset signals
   logic clk;
   logic rst;

   // Interfaces
   dpe_if inp(.clk(clk), .rst(rst));
   dpe_if outp(.clk(clk), .rst(rst));

   // Test data type and constants
   typedef logic [127:0] test_data_t [5];
   typedef test_data_t packet_data_t [2];

   packet_data_t packet_data;  // set below: JanusHDL 0.17 has no const variables
   initial packet_data = '{
      '{
         128'h7370696843494C494843206F6C6C6548,
         128'h61657420647261756765726957202D20,
         128'h6874207473657420732774656C202C6D,
         128'h00000000000000002164616561207369,
         '0
      },
      '{
         128'h6568742073692043656E696C65706950,
         128'h646E756F7261204C4448207473656220,
         128'h494843206F6720732774654C20293A20,
         128'h7261756765726957207370696843494C,
         128'h000000000000000000216D6165742064
      }
   };

   // Clock generation
   // 80 MHz at 1 ns precision: halves of 6, 6, 7, 6 ns, 12.5 ns on average
   initial begin
      clk = 1'b0;
      forever begin
         #6ns clk = 1'b1;
         #6ns clk = 1'b0;
         #7ns clk = 1'b1;
         #6ns clk = 1'b0;
      end
   end

   // DUT instantiation
   chacha20poly1305_encrypt DUT (
      .clk_80p0(clk),
      .encrypt_key(256'h9F9E9D9C9B9A999897969594939291908F8E8D8C8B8A89888786858483828180),
      .encrypt_nonce(96'h474645444342414000000007),
      .encrypt_aad(256'h0000006174616420646574616369746E6568747561206C616E6F697469646441),
      .encrypt_aad_len(8'd29),
      .encrypt_s_axis_tdata(inp.tdata),
      .encrypt_s_axis_tkeep(inp.tkeep),
      .encrypt_s_axis_tlast(inp.tlast),
      .encrypt_s_axis_tvalid(inp.tvalid),
      .encrypt_m_axis_tready(outp.tready),
      .encrypt_s_axis_tready(inp.tready),
      .encrypt_m_axis_tdata(outp.tdata),
      .encrypt_m_axis_tkeep(outp.tkeep),
      .encrypt_m_axis_tlast(outp.tlast),
      .encrypt_m_axis_tvalid(outp.tvalid)
   );

   // Main stimulus process
   initial begin
      rst = 1;
      // Initialize input interface
      inp.tvalid = 0;
      inp.tlast = 0;
      inp.tkeep = '0;
      inp.tdata = '0;
      inp.tuser_bypass_all = 0;
      inp.tuser_bypass_stage = 0;
      inp.tuser_src = DPE_ADDR_ETH_1;
      inp.tuser_dst = DPE_ADDR_ETH_2;
      outp.tready = 1;

      // Reset assertion
      repeat (4) @(negedge clk);
      @(posedge clk);
      @(negedge clk);
      rst = 0;
      @(negedge clk);

      // Input stimulus
      begin
         @(posedge clk);
         // Send packet 0
         @(negedge clk);
         inp.tvalid = 1;
         for (int i = 0; i < 4; i++) begin
            inp.tdata = packet_data[0][i];
            inp.tkeep = 16'hFFFF;
            inp.tlast = (i == 3);
            @(posedge clk);
            while (!inp.tready) @(posedge clk);
            @(negedge clk);
         end
         inp.tvalid = 0;
         inp.tlast = 0;
         inp.tkeep = '0;
         inp.tdata = '0;
         // Send packet 1
         inp.tvalid = 1;
         for (int i = 0; i < 5; i++) begin
            inp.tdata = packet_data[1][i];
            inp.tkeep = 16'hFFFF;
            inp.tlast = (i == 4);
            @(posedge clk);
            while (!inp.tready) @(posedge clk);
            @(negedge clk);
         end
         inp.tvalid = 0;
         inp.tlast = 0;
         inp.tkeep = '0;
         inp.tdata = '0;
      end

      $display("Stimulus completed successfully");
      repeat (200) @(negedge clk);
      $finish(2);
   end

   // Output ready control process
   initial begin
      @(posedge clk);
      @(negedge clk);
      outp.tready = 1;
   end

   // Monitor process
   int expected_data_count;

   always @(posedge clk) begin
      if (rst) begin
         expected_data_count <= 0;
      end else begin
         if (outp.tvalid && outp.tready) begin
            expected_data_count <= expected_data_count + 1;

            if (outp.tlast) begin
               $display("Packet received with %0d words", expected_data_count + 1);
               expected_data_count <= 0;
            end
         end
      end
   end
endmodule
