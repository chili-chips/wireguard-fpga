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
//   WireGuard Encryptor testbench
//==========================================================================

`define NULL 0

module tb;
   import net_pkg::*;
   // Inputs
   logic clk;
   logic rst;
   logic pcapfinished;
   logic fcr_idle;

   dpe_if from_pcap(.clk(clk), .rst(rst));
   dpe_if to_encryptor(.clk(clk), .rst(rst));
   dpe_if from_encryptor(.clk(clk), .rst(rst));
   dpe_if to_pcap(.clk(clk), .rst(rst));

   dpe_pcapreader #(
      .PCAP_FILENAME("../plaintext_mix.pcap"),
      .TUSER_BYPASS_STAGE(1'b0)
   ) pcaprd (
	   .outp(from_pcap),
      .pcapfinished(pcapfinished)
   );

   // The peer's routing-table entry; MAC, IP and port in bus byte order
   localparam wg_peer_cfg_t PEER = '{
      local_mac:   48'hAABBCCDDEEFF,
      local_ip:    32'h0100A8C0,  // 192.168.0.1
      local_port:  16'h6DCA,
      remote_mac:  48'hFFEEDDCCBBAA,
      remote_ip:   32'h0200A8C0,  // 192.168.0.2
      remote_port: 16'h6CCA,
      remote_id:   32'hAABBCCDD,
      key:         256'h0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF,
      send_cnt:    64'd1
   };

   // Stalls on both sides: bubbles into the encryptor, backpressure out of
   // it. ../wg_check.py checks the output (see the Makefile)
   dpe_tb_throttle #(.PASS_PCT(60), .SEED(16'hACE1)) stall_in (
      .inp (from_pcap),
      .outp(to_encryptor)
   );

   dpe_tb_throttle #(.PASS_PCT(60), .SEED(16'h1D2C)) stall_out (
      .inp (from_encryptor),
      .outp(to_pcap)
   );

   dpe_wg_encryptor encryptor (
      .inp(to_encryptor),
      .outp(from_encryptor),

      .fcr_idle(fcr_idle),

      .ram_peer_idx(),
      .ram_peer(PEER),
      .ram_new_send_cnt(),
      .ram_update_send_cnt()
   );

   dpe_pcapwriter #(
	   .PCAP_FILENAME("ciphertext_mix.pcap")  // in output/
   ) pcapwr (
	   .inp(to_pcap)
   );

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

   initial begin
      rst = 1;
      @(negedge clk);
      rst = 0;

      while (~pcapfinished) begin
	      @(negedge clk);
	   end

      while (~fcr_idle) begin
	      @(negedge clk);
	   end

      repeat (2) @(negedge clk);

      $finish;
   end
endmodule

// -----------------------------------------------------------------------------
// Project:     WireGuard-FPGA
// Description: NLnet-funded open-source implementation
// Funding:     https://nlnet.nl/project/KlusterLab-Wireguard (2023-12 to 2025-12)
// -----------------------------------------------------------------------------
