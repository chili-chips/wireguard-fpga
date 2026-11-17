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
//   DPE WireGuard Disassembler testbench, self-checking.
//
//   Frames are built byte by byte at net_pkg's offsets and sent as 128-bit
//   beats (tkeep on the last). The lookup is modelled here: two receiver
//   indices are known peers. Every packet must come out in order, its data
//   unchanged, with tid and bypass_stage as expected; the output stalls now
//   and then. Prints RESULT: PASS or RESULT: FAIL.
//==========================================================================

module tb;
   import dpe_pkg::*;
   import net_pkg::*;

   localparam int NPKT    = 8;
   localparam int MAXLEN  = 96;
   localparam int MAXBEAT = (MAXLEN + BEAT_BYTES - 1) / BEAT_BYTES;

   // The lookup: receiver index -> peer
   localparam wg_receiver_t RCV_A  = 32'hCAFE_0001;
   localparam dpe_peer_idx_t PEER_A = 5;
   localparam wg_receiver_t RCV_B  = 32'h0000_0002;
   localparam dpe_peer_idx_t PEER_B = 9;

   logic clk;
   logic rst;
   dpe_if inp (.clk(clk), .rst(rst));
   dpe_if outp(.clk(clk), .rst(rst));

   logic        fcr_idle;
   wg_receiver_t wg_rcv;
   dpe_peer_idx_t wg_idx;
   logic        wg_idx_match;

   always_comb begin
      wg_idx_match = 1'b1;
      if (wg_rcv == RCV_A)      wg_idx = PEER_A;
      else if (wg_rcv == RCV_B) wg_idx = PEER_B;
      else begin
         wg_idx       = '0;
         wg_idx_match = 1'b0;
      end
   end

   dpe_wg_disassembler DUT (
      .fcr_idle     (fcr_idle),
      .wg_rcv       (wg_rcv),
      .wg_idx       (wg_idx),
      .wg_idx_match (wg_idx_match),
      .inp          (inp),
      .outp         (outp)
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

   //------------------------------------------------------------------
   // The packets, and what must come out
   logic [7:0]  frame   [NPKT][MAXLEN];
   int          len     [NPKT];
   dpe_tuser_t  user_in [NPKT];
   dpe_peer_idx_t tid_in  [NPKT];
   logic        exp_peer[NPKT];  // tid = peer, bypass_stage clear
   dpe_peer_idx_t peer    [NPKT];
   logic        exp_same[NPKT];  // comes out unchanged (came in with a bypass)

   // verilator lint_off UNUSEDSIGNAL
   // (p indexes the NPKT packets: its upper bits are unused)
   function automatic void put_be16(int p, int off, logic [15:0] v);
      frame[p][off]   = v[15:8];
      frame[p][off+1] = v[7:0];
   endfunction

   function automatic void put_le32(int p, int off, logic [31:0] v);
      for (int i = 0; i < 4; i++) frame[p][off+i] = v[8*i+:8];
   endfunction
   // verilator lint_on UNUSEDSIGNAL

   // A WireGuard data frame to receiver `rcv`; kind changes one field
   typedef enum {WG, NOT_WG_TYPE, TCP, ARP} kind_e;
   function automatic void make(int p, int n, kind_e kind, logic [31:0] rcv);
      len[p] = n;
      for (int i = 0; i < MAXLEN; i++) frame[p][i] = 8'((p << 4) + i);
      put_be16(p, ETH_TYPE_OFFSET, kind == ARP ? 16'h0806 : ETHERTYPE_IPV4);
      frame[p][IPV4_VER_IHL_OFFSET] = {IPV4_VERSION, 4'd5};
      frame[p][IPV4_PROTO_OFFSET]   = kind == TCP ? 8'd6 : IP_PROTO_UDP;
      put_le32(p, WG_TYPE_OFFSET, kind == NOT_WG_TYPE ? 32'd1 : WG_TYPE_DATA);
      put_le32(p, WG_RECEIVER_OFFSET, rcv);
      user_in[p] = '{bypass_all: 1'b0, bypass_stage: 1'b0, src: DPE_ADDR_ETH_1, dst: DPE_ADDR_CPU};
      tid_in[p]   = dpe_peer_idx_t'('hA0 + p);
      exp_peer[p] = 1'b0;
      peer[p]     = '0;
      exp_same[p] = 1'b0;
   endfunction

   initial begin
      make(0, 90, WG, RCV_A);           exp_peer[0] = 1'b1; peer[0] = PEER_A;
      make(1, 80, WG, 32'h0000_1234);   // unknown receiver
      make(2, 74, WG, RCV_B);           exp_peer[2] = 1'b1; peer[2] = PEER_B;
      make(3, 80, NOT_WG_TYPE, RCV_A);  // UDP, but a handshake message
      make(4, 64, TCP, RCV_A);
      make(5, 60, ARP, RCV_A);
      make(6, 12, WG, RCV_A);           // one beat: too short for WireGuard
      make(7, 90, WG, RCV_A);           // already marked bypass_all
      user_in[7].bypass_all = 1'b1;
      exp_same[7] = 1'b1;
   end

   //------------------------------------------------------------------
   // Source: the packets back to back
   initial begin
      rst = 1'b1;
      inp.tvalid = 1'b0;
      inp.tlast  = 1'b0;
      inp.tkeep  = '0;
      inp.tdata  = '0;
      inp.tuser  = '0;
      inp.tid    = '0;
      repeat (5) @(negedge clk);
      rst = 1'b0;
      @(negedge clk);
      for (int p = 0; p < NPKT; p++) begin
         for (int b = 0; b * BEAT_BYTES < len[p]; b++) begin
            inp.tvalid = 1'b1;
            inp.tuser  = user_in[p];
            inp.tid    = tid_in[p];
            inp.tlast  = (b + 1) * BEAT_BYTES >= len[p];
            for (int i = 0; i < BEAT_BYTES; i++) begin
               inp.tdata[8*i+:8] = b * BEAT_BYTES + i < len[p] ? frame[p][b*BEAT_BYTES+i] : 8'h00;
               inp.tkeep[i]      = b * BEAT_BYTES + i < len[p];
            end
            @(posedge clk);
            while (!inp.tready) @(posedge clk);
            @(negedge clk);
         end
      end
      inp.tvalid = 1'b0;
      inp.tlast  = 1'b0;
   end

   //------------------------------------------------------------------
   // Output back-pressure: a few stalls, from a 5-bit LFSR
   logic [4:0] lfsr;
   always_ff @(posedge clk) begin
      if (rst) lfsr <= 5'h1F;
      else     lfsr <= {lfsr[3:0], lfsr[4] ^ lfsr[2]};
   end
   assign outp.tready = !rst && lfsr[1:0] != 2'b00;

   //------------------------------------------------------------------
   // Sink: every beat against the packet it belongs to
   int  rx_pkt, rx_beat, errors;
   initial begin
      rx_pkt  = 0;
      rx_beat = 0;
      errors  = 0;
   end

   initial forever begin
      @(posedge clk);
      if (!rst && outp.tvalid && outp.tready) begin
         automatic int        p = rx_pkt;
         automatic beat_t     d;
         automatic logic [15:0] k;
         automatic dpe_tuser_t u;
         automatic dpe_peer_idx_t t;
         for (int i = 0; i < BEAT_BYTES; i++) begin
            d[8*i+:8] = rx_beat * BEAT_BYTES + i < len[p] ? frame[p][rx_beat*BEAT_BYTES+i] : 8'h00;
            k[i]      = rx_beat * BEAT_BYTES + i < len[p];
         end
         u = user_in[p];
         t = tid_in[p];
         if (!exp_same[p]) begin
            u.bypass_stage = !exp_peer[p];
            if (exp_peer[p]) t = peer[p];
         end
         if (p >= NPKT) begin
            errors++;
            $display("%t FAIL: an extra beat after the last packet", $time);
         end else if (outp.tdata !== d || outp.tkeep !== k ||
                      outp.tlast !== ((rx_beat + 1) * BEAT_BYTES >= len[p]) ||
                      outp.tuser !== u || outp.tid !== t) begin
            errors++;
            $display("%t FAIL: packet %0d beat %0d: tid %h (expected %h), tuser %h (expected %h)%s",
                     $time, p, rx_beat, outp.tid, t, outp.tuser, u,
                     outp.tdata !== d ? ", data changed" : "");
         end
         if (outp.tlast) begin
            $display("%t packet %0d out: tid %h, bypass_stage %0d", $time, p, outp.tid,
                     outp.tuser.bypass_stage);
            rx_pkt++;
            rx_beat = 0;
         end else begin
            rx_beat++;
         end
      end
   end

   //------------------------------------------------------------------
   initial begin
      int n;
      n = 0;
      @(negedge rst);
      while (rx_pkt < NPKT && n < 2000) begin
         @(posedge clk);
         n++;
      end
      repeat (5) @(posedge clk);
      if (rx_pkt != NPKT) begin
         errors++;
         $display("FAIL: %0d of %0d packets out", rx_pkt, NPKT);
      end
      if (!fcr_idle) begin
         errors++;
         $display("FAIL: not idle at the end");
      end
      if (errors == 0) $display("RESULT: PASS");
      else             $display("RESULT: FAIL (%0d errors)", errors);
      $finish(2);
   end
endmodule

// -----------------------------------------------------------------------------
// Project:     WireGuard-FPGA
// Description: NLnet-funded open-source implementation
// Funding:     https://nlnet.nl/project/KlusterLab-Wireguard (2023-12 to 2025-12)
// -----------------------------------------------------------------------------
