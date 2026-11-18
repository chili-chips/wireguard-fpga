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
//   DPE WireGuard Disassembler: finds the WireGuard data packets and their
//   peer, for the decryptor.
//
//   It parses each packet's headers (net_pkg) as it comes in: Ethernet II
//   with IPv4, protocol UDP, WireGuard type 4 (transport data), and the
//   receiver index. The receiver index goes out on wg_rcv; the lookup
//   answers combinationally from it with wg_idx_match and the peer, wg_idx,
//   sampled one clock later. The packet waits in a buffer until then, so
//   its first beat goes out with the answer:
//     - a WireGuard data packet of a known peer: tid = wg_idx, bypass_stage
//       clear (the decryptor takes the peer from tid);
//     - any other packet: bypass_stage set (the decryptor passes it on);
//     - a packet that comes in with bypass_all or bypass_stage: unchanged.
//   The data is never changed.
//
//  inp ---+------------------------------> data FIFO ----+--> outp
//         |                                (8 beats)     |   (tid, tuser
//         '--> parser --> wg_rcv --> lookup               |    from the
//                |                     |                  |    decision)
//                '-------> decision FIFO <-- wg_idx_match, wg_idx
//==========================================================================

module dpe_wg_disassembler
  import dpe_pkg::*;
  import net_pkg::*;
(
    output logic          fcr_idle,      // no packet in the disassembler
    output wg_receiver_t  wg_rcv,        // receiver index of the packet just parsed
    input  dpe_peer_idx_t wg_idx,        // its peer (lookup, combinational on wg_rcv)
    input  logic          wg_idx_match,  // the lookup knows that receiver index
    dpe_if.s_axis         inp,
    dpe_if.m_axis         outp
);
  // The parser looks at beats 0 to HDR_LAST_BEAT: the last one holds the end
  // of the receiver index (the counter is not needed here)
  localparam int HDR_LAST_BEAT = beat_of(WG_RECEIVER_OFFSET + 3);  // 3
  localparam int FIFO_BEATS = 8;  // more than the header's beats: no deadlock
  localparam int DEC_DEPTH = 16;  // a decision for every packet the data FIFO can hold

  logic  in_hs;
  assign in_hs = inp.tvalid & inp.tready;

  //------------------------------------------------------------------
  // Parser: one check per header beat, as the beats come in
  logic [ 1:0] in_beat;  // beat number in the packet, held at HDR_LAST_BEAT
  logic        decided;  // this packet's decision is made
  logic        hdr_ok;  // every check so far passed
  logic        pass_on;  // came in with bypass_all or bypass_stage: no change
  logic [15:0] rcv_lo;  // receiver index, the bytes in beat 2

  logic        beat_ok;  // the check of this beat
  always_comb begin
    beat_ok = 1'b1;
    unique case (in_beat)
      2'(beat_of(
          ETH_TYPE_OFFSET
      )):
      beat_ok = be16(inp.tdata, ETH_TYPE_OFFSET) == ETHERTYPE_IPV4 &&
          byte_at(inp.tdata, IPV4_VER_IHL_OFFSET) >> 4 == 8'(IPV4_VERSION);
      2'(beat_of(
          IPV4_PROTO_OFFSET
      )):
      beat_ok = byte_at(inp.tdata, IPV4_PROTO_OFFSET) == IP_PROTO_UDP;
      2'(beat_of(WG_TYPE_OFFSET)): beat_ok = le32(inp.tdata, WG_TYPE_OFFSET) == WG_TYPE_DATA;
      default: beat_ok = 1'b1;
    endcase
  end

  // This beat completes the packet's header (or the packet ends before)
  logic  decide, is_wg, first_pass_on;
  assign first_pass_on = inp.tuser.bypass_all | inp.tuser.bypass_stage;
  assign decide        = in_hs & ~decided & ((in_beat == 2'(HDR_LAST_BEAT)) | inp.tlast);
  assign is_wg         = (in_beat == 2'(HDR_LAST_BEAT)) & hdr_ok & beat_ok & ~pass_on;

  always_ff @(posedge inp.clk) begin
    if (inp.rst) begin
      in_beat <= '0;
      decided <= 1'b0;
      hdr_ok  <= 1'b0;
      pass_on <= 1'b0;
      rcv_lo  <= '0;
    end
    else if (in_hs) begin
      if (inp.tlast) begin
        in_beat <= '0;
        decided <= 1'b0;
      end
      else begin
        if (in_beat != 2'(HDR_LAST_BEAT)) begin
          in_beat <= in_beat + 2'd1;
        end
        if (decide) begin
          decided <= 1'b1;
        end
      end
      hdr_ok <= (in_beat == '0) ? beat_ok : hdr_ok & beat_ok;
      if (in_beat == '0) begin
        pass_on <= first_pass_on;
      end
      if (in_beat == 2'(beat_of(WG_RECEIVER_OFFSET))) begin
        rcv_lo <= le16(inp.tdata, WG_RECEIVER_OFFSET);
      end
    end
  end

  //------------------------------------------------------------------
  // Lookup: wg_rcv registered at the decision, its answer a clock later
  logic dec_pending;  // a decision waits for the lookup's answer
  logic dec_is_wg;  // ... of a WireGuard data packet
  logic dec_pass_on;  // ... of a packet to pass on unchanged

  always_ff @(posedge inp.clk) begin
    if (inp.rst) begin
      dec_pending <= 1'b0;
      dec_is_wg   <= 1'b0;
      dec_pass_on <= 1'b0;
      wg_rcv      <= '0;
    end
    else begin
      dec_pending <= decide;
      if (decide) begin
        dec_is_wg   <= is_wg;
        dec_pass_on <= (in_beat == '0) ? first_pass_on : pass_on;
        if (is_wg) begin
          wg_rcv <= {le16(inp.tdata, WG_RECEIVER_OFFSET + 2), rcv_lo};
        end
      end
    end
  end

  //------------------------------------------------------------------
  // Decision FIFO: one entry per packet, in packet order
  typedef struct packed {
    logic          to_peer;  // tid = peer, bypass_stage clear
    logic          pass_on;  // unchanged
    dpe_peer_idx_t peer;
  } decision_t;

  decision_t dec_mem[DEC_DEPTH];
  logic [$clog2(DEC_DEPTH):0] dec_wr, dec_rd;  // one bit more: full and empty
  logic dec_avail, dec_pop;
  decision_t dec;

  assign dec_avail = dec_wr != dec_rd;
  assign dec       = dec_mem[dec_rd[$clog2(DEC_DEPTH)-1:0]];

  always_ff @(posedge inp.clk) begin
    if (dec_pending) begin
      dec_mem[dec_wr[$clog2(DEC_DEPTH)-1:0]] <=
          '{to_peer: dec_is_wg & wg_idx_match & !dec_pass_on, pass_on: dec_pass_on, peer: wg_idx};
    end
  end

  always_ff @(posedge inp.clk) begin
    if (inp.rst) begin
      dec_wr <= '0;
      dec_rd <= '0;
    end
    else begin
      if (dec_pending) begin
        dec_wr <= dec_wr + 1'b1;
      end
      if (dec_pop) begin
        dec_rd <= dec_rd + 1'b1;
      end
    end
  end

  //------------------------------------------------------------------
  // Data FIFO: the packet waits for its decision
  dpe_if buffered (
      .clk (inp.clk),
      .rst (inp.rst)
  );

  axis_fifo #(
      .DEPTH (FIFO_BEATS * DPE_DATA_BYTES)  // bytes
  ) u_fifo (
      .s_axis              (inp),
      .m_axis              (buffered),
      .pause_req           (1'b0),
      .pause_ack           (  /*LINT:OK*/),  // no pause
      .status_depth        (  /*LINT:OK*/),  // status not used
      .status_depth_commit (  /*LINT:OK*/),  // status not used
      .status_overflow     (  /*LINT:OK*/),  // status not used
      .status_bad_frame    (  /*LINT:OK*/),  // status not used
      .status_good_frame   (  /*LINT:OK*/)   // status not used
  );

  //------------------------------------------------------------------
  // Output: each beat with its packet's decision
  assign outp.tvalid     = buffered.tvalid & dec_avail;
  assign buffered.tready = outp.tready & dec_avail;
  assign dec_pop         = outp.tvalid & outp.tready & buffered.tlast;

  assign outp.tdata      = buffered.tdata;
  assign outp.tkeep      = buffered.tkeep;
  assign outp.tlast      = buffered.tlast;

  always_comb begin
    outp.tuser = buffered.tuser;
    outp.tid   = buffered.tid;
    if (!dec.pass_on) begin
      outp.tuser.bypass_stage = !dec.to_peer;
      if (dec.to_peer) begin
        outp.tid = dec.peer;
      end
    end
  end

  assign fcr_idle = ~buffered.tvalid & ~dec_avail & ~dec_pending & (in_beat == '0);
endmodule

// -----------------------------------------------------------------------------
// Project:     WireGuard-FPGA
// Description: NLnet-funded open-source implementation
// Funding:     https://nlnet.nl/project/KlusterLab-Wireguard (2023-12 to 2025-12)
// -----------------------------------------------------------------------------
