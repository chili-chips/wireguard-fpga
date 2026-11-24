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
//   with IPv4 (no options), protocol UDP to wg_ip:wg_port (this device's
//   address and listen port, CSR; anything else passes through), the
//   WireGuard message type, and the receiver index. The receiver index
//   goes out on wg_rcv; the peer table answers combinationally from it
//   with rcv_rsp (match, idx), sampled one clock later. The packet waits
//   in a buffer until then, so its first beat goes out with the answer:
//     - WireGuard data of a known receiver index: tid = its peer,
//       bypass_stage clear (the decryptor takes the peer from tid);
//     - a WireGuard handshake (types 1 to 3): bypass_all, dst CPU;
//     - WireGuard data of an unknown or stale index, or of no defined
//       type: dropped;
//     - any other packet: bypass_stage set (the decryptor passes it on);
//     - a packet that comes in with bypass_all or bypass_stage: unchanged.
//   The data is never changed.
//
//  inp ---+------------------------------> data FIFO ----+--> outp
//         |                                (8 beats)     |   (tid, tuser
//         '--> parser --> wg_rcv --> lookup               |    from the
//                |                     |                  |    decision)
//                '-------> decision FIFO <-- rcv_rsp (match, idx)
//==========================================================================

module dpe_wg_disassembler
  import dpe_pkg::*;
  import net_pkg::*;
(
    output logic         idle,     // no packet in the disassembler
    output wg_receiver_t wg_rcv,   // receiver index of the packet just parsed
    input  rcv_rsp_t     rcv_rsp,  // its peer (lookup, combinational on wg_rcv)
    input  ipv4_addr_t   wg_ip,    // this device's WireGuard address (CSR)
    input  udp_port_t    wg_port,  // the WireGuard UDP listen port (CSR)
    dpe_if.s_axis        inp,
    dpe_if.m_axis        outp
);
  // The parser looks at beats 0 to HDR_LAST_BEAT: the last one holds the end
  // of the receiver index (the counter is not needed here)
  localparam int HDR_LAST_BEAT = beat_of(WG_RECEIVER_OFFSET + 3);  // 3
  localparam int FIFO_BEATS = 8;  // more than the header's beats: no deadlock
  localparam int DCSN_DEPTH = 16;  // a decision for every packet the data FIFO can hold

  logic  in_hs;
  assign in_hs = inp.tvalid & inp.tready;

  //------------------------------------------------------------------
  // Parser: one check per header beat, as the beats come in
  logic [ 1:0] in_beat;  // beat number in the packet, held at HDR_LAST_BEAT
  logic        hdr_done;  // this packet's decision is made
  logic        hdr_ok;  // every check so far passed
  logic        keep_tuser;  // came in with bypass_all or bypass_stage: no change
  logic [15:0] rcv_lo;  // receiver index, the bytes in beat 2

  logic        beat_ok;  // the check of this beat
  always_comb begin
    beat_ok = 1'b1;
    unique case (in_beat)
      2'(beat_of(
          ETH_TYPE_OFFSET
      )):
      // IPv4 without options: the UDP and WireGuard offsets hold
          beat_ok = be16(inp.tdata, ETH_TYPE_OFFSET) == ETHERTYPE_IPV4 &
          byte_at(inp.tdata, IPV4_VER_IHL_OFFSET) == {IPV4_VERSION, 4'd5};
      2'(beat_of(
          IPV4_PROTO_OFFSET
      )):
      // UDP, to wg_ip (its upper half here, the lower half in the next beat)
          beat_ok = byte_at(inp.tdata, IPV4_PROTO_OFFSET) == IP_PROTO_UDP &
          be16(inp.tdata, IPV4_DST_OFFSET) == wg_ip[31:16];
      2'(beat_of(
          UDP_DST_PORT_OFFSET
      )):
      beat_ok = be16(inp.tdata, IPV4_DST_OFFSET + 2) == wg_ip[15:0] &
          be16(inp.tdata, UDP_DST_PORT_OFFSET) == wg_port;
      default: beat_ok = 1'b1;
    endcase
  end

  // This beat completes the packet's header (or the packet ends before)
  logic decide, is_wg, first_keep_tuser;
  logic [31:0] wg_type;  // the WireGuard message type, from its beat (below)
  logic        is_hs;  // a handshake message (types 1 to 3): for the CPU
  assign is_hs   = (in_beat == 2'(HDR_LAST_BEAT))
                 & hdr_ok
                 & beat_ok
                 & ~keep_tuser
                 & (wg_type >= 32'd1)
                 & (wg_type <= 32'd3);
  assign first_keep_tuser = inp.tuser.bypass_all | inp.tuser.bypass_stage;
  assign decide = in_hs & ~hdr_done & ((in_beat == 2'(HDR_LAST_BEAT)) | inp.tlast);
  // a WireGuard packet of another type (none is defined) is dropped as a bad one
  assign is_wg = (in_beat == 2'(HDR_LAST_BEAT)) & hdr_ok & beat_ok & ~keep_tuser & ~is_hs;

  always_ff @(posedge inp.clk) begin
    if (inp.rst) begin
      in_beat    <= '0;
      hdr_done   <= 1'b0;
      hdr_ok     <= 1'b0;
      keep_tuser <= 1'b0;
      rcv_lo     <= '0;
      wg_type    <= '0;
    end
    else if (in_hs) begin
      if (inp.tlast) begin
        in_beat  <= '0;
        hdr_done <= 1'b0;
      end
      else begin
        if (in_beat != 2'(HDR_LAST_BEAT)) begin
          in_beat <= in_beat + 2'd1;
        end
        if (decide) begin
          hdr_done <= 1'b1;
        end
      end
      hdr_ok <= (in_beat == '0) ? beat_ok : hdr_ok & beat_ok;
      if (in_beat == '0) begin
        keep_tuser <= first_keep_tuser;
      end
      if (in_beat == 2'(beat_of(WG_TYPE_OFFSET))) begin
        wg_type <= le32(inp.tdata, WG_TYPE_OFFSET);
      end
      if (in_beat == 2'(beat_of(WG_RECEIVER_OFFSET))) begin
        rcv_lo <= le16(inp.tdata, WG_RECEIVER_OFFSET);
      end
    end
  end

  //------------------------------------------------------------------
  // Lookup: wg_rcv registered at the decision, its answer a clock later
  logic dcsn_pending;  // a decision waits for the lookup's answer
  logic dcsn_is_wg;  // ... of a WireGuard data packet (or a bad WireGuard one)
  logic dcsn_is_data;  // ... and of type data
  logic dcsn_is_hs;  // ... of a WireGuard handshake: for the CPU
  logic dcsn_keep_tuser;  // ... of a packet to pass on unchanged

  always_ff @(posedge inp.clk) begin
    if (inp.rst) begin
      dcsn_pending    <= 1'b0;
      dcsn_is_wg      <= 1'b0;
      dcsn_is_data    <= 1'b0;
      dcsn_is_hs      <= 1'b0;
      dcsn_keep_tuser <= 1'b0;
      wg_rcv          <= '0;
    end
    else begin
      dcsn_pending <= decide;
      if (decide) begin
        dcsn_is_wg      <= is_wg;
        dcsn_is_data    <= wg_type == WG_TYPE_DATA;
        dcsn_is_hs      <= is_hs;
        dcsn_keep_tuser <= (in_beat == '0) ? first_keep_tuser : keep_tuser;
        if (is_wg) begin
          wg_rcv <= {le16(inp.tdata, WG_RECEIVER_OFFSET + 2), rcv_lo};
        end
      end
    end
  end

  //------------------------------------------------------------------
  // Decision FIFO: one entry per packet, in packet order
  typedef struct packed {
    logic          decrypt;     // [11]   tid = peer, bypass_stage clear
    logic          to_cpu;      // [10]   a handshake: bypass_all, to the CPU
    logic          drop;        // [9]    WireGuard data of an unknown receiver index, or bad
    logic          keep_tuser;  // [8]    unchanged
    dpe_peer_idx_t peer_idx;    // [7:0]
  } dcsn_t;

  dcsn_t dcsn_mem[DCSN_DEPTH];
  logic [$clog2(DCSN_DEPTH):0] dcsn_wr, dcsn_rd;  // one bit more: full and empty
  logic dcsn_avail, dcsn_pop;
  dcsn_t dcsn;

  assign dcsn_avail = dcsn_wr != dcsn_rd;
  assign dcsn       = dcsn_mem[dcsn_rd[$clog2(DCSN_DEPTH)-1:0]];

  always_ff @(posedge inp.clk) begin
    if (dcsn_pending) begin
      dcsn_mem[dcsn_wr[$clog2(
          DCSN_DEPTH
      )-1:0]] <=
      '{
          decrypt: dcsn_is_wg & dcsn_is_data & rcv_rsp.match & ~dcsn_keep_tuser,
          to_cpu: dcsn_is_hs & ~dcsn_keep_tuser,
          drop: dcsn_is_wg & ~(dcsn_is_data & rcv_rsp.match) & ~dcsn_keep_tuser,
          keep_tuser: dcsn_keep_tuser,
          peer_idx: rcv_rsp.idx
      };
    end
  end

  always_ff @(posedge inp.clk) begin
    if (inp.rst) begin
      dcsn_wr <= '0;
      dcsn_rd <= '0;
    end
    else begin
      if (dcsn_pending) begin
        dcsn_wr <= dcsn_wr + 1'b1;
      end
      if (dcsn_pop) begin
        dcsn_rd <= dcsn_rd + 1'b1;
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
      .s_axis (inp),
      .m_axis (buffered)
  );

  //------------------------------------------------------------------
  // Output: each beat with its packet's decision
  assign outp.tvalid     = buffered.tvalid & dcsn_avail & ~dcsn.drop;
  assign buffered.tready = (outp.tready | dcsn.drop) & dcsn_avail;
  assign dcsn_pop        = buffered.tvalid & buffered.tready & buffered.tlast;

  assign outp.tdata      = buffered.tdata;
  assign outp.tkeep      = buffered.tkeep;
  assign outp.tlast      = buffered.tlast;

  always_comb begin
    outp.tuser = buffered.tuser;
    outp.tid   = buffered.tid;
    if (dcsn.to_cpu) begin
      outp.tuser.bypass_all   = 1'b1;
      outp.tuser.bypass_stage = 1'b1;
      outp.tuser.dst          = DPE_ADDR_CPU;
    end
    else if (!dcsn.keep_tuser) begin
      outp.tuser.bypass_stage = ~dcsn.decrypt;
      if (dcsn.decrypt) begin
        outp.tid = dcsn.peer_idx;
      end
    end
  end

  assign idle = ~buffered.tvalid & ~dcsn_avail & ~dcsn_pending & (in_beat == '0);
endmodule

// -----------------------------------------------------------------------------
// Project:     WireGuard-FPGA
// Description: NLnet-funded open-source implementation
// Funding:     https://nlnet.nl/project/KlusterLab-Wireguard (2023-12 to 2025-12)
// -----------------------------------------------------------------------------
