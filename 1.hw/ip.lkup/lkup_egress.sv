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
//   Egress IP Lookup module for WireGuard Data Plane.
//
//   Functionality:
//   1. Control Plane: Acts as a bridge between the CSR interface and the internal
//      Routing Memory (`lkup_route_mem`). Handles address decoding/multiplexing
//      for writing and reading routing rules.
//
//   2. Data Plane: Parses incoming AXI Stream packets to extract the IPv4
//      Destination Address. Uses a store-and-forward mechanism (beat buffer)
//      to hold data while performing the routing table lookup.
//
//   3. Routing Action: Updates the outgoing AXI Stream sideband signals
//      (tuser_dst, tid/peer_idx) based on the lookup result, directing the
//      packet to the correct physical port and associating it with a Peer;
//      tuser.bypass_stage is the route's encrypt flag inverted, for the
//      encryptor after this stage. A frame that ends before its IPv4
//      destination does goes to the CPU, peer 0, not encrypted.
//==========================================================================


module lkup_egress
  import csr_pkg::*;
  import dpe_pkg::*;
  import net_pkg::*;
  import lkup_pkg::*;
#(
    parameter int ENTRY_COUNT = 64
) (
    dpe_if.s_axis   inp,
    dpe_if.m_axis   outp,
    output logic    idle,     // no frame in it

    // the CSR routing_table regfile (csr.rdl): one port for the whole table
    input  rt_cfg_t csr_cfg,
    output rt_sta_t csr_sta
);

  // -----------------------------------------------------------
  // CSR ACCESS: entry[addr[9:4]], its field at addr[3:2]
  // -----------------------------------------------------------
  typedef enum logic [1:0] {
    FIELD_PREFIX = 2'd0,  // entry.ip       (offset 0x0)
    FIELD_MASK   = 2'd1,  // entry.mask     (offset 0x4)
    FIELD_PEER   = 2'd2,  // entry.peer_idx (offset 0x8)
    FIELD_DST    = 2'd3   // entry.dst      (offset 0xC)
  } rt_field_t;

  localparam int ENTRY_W = $clog2(ENTRY_COUNT);  // 6: addr[9:4]

  logic csr_wr, csr_rd;
  logic      [       ENTRY_W-1:0] mem_idx;
  rt_field_t                      field;
  logic      [CSR_DATA_WIDTH-1:0] wr_data;

  assign csr_wr  = csr_cfg.req & csr_cfg.req_is_wr;
  assign csr_rd  = csr_cfg.req & ~csr_cfg.req_is_wr;
  assign mem_idx = csr_cfg.addr[ENTRY_W+3:4];
  assign field   = rt_field_t'(csr_cfg.addr[3:2]);
  assign wr_data = csr_cfg.wr_data;

  // the CPU writes one register of an entry: the fields it holds. The
  // peer_idx register has peer_idx in byte 0 and encrypt in byte 1 (bit 8),
  // each written with its byte lane
  route_we_t we;
  route_t wdata, rdata;
  assign we = '{
          prefix: csr_wr & (field == FIELD_PREFIX),
          mask: csr_wr & (field == FIELD_MASK),
          peer_idx: csr_wr & (field == FIELD_PEER) & csr_cfg.wr_biten[0],
          encrypt: csr_wr & (field == FIELD_PEER) & csr_cfg.wr_biten[8],
          dst: csr_wr & (field == FIELD_DST)
      };
  assign wdata = '{
          prefix: wr_data,
          mask: wr_data,
          act: '{
              peer_idx: dpe_peer_idx_t'(wr_data),
              encrypt: wr_data[8],
              dst: dpe_addr_t'(wr_data[$bits(dpe_addr_t)-1:0])
          }
      };

  // A write is done in its request's clock. A read answers one clock later:
  // lkup_route_mem registers the entry the request addresses (rdata)
  logic      rd_ack;
  rt_field_t rd_field;
  always_ff @(posedge inp.clk) begin
    if (inp.rst) begin
      rd_ack   <= 1'b0;
      rd_field <= FIELD_PREFIX;
    end
    else begin
      rd_ack <= csr_rd;
      if (csr_rd) begin
        rd_field <= field;
      end
    end
  end

  logic [CSR_DATA_WIDTH-1:0] rd_data;
  always_comb begin
    rd_data = '0;
    unique case (rd_field)
      FIELD_PREFIX: rd_data = rdata.prefix;
      FIELD_MASK:   rd_data = rdata.mask;
      FIELD_PEER:   rd_data = CSR_DATA_WIDTH'({rdata.act.encrypt, rdata.act.peer_idx});
      FIELD_DST:    rd_data = CSR_DATA_WIDTH'(rdata.act.dst);
      default:      rd_data = '0;
    endcase
  end
  assign csr_sta.wr_ack  = csr_wr;
  assign csr_sta.rd_ack  = rd_ack;
  assign csr_sta.rd_data = rd_data;

  route_act_t route;  // what the entry the lookup picks for route_req_ip does
  ipv4_addr_t route_req_ip;

  lkup_route_mem #(
      .ENTRY_COUNT (ENTRY_COUNT)
  ) u_mem (
      .clk (inp.clk),

      .waddr (mem_idx),
      .we    (we),
      .wdata (wdata),

      .raddr (mem_idx),
      .rdata (rdata),

      .req_ip        (route_req_ip),
      .rsp_hit       (  /*LINT:OK*/),  // a miss takes the defaults
      .rsp_route_idx (  /*LINT:OK*/),  // not needed: the entry comes with it
      .rsp           (route)
  );

  // --------------------------------------------------------------------------
  // 3. DATA PLANE LOGIC (Packet Processing FSM)
  // --------------------------------------------------------------------------

  typedef enum logic [2:0] {
    IDLE,
    COLLECT,
    DECIDE,
    SRC,      // a decrypted packet: is its inner source its peer's?
    DROP,     // no: drop it
    FLUSH,
    FWD
  } state_t;
  state_t state, state_next;

  // the beats buffered before the decision: up to the IPv4 destination's
  localparam int BUF_BEATS = beat_of(IPV4_DST_OFFSET + 2) + 1;  // 3
  typedef logic [$clog2(BUF_BEATS)-1:0] buf_idx_t;

  buf_idx_t in_beat;
  // the beats that hold the IPv4 destination: its bytes 0, 1, then 2, 3
  localparam buf_idx_t DA_HI_BEAT = buf_idx_t'(beat_of(IPV4_DST_OFFSET));      // 1
  localparam buf_idx_t DA_LO_BEAT = buf_idx_t'(beat_of(IPV4_DST_OFFSET + 2));  // 2

  // the frame's own tuser fields, from its first beat
  dpe_addr_t     frame_src;
  logic          frame_bypass_all;
  logic          da_ok;  // the frame holds its whole IPv4 destination
  logic          ipv4;  // EtherType IPv4: anything else takes the default route
  // decrypted: it came out of the decryptor (bypass_stage clear), from peer
  // from_peer (tid: the entry's peer tag, the entry that peer's routes
  // point at, also for its next or old session); its inner source must be
  // one that peer may use
  logic          decrypted;
  dpe_peer_idx_t from_peer;
  ipv4_addr_t    src_ip;
  logic          last_in;  // the frame's last beat is in the buffer

  typedef struct packed {
    dpe_data_t data;  // [144:17]
    dpe_keep_t keep;  // [16:1]
    logic      last;  // [0]
  } buf_beat_t;

  buf_beat_t beat_buf   [BUF_BEATS];  // the buffered beats (no reset)
  logic      beat_valid [BUF_BEATS];  // which of them hold a beat
  buf_idx_t  buf_rd_ptr;

  route_act_t decided, decided_next;  // what happens to the frame

  buf_idx_t flush_limit, flush_limit_next;

  logic  in_hs;
  assign in_hs = inp.tvalid & inp.tready;

  always_comb begin
    unique case (state)
      IDLE, COLLECT:      inp.tready = 1'b1;
      DECIDE, SRC, FLUSH: inp.tready = 1'b0;
      DROP:               inp.tready = ~last_in;
      FWD:                inp.tready = outp.tready;
      default:            inp.tready = 1'b0;
    endcase
  end

  always_comb begin
    state_next       = state;
    decided_next     = decided;
    flush_limit_next = flush_limit;

    unique case (state)
      IDLE: begin
        if (in_hs) begin
          if (inp.tuser.bypass_all) begin
            decided_next = '{
                peer_idx: inp.tid,
                encrypt: ~inp.tuser.bypass_stage,
                dst: inp.tuser.dst
            };
            flush_limit_next = '0;
            state_next = FLUSH;
          end
          else if (inp.tlast) begin
            // no IPv4 destination in it: the lookup takes what there is
            flush_limit_next = '0;
            state_next       = DECIDE;
          end
          else begin
            state_next = COLLECT;
          end
        end
      end

      // the IPv4 destination: bytes 0, 1 in beat 1, bytes 2, 3 in beat 2; a frame
      // that ends before is decided at its end
      COLLECT: begin
        if (in_hs && (in_beat == DA_LO_BEAT || inp.tlast)) begin
          flush_limit_next = in_beat;
          state_next       = DECIDE;
        end
      end

      DECIDE: begin
        // the encryptor after this stage: through the tunnel only when the
        // route says so (the routing entry's encrypt flag). A frame that ends
        // before its IPv4 destination does takes the defaults: to the CPU,
        // never into the tunnel
        // Not IPv4 (ARP, ...): the defaults as well
        decided_next = (da_ok & ipv4) ? route : ROUTE_DEFAULT;
        state_next   = (decrypted & da_ok & ipv4) ? SRC : FLUSH;
      end

      // route now answers for the inner source (route_req_ip, loaded in
      // S_DECIDE): through the tunnel from that peer, or the packet goes
      // (WireGuard's AllowedIPs)
      SRC: begin
        state_next = (route.encrypt & (route.peer_idx == from_peer)) ? FLUSH : DROP;
      end

      DROP: begin
        if (last_in || (in_hs && inp.tlast)) begin
          state_next = IDLE;
        end
      end

      FLUSH: begin
        if (outp.tready && beat_valid[buf_rd_ptr]) begin
          if (beat_buf[buf_rd_ptr].last) begin
            state_next = IDLE;
          end
          else if (buf_rd_ptr == flush_limit) begin
            state_next = FWD;
          end
        end
      end

      FWD: begin
        if (in_hs && inp.tlast) begin
          state_next = IDLE;
        end
      end

      default: begin
        state_next = state;
      end

    endcase
  end

  always_ff @(posedge inp.clk) begin
    if (inp.rst) begin
      state      <= IDLE;
      in_beat    <= '0;
      buf_rd_ptr <= '0;
      for (int i = 0; i < BUF_BEATS; i++) begin
        beat_valid[i] <= 1'b0;
      end
      decided          <= ROUTE_DEFAULT;
      route_req_ip     <= '0;
      flush_limit      <= '0;
      frame_src        <= DPE_ADDR_CPU;
      frame_bypass_all <= 1'b0;
      da_ok            <= 1'b0;
      ipv4             <= 1'b0;
      decrypted        <= 1'b0;
      from_peer        <= '0;
      src_ip           <= '0;
      last_in          <= 1'b0;
    end
    else begin
      state       <= state_next;
      flush_limit <= flush_limit_next;

      if (state == IDLE && in_hs) begin
        frame_src        <= inp.tuser.src;
        frame_bypass_all <= inp.tuser.bypass_all;
        da_ok            <= 1'b0;
        ipv4             <= be16(inp.tdata, ETH_TYPE_OFFSET) == ETHERTYPE_IPV4;
        decrypted        <= ~inp.tuser.bypass_all & ~inp.tuser.bypass_stage;
        from_peer        <= inp.tid;
      end

      if ((state == IDLE || state == COLLECT) && in_hs) begin
        last_in <= inp.tlast;
      end
      if (state == DECIDE) begin
        route_req_ip <= src_ip;  // the next lookup: the inner source
      end

      if (state == IDLE) begin
        if (in_hs && !inp.tuser.bypass_all) begin
          in_beat <= buf_idx_t'(1);
        end
        else begin
          in_beat <= '0;
        end
      end
      else if (state == COLLECT && in_hs) begin
        in_beat <= in_beat + buf_idx_t'(1);
      end
      else if (state == FWD && in_hs && inp.tlast) begin
        in_beat <= '0;
      end

      if (state == IDLE && in_hs) begin
        beat_valid[0] <= 1'b1;
      end

      if (state == COLLECT && in_hs) begin
        beat_valid[in_beat] <= 1'b1;

        if (in_beat == DA_HI_BEAT) begin
          route_req_ip[31:16] <= be16(inp.tdata, IPV4_DST_OFFSET);
          src_ip <= {be16(inp.tdata, IPV4_SRC_OFFSET), be16(inp.tdata, IPV4_SRC_OFFSET + 2)};
        end
        if (in_beat == DA_LO_BEAT) begin
          route_req_ip[15:0] <= be16(inp.tdata, IPV4_DST_OFFSET + 2);
          da_ok              <= inp.tkeep[(IPV4_DST_OFFSET+3)%BEAT_BYTES];
        end
      end

      // (FLUSH)
      if (state == FLUSH && outp.tready && beat_valid[buf_rd_ptr]) begin
        beat_valid[buf_rd_ptr] <= 1'b0;
        if (!beat_buf[buf_rd_ptr].last && (buf_rd_ptr < flush_limit)) begin
          buf_rd_ptr <= buf_rd_ptr + buf_idx_t'(1);
        end
        else begin
          buf_rd_ptr <= '0;
        end
      end

      // Buffer reset after IDLE
      if (state_next == IDLE) begin
        for (int i = 0; i < BUF_BEATS; i++) begin
          beat_valid[i] <= 1'b0;
        end
        buf_rd_ptr <= '0;
      end

      decided <= decided_next;
    end
  end

  // The buffered beats' data: no reset value (only their valid flags above),
  // and held while in reset, as before
  always_ff @(posedge inp.clk) begin
    if (!inp.rst && state == IDLE && in_hs) begin
      beat_buf[0].data <= inp.tdata;
      beat_buf[0].keep <= inp.tkeep;
      beat_buf[0].last <= inp.tlast;
    end
    if (!inp.rst && state == COLLECT && in_hs) begin
      beat_buf[in_beat].data <= inp.tdata;
      beat_buf[in_beat].keep <= inp.tkeep;
      beat_buf[in_beat].last <= inp.tlast;
    end
  end


  dpe_data_t flush_tdata;
  dpe_keep_t flush_tkeep;
  logic      flush_tlast;
  logic      flush_tvalid;

  assign flush_tdata = beat_buf[buf_rd_ptr].data;
  assign flush_tkeep = beat_buf[buf_rd_ptr].keep;
  assign flush_tlast = beat_buf[buf_rd_ptr].last;
  assign flush_tvalid = (state == FLUSH) & beat_valid[buf_rd_ptr];

  assign outp.tvalid = (state == FLUSH) ? flush_tvalid : (state == FWD) ? inp.tvalid : 1'b0;
  assign outp.tdata = (state == FLUSH) ? flush_tdata : (state == FWD) ? inp.tdata : '0;
  assign outp.tkeep = (state == FLUSH) ? flush_tkeep : (state == FWD) ? inp.tkeep : '0;
  assign outp.tlast = (state == FLUSH) ? flush_tlast : (state == FWD) ? inp.tlast : 1'b0;

  // the encryptor after this stage takes bypass_stage: clear to encrypt
  assign outp.tuser = '{
          bypass_all: frame_bypass_all,
          bypass_stage: ~decided.encrypt,
          src: frame_src,
          dst: decided.dst
      };
  assign outp.tid = decided.peer_idx;
  assign idle = state == IDLE;

endmodule

/*
-----------------------------------------------------------------------------
Version History:
-----------------------------------------------------------------------------
 2025/12/7 IV: original creation
*/

// -----------------------------------------------------------------------------
// Project:     WireGuard-FPGA
// Description: NLnet-funded open-source implementation
// Funding:     https://nlnet.nl/project/KlusterLab-Wireguard (2023-12 to 2025-12)
// -----------------------------------------------------------------------------
