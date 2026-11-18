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
//      (tuser_dst, tid/peer_id) based on the lookup result, directing the
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
    dpe_if.s_axis    s_axis,
    dpe_if.m_axis    m_axis,

    // the CSR routing_table regfile (csr.rdl): one port for the whole table
    input  csr_cfg_t csr_cfg,
    output csr_sta_t csr_sta
);

  // -----------------------------------------------------------
  // CSR ACCESS: entry[addr[9:4]], its field at addr[3:2]
  // -----------------------------------------------------------
  typedef enum logic [1:0] {
    FIELD_IP   = 2'd0,  // entry.ip       (offset 0x0)
    FIELD_MASK = 2'd1,  // entry.mask     (offset 0x4)
    FIELD_PEER = 2'd2,  // entry.peer_idx (offset 0x8)
    FIELD_DST  = 2'd3   // entry.dst      (offset 0xC)
  } rt_field_e;

  logic csr_wr, csr_rd;
  logic      [ 5:0] mem_idx;
  rt_field_e        field;
  logic      [31:0] wr_data;

  assign csr_wr  = csr_cfg.req & csr_cfg.req_is_wr;
  assign csr_rd  = csr_cfg.req & ~csr_cfg.req_is_wr;
  assign mem_idx = csr_cfg.addr[9:4];
  assign field   = rt_field_e'(csr_cfg.addr[3:2]);
  assign wr_data = csr_cfg.wr_data;

  // the CPU writes one register of an entry: the fields it holds. The
  // peer_idx register has peer_idx in byte 0 and encrypt in byte 1 (bit 8),
  // each written with its byte lane
  route_we_t we;
  route_t wdata, rdata;
  assign we = '{
          prefix: csr_wr & (field == FIELD_IP),
          mask: csr_wr & (field == FIELD_MASK),
          peer: csr_wr & (field == FIELD_PEER) & csr_cfg.wr_biten[0],
          encrypt: csr_wr & (field == FIELD_PEER) & csr_cfg.wr_biten[8],
          dst: csr_wr & (field == FIELD_DST)
      };
  assign wdata = '{
          prefix: wr_data,
          mask: wr_data,
          act: '{
              peer: dpe_peer_idx_t'(wr_data),
              encrypt: wr_data[8],
              dst: dpe_addr_t'(wr_data[$bits(dpe_addr_t)-1:0])
          }
      };

  // A write is done in its request's clock. A read answers one clock later:
  // lkup_route_mem registers the entry the request addresses (rdata)
  logic      rd_ack;
  rt_field_e rd_field;
  always_ff @(posedge s_axis.clk) begin
    if (s_axis.rst) begin
      rd_ack   <= 1'b0;
      rd_field <= FIELD_IP;
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
    unique case (rd_field)
      FIELD_IP:   rd_data = rdata.prefix;
      FIELD_MASK: rd_data = rdata.mask;
      FIELD_PEER: rd_data = CSR_DATA_WIDTH'({rdata.act.encrypt, rdata.act.peer});
      FIELD_DST:  rd_data = CSR_DATA_WIDTH'(rdata.act.dst);
    endcase
  end
  assign csr_sta.wr_ack  = csr_wr;
  assign csr_sta.rd_ack  = rd_ack;
  assign csr_sta.rd_data = rd_data;

  route_act_t        route;  // what the entry the lookup picks for route_req_ip does
  logic       [31:0] route_req_ip;

  lkup_route_mem #(
      .ENTRY_COUNT (ENTRY_COUNT)
  ) u_mem (
      .clk (s_axis.clk),

      .waddr (mem_idx),
      .we    (we),
      .wdata (wdata),

      .raddr (mem_idx),
      .rdata (rdata),

      .req_ip         (route_req_ip),
      .resp_hit       (  /*LINT:OK*/),  // a miss takes the defaults
      .resp_route_idx (  /*LINT:OK*/),  // not needed: the entry comes with it
      .resp           (route)
  );

  // --------------------------------------------------------------------------
  // 3. DATA PLANE LOGIC (Packet Processing FSM)
  // --------------------------------------------------------------------------

  typedef enum logic [2:0] {
    S_IDLE,
    S_COLLECT,
    S_DECIDE,
    S_FLUSH,
    S_FWD
  } state_e;
  state_e state, state_next;

  logic [1:0] beat;
  // the beats that hold the IPv4 destination: its bytes 0, 1, then 2, 3
  localparam logic [1:0] DA_HI_BEAT = 2'(beat_of(IPV4_DST_OFFSET));      // 1
  localparam logic [1:0] DA_LO_BEAT = 2'(beat_of(IPV4_DST_OFFSET + 2));  // 2

  // the frame's own tuser fields, from its first beat
  dpe_addr_t frame_src;
  logic      frame_bypass_all;
  logic      da_ok;  // the frame holds its whole IPv4 destination

  typedef struct packed {
    dpe_data_t data;
    dpe_keep_t keep;
    logic      last;
  } beat_t;

  beat_t       beat_buf   [3];  // the buffered beats (no reset)
  logic        beat_valid [3];  // which of them hold a beat
  logic  [1:0] buf_rd_ptr;

  route_act_t decided, decided_n;  // what happens to the frame

  logic [1:0] flush_limit, flush_limit_n;

  logic  in_hs;
  assign in_hs = s_axis.tvalid & s_axis.tready;

  always_comb begin
    unique case (state)
      S_IDLE, S_COLLECT: s_axis.tready = 1'b1;
      S_DECIDE, S_FLUSH: s_axis.tready = 1'b0;
      S_FWD:             s_axis.tready = m_axis.tready;
      default:           s_axis.tready = 1'b0;
    endcase
  end

  always_comb begin
    state_next    = state;
    decided_n     = decided;
    flush_limit_n = flush_limit;

    unique case (state)
      S_IDLE: begin
        if (in_hs) begin
          if (s_axis.tuser.bypass_all) begin
            decided_n = '{
                peer: s_axis.tid,
                encrypt: ~s_axis.tuser.bypass_stage,
                dst: s_axis.tuser.dst
            };
            flush_limit_n = 2'd0;
            state_next = S_FLUSH;
          end
          else if (s_axis.tlast) begin
            // no IPv4 destination in it: the lookup takes what there is
            flush_limit_n = 2'd0;
            state_next    = S_DECIDE;
          end
          else begin
            state_next = S_COLLECT;
          end
        end
      end

      // the IPv4 destination: bytes 0, 1 in beat 1, bytes 2, 3 in beat 2; a frame
      // that ends before is decided at its end
      S_COLLECT: begin
        if (in_hs && (beat == DA_LO_BEAT || s_axis.tlast)) begin
          flush_limit_n = beat;
          state_next    = S_DECIDE;
        end
      end

      S_DECIDE: begin
        // the encryptor after this stage: through the tunnel only when the
        // route says so (the routing entry's encrypt flag). A frame that ends
        // before its IPv4 destination does takes the defaults: to the CPU,
        // never into the tunnel
        decided_n  = da_ok ? route : ROUTE_DEFAULT;
        state_next = S_FLUSH;
      end

      S_FLUSH: begin
        if (m_axis.tready && beat_valid[buf_rd_ptr]) begin
          if (beat_buf[buf_rd_ptr].last) begin
            state_next = S_IDLE;
          end
          else if (buf_rd_ptr == flush_limit) begin
            state_next = S_FWD;
          end
        end
      end

      S_FWD: begin
        if (in_hs && s_axis.tlast) begin
          state_next = S_IDLE;
        end
      end

      default: begin
        state_next = state;
      end

    endcase
  end

  always_ff @(posedge s_axis.clk) begin
    if (s_axis.rst) begin
      state            <= S_IDLE;
      beat             <= 2'd0;
      buf_rd_ptr       <= 2'd0;
      beat_valid[0]    <= 1'b0;
      beat_valid[1]    <= 1'b0;
      beat_valid[2]    <= 1'b0;
      decided          <= ROUTE_DEFAULT;
      route_req_ip     <= 32'd0;
      flush_limit      <= 2'd0;
      frame_src        <= DPE_ADDR_CPU;
      frame_bypass_all <= 1'b0;
      da_ok            <= 1'b0;
    end
    else begin
      state       <= state_next;
      flush_limit <= flush_limit_n;

      if (state == S_IDLE && in_hs) begin
        frame_src        <= s_axis.tuser.src;
        frame_bypass_all <= s_axis.tuser.bypass_all;
        da_ok            <= 1'b0;
      end

      if (state == S_IDLE) begin
        if (in_hs && !s_axis.tuser.bypass_all) begin
          beat <= 2'd1;
        end
        else begin
          beat <= 2'd0;
        end
      end
      else if (state == S_COLLECT && in_hs) begin
        beat <= beat + 2'd1;
      end
      else if (state == S_FWD && in_hs && s_axis.tlast) begin
        beat <= 2'd0;
      end

      if (state == S_IDLE && in_hs) begin
        beat_valid[0] <= 1'b1;
      end

      if (state == S_COLLECT && in_hs) begin
        beat_valid[beat] <= 1'b1;

        if (beat == DA_HI_BEAT) begin
          route_req_ip[31:16] <= be16(s_axis.tdata, IPV4_DST_OFFSET);
        end
        if (beat == DA_LO_BEAT) begin
          route_req_ip[15:0] <= be16(s_axis.tdata, IPV4_DST_OFFSET + 2);
          da_ok              <= s_axis.tkeep[(IPV4_DST_OFFSET+3)%BEAT_BYTES];
        end
      end

      // (FLUSH)
      if (state == S_FLUSH && m_axis.tready && beat_valid[buf_rd_ptr]) begin
        beat_valid[buf_rd_ptr] <= 1'b0;
        if (!beat_buf[buf_rd_ptr].last && (buf_rd_ptr < flush_limit)) begin
          buf_rd_ptr <= buf_rd_ptr + 2'd1;
        end
        else begin
          buf_rd_ptr <= 2'd0;
        end
      end

      // Buffer reset after IDLE
      if (state_next == S_IDLE) begin
        beat_valid[0] <= 1'b0;
        beat_valid[1] <= 1'b0;
        beat_valid[2] <= 1'b0;
        buf_rd_ptr    <= 2'd0;
      end

      decided <= decided_n;
    end
  end

  // The buffered beats' data: no reset value (only their valid flags above),
  // and held while in reset, as before
  always_ff @(posedge s_axis.clk) begin
    if (!s_axis.rst && state == S_IDLE && in_hs) begin
      beat_buf[0].data <= s_axis.tdata;
      beat_buf[0].keep <= s_axis.tkeep;
      beat_buf[0].last <= s_axis.tlast;
    end
    if (!s_axis.rst && state == S_COLLECT && in_hs) begin
      beat_buf[beat].data <= s_axis.tdata;
      beat_buf[beat].keep <= s_axis.tkeep;
      beat_buf[beat].last <= s_axis.tlast;
    end
  end


  dpe_data_t        flush_tdata;
  logic      [15:0] flush_tkeep;
  logic             flush_tlast;
  logic             flush_tvalid;

  assign flush_tdata = beat_buf[buf_rd_ptr].data;
  assign flush_tkeep = beat_buf[buf_rd_ptr].keep;
  assign flush_tlast = beat_buf[buf_rd_ptr].last;
  assign flush_tvalid = (state == S_FLUSH) & beat_valid[buf_rd_ptr];

  assign m_axis.tvalid = (state == S_FLUSH) ? flush_tvalid :
                         (state == S_FWD)   ? s_axis.tvalid : 1'b0;
  assign m_axis.tdata = (state == S_FLUSH) ? flush_tdata : (state == S_FWD) ? s_axis.tdata : '0;
  assign m_axis.tkeep = (state == S_FLUSH) ? flush_tkeep : (state == S_FWD) ? s_axis.tkeep : '0;
  assign m_axis.tlast = (state == S_FLUSH) ? flush_tlast : (state == S_FWD) ? s_axis.tlast : 1'b0;

  // the encryptor after this stage takes bypass_stage: clear to encrypt
  assign m_axis.tuser = '{
          bypass_all: frame_bypass_all,
          bypass_stage: ~decided.encrypt,
          src: frame_src,
          dst: decided.dst
      };
  assign m_axis.tid = decided.peer;

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
