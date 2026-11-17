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
//   Data Plane Engine (DPE) Routing Memory (TCAM & RAM).
//   Stores IPv4 routing rules (Prefix, Mask) and actions (Destination, Peer).
//
//   Architecture:
//   - Implements a TCAM-like structure for parallel IP lookup.
//   - Uses a Priority Encoder logic (First Match Wins).
//   - Relies on software/driver to sort entries by Longest Prefix Match (LPM),
//     where the most specific route is at Index 0.
//==========================================================================

module dpe_route_mem
  import dpe_pkg::*;
#(
    parameter int            ENTRY_COUNT      = 64,
    parameter int            ROUTE_IDX_W      = $clog2(ENTRY_COUNT),
    parameter dpe_addr_t     DEFAULT_DST_PORT = DPE_ADDR_CPU,
    parameter dpe_peer_idx_t DEFAULT_PEER_IDX = '0
) (
    input  logic                            clk,
    // Write Interface
    input  logic          [ROUTE_IDX_W-1:0] waddr,
    input  logic                            we_prefix,
    input  logic          [           31:0] wdata_prefix,
    input  logic                            we_mask,
    input  logic          [           31:0] wdata_mask,
    input  logic                            we_peer,
    input  dpe_peer_idx_t                   wdata_peer,
    input  logic                            we_dst,
    input  dpe_addr_t                       wdata_dst,

    // Read Interface
    input  logic          [ROUTE_IDX_W-1:0] raddr,
    output logic          [           31:0] rdata_prefix,
    output logic          [           31:0] rdata_mask,
    output dpe_peer_idx_t                   rdata_peer,
    output dpe_addr_t                       rdata_dst,

    // Lookup Interface
    input  logic          [           31:0] req_ip,
    output logic                            resp_hit,
    output logic          [ROUTE_IDX_W-1:0] resp_route_idx,
    output dpe_addr_t                       resp_dst,
    output dpe_peer_idx_t                   resp_peer
);

  // Storage arrays
  logic          [31:0] cam_prefix[ENTRY_COUNT];
  logic          [31:0] cam_mask  [ENTRY_COUNT];


  dpe_addr_t            ram_dst   [ENTRY_COUNT];
  dpe_peer_idx_t        ram_peer  [ENTRY_COUNT];


  // ---------------------------
  // WRITE LOGIC
  // ---------------------------
  always_ff @(posedge clk) begin
    if (we_prefix) begin
      cam_prefix[waddr] <= wdata_prefix;
    end
    if (we_mask) begin
      cam_mask[waddr] <= wdata_mask;
    end
    if (we_peer) begin
      ram_peer[waddr] <= wdata_peer;
    end
    if (we_dst) begin
      ram_dst[waddr] <= wdata_dst;
    end
  end

  // ---------------------------
  // READ LOGIC
  // ---------------------------
  always_ff @(posedge clk) begin
    rdata_prefix <= cam_prefix[raddr];
    rdata_mask   <= cam_mask[raddr];
    rdata_peer   <= ram_peer[raddr];
    rdata_dst    <= ram_dst[raddr];
  end

  // ---------------------------
  // LOOKUP LOGIC (Priority Encoder)
  // ---------------------------
  logic [ENTRY_COUNT-1:0] hit_vec;

  genvar k;
  generate
    for (k = 0; k < ENTRY_COUNT; k++) begin : g_cam_match
      assign hit_vec[k] = ((req_ip & cam_mask[k]) == (cam_prefix[k] & cam_mask[k]));
    end
  endgenerate

  logic [ROUTE_IDX_W-1:0] best_idx;
  logic                   hit_found;

  always_comb begin
    best_idx  = '0;
    hit_found = 1'b0;

    for (int i = 0; i < ENTRY_COUNT; i++) begin
      if (hit_vec[i]) begin
        if (!hit_found) begin
          hit_found = 1'b1;
          best_idx  = i[ROUTE_IDX_W-1:0];
        end
      end
    end
  end

  assign resp_hit       = hit_found;
  assign resp_route_idx = hit_found ? best_idx : '0;

  assign resp_dst       = hit_found ? ram_dst[best_idx]  : DEFAULT_DST_PORT;
  assign resp_peer      = hit_found ? ram_peer[best_idx] : DEFAULT_PEER_IDX;

endmodule

/*
-----------------------------------------------------------------------------
Version History:
-----------------------------------------------------------------------------
 2025/12/7 IV: original creation
*/
