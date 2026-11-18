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
//   Stores IPv4 routing rules (Prefix, Mask) and actions (Destination, Peer,
//   Encrypt): one route_t (lkup_pkg) per entry.
//
//   Architecture:
//   - Implements a TCAM-like structure for parallel IP lookup.
//   - Uses a Priority Encoder logic (First Match Wins).
//   - Relies on software/driver to sort entries by Longest Prefix Match (LPM),
//     where the most specific route is at Index 0.
//==========================================================================

module lkup_route_mem
  import dpe_pkg::*;
  import lkup_pkg::*;
#(
    parameter int         ENTRY_COUNT = 64,
    parameter int         ROUTE_IDX_W = $clog2(ENTRY_COUNT),
    parameter route_act_t DEFAULT     = ROUTE_DEFAULT         // no entry matches
) (
    input  logic                         clk,
    // Write Interface: the fields of entry waddr that we selects
    input  logic       [ROUTE_IDX_W-1:0] waddr,
    input  route_we_t                    we,
    input  route_t                       wdata,

    // Read Interface: entry raddr, a clock later
    input  logic       [ROUTE_IDX_W-1:0] raddr,
    output route_t                       rdata,

    // Lookup Interface: the first entry that matches req_ip
    input  logic       [           31:0] req_ip,
    output logic                         rsp_hit,
    output logic       [ROUTE_IDX_W-1:0] rsp_route_idx,
    output route_act_t                   rsp             // what it does
);

  route_t routes[ENTRY_COUNT];

  // ---------------------------
  // WRITE LOGIC
  // ---------------------------
  always_ff @(posedge clk) begin
    if (we.prefix) begin
      routes[waddr].prefix <= wdata.prefix;
    end
    if (we.mask) begin
      routes[waddr].mask <= wdata.mask;
    end
    if (we.peer_idx) begin
      routes[waddr].act.peer_idx <= wdata.act.peer_idx;
    end
    if (we.encrypt) begin
      routes[waddr].act.encrypt <= wdata.act.encrypt;
    end
    if (we.dst) begin
      routes[waddr].act.dst <= wdata.act.dst;
    end
  end

  // ---------------------------
  // READ LOGIC
  // ---------------------------
  always_ff @(posedge clk) begin
    rdata <= routes[raddr];
  end

  // ---------------------------
  // LOOKUP LOGIC (Priority Encoder)
  // ---------------------------
  logic [ENTRY_COUNT-1:0] hit_vec;

  for (genvar k = 0; k < ENTRY_COUNT; k++) begin : g_cam_match
    assign hit_vec[k] = ((req_ip & routes[k].mask) == (routes[k].prefix & routes[k].mask));
  end

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

  assign rsp_hit       = hit_found;
  assign rsp_route_idx = hit_found ? best_idx             : '0;
  assign rsp           = hit_found ? routes[best_idx].act : DEFAULT;

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
