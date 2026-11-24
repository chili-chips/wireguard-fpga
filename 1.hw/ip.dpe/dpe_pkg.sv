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
//   Package with declaration commonly used across the entire DPE
//==========================================================================

`ifndef _DPE_PKG
`define _DPE_PKG
package dpe_pkg;
  // The widths of dpe_if, in one place: the interface, the blocks that use it
  // and the AXI-Stream modules they instantiate all take them from here
  localparam int DPE_DATA_BYTES = 16;                  // a beat: 16 bytes
  localparam int DPE_DATA_W     = 8 * DPE_DATA_BYTES;  // tdata, 128 bits
  localparam int DPE_KEEP_W     = DPE_DATA_BYTES;      // tkeep, a bit per byte
  localparam int DPE_ID_W       = 8;                   // tid, the peer index
  localparam int DPE_PORTS      = 5;                   // the CPU (address 0) and Ethernet 1 to 4

  typedef logic [7:0] byte_t;
  typedef logic [DPE_DATA_W-1:0] dpe_data_t;  // a beat
  typedef logic [DPE_KEEP_W-1:0] dpe_keep_t;
  typedef logic [DPE_ID_W-1:0] dpe_peer_idx_t;  // a WireGuard peer (tid)

  // A DPE port, or a group of them: where a packet comes from or goes
  typedef enum logic [2:0] {
    DPE_ADDR_CPU      = 3'h0,
    DPE_ADDR_ETH_1    = 3'h1,
    DPE_ADDR_ETH_2    = 3'h2,
    DPE_ADDR_ETH_3    = 3'h3,
    DPE_ADDR_ETH_4    = 3'h4,
    DPE_ADDR_MCAST_13 = 3'h5,  // ETH 1 and 3
    DPE_ADDR_MCAST_24 = 3'h6,  // ETH 2 and 4
    DPE_ADDR_BCAST    = 3'h7   // every port
  } dpe_addr_t;

  // AXI-Stream TUSER of the DPE: TUSER[7] bypass_all, [6] bypass_stage,
  // [5:3] src, [2:0] dst (the order of the fields)
  typedef struct packed {
    logic      bypass_all;    // [7]   skip the whole DPE
    logic      bypass_stage;  // [6]   skip the next DPE stage
    dpe_addr_t src;           // [5:3] where the packet came from
    dpe_addr_t dst;           // [2:0] where it goes
  } dpe_tuser_t;

  localparam int DPE_USER_W = $bits(dpe_tuser_t);  // tuser, 8 bits
endpackage : dpe_pkg
`endif

// -----------------------------------------------------------------------------
// Project:     WireGuard-FPGA
// Description: NLnet-funded open-source implementation
// Funding:     https://nlnet.nl/project/KlusterLab-Wireguard (2023-12 to 2025-12)
// -----------------------------------------------------------------------------
