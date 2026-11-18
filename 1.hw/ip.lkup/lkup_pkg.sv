// SPDX-FileCopyrightText: 2026 Chili.CHIPS
//
// SPDX-License-Identifier: BSD-3-Clause

//==========================================================================
// Wireguard-1GE FPGA * NLnet-sponsored open-source implementation
//--------------------------------------------------------------------------
// Description: the IP lookup engine's (ip.lkup) types. Its CSR port is the
//  routing_table regfile of csr.rdl (external): the generated structs by
//  short names, named from the lookup's side
//   - csr_cfg_t: CPU to table: request, write, address, data
//   - csr_sta_t: table to CPU: write and read acknowledge, read data
//  and the same for the cryptokey_table regfile (the peer table,
//  lkup_peer_table), ck_cfg_t and ck_sta_t, with its word map
//==========================================================================

package lkup_pkg;
  import csr_pkg::*;
  import dpe_pkg::*;

  // what a route does with a packet: to dst, for peer, through the tunnel
  // when encrypt is set
  typedef struct packed {
    dpe_peer_idx_t peer;     // [11:4]
    logic          encrypt;  // [   3]
    dpe_addr_t     dst;      // [ 2:0]
  } route_act_t;

  // a routing-table entry (csr.rdl routing_table.entry): a packet whose IPv4
  // destination matches prefix under mask gets act
  typedef struct packed {
    logic [31:0] prefix;  // [75:44]
    logic [31:0] mask;    // [43:12]
    route_act_t  act;     // [11: 0]
  } route_t;

  // a write enable per field: the CPU writes one field per access
  typedef struct packed {
    logic prefix;
    logic mask;
    logic peer;
    logic encrypt;
    logic dst;
  } route_we_t;

  // no route matches: to the CPU, as it is
  localparam route_act_t ROUTE_DEFAULT = '{peer: '0, encrypt: 1'b0, dst: DPE_ADDR_CPU};

  typedef csr__routing_table__external__out_t csr_cfg_t;
  typedef csr__routing_table__external__in_t csr_sta_t;

  typedef csr__cryptokey_table__external__out_t ck_cfg_t;
  typedef csr__cryptokey_table__external__in_t ck_sta_t;

  // the cryptokey table: 64 entries of 32 words (csr.rdl: 30 used, stride
  // 0x80), so a CSR address is {entry, word, 2'b00}
  localparam int CK_ENTRIES = 64;
  localparam int CK_ENTRY_W = $clog2(CK_ENTRIES);  // 6: addr[12:7]
  localparam int CK_WORDS   = 30;
  localparam int CK_WORD_W  = 5;                   // addr[6:2]

  // its words, in csr.rdl order
  typedef enum logic [CK_WORD_W-1:0] {
    CK_LOCAL_MAC_HI  = 5'd0,   // [15:0]: MAC bits 47:32
    CK_LOCAL_MAC_LO  = 5'd1,
    CK_LOCAL_IP      = 5'd2,
    CK_LOCAL_PORT    = 5'd3,   // [15:0]
    CK_LOCAL_ID      = 5'd4,   // our receiver index: random upper bits, the entry in [5:0]
    CK_REMOTE_MAC_HI = 5'd5,
    CK_REMOTE_MAC_LO = 5'd6,
    CK_REMOTE_IP     = 5'd7,
    CK_REMOTE_PORT   = 5'd8,
    CK_REMOTE_ID     = 5'd9,
    CK_ENC_KEY_0     = 5'd10,  // key bits 255:224, ... CK_ENC_KEY_0 + 7: bits 31:0
    CK_DEC_KEY_0     = 5'd18,
    CK_SEND_CNT_HI   = 5'd26,
    CK_SEND_CNT_LO   = 5'd27,
    CK_RECV_CNT_HI   = 5'd28,
    CK_RECV_CNT_LO   = 5'd29
  } ck_word_e;

endpackage

// -----------------------------------------------------------------------------
// Project:     WireGuard-FPGA
// Description: NLnet-funded open-source implementation
// Funding:     https://nlnet.nl/project/KlusterLab-Wireguard (2023-12 to 2025-12)
// -----------------------------------------------------------------------------
