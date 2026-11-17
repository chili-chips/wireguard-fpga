// SPDX-FileCopyrightText: 2026 Chili.CHIPS
//
// SPDX-License-Identifier: BSD-3-Clause

// Gold-side LEQ wrappers for commit 1e2e322 (wg_peer_cfg_t ports, 8-bit
// wg_idx): the top ports of ../leq_tops.sv, adapted to the old blocks'
// nine routing-table ports and 7-bit wg_idx. Proof, gold = bbfec39:
//   LEQ_TOPS_GOLD=leq_gold/leq_tops.1e2e322.sv bash run-leq.sh <bbfec39 1.hw> <1e2e322 1.hw>
// The decryptor needs its 512-deep output FIFO set to 16 on both sides
// (the solver stops at the large memory); the encryptor and disassembler
// differ only in the intended remote_mac reset and wg_idx bit 7.

`define LEQ_DPE_S(n) \
    input  logic                n``_tvalid, \
    output logic                n``_tready, \
    input  logic [127:0]        n``_tdata, \
    input  logic                n``_tlast, \
    input  logic [ 15:0]        n``_tkeep, \
    input  dpe_pkg::dpe_tuser_t n``_tuser, \
    input  logic [  7:0]        n``_tid
`define LEQ_DPE_M(n) \
    output logic                n``_tvalid, \
    input  logic                n``_tready, \
    output logic [127:0]        n``_tdata, \
    output logic                n``_tlast, \
    output logic [ 15:0]        n``_tkeep, \
    output dpe_pkg::dpe_tuser_t n``_tuser, \
    output logic [  7:0]        n``_tid
// the dpe_if named n, driven from those ports
`define LEQ_DPE_S_IF(n) \
  dpe_if n (.clk(clk), .rst(rst)); \
  assign n.tvalid   = n``_tvalid; \
  assign n``_tready = n.tready; \
  assign n.tdata    = n``_tdata; \
  assign n.tlast    = n``_tlast; \
  assign n.tkeep    = n``_tkeep; \
  assign n.tuser    = n``_tuser; \
  assign n.tid      = n``_tid;
`define LEQ_DPE_M_IF(n) \
  dpe_if n (.clk(clk), .rst(rst)); \
  assign n``_tvalid = n.tvalid; \
  assign n.tready   = n``_tready; \
  assign n``_tdata  = n.tdata; \
  assign n``_tlast  = n.tlast; \
  assign n``_tkeep  = n.tkeep; \
  assign n``_tuser  = n.tuser; \
  assign n``_tid    = n.tid;

// the peer table ports of the encryptor and the decryptor
`define LEQ_PEER_PORTS \
    output logic          fcr_idle, \
    output dpe_peer_idx_t ram_peer_idx, \
    input  wg_peer_cfg_t  ram_peer, \
    output wg_counter_t   ram_new_send_cnt, \
    output logic          ram_update_send_cnt

`ifdef LEQ_TOP_leq_dpe_wg_encryptor
module leq_dpe_wg_encryptor
  import dpe_pkg::*;
  import net_pkg::*;
(
    input logic clk,
    input logic rst,
    `LEQ_DPE_S(inp),
    `LEQ_DPE_M(outp),
    `LEQ_PEER_PORTS
);
  `LEQ_DPE_S_IF(inp)
  `LEQ_DPE_M_IF(outp)
  dpe_wg_encryptor u_dut (
      .ram_local_mac(ram_peer.local_mac),
      .ram_local_ip(ram_peer.local_ip),
      .ram_local_port(ram_peer.local_port),
      .ram_remote_mac(ram_peer.remote_mac),
      .ram_remote_ip(ram_peer.remote_ip),
      .ram_remote_port(ram_peer.remote_port),
      .ram_remote_id(ram_peer.remote_id),
      .ram_encrypt_key(ram_peer.key),
      .ram_send_cnt(ram_peer.send_cnt),
      .*
  );
endmodule
`endif

`ifdef LEQ_TOP_leq_dpe_wg_decryptor
module leq_dpe_wg_decryptor
  import dpe_pkg::*;
  import net_pkg::*;
(
    input logic clk,
    input logic rst,
    `LEQ_DPE_S(inp),
    `LEQ_DPE_M(outp),
    `LEQ_PEER_PORTS
);
  `LEQ_DPE_S_IF(inp)
  `LEQ_DPE_M_IF(outp)
  dpe_wg_decryptor u_dut (
      .ram_local_mac(ram_peer.local_mac),
      .ram_local_ip(ram_peer.local_ip),
      .ram_local_port(ram_peer.local_port),
      .ram_remote_mac(ram_peer.remote_mac),
      .ram_remote_ip(ram_peer.remote_ip),
      .ram_remote_port(ram_peer.remote_port),
      .ram_remote_id(ram_peer.remote_id),
      .ram_decrypt_key(ram_peer.key),
      .ram_send_cnt(ram_peer.send_cnt),
      .*
  );
endmodule
`endif

`ifdef LEQ_TOP_leq_dpe_egress_ip_lookup
module leq_dpe_egress_ip_lookup (
    input logic clk,
    input logic rst,
    `LEQ_DPE_S(s_axis),
    `LEQ_DPE_M(m_axis),
    input  csr_pkg::csr__routing_table__external__out_t hwif_out,
    output csr_pkg::csr__routing_table__external__in_t  hwif_in
);
  `LEQ_DPE_S_IF(s_axis)
  `LEQ_DPE_M_IF(m_axis)
  dpe_egress_ip_lookup #(.ENTRY_COUNT(64)) u_dut (.*);
endmodule
`endif

`ifdef LEQ_TOP_leq_dpe_wg_disassembler
module leq_dpe_wg_disassembler
  import dpe_pkg::*;
  import net_pkg::*;
(
    input logic clk,
    input logic rst,
    `LEQ_DPE_S(inp),
    `LEQ_DPE_M(outp),
    output logic          fcr_idle,
    output wg_receiver_t  wg_rcv,
    input  dpe_peer_idx_t wg_idx,
    input  logic          wg_idx_match
);
  `LEQ_DPE_S_IF(inp)
  `LEQ_DPE_M_IF(outp)
  dpe_wg_disassembler u_dut (
      .wg_idx(wg_idx[6:0]),  // gold: 7 bits
      .*
  );
endmodule
`endif

// -----------------------------------------------------------------------------
// Project:     WireGuard-FPGA
// Description: NLnet-funded open-source implementation
// Funding:     https://nlnet.nl/project/KlusterLab-Wireguard (2023-12 to 2025-12)
// -----------------------------------------------------------------------------
