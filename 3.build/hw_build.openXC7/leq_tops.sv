// SPDX-FileCopyrightText: 2026 Chili.CHIPS
//
// SPDX-License-Identifier: BSD-3-Clause

//==========================================================================
// run-leq.sh: the DPE blocks that 1.hw/top.filelist does not instantiate
// yet, each a top of its own, so the LEQ covers the whole design. A top
// cannot have an interface port: each wrapper takes the dpe_if signals as
// plain ports and builds the interfaces inside.
// run-leq.sh defines LEQ_TOP_<top> for the one it proves: a wrapper whose
// block does not compile yet stops only its own run.
//==========================================================================

// the ports of a dpe_if sink (s_axis) or source (m_axis) named n
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
`define LEQ_PEER_PORTS(key) \
    output logic         fcr_idle, \
    output logic [  7:0] ram_peer_idx, \
    input  logic [ 47:0] ram_local_mac, \
    input  logic [ 31:0] ram_local_ip, \
    input  logic [ 15:0] ram_local_port, \
    input  logic [ 47:0] ram_remote_mac, \
    input  logic [ 31:0] ram_remote_ip, \
    input  logic [ 15:0] ram_remote_port, \
    input  logic [ 31:0] ram_remote_id, \
    input  logic [255:0] key, \
    input  logic [ 63:0] ram_send_cnt, \
    output logic [ 63:0] ram_new_send_cnt, \
    output logic         ram_update_send_cnt

`ifdef LEQ_TOP_leq_dpe_wg_encryptor
module leq_dpe_wg_encryptor (
    input logic clk,
    input logic rst,
    `LEQ_DPE_S(inp),
    `LEQ_DPE_M(outp),
    `LEQ_PEER_PORTS(ram_encrypt_key)
);
  `LEQ_DPE_S_IF(inp)
  `LEQ_DPE_M_IF(outp)
  dpe_wg_encryptor u_dut (.*);
endmodule
`endif

`ifdef LEQ_TOP_leq_dpe_wg_decryptor
module leq_dpe_wg_decryptor (
    input logic clk,
    input logic rst,
    `LEQ_DPE_S(inp),
    `LEQ_DPE_M(outp),
    `LEQ_PEER_PORTS(ram_decrypt_key)
);
  `LEQ_DPE_S_IF(inp)
  `LEQ_DPE_M_IF(outp)
  dpe_wg_decryptor u_dut (.*);
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
