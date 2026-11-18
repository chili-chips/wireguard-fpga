// SPDX-FileCopyrightText: 2026 Chili.CHIPS
//
// SPDX-License-Identifier: BSD-3-Clause

//==========================================================================
// run-leq.sh: the DPE blocks that 1.hw/top.filelist does not instantiate
// yet, each a top of its own, so the LEQ covers the whole design. A top
// cannot have an interface port: each wrapper takes a dpe_if as its
// handshake ports plus one struct (leq_beat_t, every forward signal) and
// builds the interface inside (leq_dpe_src, leq_dpe_snk).
// run-leq.sh defines LEQ_TOP_<top> for the one it proves: a wrapper whose
// block does not compile yet stops only its own run.
//==========================================================================

package leq_pkg;
  import dpe_pkg::*;

  // a dpe_if beat: the signals that go with tvalid
  typedef struct packed {
    dpe_data_t     tdata;
    logic          tlast;
    dpe_keep_t     tkeep;
    dpe_tuser_t    tuser;
    dpe_peer_idx_t tid;
  } leq_beat_t;
endpackage

// a dpe_if driven from top ports: the block's sink (s_axis) side
module leq_dpe_src
  import leq_pkg::*;
(
    input  logic      tvalid,
    output logic      tready,
    input  leq_beat_t beat,
    dpe_if.m_axis     axis
);
  assign axis.tvalid = tvalid;
  assign tready      = axis.tready;
  assign axis.tdata  = beat.tdata;
  assign axis.tlast  = beat.tlast;
  assign axis.tkeep  = beat.tkeep;
  assign axis.tuser  = beat.tuser;
  assign axis.tid    = beat.tid;
endmodule

// a dpe_if read out to top ports: the block's source (m_axis) side
module leq_dpe_snk
  import leq_pkg::*;
(
    dpe_if.s_axis     axis,
    output logic      tvalid,
    input  logic      tready,
    output leq_beat_t beat
);
  assign tvalid      = axis.tvalid;
  assign axis.tready = tready;
  assign beat        = '{
          tdata: axis.tdata,
          tlast: axis.tlast,
          tkeep: axis.tkeep,
          tuser: axis.tuser,
          tid: axis.tid
      };
endmodule

`ifdef LEQ_TOP_leq_dpe_wg_encryptor
module leq_dpe_wg_encryptor
  import dpe_pkg::*;
  import net_pkg::*;
  import leq_pkg::*;
(
    input  logic          clk,
    input  logic          rst,
    input  logic          inp_tvalid,
    output logic          inp_tready,
    input  leq_beat_t     inp_beat,
    output logic          outp_tvalid,
    input  logic          outp_tready,
    output leq_beat_t     outp_beat,
    output logic          fcr_idle,
    output dpe_peer_idx_t ram_peer_idx,
    input  wg_peer_cfg_t  ram_peer,
    output wg_counter_t   ram_new_send_cnt,
    output logic          ram_update_send_cnt
);
  dpe_if inp (.clk(clk), .rst(rst));
  dpe_if outp (.clk(clk), .rst(rst));
  leq_dpe_src u_inp (.tvalid(inp_tvalid), .tready(inp_tready), .beat(inp_beat), .axis(inp));
  leq_dpe_snk u_outp (.axis(outp), .tvalid(outp_tvalid), .tready(outp_tready), .beat(outp_beat));
  dpe_wg_encryptor u_dut (.*);
endmodule
`endif

`ifdef LEQ_TOP_leq_dpe_wg_decryptor
module leq_dpe_wg_decryptor
  import dpe_pkg::*;
  import net_pkg::*;
  import leq_pkg::*;
(
    input  logic          clk,
    input  logic          rst,
    input  logic          inp_tvalid,
    output logic          inp_tready,
    input  leq_beat_t     inp_beat,
    output logic          outp_tvalid,
    input  logic          outp_tready,
    output leq_beat_t     outp_beat,
    output logic          fcr_idle,
    output dpe_peer_idx_t ram_peer_idx,
    input  wg_peer_cfg_t  ram_peer,
    output wg_counter_t   ram_new_send_cnt,
    output logic          ram_update_send_cnt
);
  dpe_if inp (.clk(clk), .rst(rst));
  dpe_if outp (.clk(clk), .rst(rst));
  leq_dpe_src u_inp (.tvalid(inp_tvalid), .tready(inp_tready), .beat(inp_beat), .axis(inp));
  leq_dpe_snk u_outp (.axis(outp), .tvalid(outp_tvalid), .tready(outp_tready), .beat(outp_beat));
  dpe_wg_decryptor u_dut (.*);
endmodule
`endif

`ifdef LEQ_TOP_leq_egress_ip_lookup
module leq_egress_ip_lookup
  import dpe_pkg::*;
  import lkup_pkg::*;
  import leq_pkg::*;
(
    input  logic      clk,
    input  logic      rst,
    input  logic      s_axis_tvalid,
    output logic      s_axis_tready,
    input  leq_beat_t s_axis_beat,
    output logic      m_axis_tvalid,
    input  logic      m_axis_tready,
    output leq_beat_t m_axis_beat,
    input  csr_cfg_t  csr_cfg,
    output csr_sta_t  csr_sta
);
  dpe_if s_axis (.clk(clk), .rst(rst));
  dpe_if m_axis (.clk(clk), .rst(rst));
  leq_dpe_src u_s (
      .tvalid (s_axis_tvalid),
      .tready (s_axis_tready),
      .beat   (s_axis_beat),
      .axis   (s_axis)
  );
  leq_dpe_snk u_m (
      .axis   (m_axis),
      .tvalid (m_axis_tvalid),
      .tready (m_axis_tready),
      .beat   (m_axis_beat)
  );
  egress_ip_lookup #(.ENTRY_COUNT(64)) u_dut (.*);
endmodule
`endif

`ifdef LEQ_TOP_leq_dpe_wg_disassembler
module leq_dpe_wg_disassembler
  import dpe_pkg::*;
  import net_pkg::*;
  import leq_pkg::*;
(
    input  logic          clk,
    input  logic          rst,
    input  logic          inp_tvalid,
    output logic          inp_tready,
    input  leq_beat_t     inp_beat,
    output logic          outp_tvalid,
    input  logic          outp_tready,
    output leq_beat_t     outp_beat,
    output logic          fcr_idle,
    output wg_receiver_t  wg_rcv,
    input  dpe_peer_idx_t wg_idx,
    input  logic          wg_idx_match
);
  dpe_if inp (.clk(clk), .rst(rst));
  dpe_if outp (.clk(clk), .rst(rst));
  leq_dpe_src u_inp (.tvalid(inp_tvalid), .tready(inp_tready), .beat(inp_beat), .axis(inp));
  leq_dpe_snk u_outp (.axis(outp), .tvalid(outp_tvalid), .tready(outp_tready), .beat(outp_beat));
  dpe_wg_disassembler u_dut (.*);
endmodule
`endif

// -----------------------------------------------------------------------------
// Project:     WireGuard-FPGA
// Description: NLnet-funded open-source implementation
// Funding:     https://nlnet.nl/project/KlusterLab-Wireguard (2023-12 to 2025-12)
// -----------------------------------------------------------------------------
