// SPDX-FileCopyrightText: 2026 Chili.CHIPS
//
// Enhanced by Chili.CHIPS with NLnet-sponsored project
// wireguard-fpga (https://github.com/chili-chips/wireguard-fpga).
// The original header follows.

// Copyright (c) 2015-2018 Alex Forencich
//
// SPDX-License-Identifier: MIT

// Language: Verilog 2001 (AXIS ports: SystemVerilog dpe_if, by Chili.CHIPS)

/*
 * 1G Ethernet MAC with GMII interface and TX and RX FIFOs
 */
module eth_mac_1g_gmii_fifo
  import dpe_pkg::*;
#(
    parameter bit ENABLE_PADDING         = 1,
    parameter int MIN_FRAME_LENGTH       = 64,
    parameter int TX_FIFO_DEPTH          = 4096,
    parameter int TX_FIFO_RAM_PIPELINE   = 1,
    parameter int TX_FRAME_FIFO          = 1,
    parameter int TX_DROP_OVERSIZE_FRAME = TX_FRAME_FIFO,
    parameter int TX_DROP_BAD_FRAME      = TX_DROP_OVERSIZE_FRAME,
    parameter int TX_DROP_WHEN_FULL      = 0,
    parameter int RX_FIFO_DEPTH          = 4096,
    parameter int RX_FIFO_RAM_PIPELINE   = 1,
    parameter int RX_FRAME_FIFO          = 1,
    parameter int RX_DROP_OVERSIZE_FRAME = RX_FRAME_FIFO,
    parameter int RX_DROP_BAD_FRAME      = RX_DROP_OVERSIZE_FRAME,
    parameter int RX_DROP_WHEN_FULL      = RX_DROP_OVERSIZE_FRAME
) (
    input  logic       gtx_clk,
    input  logic       gtx_rst,
    // the DPE side, in the logic clock domain (tx_axis.clk)
    dpe_if.s_axis      tx_axis,
    dpe_if.m_axis      rx_axis,

    /*
     * GMII interface
     */
    input  logic       gmii_rx_clk,
    input  logic [7:0] gmii_rxd,
    input  logic       gmii_rx_dv,
    input  logic       gmii_rx_er,
    input  logic       mii_tx_clk,
    output logic       gmii_tx_clk,
    output logic [7:0] gmii_txd,
    output logic       gmii_tx_en,
    output logic       gmii_tx_er,

    /*
     * Status
     */
    output logic [1:0] speed,

    /*
     * Configuration
     */
    input  logic [7:0] cfg_ifg,
    input  logic       cfg_tx_enable,
    input  logic       cfg_rx_enable
);

  // Chili.CHIPS: the AXIS side is dpe_if, its widths from dpe_pkg; the body
  // below keeps its original port names, bound here to the interface ports
  localparam int AXIS_DATA_WIDTH  = DPE_DATA_W;
  localparam bit AXIS_KEEP_ENABLE = 1;
  localparam int AXIS_KEEP_WIDTH  = DPE_KEEP_W;

  logic  logic_clk;
  assign logic_clk = tx_axis.clk;
  logic  logic_rst;
  assign logic_rst = tx_axis.rst;

  logic [AXIS_DATA_WIDTH-1:0] tx_axis_tdata;
  assign                      tx_axis_tdata  = tx_axis.tdata;
  logic [AXIS_KEEP_WIDTH-1:0] tx_axis_tkeep;
  assign                      tx_axis_tkeep  = tx_axis.tkeep;
  logic                       tx_axis_tvalid;
  assign                      tx_axis_tvalid = tx_axis.tvalid;
  logic                       tx_axis_tready;
  logic                       tx_axis_tlast;
  assign                      tx_axis_tlast  = tx_axis.tlast;
  logic                       tx_axis_tuser;
  assign                      tx_axis_tuser  = 1'b0;  // no bad-frame marking
  assign                      tx_axis.tready = tx_axis_tready;

  logic [AXIS_DATA_WIDTH-1:0] rx_axis_tdata;
  logic [AXIS_KEEP_WIDTH-1:0] rx_axis_tkeep;
  logic                       rx_axis_tvalid;
  logic                       rx_axis_tready;
  assign                      rx_axis_tready = rx_axis.tready;
  logic                       rx_axis_tlast;
  logic                       rx_axis_tuser;  // the bad-frame flag is not used
  assign                      rx_axis.tdata  = rx_axis_tdata;
  assign                      rx_axis.tkeep  = rx_axis_tkeep;
  assign                      rx_axis.tvalid = rx_axis_tvalid;
  assign                      rx_axis.tlast  = rx_axis_tlast;
  assign                      rx_axis.tuser  = '0;  // no DPE routing yet: the multiplexer sets src
  assign                      rx_axis.tid    = '0;  // no peer yet

  logic       tx_clk;
  logic       rx_clk;
  logic       tx_rst;
  logic       rx_rst;

  logic [7:0] tx_fifo_axis_tdata;
  logic       tx_fifo_axis_tvalid;
  logic       tx_fifo_axis_tready;
  logic       tx_fifo_axis_tlast;
  logic       tx_fifo_axis_tuser;

  logic [7:0] rx_fifo_axis_tdata;
  logic       rx_fifo_axis_tvalid;
  logic       rx_fifo_axis_tlast;
  logic       rx_fifo_axis_tuser;

  logic [1:0] speed_int;

  logic [1:0] speed_sync_reg_1;
  logic [1:0] speed_sync_reg_2;

  assign speed = speed_sync_reg_2;

  // the link speed, synchronized: a select, reset to gigabit (as the MAC)
  always_ff @(posedge logic_clk) begin
    if (logic_rst) begin
      speed_sync_reg_1 <= 2'b10;
      speed_sync_reg_2 <= 2'b10;
    end
    else begin
      speed_sync_reg_1 <= speed_int;
      speed_sync_reg_2 <= speed_sync_reg_1;
    end
  end

  eth_mac_1g_gmii #(
      .ENABLE_PADDING   (ENABLE_PADDING),
      .MIN_FRAME_LENGTH (MIN_FRAME_LENGTH)
  ) eth_mac_1g_gmii_inst (
      .gtx_clk        (gtx_clk),
      .gtx_rst        (gtx_rst),
      .tx_clk         (tx_clk),
      .tx_rst         (tx_rst),
      .rx_clk         (rx_clk),
      .rx_rst         (rx_rst),
      .tx_axis_tdata  (tx_fifo_axis_tdata),
      .tx_axis_tvalid (tx_fifo_axis_tvalid),
      .tx_axis_tready (tx_fifo_axis_tready),
      .tx_axis_tlast  (tx_fifo_axis_tlast),
      .tx_axis_tuser  (tx_fifo_axis_tuser),
      .rx_axis_tdata  (rx_fifo_axis_tdata),
      .rx_axis_tvalid (rx_fifo_axis_tvalid),
      .rx_axis_tlast  (rx_fifo_axis_tlast),
      .rx_axis_tuser  (rx_fifo_axis_tuser),
      .gmii_rx_clk    (gmii_rx_clk),
      .gmii_rxd       (gmii_rxd),
      .gmii_rx_dv     (gmii_rx_dv),
      .gmii_rx_er     (gmii_rx_er),
      .gmii_tx_clk    (gmii_tx_clk),
      .mii_tx_clk     (mii_tx_clk),
      .gmii_txd       (gmii_txd),
      .gmii_tx_en     (gmii_tx_en),
      .gmii_tx_er     (gmii_tx_er),
      .speed          (speed_int),
      .cfg_ifg        (cfg_ifg),
      .cfg_tx_enable  (cfg_tx_enable),
      .cfg_rx_enable  (cfg_rx_enable)
  );

  axis_async_fifo_adapter #(
      .DEPTH                (TX_FIFO_DEPTH),
      .S_DATA_WIDTH         (AXIS_DATA_WIDTH),
      .S_KEEP_ENABLE        (AXIS_KEEP_ENABLE),
      .S_KEEP_WIDTH         (AXIS_KEEP_WIDTH),
      .M_DATA_WIDTH         (8),
      .M_KEEP_ENABLE        (0),
      .KEEP_AS_COUNT        (1),                       // frames: tkeep contiguous
      .USER_ENABLE          (1),
      .USER_WIDTH           (1),
      .RAM_PIPELINE         (TX_FIFO_RAM_PIPELINE),
      .FRAME_FIFO           (TX_FRAME_FIFO),
      .USER_BAD_FRAME_VALUE (1'b1),
      .USER_BAD_FRAME_MASK  (1'b1),
      .DROP_OVERSIZE_FRAME  (TX_DROP_OVERSIZE_FRAME),
      .DROP_BAD_FRAME       (TX_DROP_BAD_FRAME),
      .DROP_WHEN_FULL       (TX_DROP_WHEN_FULL)
  ) tx_fifo (
      // AXI input
      .s_clk         (logic_clk),
      .s_rst         (logic_rst),
      .s_axis_tdata  (tx_axis_tdata),
      .s_axis_tkeep  (tx_axis_tkeep),
      .s_axis_tvalid (tx_axis_tvalid),
      .s_axis_tready (tx_axis_tready),
      .s_axis_tlast  (tx_axis_tlast),
      .s_axis_tuser  (tx_axis_tuser),
      // AXI output
      .m_clk         (tx_clk),
      .m_rst         (tx_rst),
      .m_axis_tdata  (tx_fifo_axis_tdata),
      .m_axis_tkeep  (  /*LINT:OK*/),
      .m_axis_tvalid (tx_fifo_axis_tvalid),
      .m_axis_tready (tx_fifo_axis_tready),
      .m_axis_tlast  (tx_fifo_axis_tlast),
      .m_axis_tuser  (tx_fifo_axis_tuser)
  );

  axis_async_fifo_adapter #(
      .DEPTH                (RX_FIFO_DEPTH),
      .S_DATA_WIDTH         (8),
      .S_KEEP_ENABLE        (0),
      .M_DATA_WIDTH         (AXIS_DATA_WIDTH),
      .M_KEEP_ENABLE        (AXIS_KEEP_ENABLE),
      .M_KEEP_WIDTH         (AXIS_KEEP_WIDTH),
      .KEEP_AS_COUNT        (1),                       // frames: tkeep contiguous
      .USER_ENABLE          (1),
      .USER_WIDTH           (1),
      .RAM_PIPELINE         (RX_FIFO_RAM_PIPELINE),
      .FRAME_FIFO           (RX_FRAME_FIFO),
      .USER_BAD_FRAME_VALUE (1'b1),
      .USER_BAD_FRAME_MASK  (1'b1),
      .DROP_OVERSIZE_FRAME  (RX_DROP_OVERSIZE_FRAME),
      .DROP_BAD_FRAME       (RX_DROP_BAD_FRAME),
      .DROP_WHEN_FULL       (RX_DROP_WHEN_FULL)
  ) rx_fifo (
      // AXI input
      .s_clk         (rx_clk),
      .s_rst         (rx_rst),
      .s_axis_tdata  (rx_fifo_axis_tdata),
      .s_axis_tkeep  (1'b1),
      .s_axis_tvalid (rx_fifo_axis_tvalid),
      .s_axis_tready (  /*LINT:OK*/),
      .s_axis_tlast  (rx_fifo_axis_tlast),
      .s_axis_tuser  (rx_fifo_axis_tuser),
      // AXI output
      .m_clk         (logic_clk),
      .m_rst         (logic_rst),
      .m_axis_tdata  (rx_axis_tdata),
      .m_axis_tkeep  (rx_axis_tkeep),
      .m_axis_tvalid (rx_axis_tvalid),
      .m_axis_tready (rx_axis_tready),
      .m_axis_tlast  (rx_axis_tlast),
      .m_axis_tuser  (rx_axis_tuser)
  );

endmodule

