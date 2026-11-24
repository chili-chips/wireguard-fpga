// SPDX-FileCopyrightText: 2026 Chili.CHIPS
//
// Enhanced by Chili.CHIPS with NLnet-sponsored project
// wireguard-fpga (https://github.com/chili-chips/wireguard-fpga).
// The original header follows.

// Copyright (c) 2015-2023 Alex Forencich
//
// SPDX-License-Identifier: MIT

// Language: Verilog 2001

/*
 * 1G Ethernet MAC
 */
module eth_mac_1g #(
    parameter int DATA_WIDTH       = 8,
    parameter bit ENABLE_PADDING   = 1,
    parameter int MIN_FRAME_LENGTH = 64
) (
    input  logic                  rx_clk,
    input  logic                  rx_rst,
    input  logic                  tx_clk,
    input  logic                  tx_rst,

    /*
     * AXI input
     */
    input  logic [DATA_WIDTH-1:0] tx_axis_tdata,
    input  logic                  tx_axis_tvalid,
    output logic                  tx_axis_tready,
    input  logic                  tx_axis_tlast,
    input  logic                  tx_axis_tuser,

    /*
     * AXI output
     */
    output logic [DATA_WIDTH-1:0] rx_axis_tdata,
    output logic                  rx_axis_tvalid,
    output logic                  rx_axis_tlast,
    output logic                  rx_axis_tuser,

    /*
     * GMII interface
     */
    input  logic [DATA_WIDTH-1:0] gmii_rxd,
    input  logic                  gmii_rx_dv,
    input  logic                  gmii_rx_er,
    output logic [DATA_WIDTH-1:0] gmii_txd,
    output logic                  gmii_tx_en,
    output logic                  gmii_tx_er,

    /*
     * Control
     */
    input  logic                  rx_mii_select,
    input  logic                  tx_mii_select,

    /*
     * Configuration
     */
    input  logic [7:0]            cfg_ifg,
    input  logic                  cfg_tx_enable,
    input  logic                  cfg_rx_enable
);

  axis_gmii_rx #(
      .DATA_WIDTH (DATA_WIDTH)
  ) axis_gmii_rx_inst (
      .clk           (rx_clk),
      .rst           (rx_rst),
      .gmii_rxd      (gmii_rxd),
      .gmii_rx_dv    (gmii_rx_dv),
      .gmii_rx_er    (gmii_rx_er),
      .m_axis_tdata  (rx_axis_tdata),
      .m_axis_tvalid (rx_axis_tvalid),
      .m_axis_tlast  (rx_axis_tlast),
      .m_axis_tuser  (rx_axis_tuser),
      .mii_select    (rx_mii_select),
      .cfg_rx_enable (cfg_rx_enable)
  );

  axis_gmii_tx #(
      .DATA_WIDTH       (DATA_WIDTH),
      .ENABLE_PADDING   (ENABLE_PADDING),
      .MIN_FRAME_LENGTH (MIN_FRAME_LENGTH)
  ) axis_gmii_tx_inst (
      .clk           (tx_clk),
      .rst           (tx_rst),
      .s_axis_tdata  (tx_axis_tdata),
      .s_axis_tvalid (tx_axis_tvalid),
      .s_axis_tready (tx_axis_tready),
      .s_axis_tlast  (tx_axis_tlast),
      .s_axis_tuser  (tx_axis_tuser),
      .gmii_txd      (gmii_txd),
      .gmii_tx_en    (gmii_tx_en),
      .gmii_tx_er    (gmii_tx_er),
      .mii_select    (tx_mii_select),
      .cfg_ifg       (cfg_ifg),
      .cfg_tx_enable (cfg_tx_enable)
  );

endmodule

