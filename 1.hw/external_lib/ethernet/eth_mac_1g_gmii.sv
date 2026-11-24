// SPDX-FileCopyrightText: 2026 Chili.CHIPS
//
// Enhanced by Chili.CHIPS with NLnet-sponsored project
// wireguard-fpga (https://github.com/chili-chips/wireguard-fpga).
// The original header follows.

// Copyright (c) 2015-2018 Alex Forencich
//
// SPDX-License-Identifier: MIT

// Language: Verilog 2001

/*
 * 1G Ethernet MAC with GMII interface
 */
module eth_mac_1g_gmii #(
    parameter bit ENABLE_PADDING   = 1,
    parameter int MIN_FRAME_LENGTH = 64
) (
    input  logic       gtx_clk,
    input  logic       gtx_rst,
    output logic       rx_clk,
    output logic       rx_rst,
    output logic       tx_clk,
    output logic       tx_rst,

    /*
     * AXI input
     */
    input  logic [7:0] tx_axis_tdata,
    input  logic       tx_axis_tvalid,
    output logic       tx_axis_tready,
    input  logic       tx_axis_tlast,
    input  logic       tx_axis_tuser,

    /*
     * AXI output
     */
    output logic [7:0] rx_axis_tdata,
    output logic       rx_axis_tvalid,
    output logic       rx_axis_tlast,
    output logic       rx_axis_tuser,

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

  logic [7:0] mac_gmii_rxd;
  logic       mac_gmii_rx_dv;
  logic       mac_gmii_rx_er;
  logic [7:0] mac_gmii_txd;
  logic       mac_gmii_tx_en;
  logic       mac_gmii_tx_er;

  logic [1:0] speed_reg;
  logic       mii_select_reg;

  (* srl_style = "register" *)
  logic [1:0] tx_mii_select_sync;

  always_ff @(posedge tx_clk) begin
    if (tx_rst) begin
      tx_mii_select_sync <= '0;
    end
    else begin
      tx_mii_select_sync <= {tx_mii_select_sync[0], mii_select_reg};
    end
  end

  (* srl_style = "register" *)
  logic [1:0] rx_mii_select_sync;

  always_ff @(posedge rx_clk) begin
    if (rx_rst) begin
      rx_mii_select_sync <= '0;
    end
    else begin
      rx_mii_select_sync <= {rx_mii_select_sync[0], mii_select_reg};
    end
  end

  // PHY speed detection
  logic [2:0] rx_prescale;

  always_ff @(posedge rx_clk) begin
    if (rx_rst) begin
      rx_prescale <= '0;
    end
    else begin
      rx_prescale <= rx_prescale + 3'd1;
    end
  end

  (* srl_style = "register" *)
  logic [2:0] rx_prescale_sync;

  always_ff @(posedge gtx_clk) begin
    if (gtx_rst) begin
      rx_prescale_sync <= '0;
    end
    else begin
      rx_prescale_sync <= {rx_prescale_sync[1:0], rx_prescale[2]};
    end
  end

  logic [6:0] rx_speed_count_1;
  logic [1:0] rx_speed_count_2;

  always_ff @(posedge gtx_clk) begin
    if (gtx_rst) begin
      rx_speed_count_1 <= 0;
      rx_speed_count_2 <= 0;
      speed_reg        <= 2'b10;
      mii_select_reg   <= 1'b0;
    end
    else begin
      rx_speed_count_1 <= rx_speed_count_1 + 1;

      if (rx_prescale_sync[1] ^ rx_prescale_sync[2]) begin
        rx_speed_count_2 <= rx_speed_count_2 + 1;
      end

      if (&rx_speed_count_1) begin
        // reference count overflow - 10M
        rx_speed_count_1 <= 0;
        rx_speed_count_2 <= 0;
        speed_reg        <= 2'b00;
        mii_select_reg   <= 1'b1;
      end

      if (&rx_speed_count_2) begin
        // prescaled count overflow - 100M or 1000M
        rx_speed_count_1 <= 0;
        rx_speed_count_2 <= 0;
        if (rx_speed_count_1[6:5] != 0) begin
          // large reference count - 100M
          speed_reg      <= 2'b01;
          mii_select_reg <= 1'b1;
        end
        else begin
          // small reference count - 1000M
          speed_reg      <= 2'b10;
          mii_select_reg <= 1'b0;
        end
      end
    end
  end

  assign speed = speed_reg;

  gmii_phy_if gmii_phy_if_inst (
      .clk (gtx_clk),
      .rst (gtx_rst),

      .mac_gmii_rx_clk (rx_clk),
      .mac_gmii_rx_rst (rx_rst),
      .mac_gmii_rxd    (mac_gmii_rxd),
      .mac_gmii_rx_dv  (mac_gmii_rx_dv),
      .mac_gmii_rx_er  (mac_gmii_rx_er),
      .mac_gmii_tx_clk (tx_clk),
      .mac_gmii_tx_rst (tx_rst),
      .mac_gmii_txd    (mac_gmii_txd),
      .mac_gmii_tx_en  (mac_gmii_tx_en),
      .mac_gmii_tx_er  (mac_gmii_tx_er),

      .phy_gmii_rx_clk (gmii_rx_clk),
      .phy_gmii_rxd    (gmii_rxd),
      .phy_gmii_rx_dv  (gmii_rx_dv),
      .phy_gmii_rx_er  (gmii_rx_er),
      .phy_mii_tx_clk  (mii_tx_clk),
      .phy_gmii_tx_clk (gmii_tx_clk),
      .phy_gmii_txd    (gmii_txd),
      .phy_gmii_tx_en  (gmii_tx_en),
      .phy_gmii_tx_er  (gmii_tx_er),

      .mii_select (mii_select_reg)
  );

  eth_mac_1g #(
      .ENABLE_PADDING   (ENABLE_PADDING),
      .MIN_FRAME_LENGTH (MIN_FRAME_LENGTH)
  ) eth_mac_1g_inst (
      .tx_clk         (tx_clk),
      .tx_rst         (tx_rst),
      .rx_clk         (rx_clk),
      .rx_rst         (rx_rst),
      .tx_axis_tdata  (tx_axis_tdata),
      .tx_axis_tvalid (tx_axis_tvalid),
      .tx_axis_tready (tx_axis_tready),
      .tx_axis_tlast  (tx_axis_tlast),
      .tx_axis_tuser  (tx_axis_tuser),
      .rx_axis_tdata  (rx_axis_tdata),
      .rx_axis_tvalid (rx_axis_tvalid),
      .rx_axis_tlast  (rx_axis_tlast),
      .rx_axis_tuser  (rx_axis_tuser),
      .gmii_rxd       (mac_gmii_rxd),
      .gmii_rx_dv     (mac_gmii_rx_dv),
      .gmii_rx_er     (mac_gmii_rx_er),
      .gmii_txd       (mac_gmii_txd),
      .gmii_tx_en     (mac_gmii_tx_en),
      .gmii_tx_er     (mac_gmii_tx_er),
      .rx_mii_select  (rx_mii_select_sync[1]),
      .tx_mii_select  (tx_mii_select_sync[1]),
      .cfg_ifg        (cfg_ifg),
      .cfg_tx_enable  (cfg_tx_enable),
      .cfg_rx_enable  (cfg_rx_enable)
  );

endmodule

