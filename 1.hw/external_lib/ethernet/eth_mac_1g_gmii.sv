// SPDX-FileCopyrightText: 2026 Chili.CHIPS
//
// Enhanced by Chili.CHIPS with NLnet-sponsored project
// wireguard-fpga (https://github.com/chili-chips/wireguard-fpga).
// The original header follows.

// Copyright (c) 2015-2018 Alex Forencich
//
// SPDX-License-Identifier: MIT

// Language: Verilog 2001

`resetall
`default_nettype none

/*
 * 1G Ethernet MAC with GMII interface
 */
module eth_mac_1g_gmii #(
    // target ("SIM", "GENERIC", "XILINX", "ALTERA")
    parameter TARGET            = "GENERIC",
    // IODDR style ("IODDR", "IODDR2")
    // Use IODDR for Virtex-4, Virtex-5, Virtex-6, 7 Series, Ultrascale
    // Use IODDR2 for Spartan-6
    parameter IODDR_STYLE       = "IODDR2",
    // Clock input style ("BUFG", "BUFR", "BUFIO", "BUFIO2")
    // Use BUFR for Virtex-5, Virtex-6, 7-series
    // Use BUFG for Ultrascale
    // Use BUFIO2 for Spartan-6
    parameter CLOCK_INPUT_STYLE = "BUFIO2",
    parameter ENABLE_PADDING    = 1,
    parameter MIN_FRAME_LENGTH  = 64
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
    output logic       tx_error_underflow,
    output logic       rx_error_bad_frame,
    output logic       rx_error_bad_fcs,
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

  logic [1:0] speed_reg = 2'b10;
  logic       mii_select_reg = 1'b0;

  (* srl_style = "register" *)
  logic [1:0] tx_mii_select_sync = 2'd0;

  always_ff @(posedge tx_clk) begin
    tx_mii_select_sync <= {tx_mii_select_sync[0], mii_select_reg};
  end

  (* srl_style = "register" *)
  logic [1:0] rx_mii_select_sync = 2'd0;

  always_ff @(posedge rx_clk) begin
    rx_mii_select_sync <= {rx_mii_select_sync[0], mii_select_reg};
  end

  // PHY speed detection
  logic [2:0] rx_prescale = 3'd0;

  always_ff @(posedge rx_clk) begin
    rx_prescale <= rx_prescale + 3'd1;
  end

  (* srl_style = "register" *)
  logic [2:0] rx_prescale_sync = 3'd0;

  always_ff @(posedge gtx_clk) begin
    rx_prescale_sync <= {rx_prescale_sync[1:0], rx_prescale[2]};
  end

  logic [6:0] rx_speed_count_1 = 0;
  logic [1:0] rx_speed_count_2 = 0;

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
        // verilator lint_off WIDTHTRUNC
        if (rx_speed_count_1[6:5]) begin
          // verilator lint_on WIDTHTRUNC
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

  gmii_phy_if #(
      .TARGET            (TARGET),
      .IODDR_STYLE       (IODDR_STYLE),
      .CLOCK_INPUT_STYLE (CLOCK_INPUT_STYLE)
  ) gmii_phy_if_inst (
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
      .tx_clk                         (tx_clk),
      .tx_rst                         (tx_rst),
      .rx_clk                         (rx_clk),
      .rx_rst                         (rx_rst),
      .tx_axis_tdata                  (tx_axis_tdata),
      .tx_axis_tvalid                 (tx_axis_tvalid),
      .tx_axis_tready                 (tx_axis_tready),
      .tx_axis_tlast                  (tx_axis_tlast),
      .tx_axis_tuser                  (tx_axis_tuser),
      .rx_axis_tdata                  (rx_axis_tdata),
      .rx_axis_tvalid                 (rx_axis_tvalid),
      .rx_axis_tlast                  (rx_axis_tlast),
      .rx_axis_tuser                  (rx_axis_tuser),
      .gmii_rxd                       (mac_gmii_rxd),
      .gmii_rx_dv                     (mac_gmii_rx_dv),
      .gmii_rx_er                     (mac_gmii_rx_er),
      .gmii_txd                       (mac_gmii_txd),
      .gmii_tx_en                     (mac_gmii_tx_en),
      .gmii_tx_er                     (mac_gmii_tx_er),
      .rx_clk_enable                  (1'b1),
      .tx_clk_enable                  (1'b1),
      .rx_mii_select                  (rx_mii_select_sync[1]),
      .tx_mii_select                  (tx_mii_select_sync[1]),
      .tx_error_underflow             (tx_error_underflow),
      .rx_error_bad_frame             (rx_error_bad_frame),
      .rx_error_bad_fcs               (rx_error_bad_fcs),
      .cfg_ifg                        (cfg_ifg),
      .cfg_tx_enable                  (cfg_tx_enable),
      .cfg_rx_enable                  (cfg_rx_enable),
      .tx_ptp_ts                      (),
      .rx_ptp_ts                      (),
      .tx_axis_ptp_ts                 (),
      .tx_axis_ptp_ts_tag             (),
      .tx_axis_ptp_ts_valid           (),
      .tx_lfc_req                     (),
      .tx_lfc_resend                  (),
      .rx_lfc_en                      (),
      .rx_lfc_req                     (),
      .rx_lfc_ack                     (),
      .tx_pfc_req                     (),
      .tx_pfc_resend                  (),
      .rx_pfc_en                      (),
      .rx_pfc_req                     (),
      .rx_pfc_ack                     (),
      .tx_lfc_pause_en                (),
      .tx_pause_req                   (),
      .tx_pause_ack                   (),
      .tx_start_packet                (),
      .rx_start_packet                (),
      .stat_tx_mcf                    (),
      .stat_rx_mcf                    (),
      .stat_tx_lfc_pkt                (),
      .stat_tx_lfc_xon                (),
      .stat_tx_lfc_xoff               (),
      .stat_tx_lfc_paused             (),
      .stat_tx_pfc_pkt                (),
      .stat_tx_pfc_xon                (),
      .stat_tx_pfc_xoff               (),
      .stat_tx_pfc_paused             (),
      .stat_rx_lfc_pkt                (),
      .stat_rx_lfc_xon                (),
      .stat_rx_lfc_xoff               (),
      .stat_rx_lfc_paused             (),
      .stat_rx_pfc_pkt                (),
      .stat_rx_pfc_xon                (),
      .stat_rx_pfc_xoff               (),
      .stat_rx_pfc_paused             (),
      .cfg_mcf_rx_eth_dst_mcast       (),
      .cfg_mcf_rx_check_eth_dst_mcast (),
      .cfg_mcf_rx_eth_dst_ucast       (),
      .cfg_mcf_rx_check_eth_dst_ucast (),
      .cfg_mcf_rx_eth_src             (),
      .cfg_mcf_rx_check_eth_src       (),
      .cfg_mcf_rx_eth_type            (),
      .cfg_mcf_rx_opcode_lfc          (),
      .cfg_mcf_rx_check_opcode_lfc    (),
      .cfg_mcf_rx_opcode_pfc          (),
      .cfg_mcf_rx_check_opcode_pfc    (),
      .cfg_mcf_rx_forward             (),
      .cfg_mcf_rx_enable              (),
      .cfg_tx_lfc_eth_dst             (),
      .cfg_tx_lfc_eth_src             (),
      .cfg_tx_lfc_eth_type            (),
      .cfg_tx_lfc_opcode              (),
      .cfg_tx_lfc_en                  (),
      .cfg_tx_lfc_quanta              (),
      .cfg_tx_lfc_refresh             (),
      .cfg_tx_pfc_eth_dst             (),
      .cfg_tx_pfc_eth_src             (),
      .cfg_tx_pfc_eth_type            (),
      .cfg_tx_pfc_opcode              (),
      .cfg_tx_pfc_en                  (),
      .cfg_tx_pfc_quanta              (),
      .cfg_tx_pfc_refresh             (),
      .cfg_rx_lfc_opcode              (),
      .cfg_rx_lfc_en                  (),
      .cfg_rx_pfc_opcode              (),
      .cfg_rx_pfc_en                  ()
  );

endmodule

`resetall
