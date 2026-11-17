// SPDX-FileCopyrightText: 2026 Chili.CHIPS
//
// Enhanced by Chili.CHIPS with NLnet-sponsored project
// wireguard-fpga (https://github.com/chili-chips/wireguard-fpga).
// The original header follows.

// Copyright (c) 2019 Alex Forencich
//
// SPDX-License-Identifier: MIT

// Language: Verilog 2001

`resetall
`default_nettype none

/*
 * MII PHY interface
 */
module mii_phy_if #(
    // target ("SIM", "GENERIC", "XILINX", "ALTERA")
    parameter TARGET            = "GENERIC",
    // Clock input style ("BUFG", "BUFR", "BUFIO", "BUFIO2")
    // Use BUFR for Virtex-5, Virtex-6, 7-series
    // Use BUFG for Ultrascale
    // Use BUFIO2 for Spartan-6
    parameter CLOCK_INPUT_STYLE = "BUFIO2"
) (
    input  logic       rst,

    /*
     * MII interface to MAC
     */
    output logic       mac_mii_rx_clk,
    output logic       mac_mii_rx_rst,
    output logic [3:0] mac_mii_rxd,
    output logic       mac_mii_rx_dv,
    output logic       mac_mii_rx_er,
    output logic       mac_mii_tx_clk,
    output logic       mac_mii_tx_rst,
    input  logic [3:0] mac_mii_txd,
    input  logic       mac_mii_tx_en,
    input  logic       mac_mii_tx_er,

    /*
     * MII interface to PHY
     */
    input  logic       phy_mii_rx_clk,
    input  logic [3:0] phy_mii_rxd,
    input  logic       phy_mii_rx_dv,
    input  logic       phy_mii_rx_er,
    input  logic       phy_mii_tx_clk,
    output logic [3:0] phy_mii_txd,
    output logic       phy_mii_tx_en,
    output logic       phy_mii_tx_er
);

  ssio_sdr_in #(
      .TARGET            (TARGET),
      .CLOCK_INPUT_STYLE (CLOCK_INPUT_STYLE),
      .WIDTH             (6)
  ) rx_ssio_sdr_inst (
      .input_clk  (phy_mii_rx_clk),
      .input_d    ({phy_mii_rxd, phy_mii_rx_dv, phy_mii_rx_er}),
      .output_clk (mac_mii_rx_clk),
      .output_q   ({mac_mii_rxd, mac_mii_rx_dv, mac_mii_rx_er})
  );

  (* IOB = "TRUE" *)
  logic [3:0] phy_mii_txd_reg = 4'd0;
  (* IOB = "TRUE" *)
  logic phy_mii_tx_en_reg = 1'b0, phy_mii_tx_er_reg = 1'b0;

  assign phy_mii_txd   = phy_mii_txd_reg;
  assign phy_mii_tx_en = phy_mii_tx_en_reg;
  assign phy_mii_tx_er = phy_mii_tx_er_reg;

  always_ff @(posedge mac_mii_tx_clk) begin
    phy_mii_txd_reg   <= mac_mii_txd;
    phy_mii_tx_en_reg <= mac_mii_tx_en;
    phy_mii_tx_er_reg <= mac_mii_tx_er;
  end

  generate

    if (TARGET == "XILINX") begin
      BUFG mii_bufg_inst (
          .I (phy_mii_tx_clk),
          .O (mac_mii_tx_clk)
      );
    end
    else begin
      assign mac_mii_tx_clk = phy_mii_tx_clk;
    end

  endgenerate

  // reset sync
  logic [3:0] tx_rst_reg = 4'hf;
  assign      mac_mii_tx_rst = tx_rst_reg[0];

  always_ff @(posedge mac_mii_tx_clk or posedge rst) begin
    if (rst) begin
      tx_rst_reg <= 4'hf;
    end
    else begin
      tx_rst_reg <= {1'b0, tx_rst_reg[3:1]};
    end
  end

  logic [3:0] rx_rst_reg = 4'hf;
  assign      mac_mii_rx_rst = rx_rst_reg[0];

  always_ff @(posedge mac_mii_rx_clk or posedge rst) begin
    if (rst) begin
      rx_rst_reg <= 4'hf;
    end
    else begin
      rx_rst_reg <= {1'b0, rx_rst_reg[3:1]};
    end
  end

endmodule

`resetall
