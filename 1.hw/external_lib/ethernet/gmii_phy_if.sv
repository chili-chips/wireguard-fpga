// SPDX-FileCopyrightText: 2026 Chili.CHIPS
//
// Enhanced by Chili.CHIPS with NLnet-sponsored project
// wireguard-fpga (https://github.com/chili-chips/wireguard-fpga).
// The original header follows.

// verilator lint_off GENUNNAMED

// Copyright (c) 2015-2018 Alex Forencich
//
// SPDX-License-Identifier: MIT

// Language: Verilog 2001

`resetall
`default_nettype none

/*
 * GMII PHY interface
 */
module gmii_phy_if #(
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
    parameter CLOCK_INPUT_STYLE = "BUFIO2"
) (
    input  logic       clk,
    input  logic       rst,

    /*
     * GMII interface to MAC
     */
    output logic       mac_gmii_rx_clk,
    output logic       mac_gmii_rx_rst,
    output logic [7:0] mac_gmii_rxd,
    output logic       mac_gmii_rx_dv,
    output logic       mac_gmii_rx_er,
    output logic       mac_gmii_tx_clk,
    output logic       mac_gmii_tx_rst,
    input  logic [7:0] mac_gmii_txd,
    input  logic       mac_gmii_tx_en,
    input  logic       mac_gmii_tx_er,

    /*
     * GMII interface to PHY
     */
    input  logic       phy_gmii_rx_clk,
    input  logic [7:0] phy_gmii_rxd,
    input  logic       phy_gmii_rx_dv,
    input  logic       phy_gmii_rx_er,
    input  logic       phy_mii_tx_clk,
    output logic       phy_gmii_tx_clk,
    output logic [7:0] phy_gmii_txd,
    output logic       phy_gmii_tx_en,
    output logic       phy_gmii_tx_er,

    /*
     * Control
     */
    input  logic       mii_select
);

  ssio_sdr_in #(
      .TARGET            (TARGET),
      .CLOCK_INPUT_STYLE (CLOCK_INPUT_STYLE),
      .WIDTH             (10)
  ) rx_ssio_sdr_inst (
      .input_clk  (phy_gmii_rx_clk),
      .input_d    ({phy_gmii_rxd, phy_gmii_rx_dv, phy_gmii_rx_er}),
      .output_clk (mac_gmii_rx_clk),
      .output_q   ({mac_gmii_rxd, mac_gmii_rx_dv, mac_gmii_rx_er})
  );

  ssio_sdr_out #(
      .TARGET      (TARGET),
      .IODDR_STYLE (IODDR_STYLE),
      .WIDTH       (10)
  ) tx_ssio_sdr_inst (
      .clk        (mac_gmii_tx_clk),
      .input_d    ({mac_gmii_txd, mac_gmii_tx_en, mac_gmii_tx_er}),
      .output_clk (phy_gmii_tx_clk),
      .output_q   ({phy_gmii_txd, phy_gmii_tx_en, phy_gmii_tx_er})
  );

  generate

    if (TARGET == "XILINX") begin
      BUFGMUX gmii_bufgmux_inst (
          .I0 (clk),
          .I1 (phy_mii_tx_clk),
          .S  (mii_select),
          .O  (mac_gmii_tx_clk)
      );
    end
    else begin
      assign mac_gmii_tx_clk = mii_select ? phy_mii_tx_clk : clk;
    end

  endgenerate

  // reset sync
  logic [3:0] tx_rst_reg = 4'hf;
  assign      mac_gmii_tx_rst = tx_rst_reg[0];

  always_ff @(posedge mac_gmii_tx_clk or posedge rst) begin
    if (rst) begin
      tx_rst_reg <= 4'hf;
    end
    else begin
      tx_rst_reg <= {1'b0, tx_rst_reg[3:1]};
    end
  end

  logic [3:0] rx_rst_reg = 4'hf;
  assign      mac_gmii_rx_rst = rx_rst_reg[0];

  always_ff @(posedge mac_gmii_rx_clk or posedge rst) begin
    if (rst) begin
      rx_rst_reg <= 4'hf;
    end
    else begin
      rx_rst_reg <= {1'b0, rx_rst_reg[3:1]};
    end
  end

endmodule

`resetall
// verilator lint_on GENUNNAMED
