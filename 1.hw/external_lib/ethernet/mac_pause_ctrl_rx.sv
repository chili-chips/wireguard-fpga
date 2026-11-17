// SPDX-FileCopyrightText: 2026 Chili.CHIPS
//
// Enhanced by Chili.CHIPS with NLnet-sponsored project
// wireguard-fpga (https://github.com/chili-chips/wireguard-fpga).
// The original header follows.

// Copyright (c) 2023 Alex Forencich
//
// SPDX-License-Identifier: MIT

// Language: Verilog 2001

`resetall
`default_nettype none

/*
 * PFC and pause frame receive handling
 */
module mac_pause_ctrl_rx #(
    parameter MCF_PARAMS_SIZE = 18,
    parameter PFC_ENABLE      = 1
) (
    input  logic                         clk,
    input  logic                         rst,

    /*
     * MAC control frame interface
     */
    input  logic                         mcf_valid,
    input  logic [                 47:0] mcf_eth_dst,
    input  logic [                 47:0] mcf_eth_src,
    input  logic [                 15:0] mcf_eth_type,
    input  logic [                 15:0] mcf_opcode,
    input  logic [MCF_PARAMS_SIZE*8-1:0] mcf_params,

    /*
     * Link-level Flow Control (LFC) (IEEE 802.3 annex 31B PAUSE)
     */
    input  logic                         rx_lfc_en,
    output logic                         rx_lfc_req,
    input  logic                         rx_lfc_ack,

    /*
     * Priority Flow Control (PFC) (IEEE 802.3 annex 31D PFC)
     */
    input  logic [7:0]                   rx_pfc_en,
    output logic [7:0]                   rx_pfc_req,
    input  logic [7:0]                   rx_pfc_ack,

    /*
     * Configuration
     */
    input  logic [15:0]                  cfg_rx_lfc_opcode,
    input  logic                         cfg_rx_lfc_en,
    input  logic [15:0]                  cfg_rx_pfc_opcode,
    input  logic                         cfg_rx_pfc_en,
    input  logic [ 9:0]                  cfg_quanta_step,
    input  logic                         cfg_quanta_clk_en,

    /*
     * Status
     */
    output logic                         stat_rx_lfc_pkt,
    output logic                         stat_rx_lfc_xon,
    output logic                         stat_rx_lfc_xoff,
    output logic                         stat_rx_lfc_paused,
    output logic                         stat_rx_pfc_pkt,
    output logic [7:0]                   stat_rx_pfc_xon,
    output logic [7:0]                   stat_rx_pfc_xoff,
    output logic [7:0]                   stat_rx_pfc_paused
);

  localparam QFB = 8;

  // check configuration
  initial begin
    if (MCF_PARAMS_SIZE < (PFC_ENABLE ? 18 : 2)) begin
      $error("Error: MCF_PARAMS_SIZE too small for requested configuration (instance %m)");
      $finish;
    end
  end

  logic lfc_req_reg = 1'b0, lfc_req_next;
  logic [7:0] pfc_req_reg = 8'd0, pfc_req_next;

  logic [16+QFB-1:0] lfc_quanta_reg = 0, lfc_quanta_next;
  logic [16+QFB-1:0] pfc_quanta_reg[0:7], pfc_quanta_next[0:7];

  logic stat_rx_lfc_pkt_reg = 1'b0, stat_rx_lfc_pkt_next;
  logic stat_rx_lfc_xon_reg = 1'b0, stat_rx_lfc_xon_next;
  logic stat_rx_lfc_xoff_reg = 1'b0, stat_rx_lfc_xoff_next;
  logic stat_rx_pfc_pkt_reg = 1'b0, stat_rx_pfc_pkt_next;
  logic [7:0] stat_rx_pfc_xon_reg = 0, stat_rx_pfc_xon_next;
  logic [7:0] stat_rx_pfc_xoff_reg = 0, stat_rx_pfc_xoff_next;

  assign rx_lfc_req         = lfc_req_reg;
  assign rx_pfc_req         = pfc_req_reg;

  assign stat_rx_lfc_pkt    = stat_rx_lfc_pkt_reg;
  assign stat_rx_lfc_xon    = stat_rx_lfc_xon_reg;
  assign stat_rx_lfc_xoff   = stat_rx_lfc_xoff_reg;
  assign stat_rx_lfc_paused = lfc_req_reg;
  assign stat_rx_pfc_pkt    = stat_rx_pfc_pkt_reg;
  assign stat_rx_pfc_xon    = stat_rx_pfc_xon_reg;
  assign stat_rx_pfc_xoff   = stat_rx_pfc_xoff_reg;
  assign stat_rx_pfc_paused = pfc_req_reg;

  initial begin
    for (int k = 0; k < 8; k = k + 1) begin
      pfc_quanta_reg[k] = 0;
    end
  end

  always_comb begin
    stat_rx_lfc_pkt_next  = 1'b0;
    stat_rx_lfc_xon_next  = 1'b0;
    stat_rx_lfc_xoff_next = 1'b0;
    stat_rx_pfc_pkt_next  = 1'b0;
    stat_rx_pfc_xon_next  = 0;
    stat_rx_pfc_xoff_next = 0;

    if (cfg_quanta_clk_en && rx_lfc_ack) begin
      if (lfc_quanta_reg > cfg_quanta_step) begin
        lfc_quanta_next = lfc_quanta_reg - cfg_quanta_step;
      end
      else begin
        lfc_quanta_next = 0;
      end
    end
    else begin
      lfc_quanta_next = lfc_quanta_reg;
    end

    lfc_req_next = (lfc_quanta_reg != 0) && rx_lfc_en && cfg_rx_lfc_en;

    for (int k = 0; k < 8; k = k + 1) begin
      if (cfg_quanta_clk_en && rx_pfc_ack[k]) begin
        if (pfc_quanta_reg[k] > cfg_quanta_step) begin
          pfc_quanta_next[k] = pfc_quanta_reg[k] - cfg_quanta_step;
        end
        else begin
          pfc_quanta_next[k] = 0;
        end
      end
      else begin
        pfc_quanta_next[k] = pfc_quanta_reg[k];
      end

      pfc_req_next[k] = (pfc_quanta_reg[k] != 0) && rx_pfc_en[k] && cfg_rx_pfc_en;
    end

    if (mcf_valid) begin
      if (mcf_opcode == cfg_rx_lfc_opcode && cfg_rx_lfc_en) begin
        stat_rx_lfc_pkt_next  = 1'b1;
        stat_rx_lfc_xon_next  = {mcf_params[7:0], mcf_params[15:8]} == 0;
        stat_rx_lfc_xoff_next = {mcf_params[7:0], mcf_params[15:8]} != 0;
        lfc_quanta_next       = {mcf_params[7:0], mcf_params[15:8], {QFB{1'b0}}};
      end
      else if (PFC_ENABLE && mcf_opcode == cfg_rx_pfc_opcode && cfg_rx_pfc_en) begin
        stat_rx_pfc_pkt_next = 1'b1;
        for (int k = 0; k < 8; k = k + 1) begin
          if (mcf_params[k+8]) begin
            stat_rx_pfc_xon_next[k] = mcf_params[16+(k*16)+:16] == 0;  // either byte order
            stat_rx_pfc_xoff_next[k] = mcf_params[16+(k*16)+:16] != 0;  // either byte order
            pfc_quanta_next[k] = {
              mcf_params[16+(k*16)+0+:8], mcf_params[16+(k*16)+8+:8], {QFB{1'b0}}
            };
          end
        end
      end
    end
  end

  always_ff @(posedge clk) begin
    lfc_req_reg    <= lfc_req_next;
    pfc_req_reg    <= pfc_req_next;

    lfc_quanta_reg <= lfc_quanta_next;
    for (int k = 0; k < 8; k = k + 1) begin
      pfc_quanta_reg[k] <= pfc_quanta_next[k];
    end

    stat_rx_lfc_pkt_reg  <= stat_rx_lfc_pkt_next;
    stat_rx_lfc_xon_reg  <= stat_rx_lfc_xon_next;
    stat_rx_lfc_xoff_reg <= stat_rx_lfc_xoff_next;
    stat_rx_pfc_pkt_reg  <= stat_rx_pfc_pkt_next;
    stat_rx_pfc_xon_reg  <= stat_rx_pfc_xon_next;
    stat_rx_pfc_xoff_reg <= stat_rx_pfc_xoff_next;

    if (rst) begin
      lfc_req_reg    <= 1'b0;
      pfc_req_reg    <= 8'd0;
      lfc_quanta_reg <= 0;
      for (int k = 0; k < 8; k = k + 1) begin
        pfc_quanta_reg[k] <= 0;
      end

      stat_rx_lfc_pkt_reg  <= 1'b0;
      stat_rx_lfc_xon_reg  <= 1'b0;
      stat_rx_lfc_xoff_reg <= 1'b0;
      stat_rx_pfc_pkt_reg  <= 1'b0;
      stat_rx_pfc_xon_reg  <= 0;
      stat_rx_pfc_xoff_reg <= 0;
    end
  end

endmodule

`resetall
