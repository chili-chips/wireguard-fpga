// SPDX-FileCopyrightText: 2026 Chili.CHIPS
//
// Enhanced by Chili.CHIPS with NLnet-sponsored project
// wireguard-fpga (https://github.com/chili-chips/wireguard-fpga).
// The original header follows.

// Copyright (c) 2016-2018 Alex Forencich
//
// SPDX-License-Identifier: MIT

// Language: Verilog 2001

/*
 * Source synchronous SDR input (Xilinx 7-series: the clock on a BUFG)
 */
module ssio_sdr_in #(
    parameter int WIDTH = 1  // width of register in bits
) (
    input  logic             input_clk,

    input  logic [WIDTH-1:0] input_d,

    output logic             output_clk,

    output logic [WIDTH-1:0] output_q
);

  // the RX clock on a BUFG, to the input registers and to the logic
  BUFG clk_bufg (
      .I (input_clk),
      .O (output_clk)
  );

  (* IOB = "TRUE" *)
  logic [WIDTH-1:0] output_q_reg;

  assign output_q = output_q_reg;

  always_ff @(posedge output_clk) begin
    output_q_reg <= input_d;
  end

endmodule

