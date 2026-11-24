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
 * Source synchronous SDR output (Xilinx 7-series ODDR: the forwarded clock)
 */
module ssio_sdr_out #(
    parameter int WIDTH = 1  // width of register in bits
) (
    input  logic             clk,

    input  logic [WIDTH-1:0] input_d,

    output logic             output_clk,
    output logic [WIDTH-1:0] output_q
);

  // the clock to the PHY: 0 on the rising edge, 1 on the falling edge
  ODDR #(
      .DDR_CLK_EDGE ("SAME_EDGE"),
      .SRTYPE       ("ASYNC")
  ) clk_oddr_inst (
      .Q  (output_clk),
      .C  (clk),
      .CE (1'b1),
      .D1 (1'b0),
      .D2 (1'b1),
      .R  (1'b0),
      .S  (1'b0)
  );

  (* IOB = "TRUE" *)
  logic [WIDTH-1:0] output_q_reg;

  assign output_q = output_q_reg;

  always_ff @(posedge clk) begin
    output_q_reg <= input_d;
  end

endmodule

