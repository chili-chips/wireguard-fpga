// SPDX-FileCopyrightText: 2026 Chili.CHIPS
//
// Enhanced by Chili.CHIPS with NLnet-sponsored project
// wireguard-fpga (https://github.com/chili-chips/wireguard-fpga).
// The original header follows.

// Copyright (c) 2018 Alex Forencich
//
// SPDX-License-Identifier: MIT

// Language: Verilog 2001 (ports: SystemVerilog dpe_if, by Chili.CHIPS)

`resetall
`default_nettype none

/*
 * AXI4-Stream pipeline register
 */
module axis_pipeline_register #(
    // Propagate tkeep signal
    parameter KEEP_ENABLE = 1,
    // Propagate tlast signal
    parameter LAST_ENABLE = 1,
    // Propagate tid signal
    parameter ID_ENABLE   = 0,
    // Propagate tuser signal
    parameter USER_ENABLE = 1,
    // Register type
    // 0 to bypass, 1 for simple buffer, 2 for skid buffer
    parameter REG_TYPE    = 2,
    // Number of registers in pipeline
    parameter LENGTH      = 2
) (
    dpe_if.s_axis s_axis,
    dpe_if.m_axis m_axis
);

  // Chili.CHIPS: LENGTH registers in a chain of dpe_if links;
  // link[0] is the input, link[LENGTH] the output
  dpe_if link[LENGTH+1] (
      .clk (s_axis.clk),
      .rst (s_axis.rst)
  );

  assign link[0].tdata       = s_axis.tdata;
  assign link[0].tkeep       = s_axis.tkeep;
  assign link[0].tvalid      = s_axis.tvalid;
  assign s_axis.tready       = link[0].tready;
  assign link[0].tlast       = s_axis.tlast;
  assign link[0].tid         = s_axis.tid;
  assign link[0].tuser       = s_axis.tuser;

  assign m_axis.tdata        = link[LENGTH].tdata;
  assign m_axis.tkeep        = link[LENGTH].tkeep;
  assign m_axis.tvalid       = link[LENGTH].tvalid;
  assign link[LENGTH].tready = m_axis.tready;
  assign m_axis.tlast        = link[LENGTH].tlast;
  assign m_axis.tid          = link[LENGTH].tid;
  assign m_axis.tuser        = link[LENGTH].tuser;

  for (genvar i = 0; i < LENGTH; i = i + 1) begin : pipe_reg
    axis_register #(
        .KEEP_ENABLE (KEEP_ENABLE),
        .LAST_ENABLE (LAST_ENABLE),
        .ID_ENABLE   (ID_ENABLE),
        .USER_ENABLE (USER_ENABLE),
        .REG_TYPE    (REG_TYPE)
    ) reg_inst (
        .s_axis (link[i]),
        .m_axis (link[i+1])
    );
  end

endmodule

`resetall
