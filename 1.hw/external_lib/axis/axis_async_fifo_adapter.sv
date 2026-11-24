// SPDX-FileCopyrightText: 2026 Chili.CHIPS
//
// Enhanced by Chili.CHIPS with NLnet-sponsored project
// wireguard-fpga (https://github.com/chili-chips/wireguard-fpga).
// The original header follows.

// Copyright (c) 2019 Alex Forencich
//
// SPDX-License-Identifier: MIT

// Language: Verilog 2001

/*
 * AXI4-Stream asynchronous FIFO with width converter
 */
module axis_async_fifo_adapter #(
    // FIFO depth in words
    // KEEP_WIDTH words per cycle if KEEP_ENABLE set
    // Rounded up to nearest power of 2 cycles
    parameter int                    DEPTH                = 4096,
    // Width of input AXI stream interface in bits
    parameter int                    S_DATA_WIDTH         = 8,
    // Propagate tkeep signal on input interface
    // If disabled, tkeep assumed to be 1'b1
    parameter bit                    S_KEEP_ENABLE        = (S_DATA_WIDTH > 8),
    // tkeep signal width (words per cycle) on input interface
    parameter int                    S_KEEP_WIDTH         = ((S_DATA_WIDTH + 7) / 8),
    // Width of output AXI stream interface in bits
    parameter int                    M_DATA_WIDTH         = 8,
    // Propagate tkeep signal on output interface
    // If disabled, tkeep assumed to be 1'b1
    parameter bit                    M_KEEP_ENABLE        = (M_DATA_WIDTH > 8),
    // tkeep signal width (words per cycle) on output interface
    parameter int                    M_KEEP_WIDTH         = ((M_DATA_WIDTH + 7) / 8),
    // Propagate tuser signal
    parameter bit                    USER_ENABLE          = 1,
    // tuser signal width
    parameter int                    USER_WIDTH           = 1,
    // number of RAM pipeline registers in FIFO
    parameter int                    RAM_PIPELINE         = 1,
    // Frame FIFO mode - operate on frames instead of cycles
    // When set, m_axis_tvalid will not be deasserted within a frame
    // Requires LAST_ENABLE set
    parameter bit                    FRAME_FIFO           = 0,
    // tuser value for bad frame marker
    parameter logic [USER_WIDTH-1:0] USER_BAD_FRAME_VALUE = 1'b1,
    // tuser mask for bad frame marker
    parameter logic [USER_WIDTH-1:0] USER_BAD_FRAME_MASK  = 1'b1,
    // Drop frames larger than FIFO
    // Requires FRAME_FIFO set
    parameter bit                    DROP_OVERSIZE_FRAME  = FRAME_FIFO,
    // Drop frames marked bad
    // Requires FRAME_FIFO and DROP_OVERSIZE_FRAME set
    parameter bit                    DROP_BAD_FRAME       = 0,
    // Drop incoming frames when full
    // When set, s_axis_tready is always asserted
    // Requires FRAME_FIFO and DROP_OVERSIZE_FRAME set
    parameter bit                    DROP_WHEN_FULL       = 0,
    // Chili.CHIPS: the FIFO stores tkeep as a byte count (see axis_async_fifo)
    parameter bit                    KEEP_AS_COUNT        = 0
) (
    /*
     * AXI input
     */
    input  logic                    s_clk,
    input  logic                    s_rst,
    input  logic [S_DATA_WIDTH-1:0] s_axis_tdata,
    input  logic [S_KEEP_WIDTH-1:0] s_axis_tkeep,
    input  logic                    s_axis_tvalid,
    output logic                    s_axis_tready,
    input  logic                    s_axis_tlast,
    input  logic [  USER_WIDTH-1:0] s_axis_tuser,

    /*
     * AXI output
     */
    input  logic                    m_clk,
    input  logic                    m_rst,
    output logic [M_DATA_WIDTH-1:0] m_axis_tdata,
    output logic [M_KEEP_WIDTH-1:0] m_axis_tkeep,
    output logic                    m_axis_tvalid,
    input  logic                    m_axis_tready,
    output logic                    m_axis_tlast,
    output logic [  USER_WIDTH-1:0] m_axis_tuser

);

  // force keep width to 1 when disabled
  localparam int S_BYTE_LANES     = S_KEEP_ENABLE ? S_KEEP_WIDTH : 1;
  localparam int M_BYTE_LANES     = M_KEEP_ENABLE ? M_KEEP_WIDTH : 1;

  // bus byte sizes (must be identical)
  localparam int S_BYTE_SIZE      = S_DATA_WIDTH / S_BYTE_LANES;
  localparam int M_BYTE_SIZE      = M_DATA_WIDTH / M_BYTE_LANES;
  // output bus is wider
  localparam bit EXPAND_BUS       = M_BYTE_LANES > S_BYTE_LANES;
  // tkeep in the FIFO: on the wider side's setting
  localparam bit FIFO_KEEP_ENABLE = EXPAND_BUS ? M_KEEP_ENABLE : S_KEEP_ENABLE;
  // total data and keep widths
  localparam int DATA_WIDTH       = EXPAND_BUS ? M_DATA_WIDTH : S_DATA_WIDTH;
  localparam int KEEP_WIDTH       = EXPAND_BUS ? M_BYTE_LANES : S_BYTE_LANES;

  // bus width assertions
  initial begin
    if (S_BYTE_SIZE * S_BYTE_LANES != S_DATA_WIDTH) begin
      $error("Error: input data width not evenly divisible (instance %m)");
      $finish;
    end

    if (M_BYTE_SIZE * M_BYTE_LANES != M_DATA_WIDTH) begin
      $error("Error: output data width not evenly divisible (instance %m)");
      $finish;
    end

    if (S_BYTE_SIZE != M_BYTE_SIZE) begin
      $error("Error: byte size mismatch (instance %m)");
      $finish;
    end
  end

  logic [DATA_WIDTH-1:0] pre_fifo_axis_tdata;
  logic [KEEP_WIDTH-1:0] pre_fifo_axis_tkeep;
  logic                  pre_fifo_axis_tvalid;
  logic                  pre_fifo_axis_tready;
  logic                  pre_fifo_axis_tlast;
  logic [USER_WIDTH-1:0] pre_fifo_axis_tuser;

  logic [DATA_WIDTH-1:0] post_fifo_axis_tdata;
  logic [KEEP_WIDTH-1:0] post_fifo_axis_tkeep;
  logic                  post_fifo_axis_tvalid;
  logic                  post_fifo_axis_tready;
  logic                  post_fifo_axis_tlast;
  logic [USER_WIDTH-1:0] post_fifo_axis_tuser;

  generate

    if (M_BYTE_LANES > S_BYTE_LANES) begin : g_upsize_pre

      // output wider, adapt width before FIFO

      axis_adapter #(
          .S_DATA_WIDTH  (S_DATA_WIDTH),
          .S_KEEP_ENABLE (S_KEEP_ENABLE),
          .S_KEEP_WIDTH  (S_KEEP_WIDTH),
          .M_DATA_WIDTH  (M_DATA_WIDTH),
          .M_KEEP_ENABLE (M_KEEP_ENABLE),
          .M_KEEP_WIDTH  (M_KEEP_WIDTH),
          .USER_ENABLE   (USER_ENABLE),
          .USER_WIDTH    (USER_WIDTH)
      ) adapter_inst (
          .clk           (s_clk),
          .rst           (s_rst),
          // AXI input
          .s_axis_tdata  (s_axis_tdata),
          .s_axis_tkeep  (s_axis_tkeep),
          .s_axis_tvalid (s_axis_tvalid),
          .s_axis_tready (s_axis_tready),
          .s_axis_tlast  (s_axis_tlast),
          .s_axis_tuser  (s_axis_tuser),
          // AXI output
          .m_axis_tdata  (pre_fifo_axis_tdata),
          .m_axis_tkeep  (pre_fifo_axis_tkeep),
          .m_axis_tvalid (pre_fifo_axis_tvalid),
          .m_axis_tready (pre_fifo_axis_tready),
          .m_axis_tlast  (pre_fifo_axis_tlast),
          .m_axis_tuser  (pre_fifo_axis_tuser)
      );

    end
    else begin : g_bypass_pre

      assign pre_fifo_axis_tdata  = s_axis_tdata;
      assign pre_fifo_axis_tkeep  = s_axis_tkeep;
      assign pre_fifo_axis_tvalid = s_axis_tvalid;
      assign s_axis_tready        = pre_fifo_axis_tready;
      assign pre_fifo_axis_tlast  = s_axis_tlast;
      assign pre_fifo_axis_tuser  = s_axis_tuser;

    end

    axis_async_fifo #(
        .DEPTH                (DEPTH),
        .DATA_WIDTH           (DATA_WIDTH),
        .KEEP_ENABLE          (FIFO_KEEP_ENABLE),
        .KEEP_WIDTH           (KEEP_WIDTH),
        .KEEP_AS_COUNT        (KEEP_AS_COUNT),
        .LAST_ENABLE          (1),
        .USER_ENABLE          (USER_ENABLE),
        .USER_WIDTH           (USER_WIDTH),
        .RAM_PIPELINE         (RAM_PIPELINE),
        .FRAME_FIFO           (FRAME_FIFO),
        .USER_BAD_FRAME_VALUE (USER_BAD_FRAME_VALUE),
        .USER_BAD_FRAME_MASK  (USER_BAD_FRAME_MASK),
        .DROP_OVERSIZE_FRAME  (DROP_OVERSIZE_FRAME),
        .DROP_BAD_FRAME       (DROP_BAD_FRAME),
        .DROP_WHEN_FULL       (DROP_WHEN_FULL)
    ) fifo_inst (
        // AXI input
        .s_clk         (s_clk),
        .s_rst         (s_rst),
        .s_axis_tdata  (pre_fifo_axis_tdata),
        .s_axis_tkeep  (pre_fifo_axis_tkeep),
        .s_axis_tvalid (pre_fifo_axis_tvalid),
        .s_axis_tready (pre_fifo_axis_tready),
        .s_axis_tlast  (pre_fifo_axis_tlast),
        .s_axis_tuser  (pre_fifo_axis_tuser),
        // AXI output
        .m_clk         (m_clk),
        .m_rst         (m_rst),
        .m_axis_tdata  (post_fifo_axis_tdata),
        .m_axis_tkeep  (post_fifo_axis_tkeep),
        .m_axis_tvalid (post_fifo_axis_tvalid),
        .m_axis_tready (post_fifo_axis_tready),
        .m_axis_tlast  (post_fifo_axis_tlast),
        .m_axis_tuser  (post_fifo_axis_tuser)
    );

    if (M_BYTE_LANES < S_BYTE_LANES) begin : g_downsize_post

      // input wider, adapt width after FIFO

      axis_adapter #(
          .S_DATA_WIDTH  (S_DATA_WIDTH),
          .S_KEEP_ENABLE (S_KEEP_ENABLE),
          .S_KEEP_WIDTH  (S_KEEP_WIDTH),
          .M_DATA_WIDTH  (M_DATA_WIDTH),
          .M_KEEP_ENABLE (M_KEEP_ENABLE),
          .M_KEEP_WIDTH  (M_KEEP_WIDTH),
          .USER_ENABLE   (USER_ENABLE),
          .USER_WIDTH    (USER_WIDTH)
      ) adapter_inst (
          .clk           (m_clk),
          .rst           (m_rst),
          // AXI input
          .s_axis_tdata  (post_fifo_axis_tdata),
          .s_axis_tkeep  (post_fifo_axis_tkeep),
          .s_axis_tvalid (post_fifo_axis_tvalid),
          .s_axis_tready (post_fifo_axis_tready),
          .s_axis_tlast  (post_fifo_axis_tlast),
          .s_axis_tuser  (post_fifo_axis_tuser),
          // AXI output
          .m_axis_tdata  (m_axis_tdata),
          .m_axis_tkeep  (m_axis_tkeep),
          .m_axis_tvalid (m_axis_tvalid),
          .m_axis_tready (m_axis_tready),
          .m_axis_tlast  (m_axis_tlast),
          .m_axis_tuser  (m_axis_tuser)
      );

    end
    else begin : g_bypass_post

      assign m_axis_tdata          = post_fifo_axis_tdata;
      assign m_axis_tkeep          = post_fifo_axis_tkeep;
      assign m_axis_tvalid         = post_fifo_axis_tvalid;
      assign post_fifo_axis_tready = m_axis_tready;
      assign m_axis_tlast          = post_fifo_axis_tlast;
      assign m_axis_tuser          = post_fifo_axis_tuser;

    end

  endgenerate

endmodule

