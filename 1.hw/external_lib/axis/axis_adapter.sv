// SPDX-FileCopyrightText: 2026 Chili.CHIPS
//
// Enhanced by Chili.CHIPS with NLnet-sponsored project
// wireguard-fpga (https://github.com/chili-chips/wireguard-fpga).
// The original header follows.

// Copyright (c) 2014-2023 Alex Forencich
//
// SPDX-License-Identifier: MIT

// Language: Verilog 2001

/*
 * AXI4-Stream bus width adapter
 */
module axis_adapter #(
    // Width of input AXI stream interface in bits
    parameter int S_DATA_WIDTH  = 8,
    // Propagate tkeep signal on input interface
    // If disabled, tkeep assumed to be 1'b1
    parameter bit S_KEEP_ENABLE = (S_DATA_WIDTH > 8),
    // tkeep signal width (words per cycle) on input interface
    parameter int S_KEEP_WIDTH  = ((S_DATA_WIDTH + 7) / 8),
    // Width of output AXI stream interface in bits
    parameter int M_DATA_WIDTH  = 8,
    // Propagate tkeep signal on output interface
    // If disabled, tkeep assumed to be 1'b1
    parameter bit M_KEEP_ENABLE = (M_DATA_WIDTH > 8),
    // tkeep signal width (words per cycle) on output interface
    parameter int M_KEEP_WIDTH  = ((M_DATA_WIDTH + 7) / 8),
    // Propagate tuser signal
    parameter bit USER_ENABLE   = 1,
    // tuser signal width
    parameter int USER_WIDTH    = 1
) (
    input  logic                    clk,
    input  logic                    rst,

    /*
     * AXI input
     */
    input  logic [S_DATA_WIDTH-1:0] s_axis_tdata,
    input  logic [S_KEEP_WIDTH-1:0] s_axis_tkeep,
    input  logic                    s_axis_tvalid,
    output logic                    s_axis_tready,
    input  logic                    s_axis_tlast,
    input  logic [  USER_WIDTH-1:0] s_axis_tuser,

    /*
     * AXI output
     */
    output logic [M_DATA_WIDTH-1:0] m_axis_tdata,
    output logic [M_KEEP_WIDTH-1:0] m_axis_tkeep,
    output logic                    m_axis_tvalid,
    input  logic                    m_axis_tready,
    output logic                    m_axis_tlast,
    output logic [  USER_WIDTH-1:0] m_axis_tuser
);

  // force keep width to 1 when disabled
  localparam int S_BYTE_LANES = S_KEEP_ENABLE ? S_KEEP_WIDTH : 1;
  localparam int M_BYTE_LANES = M_KEEP_ENABLE ? M_KEEP_WIDTH : 1;

  // bus byte sizes (must be identical)
  localparam int S_BYTE_SIZE  = S_DATA_WIDTH / S_BYTE_LANES;
  localparam int M_BYTE_SIZE  = M_DATA_WIDTH / M_BYTE_LANES;

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

  logic [S_KEEP_WIDTH-1:0] s_axis_tkeep_int;
  assign                   s_axis_tkeep_int = S_KEEP_ENABLE ? s_axis_tkeep : {S_KEEP_WIDTH{1'b1}};

  generate

    if (M_BYTE_LANES == S_BYTE_LANES) begin : g_bypass
      // same width; bypass

      assign s_axis_tready = m_axis_tready;

      assign m_axis_tdata = s_axis_tdata;
      assign m_axis_tkeep  = ((M_KEEP_ENABLE != 0) & (S_KEEP_ENABLE != 0))
                           ? s_axis_tkeep
                           : {M_KEEP_WIDTH{1'b1}};
      assign m_axis_tvalid = s_axis_tvalid;
      assign m_axis_tlast = s_axis_tlast;
      assign m_axis_tuser = USER_ENABLE ? s_axis_tuser : {USER_WIDTH{1'b0}};

    end
    else if (M_BYTE_LANES > S_BYTE_LANES) begin : g_upsize
      // output is wider; upsize

      // required number of segments in wider bus
      localparam int SEG_COUNT      = M_BYTE_LANES / S_BYTE_LANES;
      // data width and keep width per segment
      localparam int SEG_DATA_WIDTH = M_DATA_WIDTH / SEG_COUNT;
      localparam int SEG_KEEP_WIDTH = M_BYTE_LANES / SEG_COUNT;

      logic [$clog2(SEG_COUNT)-1:0] seg_reg;

      logic [     S_DATA_WIDTH-1:0] s_axis_tdata_reg;
      logic [     S_KEEP_WIDTH-1:0] s_axis_tkeep_reg;
      logic                         s_axis_tvalid_reg;
      logic                         s_axis_tlast_reg;
      logic [       USER_WIDTH-1:0] s_axis_tuser_reg;

      logic [     M_DATA_WIDTH-1:0] m_axis_tdata_reg;
      logic [     M_KEEP_WIDTH-1:0] m_axis_tkeep_reg;
      logic                         m_axis_tvalid_reg;
      logic                         m_axis_tlast_reg;
      logic [       USER_WIDTH-1:0] m_axis_tuser_reg;

      assign s_axis_tready = ~s_axis_tvalid_reg;

      assign m_axis_tdata  = m_axis_tdata_reg;
      assign m_axis_tkeep  = M_KEEP_ENABLE ? m_axis_tkeep_reg : {M_KEEP_WIDTH{1'b1}};
      assign m_axis_tvalid = m_axis_tvalid_reg;
      assign m_axis_tlast  = m_axis_tlast_reg;
      assign m_axis_tuser  = USER_ENABLE ? m_axis_tuser_reg : {USER_WIDTH{1'b0}};

      always_ff @(posedge clk) begin
        m_axis_tvalid_reg <= m_axis_tvalid_reg & ~m_axis_tready;

        if (!m_axis_tvalid_reg || m_axis_tready) begin
          // output register empty

          if (seg_reg == 0) begin
            m_axis_tdata_reg[seg_reg*SEG_DATA_WIDTH +: SEG_DATA_WIDTH] <=
                s_axis_tvalid_reg ? s_axis_tdata_reg : s_axis_tdata;
            m_axis_tkeep_reg <=
              M_KEEP_WIDTH'(s_axis_tvalid_reg ? s_axis_tkeep_reg : s_axis_tkeep_int);
          end
          else begin
            m_axis_tdata_reg[seg_reg*SEG_DATA_WIDTH+:SEG_DATA_WIDTH] <= s_axis_tdata;
            m_axis_tkeep_reg[seg_reg*SEG_KEEP_WIDTH+:SEG_KEEP_WIDTH] <= s_axis_tkeep_int;
          end
          m_axis_tlast_reg <= s_axis_tvalid_reg ? s_axis_tlast_reg : s_axis_tlast;
          m_axis_tuser_reg <= s_axis_tvalid_reg ? s_axis_tuser_reg : s_axis_tuser;

          if (s_axis_tvalid_reg) begin
            // consume data from buffer
            s_axis_tvalid_reg <= 1'b0;

            if (s_axis_tlast_reg || seg_reg == ($clog2(SEG_COUNT))'(SEG_COUNT - 1)) begin
              seg_reg           <= 0;
              m_axis_tvalid_reg <= 1'b1;
            end
            else begin
              seg_reg <= seg_reg + 1;
            end
          end
          else if (s_axis_tvalid) begin
            // data direct from input
            if (s_axis_tlast || seg_reg == ($clog2(SEG_COUNT))'(SEG_COUNT - 1)) begin
              seg_reg           <= 0;
              m_axis_tvalid_reg <= 1'b1;
            end
            else begin
              seg_reg <= seg_reg + 1;
            end
          end
        end
        else if (s_axis_tvalid && s_axis_tready) begin
          // store input data in skid buffer
          s_axis_tdata_reg  <= s_axis_tdata;
          s_axis_tkeep_reg  <= s_axis_tkeep_int;
          s_axis_tvalid_reg <= 1'b1;
          s_axis_tlast_reg  <= s_axis_tlast;
          s_axis_tuser_reg  <= s_axis_tuser;
        end

        if (rst) begin
          seg_reg           <= 0;
          s_axis_tvalid_reg <= 1'b0;
          m_axis_tvalid_reg <= 1'b0;
          m_axis_tkeep_reg  <= '0;
          m_axis_tlast_reg  <= '0;
          m_axis_tuser_reg  <= '0;
          s_axis_tkeep_reg  <= '0;
          s_axis_tlast_reg  <= '0;
          s_axis_tuser_reg  <= '0;
        end
      end

    end
    else begin : g_downsize
      // output is narrower; downsize

      // required number of segments in wider bus
      localparam int SEG_COUNT      = S_BYTE_LANES / M_BYTE_LANES;
      // data width and keep width per segment
      localparam int SEG_DATA_WIDTH = S_DATA_WIDTH / SEG_COUNT;
      localparam int SEG_KEEP_WIDTH = S_BYTE_LANES / SEG_COUNT;

      logic [S_DATA_WIDTH-1:0] s_axis_tdata_reg;
      logic [S_KEEP_WIDTH-1:0] s_axis_tkeep_reg;
      logic                    s_axis_tvalid_reg;
      logic                    s_axis_tlast_reg;
      logic [  USER_WIDTH-1:0] s_axis_tuser_reg;

      logic [M_DATA_WIDTH-1:0] m_axis_tdata_reg;
      logic [M_KEEP_WIDTH-1:0] m_axis_tkeep_reg;
      logic                    m_axis_tvalid_reg;
      logic                    m_axis_tlast_reg;
      logic [  USER_WIDTH-1:0] m_axis_tuser_reg;

      assign s_axis_tready = ~s_axis_tvalid_reg;

      assign m_axis_tdata  = m_axis_tdata_reg;
      assign m_axis_tkeep  = M_KEEP_ENABLE ? m_axis_tkeep_reg : {M_KEEP_WIDTH{1'b1}};
      assign m_axis_tvalid = m_axis_tvalid_reg;
      assign m_axis_tlast  = m_axis_tlast_reg;
      assign m_axis_tuser  = USER_ENABLE ? m_axis_tuser_reg : {USER_WIDTH{1'b0}};

      always_ff @(posedge clk) begin
        m_axis_tvalid_reg <= m_axis_tvalid_reg & ~m_axis_tready;

        if (!m_axis_tvalid_reg || m_axis_tready) begin
          // output register empty

          // the lowest output segment of the input word
          m_axis_tdata_reg <= M_DATA_WIDTH'(s_axis_tvalid_reg ? s_axis_tdata_reg : s_axis_tdata);
          m_axis_tkeep_reg <=
              M_KEEP_WIDTH'(s_axis_tvalid_reg ? s_axis_tkeep_reg : s_axis_tkeep_int);
          m_axis_tlast_reg <= 1'b0;
          m_axis_tuser_reg <= s_axis_tvalid_reg ? s_axis_tuser_reg : s_axis_tuser;

          if (s_axis_tvalid_reg) begin
            // buffer has data; shift out from buffer
            s_axis_tdata_reg  <= s_axis_tdata_reg >> SEG_DATA_WIDTH;
            s_axis_tkeep_reg  <= s_axis_tkeep_reg >> SEG_KEEP_WIDTH;

            m_axis_tvalid_reg <= 1'b1;

            if ((s_axis_tkeep_reg >> SEG_KEEP_WIDTH) == 0) begin
              s_axis_tvalid_reg <= 1'b0;
              m_axis_tlast_reg  <= s_axis_tlast_reg;
            end
          end
          else if (s_axis_tvalid && s_axis_tready) begin
            // buffer is empty; store from input
            s_axis_tdata_reg  <= s_axis_tdata >> SEG_DATA_WIDTH;
            s_axis_tkeep_reg  <= s_axis_tkeep_int >> SEG_KEEP_WIDTH;
            s_axis_tlast_reg  <= s_axis_tlast;
            s_axis_tuser_reg  <= s_axis_tuser;

            m_axis_tvalid_reg <= 1'b1;

            if (S_KEEP_ENABLE && (s_axis_tkeep_int >> SEG_KEEP_WIDTH) == 0) begin
              s_axis_tvalid_reg <= 1'b0;
              m_axis_tlast_reg  <= s_axis_tlast;
            end
            else begin
              s_axis_tvalid_reg <= 1'b1;
            end
          end
        end
        else if (s_axis_tvalid && s_axis_tready) begin
          // store input data
          s_axis_tdata_reg  <= s_axis_tdata;
          s_axis_tkeep_reg  <= s_axis_tkeep_int;
          s_axis_tvalid_reg <= 1'b1;
          s_axis_tlast_reg  <= s_axis_tlast;
          s_axis_tuser_reg  <= s_axis_tuser;
        end

        if (rst) begin
          s_axis_tvalid_reg <= 1'b0;
          m_axis_tvalid_reg <= 1'b0;
          m_axis_tkeep_reg  <= '0;
          m_axis_tlast_reg  <= '0;
          m_axis_tuser_reg  <= '0;
          s_axis_tkeep_reg  <= '0;
          s_axis_tlast_reg  <= '0;
          s_axis_tuser_reg  <= '0;
        end
      end

    end

  endgenerate

endmodule

