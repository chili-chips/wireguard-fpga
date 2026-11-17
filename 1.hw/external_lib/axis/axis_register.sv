// SPDX-FileCopyrightText: 2026 Chili.CHIPS
//
// Enhanced by Chili.CHIPS with NLnet-sponsored project
// wireguard-fpga (https://github.com/chili-chips/wireguard-fpga).
// The original header follows.

// verilator lint_off GENUNNAMED

// Copyright (c) 2014-2018 Alex Forencich
//
// SPDX-License-Identifier: MIT

// Language: Verilog 2001 (ports: SystemVerilog dpe_if, by Chili.CHIPS)

`resetall
`default_nettype none

/*
 * AXI4-Stream register
 */
module axis_register
  import dpe_pkg::*;
#(
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
    parameter REG_TYPE    = 2
) (
    dpe_if.s_axis s_axis,
    dpe_if.m_axis m_axis
);

  // Chili.CHIPS: the widths are dpe_if's, from dpe_pkg; the body below keeps
  // its original port names, bound here to the interface ports
  localparam DATA_WIDTH  = DPE_DATA_W;
  localparam KEEP_WIDTH  = DPE_KEEP_W;
  localparam ID_WIDTH    = DPE_ID_W;
  localparam DEST_ENABLE = 0;           // dpe_if carries no tdest
  localparam DEST_WIDTH  = 1;
  localparam USER_WIDTH  = DPE_USER_W;

  wire                  clk = s_axis.clk;
  wire                  rst = s_axis.rst;

  wire [DATA_WIDTH-1:0] s_axis_tdata = s_axis.tdata;
  wire [KEEP_WIDTH-1:0] s_axis_tkeep = s_axis.tkeep;
  wire                  s_axis_tvalid = s_axis.tvalid;
  wire                  s_axis_tready;
  wire                  s_axis_tlast = s_axis.tlast;
  wire [ ID_WIDTH-1:0]  s_axis_tid = s_axis.tid;
  wire [DEST_WIDTH-1:0] s_axis_tdest = '0;
  wire [USER_WIDTH-1:0] s_axis_tuser = s_axis.tuser;
  assign                s_axis.tready = s_axis_tready;

  wire [DATA_WIDTH-1:0] m_axis_tdata;
  wire [KEEP_WIDTH-1:0] m_axis_tkeep;
  wire                  m_axis_tvalid;
  wire                  m_axis_tready = m_axis.tready;
  wire                  m_axis_tlast;
  wire [ ID_WIDTH-1:0]  m_axis_tid;
  // verilator lint_off UNUSEDSIGNAL
  wire [DEST_WIDTH-1:0] m_axis_tdest;  // DEST_ENABLE is 0
  // verilator lint_on UNUSEDSIGNAL
  wire [USER_WIDTH-1:0] m_axis_tuser;
  assign                m_axis.tdata  = m_axis_tdata;
  assign                m_axis.tkeep  = m_axis_tkeep;
  assign                m_axis.tvalid = m_axis_tvalid;
  assign                m_axis.tlast  = m_axis_tlast;
  assign                m_axis.tid    = m_axis_tid;
  assign                m_axis.tuser  = m_axis_tuser;

  generate

    if (REG_TYPE > 1) begin
      // skid buffer, no bubble cycles

      // datapath registers
      reg                  s_axis_tready_reg = 1'b0;

      reg [DATA_WIDTH-1:0] m_axis_tdata_reg = {DATA_WIDTH{1'b0}};
      reg [KEEP_WIDTH-1:0] m_axis_tkeep_reg = {KEEP_WIDTH{1'b0}};
      reg m_axis_tvalid_reg = 1'b0, m_axis_tvalid_next;
      reg                  m_axis_tlast_reg = 1'b0;
      reg [  ID_WIDTH-1:0] m_axis_tid_reg = {ID_WIDTH{1'b0}};
      reg [DEST_WIDTH-1:0] m_axis_tdest_reg = {DEST_WIDTH{1'b0}};
      reg [USER_WIDTH-1:0] m_axis_tuser_reg = {USER_WIDTH{1'b0}};

      reg [DATA_WIDTH-1:0] temp_m_axis_tdata_reg = {DATA_WIDTH{1'b0}};
      reg [KEEP_WIDTH-1:0] temp_m_axis_tkeep_reg = {KEEP_WIDTH{1'b0}};
      reg temp_m_axis_tvalid_reg = 1'b0, temp_m_axis_tvalid_next;
      reg                  temp_m_axis_tlast_reg = 1'b0;
      reg [  ID_WIDTH-1:0] temp_m_axis_tid_reg = {ID_WIDTH{1'b0}};
      reg [DEST_WIDTH-1:0] temp_m_axis_tdest_reg = {DEST_WIDTH{1'b0}};
      reg [USER_WIDTH-1:0] temp_m_axis_tuser_reg = {USER_WIDTH{1'b0}};

      // datapath control
      reg                  store_axis_input_to_output;
      reg                  store_axis_input_to_temp;
      reg                  store_axis_temp_to_output;

      assign s_axis_tready = s_axis_tready_reg;

      assign m_axis_tdata  = m_axis_tdata_reg;
      assign m_axis_tkeep  = KEEP_ENABLE ? m_axis_tkeep_reg : {KEEP_WIDTH{1'b1}};
      assign m_axis_tvalid = m_axis_tvalid_reg;
      assign m_axis_tlast  = LAST_ENABLE ? m_axis_tlast_reg : 1'b1;
      assign m_axis_tid    = ID_ENABLE   ? m_axis_tid_reg   : {ID_WIDTH{1'b0}};
      assign m_axis_tdest  = DEST_ENABLE ? m_axis_tdest_reg : {DEST_WIDTH{1'b0}};
      assign m_axis_tuser  = USER_ENABLE ? m_axis_tuser_reg : {USER_WIDTH{1'b0}};

      // enable ready input next cycle if output is ready or the temp reg will
      // not be filled on the next cycle (output reg empty or no input)
      wire s_axis_tready_early;
      assign s_axis_tready_early =
          m_axis_tready || (!temp_m_axis_tvalid_reg && (!m_axis_tvalid_reg || !s_axis_tvalid));

      always @* begin
        // transfer sink ready state to source
        m_axis_tvalid_next         = m_axis_tvalid_reg;
        temp_m_axis_tvalid_next    = temp_m_axis_tvalid_reg;

        store_axis_input_to_output = 1'b0;
        store_axis_input_to_temp   = 1'b0;
        store_axis_temp_to_output  = 1'b0;

        if (s_axis_tready_reg) begin
          // input is ready
          if (m_axis_tready || !m_axis_tvalid_reg) begin
            // output is ready or currently not valid, transfer data to output
            m_axis_tvalid_next         = s_axis_tvalid;
            store_axis_input_to_output = 1'b1;
          end
          else begin
            // output is not ready, store input in temp
            temp_m_axis_tvalid_next  = s_axis_tvalid;
            store_axis_input_to_temp = 1'b1;
          end
        end
        else if (m_axis_tready) begin
          // input is not ready, but output is ready
          m_axis_tvalid_next        = temp_m_axis_tvalid_reg;
          temp_m_axis_tvalid_next   = 1'b0;
          store_axis_temp_to_output = 1'b1;
        end
      end

      always @(posedge clk) begin
        s_axis_tready_reg      <= s_axis_tready_early;
        m_axis_tvalid_reg      <= m_axis_tvalid_next;
        temp_m_axis_tvalid_reg <= temp_m_axis_tvalid_next;

        // datapath
        if (store_axis_input_to_output) begin
          m_axis_tdata_reg <= s_axis_tdata;
          m_axis_tkeep_reg <= s_axis_tkeep;
          m_axis_tlast_reg <= s_axis_tlast;
          m_axis_tid_reg   <= s_axis_tid;
          m_axis_tdest_reg <= s_axis_tdest;
          m_axis_tuser_reg <= s_axis_tuser;
        end
        else if (store_axis_temp_to_output) begin
          m_axis_tdata_reg <= temp_m_axis_tdata_reg;
          m_axis_tkeep_reg <= temp_m_axis_tkeep_reg;
          m_axis_tlast_reg <= temp_m_axis_tlast_reg;
          m_axis_tid_reg   <= temp_m_axis_tid_reg;
          m_axis_tdest_reg <= temp_m_axis_tdest_reg;
          m_axis_tuser_reg <= temp_m_axis_tuser_reg;
        end

        if (store_axis_input_to_temp) begin
          temp_m_axis_tdata_reg <= s_axis_tdata;
          temp_m_axis_tkeep_reg <= s_axis_tkeep;
          temp_m_axis_tlast_reg <= s_axis_tlast;
          temp_m_axis_tid_reg   <= s_axis_tid;
          temp_m_axis_tdest_reg <= s_axis_tdest;
          temp_m_axis_tuser_reg <= s_axis_tuser;
        end

        if (rst) begin
          s_axis_tready_reg      <= 1'b0;
          m_axis_tvalid_reg      <= 1'b0;
          temp_m_axis_tvalid_reg <= 1'b0;
        end
      end

    end
    else if (REG_TYPE == 1) begin
      // simple register, inserts bubble cycles

      // datapath registers
      reg                  s_axis_tready_reg = 1'b0;

      reg [DATA_WIDTH-1:0] m_axis_tdata_reg = {DATA_WIDTH{1'b0}};
      reg [KEEP_WIDTH-1:0] m_axis_tkeep_reg = {KEEP_WIDTH{1'b0}};
      reg m_axis_tvalid_reg = 1'b0, m_axis_tvalid_next;
      reg                  m_axis_tlast_reg = 1'b0;
      reg [  ID_WIDTH-1:0] m_axis_tid_reg = {ID_WIDTH{1'b0}};
      reg [DEST_WIDTH-1:0] m_axis_tdest_reg = {DEST_WIDTH{1'b0}};
      reg [USER_WIDTH-1:0] m_axis_tuser_reg = {USER_WIDTH{1'b0}};

      // datapath control
      reg                  store_axis_input_to_output;

      assign s_axis_tready = s_axis_tready_reg;

      assign m_axis_tdata  = m_axis_tdata_reg;
      assign m_axis_tkeep  = KEEP_ENABLE ? m_axis_tkeep_reg : {KEEP_WIDTH{1'b1}};
      assign m_axis_tvalid = m_axis_tvalid_reg;
      assign m_axis_tlast  = LAST_ENABLE ? m_axis_tlast_reg : 1'b1;
      assign m_axis_tid    = ID_ENABLE   ? m_axis_tid_reg   : {ID_WIDTH{1'b0}};
      assign m_axis_tdest  = DEST_ENABLE ? m_axis_tdest_reg : {DEST_WIDTH{1'b0}};
      assign m_axis_tuser  = USER_ENABLE ? m_axis_tuser_reg : {USER_WIDTH{1'b0}};

      // enable ready input next cycle if output buffer will be empty
      wire s_axis_tready_early = !m_axis_tvalid_next;

      always @* begin
        // transfer sink ready state to source
        m_axis_tvalid_next         = m_axis_tvalid_reg;

        store_axis_input_to_output = 1'b0;

        if (s_axis_tready_reg) begin
          m_axis_tvalid_next         = s_axis_tvalid;
          store_axis_input_to_output = 1'b1;
        end
        else if (m_axis_tready) begin
          m_axis_tvalid_next = 1'b0;
        end
      end

      always @(posedge clk) begin
        s_axis_tready_reg <= s_axis_tready_early;
        m_axis_tvalid_reg <= m_axis_tvalid_next;

        // datapath
        if (store_axis_input_to_output) begin
          m_axis_tdata_reg <= s_axis_tdata;
          m_axis_tkeep_reg <= s_axis_tkeep;
          m_axis_tlast_reg <= s_axis_tlast;
          m_axis_tid_reg   <= s_axis_tid;
          m_axis_tdest_reg <= s_axis_tdest;
          m_axis_tuser_reg <= s_axis_tuser;
        end

        if (rst) begin
          s_axis_tready_reg <= 1'b0;
          m_axis_tvalid_reg <= 1'b0;
        end
      end

    end
    else begin
      // bypass

      assign m_axis_tdata  = s_axis_tdata;
      assign m_axis_tkeep  = KEEP_ENABLE ? s_axis_tkeep : {KEEP_WIDTH{1'b1}};
      assign m_axis_tvalid = s_axis_tvalid;
      assign m_axis_tlast  = LAST_ENABLE ? s_axis_tlast : 1'b1;
      assign m_axis_tid    = ID_ENABLE   ? s_axis_tid   : {ID_WIDTH{1'b0}};
      assign m_axis_tdest  = DEST_ENABLE ? s_axis_tdest : {DEST_WIDTH{1'b0}};
      assign m_axis_tuser  = USER_ENABLE ? s_axis_tuser : {USER_WIDTH{1'b0}};

      assign s_axis_tready = m_axis_tready;

    end

  endgenerate

endmodule

`resetall
// verilator lint_on GENUNNAMED
