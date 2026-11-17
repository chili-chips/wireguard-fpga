// SPDX-FileCopyrightText: 2026 Chili.CHIPS
//
// Enhanced by Chili.CHIPS with NLnet-sponsored project
// wireguard-fpga (https://github.com/chili-chips/wireguard-fpga).
// The original header follows.

// Copyright (c) 2013-2023 Alex Forencich
//
// SPDX-License-Identifier: MIT

// Language: Verilog 2001 (ports: SystemVerilog dpe_if, by Chili.CHIPS)

`resetall
`default_nettype none

/*
 * AXI4-Stream FIFO
 */
module axis_fifo
  import dpe_pkg::*;
#(
    // FIFO depth in words
    // KEEP_WIDTH words per cycle if KEEP_ENABLE set
    // Rounded up to nearest power of 2 cycles
    parameter DEPTH                = 4096,
    // Propagate tkeep signal
    // If disabled, tkeep assumed to be 1'b1
    parameter KEEP_ENABLE          = 1,
    // Propagate tlast signal
    parameter LAST_ENABLE          = 1,
    // Propagate tid signal
    // (Chili.CHIPS: on by default, dpe_if carries the peer index in tid)
    parameter ID_ENABLE            = 1,
    // Propagate tuser signal
    parameter USER_ENABLE          = 1,
    // number of RAM pipeline registers
    parameter RAM_PIPELINE         = 1,
    // use output FIFO
    // When set, the RAM read enable and pipeline clock enables are removed
    parameter OUTPUT_FIFO_ENABLE   = 0,
    // Frame FIFO mode - operate on frames instead of cycles
    // When set, m_axis_tvalid will not be deasserted within a frame
    // Requires LAST_ENABLE set
    parameter FRAME_FIFO           = 0,
    // tuser value for bad frame marker
    parameter USER_BAD_FRAME_VALUE = 1'b1,
    // tuser mask for bad frame marker
    parameter USER_BAD_FRAME_MASK  = 1'b1,
    // Drop frames larger than FIFO
    // Requires FRAME_FIFO set
    parameter DROP_OVERSIZE_FRAME  = FRAME_FIFO,
    // Drop frames marked bad
    // Requires FRAME_FIFO and DROP_OVERSIZE_FRAME set
    parameter DROP_BAD_FRAME       = 0,
    // Drop incoming frames when full
    // When set, s_axis_tready is always asserted
    // Requires FRAME_FIFO and DROP_OVERSIZE_FRAME set
    parameter DROP_WHEN_FULL       = 0,
    // Mark incoming frames as bad frames when full
    // When set, s_axis_tready is always asserted
    // Requires FRAME_FIFO to be clear
    parameter MARK_WHEN_FULL       = 0,
    // Enable pause request input
    parameter PAUSE_ENABLE         = 0,
    // Pause between frames
    parameter FRAME_PAUSE          = FRAME_FIFO
) (
    dpe_if.s_axis                 s_axis,
    dpe_if.m_axis                 m_axis,

    /*
     * Pause
     */
    input  wire                   pause_req,
    output wire                   pause_ack,

    /*
     * Status
     */
    output wire [$clog2(DEPTH):0] status_depth,
    output wire [$clog2(DEPTH):0] status_depth_commit,
    output wire                   status_overflow,
    output wire                   status_bad_frame,
    output wire                   status_good_frame
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

  parameter ADDR_WIDTH = (KEEP_ENABLE && KEEP_WIDTH > 1) ? $clog2(
      DEPTH / KEEP_WIDTH
  ) : $clog2(
      DEPTH
  );
  parameter CL_KEEP_WDITH = $clog2(KEEP_WIDTH);

  parameter OUTPUT_FIFO_ADDR_WIDTH = RAM_PIPELINE < 2 ? 3 : $clog2(RAM_PIPELINE * 2 + 7);

  // check configuration
  initial begin
    if (FRAME_FIFO && !LAST_ENABLE) begin
      $error("Error: FRAME_FIFO set requires LAST_ENABLE set (instance %m)");
      $finish;
    end

    if (DROP_OVERSIZE_FRAME && !FRAME_FIFO) begin
      $error("Error: DROP_OVERSIZE_FRAME set requires FRAME_FIFO set (instance %m)");
      $finish;
    end

    if (DROP_BAD_FRAME && !(FRAME_FIFO && DROP_OVERSIZE_FRAME)) begin
      $error("Error: DROP_BAD_FRAME needs FRAME_FIFO and DROP_OVERSIZE_FRAME (instance %m)");
      $finish;
    end

    if (DROP_WHEN_FULL && !(FRAME_FIFO && DROP_OVERSIZE_FRAME)) begin
      $error("Error: DROP_WHEN_FULL needs FRAME_FIFO and DROP_OVERSIZE_FRAME (instance %m)");
      $finish;
    end

    if ((DROP_BAD_FRAME || MARK_WHEN_FULL) && (USER_BAD_FRAME_MASK & {USER_WIDTH{1'b1}}) == 0) begin
      $error("Error: Invalid USER_BAD_FRAME_MASK value (instance %m)");
      $finish;
    end

    if (MARK_WHEN_FULL && FRAME_FIFO) begin
      $error("Error: MARK_WHEN_FULL is not compatible with FRAME_FIFO (instance %m)");
      $finish;
    end

    if (MARK_WHEN_FULL && !LAST_ENABLE) begin
      $error("Error: MARK_WHEN_FULL set requires LAST_ENABLE set (instance %m)");
      $finish;
    end
  end

  localparam KEEP_OFFSET = DATA_WIDTH;
  localparam LAST_OFFSET = KEEP_OFFSET + (KEEP_ENABLE ? KEEP_WIDTH : 0);
  localparam ID_OFFSET   = LAST_OFFSET + (LAST_ENABLE ? 1 : 0);
  localparam DEST_OFFSET = ID_OFFSET + (ID_ENABLE ? ID_WIDTH : 0);
  localparam USER_OFFSET = DEST_OFFSET + (DEST_ENABLE ? DEST_WIDTH : 0);
  localparam WIDTH       = USER_OFFSET + (USER_ENABLE ? USER_WIDTH : 0);

  reg [ADDR_WIDTH:0] wr_ptr_reg = {ADDR_WIDTH + 1{1'b0}};
  reg [ADDR_WIDTH:0] wr_ptr_commit_reg = {ADDR_WIDTH + 1{1'b0}};
  reg [ADDR_WIDTH:0] rd_ptr_reg = {ADDR_WIDTH + 1{1'b0}};

  (* ramstyle = "no_rw_check" *)
  reg [WIDTH-1:0] mem[(2**ADDR_WIDTH)-1:0];
  reg mem_read_data_valid_reg = 1'b0;

  (* shreg_extract = "no" *)
  reg [WIDTH-1:0] m_axis_pipe_reg[RAM_PIPELINE+1-1:0];
  reg [RAM_PIPELINE+1-1:0] m_axis_tvalid_pipe_reg = 0;

  // full when first MSB different but rest same
  wire full = wr_ptr_reg == (rd_ptr_reg ^ {1'b1, {ADDR_WIDTH{1'b0}}});
  // empty when pointers match exactly
  wire empty = wr_ptr_commit_reg == rd_ptr_reg;
  // overflow within packet
  wire full_wr = wr_ptr_reg == (wr_ptr_commit_reg ^ {1'b1, {ADDR_WIDTH{1'b0}}});

  reg s_frame_reg = 1'b0;

  reg drop_frame_reg = 1'b0;
  reg mark_frame_reg = 1'b0;
  reg send_frame_reg = 1'b0;
  reg [ADDR_WIDTH:0] depth_reg = 0;
  reg [ADDR_WIDTH:0] depth_commit_reg = 0;
  reg overflow_reg = 1'b0;
  reg bad_frame_reg = 1'b0;
  reg good_frame_reg = 1'b0;

  assign s_axis_tready = FRAME_FIFO
                       ? (!full || (full_wr && DROP_OVERSIZE_FRAME) || DROP_WHEN_FULL)
                       : (!full || MARK_WHEN_FULL);

  wire [WIDTH-1:0] s_axis_word;

  generate
    assign s_axis_word[DATA_WIDTH-1:0] = s_axis_tdata;
    if (KEEP_ENABLE) begin : g_keep
      assign s_axis_word[KEEP_OFFSET+:KEEP_WIDTH] = s_axis_tkeep;
    end
    if (LAST_ENABLE) begin : g_last
      assign s_axis_word[LAST_OFFSET] = s_axis_tlast | mark_frame_reg;
    end
    if (ID_ENABLE) begin : g_id
      assign s_axis_word[ID_OFFSET+:ID_WIDTH] = s_axis_tid;
    end
    if (DEST_ENABLE) begin : g_dest
      assign s_axis_word[DEST_OFFSET+:DEST_WIDTH] = s_axis_tdest;
    end
    if (USER_ENABLE) begin : g_user
      assign s_axis_word[USER_OFFSET+:USER_WIDTH] = mark_frame_reg
                                                  ? USER_BAD_FRAME_VALUE
                                                  : s_axis_tuser;
    end
  endgenerate

  wire [     WIDTH-1:0] m_axis_word = m_axis_pipe_reg[RAM_PIPELINE+1-1];

  wire                  m_axis_tready_pipe;
  wire                  m_axis_tvalid_pipe = m_axis_tvalid_pipe_reg[RAM_PIPELINE+1-1];

  wire [DATA_WIDTH-1:0] m_axis_tdata_pipe = m_axis_word[DATA_WIDTH-1:0];
  wire [KEEP_WIDTH-1:0] m_axis_tkeep_pipe;
  assign m_axis_tkeep_pipe = KEEP_ENABLE
                           ? m_axis_word[KEEP_OFFSET+:KEEP_WIDTH]
                           : {KEEP_WIDTH{1'b1}};
  wire                m_axis_tlast_pipe = LAST_ENABLE ? m_axis_word[LAST_OFFSET] : 1'b1;
  wire [ID_WIDTH-1:0] m_axis_tid_pipe;
  assign m_axis_tid_pipe = ID_ENABLE ? m_axis_word[ID_OFFSET+:ID_WIDTH] : {ID_WIDTH{1'b0}};
  wire [DEST_WIDTH-1:0] m_axis_tdest_pipe;
  assign m_axis_tdest_pipe = DEST_ENABLE
                           ? m_axis_word[DEST_OFFSET+:DEST_WIDTH]
                           : {DEST_WIDTH{1'b0}};
  wire [USER_WIDTH-1:0] m_axis_tuser_pipe;
  assign m_axis_tuser_pipe = USER_ENABLE
                           ? m_axis_word[USER_OFFSET+:USER_WIDTH]
                           : {USER_WIDTH{1'b0}};

  wire                  m_axis_tready_out;
  wire                  m_axis_tvalid_out;

  wire [DATA_WIDTH-1:0] m_axis_tdata_out;
  wire [KEEP_WIDTH-1:0] m_axis_tkeep_out;
  wire                  m_axis_tlast_out;
  wire [  ID_WIDTH-1:0] m_axis_tid_out;
  wire [DEST_WIDTH-1:0] m_axis_tdest_out;
  wire [USER_WIDTH-1:0] m_axis_tuser_out;

  wire                  pipe_ready;

  assign status_depth = (KEEP_ENABLE && KEEP_WIDTH > 1)
                      ? {depth_reg, {CL_KEEP_WDITH{1'b0}}}
                      : depth_reg;
  assign status_depth_commit = (KEEP_ENABLE && KEEP_WIDTH > 1)
                             ? {depth_commit_reg, {CL_KEEP_WDITH{1'b0}}}
                             : depth_commit_reg;
  assign status_overflow = overflow_reg;
  assign status_bad_frame = bad_frame_reg;
  assign status_good_frame = good_frame_reg;

  // the tuser of a beat marks a bad frame
  wire s_axis_tuser_bad;
  assign s_axis_tuser_bad =
      DROP_BAD_FRAME && |(USER_BAD_FRAME_MASK & ~(s_axis_tuser ^ USER_BAD_FRAME_VALUE));

  // Write logic
  always @(posedge clk) begin
    overflow_reg   <= 1'b0;
    bad_frame_reg  <= 1'b0;
    good_frame_reg <= 1'b0;

    if (s_axis_tready && s_axis_tvalid && LAST_ENABLE) begin
      // track input frame status
      s_frame_reg <= !s_axis_tlast;
    end

    if (FRAME_FIFO) begin
      // frame FIFO mode
      if (s_axis_tready && s_axis_tvalid) begin
        // transfer in
        if ((full && DROP_WHEN_FULL) || (full_wr && DROP_OVERSIZE_FRAME) || drop_frame_reg) begin
          // full, packet overflow, or currently dropping frame
          // drop frame
          drop_frame_reg <= 1'b1;
          if (s_axis_tlast) begin
            // end of frame, reset write pointer
            wr_ptr_reg     <= wr_ptr_commit_reg;
            drop_frame_reg <= 1'b0;
            overflow_reg   <= 1'b1;
          end
        end
        else begin
          // store it
          mem[wr_ptr_reg[ADDR_WIDTH-1:0]] <= s_axis_word;
          wr_ptr_reg                      <= wr_ptr_reg + 1;
          if (s_axis_tlast || (!DROP_OVERSIZE_FRAME && (full_wr || send_frame_reg))) begin
            // end of frame or send frame
            send_frame_reg <= !s_axis_tlast;
            if (s_axis_tlast && s_axis_tuser_bad) begin
              // bad packet, reset write pointer
              wr_ptr_reg    <= wr_ptr_commit_reg;
              bad_frame_reg <= 1'b1;
            end
            else begin
              // good packet or packet overflow, update write pointer
              wr_ptr_commit_reg <= wr_ptr_reg + 1;
              good_frame_reg    <= s_axis_tlast;
            end
          end
        end
      end
      else if (s_axis_tvalid && full_wr && !DROP_OVERSIZE_FRAME) begin
        // data valid with packet overflow
        // update write pointer
        send_frame_reg    <= 1'b1;
        wr_ptr_commit_reg <= wr_ptr_reg;
      end
    end
    else begin
      // normal FIFO mode
      if (s_axis_tready && s_axis_tvalid) begin
        if (drop_frame_reg && MARK_WHEN_FULL) begin
          // currently dropping frame
          if (s_axis_tlast) begin
            // end of frame
            if (!full && mark_frame_reg) begin
              // terminate marked frame
              mark_frame_reg                  <= 1'b0;
              mem[wr_ptr_reg[ADDR_WIDTH-1:0]] <= s_axis_word;
              wr_ptr_reg                      <= wr_ptr_reg + 1;
              wr_ptr_commit_reg               <= wr_ptr_reg + 1;
            end
            // end of frame, clear drop flag
            drop_frame_reg <= 1'b0;
            overflow_reg   <= 1'b1;
          end
        end
        else if ((full || mark_frame_reg) && MARK_WHEN_FULL) begin
          // full or marking frame
          // drop frame; mark if this isn't the first cycle
          drop_frame_reg <= 1'b1;
          mark_frame_reg <= mark_frame_reg || s_frame_reg;
          if (s_axis_tlast) begin
            drop_frame_reg <= 1'b0;
            overflow_reg   <= 1'b1;
          end
        end
        else begin
          // transfer in
          mem[wr_ptr_reg[ADDR_WIDTH-1:0]] <= s_axis_word;
          wr_ptr_reg                      <= wr_ptr_reg + 1;
          wr_ptr_commit_reg               <= wr_ptr_reg + 1;
        end
      end
      else if ((!full && !drop_frame_reg && mark_frame_reg) && MARK_WHEN_FULL) begin
        // terminate marked frame
        mark_frame_reg                  <= 1'b0;
        mem[wr_ptr_reg[ADDR_WIDTH-1:0]] <= s_axis_word;
        wr_ptr_reg                      <= wr_ptr_reg + 1;
        wr_ptr_commit_reg               <= wr_ptr_reg + 1;
      end
    end

    if (rst) begin
      wr_ptr_reg        <= {ADDR_WIDTH + 1{1'b0}};
      wr_ptr_commit_reg <= {ADDR_WIDTH + 1{1'b0}};

      s_frame_reg       <= 1'b0;

      drop_frame_reg    <= 1'b0;
      mark_frame_reg    <= 1'b0;
      send_frame_reg    <= 1'b0;
      overflow_reg      <= 1'b0;
      bad_frame_reg     <= 1'b0;
      good_frame_reg    <= 1'b0;
    end
  end

  // Status
  always @(posedge clk) begin
    depth_reg        <= wr_ptr_reg - rd_ptr_reg;
    depth_commit_reg <= wr_ptr_commit_reg - rd_ptr_reg;
  end

  // Read logic
  integer j;

  always @(posedge clk) begin
    if (m_axis_tready_pipe) begin
      // output ready; invalidate stage
      m_axis_tvalid_pipe_reg[RAM_PIPELINE+1-1] <= 1'b0;
    end

    for (j = RAM_PIPELINE + 1 - 1; j > 0; j = j - 1) begin
      if (m_axis_tready_pipe || ((~m_axis_tvalid_pipe_reg) >> j)) begin
        // output ready or bubble in pipeline; transfer down pipeline
        m_axis_tvalid_pipe_reg[j]   <= m_axis_tvalid_pipe_reg[j-1];
        m_axis_pipe_reg[j]          <= m_axis_pipe_reg[j-1];
        m_axis_tvalid_pipe_reg[j-1] <= 1'b0;
      end
    end

    if (m_axis_tready_pipe || ~m_axis_tvalid_pipe_reg) begin
      // output ready or bubble in pipeline; read new data from FIFO
      m_axis_tvalid_pipe_reg[0] <= 1'b0;
      m_axis_pipe_reg[0]        <= mem[rd_ptr_reg[ADDR_WIDTH-1:0]];
      if (!empty && pipe_ready) begin
        // not empty, increment pointer
        m_axis_tvalid_pipe_reg[0] <= 1'b1;
        rd_ptr_reg                <= rd_ptr_reg + 1;
      end
    end

    if (rst) begin
      rd_ptr_reg             <= {ADDR_WIDTH + 1{1'b0}};
      m_axis_tvalid_pipe_reg <= 0;
    end
  end

  generate

    if (!OUTPUT_FIFO_ENABLE) begin

      assign pipe_ready         = 1'b1;

      assign m_axis_tready_pipe = m_axis_tready_out;
      assign m_axis_tvalid_out  = m_axis_tvalid_pipe;

      assign m_axis_tdata_out   = m_axis_tdata_pipe;
      assign m_axis_tkeep_out   = m_axis_tkeep_pipe;
      assign m_axis_tlast_out   = m_axis_tlast_pipe;
      assign m_axis_tid_out     = m_axis_tid_pipe;
      assign m_axis_tdest_out   = m_axis_tdest_pipe;
      assign m_axis_tuser_out   = m_axis_tuser_pipe;

    end
    else begin : output_fifo

      // output datapath logic
      reg  [              DATA_WIDTH-1:0] m_axis_tdata_reg = {DATA_WIDTH{1'b0}};
      reg  [              KEEP_WIDTH-1:0] m_axis_tkeep_reg = {KEEP_WIDTH{1'b0}};
      reg                                 m_axis_tvalid_reg = 1'b0;
      reg                                 m_axis_tlast_reg = 1'b0;
      reg  [                ID_WIDTH-1:0] m_axis_tid_reg = {ID_WIDTH{1'b0}};
      reg  [              DEST_WIDTH-1:0] m_axis_tdest_reg = {DEST_WIDTH{1'b0}};
      reg  [              USER_WIDTH-1:0] m_axis_tuser_reg = {USER_WIDTH{1'b0}};

      reg  [OUTPUT_FIFO_ADDR_WIDTH+1-1:0] out_fifo_wr_ptr_reg = 0;
      reg  [OUTPUT_FIFO_ADDR_WIDTH+1-1:0] out_fifo_rd_ptr_reg = 0;
      reg                                 out_fifo_half_full_reg = 1'b0;

      wire                                out_fifo_full;

      assign out_fifo_full =
          out_fifo_wr_ptr_reg == (out_fifo_rd_ptr_reg ^ {1'b1, {OUTPUT_FIFO_ADDR_WIDTH{1'b0}}});
      wire out_fifo_empty = out_fifo_wr_ptr_reg == out_fifo_rd_ptr_reg;

      (* ram_style = "distributed", ramstyle = "no_rw_check, mlab" *)
      reg [DATA_WIDTH-1:0] out_fifo_tdata[2**OUTPUT_FIFO_ADDR_WIDTH-1:0];
      (* ram_style = "distributed", ramstyle = "no_rw_check, mlab" *)
      reg [KEEP_WIDTH-1:0] out_fifo_tkeep[2**OUTPUT_FIFO_ADDR_WIDTH-1:0];
      (* ram_style = "distributed", ramstyle = "no_rw_check, mlab" *)
      reg out_fifo_tlast[2**OUTPUT_FIFO_ADDR_WIDTH-1:0];
      (* ram_style = "distributed", ramstyle = "no_rw_check, mlab" *)
      reg [ID_WIDTH-1:0] out_fifo_tid[2**OUTPUT_FIFO_ADDR_WIDTH-1:0];
      (* ram_style = "distributed", ramstyle = "no_rw_check, mlab" *)
      reg [DEST_WIDTH-1:0] out_fifo_tdest[2**OUTPUT_FIFO_ADDR_WIDTH-1:0];
      (* ram_style = "distributed", ramstyle = "no_rw_check, mlab" *)
      reg [USER_WIDTH-1:0] out_fifo_tuser[2**OUTPUT_FIFO_ADDR_WIDTH-1:0];

      assign pipe_ready         = !out_fifo_half_full_reg;

      assign m_axis_tready_pipe = 1'b1;

      assign m_axis_tdata_out   = m_axis_tdata_reg;
      assign m_axis_tkeep_out   = KEEP_ENABLE ? m_axis_tkeep_reg : {KEEP_WIDTH{1'b1}};
      assign m_axis_tvalid_out  = m_axis_tvalid_reg;
      assign m_axis_tlast_out   = LAST_ENABLE ? m_axis_tlast_reg : 1'b1;
      assign m_axis_tid_out     = ID_ENABLE   ? m_axis_tid_reg   : {ID_WIDTH{1'b0}};
      assign m_axis_tdest_out   = DEST_ENABLE ? m_axis_tdest_reg : {DEST_WIDTH{1'b0}};
      assign m_axis_tuser_out   = USER_ENABLE ? m_axis_tuser_reg : {USER_WIDTH{1'b0}};

      always @(posedge clk) begin
        m_axis_tvalid_reg <= m_axis_tvalid_reg && !m_axis_tready_out;

        out_fifo_half_full_reg <= $unsigned(
            out_fifo_wr_ptr_reg - out_fifo_rd_ptr_reg
        ) >= 2 ** (OUTPUT_FIFO_ADDR_WIDTH - 1);

        if (!out_fifo_full && m_axis_tvalid_pipe) begin
          out_fifo_tdata[out_fifo_wr_ptr_reg[OUTPUT_FIFO_ADDR_WIDTH-1:0]] <= m_axis_tdata_pipe;
          out_fifo_tkeep[out_fifo_wr_ptr_reg[OUTPUT_FIFO_ADDR_WIDTH-1:0]] <= m_axis_tkeep_pipe;
          out_fifo_tlast[out_fifo_wr_ptr_reg[OUTPUT_FIFO_ADDR_WIDTH-1:0]] <= m_axis_tlast_pipe;
          out_fifo_tid[out_fifo_wr_ptr_reg[OUTPUT_FIFO_ADDR_WIDTH-1:0]] <= m_axis_tid_pipe;
          out_fifo_tdest[out_fifo_wr_ptr_reg[OUTPUT_FIFO_ADDR_WIDTH-1:0]] <= m_axis_tdest_pipe;
          out_fifo_tuser[out_fifo_wr_ptr_reg[OUTPUT_FIFO_ADDR_WIDTH-1:0]] <= m_axis_tuser_pipe;
          out_fifo_wr_ptr_reg <= out_fifo_wr_ptr_reg + 1;
        end

        if (!out_fifo_empty && (!m_axis_tvalid_reg || m_axis_tready_out)) begin
          m_axis_tdata_reg    <= out_fifo_tdata[out_fifo_rd_ptr_reg[OUTPUT_FIFO_ADDR_WIDTH-1:0]];
          m_axis_tkeep_reg    <= out_fifo_tkeep[out_fifo_rd_ptr_reg[OUTPUT_FIFO_ADDR_WIDTH-1:0]];
          m_axis_tvalid_reg   <= 1'b1;
          m_axis_tlast_reg    <= out_fifo_tlast[out_fifo_rd_ptr_reg[OUTPUT_FIFO_ADDR_WIDTH-1:0]];
          m_axis_tid_reg      <= out_fifo_tid[out_fifo_rd_ptr_reg[OUTPUT_FIFO_ADDR_WIDTH-1:0]];
          m_axis_tdest_reg    <= out_fifo_tdest[out_fifo_rd_ptr_reg[OUTPUT_FIFO_ADDR_WIDTH-1:0]];
          m_axis_tuser_reg    <= out_fifo_tuser[out_fifo_rd_ptr_reg[OUTPUT_FIFO_ADDR_WIDTH-1:0]];
          out_fifo_rd_ptr_reg <= out_fifo_rd_ptr_reg + 1;
        end

        if (rst) begin
          out_fifo_wr_ptr_reg <= 0;
          out_fifo_rd_ptr_reg <= 0;
          m_axis_tvalid_reg   <= 1'b0;
        end
      end

    end

    if (PAUSE_ENABLE) begin : pause

      // Pause logic
      reg pause_reg = 1'b0;
      reg pause_frame_reg = 1'b0;

      assign m_axis_tready_out = m_axis_tready && !pause_reg;
      assign m_axis_tvalid     = m_axis_tvalid_out && !pause_reg;

      assign m_axis_tdata      = m_axis_tdata_out;
      assign m_axis_tkeep      = m_axis_tkeep_out;
      assign m_axis_tlast      = m_axis_tlast_out;
      assign m_axis_tid        = m_axis_tid_out;
      assign m_axis_tdest      = m_axis_tdest_out;
      assign m_axis_tuser      = m_axis_tuser_out;

      assign pause_ack         = pause_reg;

      always @(posedge clk) begin
        if (FRAME_PAUSE) begin
          if (pause_reg) begin
            // paused; update pause status
            pause_reg <= pause_req;
          end
          else if (m_axis_tvalid_out) begin
            // frame transfer; set frame bit
            pause_frame_reg <= 1'b1;
            if (m_axis_tready && m_axis_tlast) begin
              // end of frame; clear frame bit and update pause status
              pause_frame_reg <= 1'b0;
              pause_reg       <= pause_req;
            end
          end
          else if (!pause_frame_reg) begin
            // idle; update pause status
            pause_reg <= pause_req;
          end
        end
        else begin
          pause_reg <= pause_req;
        end

        if (rst) begin
          pause_frame_reg <= 1'b0;
          pause_reg       <= 1'b0;
        end
      end

    end
    else begin

      assign m_axis_tready_out = m_axis_tready;
      assign m_axis_tvalid     = m_axis_tvalid_out;

      assign m_axis_tdata      = m_axis_tdata_out;
      assign m_axis_tkeep      = m_axis_tkeep_out;
      assign m_axis_tlast      = m_axis_tlast_out;
      assign m_axis_tid        = m_axis_tid_out;
      assign m_axis_tdest      = m_axis_tdest_out;
      assign m_axis_tuser      = m_axis_tuser_out;

      assign pause_ack         = 1'b0;

    end

  endgenerate

endmodule

`resetall
