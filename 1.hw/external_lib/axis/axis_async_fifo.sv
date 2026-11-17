// SPDX-FileCopyrightText: 2026 Chili.CHIPS
//
// Enhanced by Chili.CHIPS with NLnet-sponsored project
// wireguard-fpga (https://github.com/chili-chips/wireguard-fpga).
// The original header follows.

// verilator lint_off GENUNNAMED
// verilator lint_off UNUSED

// Copyright (c) 2014-2023 Alex Forencich
//
// SPDX-License-Identifier: MIT

// Language: Verilog 2001

`resetall
`default_nettype none

/*
 * AXI4-Stream asynchronous FIFO
 */
module axis_async_fifo #(
    // FIFO depth in words
    // KEEP_WIDTH words per cycle if KEEP_ENABLE set
    // Rounded up to nearest power of 2 cycles
    parameter DEPTH                = 4096,
    // Width of AXI stream interfaces in bits
    parameter DATA_WIDTH           = 8,
    // Propagate tkeep signal
    // If disabled, tkeep assumed to be 1'b1
    parameter KEEP_ENABLE          = (DATA_WIDTH > 8),
    // tkeep signal width (words per cycle)
    parameter KEEP_WIDTH           = ((DATA_WIDTH + 7) / 8),
    // Propagate tlast signal
    parameter LAST_ENABLE          = 1,
    // Propagate tid signal
    parameter ID_ENABLE            = 0,
    // tid signal width
    parameter ID_WIDTH             = 8,
    // Propagate tdest signal
    parameter DEST_ENABLE          = 0,
    // tdest signal width
    parameter DEST_WIDTH           = 8,
    // Propagate tuser signal
    parameter USER_ENABLE          = 1,
    // tuser signal width
    parameter USER_WIDTH           = 1,
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
    /*
     * AXI input
     */
    input  logic                   s_clk,
    input  logic                   s_rst,
    input  logic [DATA_WIDTH-1:0]  s_axis_tdata,
    input  logic [KEEP_WIDTH-1:0]  s_axis_tkeep,
    input  logic                   s_axis_tvalid,
    output logic                   s_axis_tready,
    input  logic                   s_axis_tlast,
    input  logic [  ID_WIDTH-1:0]  s_axis_tid,
    input  logic [DEST_WIDTH-1:0]  s_axis_tdest,
    input  logic [USER_WIDTH-1:0]  s_axis_tuser,

    /*
     * AXI output
     */
    input  logic                   m_clk,
    input  logic                   m_rst,
    output logic [DATA_WIDTH-1:0]  m_axis_tdata,
    output logic [KEEP_WIDTH-1:0]  m_axis_tkeep,
    output logic                   m_axis_tvalid,
    input  logic                   m_axis_tready,
    output logic                   m_axis_tlast,
    output logic [  ID_WIDTH-1:0]  m_axis_tid,
    output logic [DEST_WIDTH-1:0]  m_axis_tdest,
    output logic [USER_WIDTH-1:0]  m_axis_tuser,

    /*
     * Pause
     */
    input  logic                   s_pause_req,
    output logic                   s_pause_ack,
    input  logic                   m_pause_req,
    output logic                   m_pause_ack,

    /*
     * Status
     */
    output logic [$clog2(DEPTH):0] s_status_depth,
    output logic [$clog2(DEPTH):0] s_status_depth_commit,
    output logic                   s_status_overflow,
    output logic                   s_status_bad_frame,
    output logic                   s_status_good_frame,
    output logic [$clog2(DEPTH):0] m_status_depth,
    output logic [$clog2(DEPTH):0] m_status_depth_commit,
    output logic                   m_status_overflow,
    output logic                   m_status_bad_frame,
    output logic                   m_status_good_frame
);

  // verilator lint_off WIDTHTRUNC
  parameter ADDR_WIDTH = (KEEP_ENABLE && KEEP_WIDTH > 1) ? $clog2(
      DEPTH / KEEP_WIDTH
  ) : $clog2(
      DEPTH
  );
  // verilator lint_on WIDTHTRUNC
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
  // verilator lint_off WIDTHTRUNC
  localparam LAST_OFFSET = KEEP_OFFSET + (KEEP_ENABLE ? KEEP_WIDTH : 0);
  // verilator lint_on WIDTHTRUNC
  localparam ID_OFFSET   = LAST_OFFSET + (LAST_ENABLE ? 1 : 0);
  localparam DEST_OFFSET = ID_OFFSET + (ID_ENABLE ? ID_WIDTH : 0);
  localparam USER_OFFSET = DEST_OFFSET + (DEST_ENABLE ? DEST_WIDTH : 0);
  localparam WIDTH       = USER_OFFSET + (USER_ENABLE ? USER_WIDTH : 0);

  function automatic [ADDR_WIDTH:0] bin2gray(input [ADDR_WIDTH:0] b);
    bin2gray = b ^ (b >> 1);
  endfunction

  function automatic [ADDR_WIDTH:0] gray2bin(input [ADDR_WIDTH:0] g);
    integer i;
    for (i = 0; i <= ADDR_WIDTH; i = i + 1) begin
      gray2bin[i] = ^(g >> i);
    end
  endfunction

  logic [ADDR_WIDTH:0] wr_ptr_reg = {ADDR_WIDTH + 1{1'b0}};
  logic [ADDR_WIDTH:0] wr_ptr_commit_reg = {ADDR_WIDTH + 1{1'b0}};
  logic [ADDR_WIDTH:0] wr_ptr_gray_reg = {ADDR_WIDTH + 1{1'b0}};
  logic [ADDR_WIDTH:0] wr_ptr_sync_commit_reg = {ADDR_WIDTH + 1{1'b0}};
  logic [ADDR_WIDTH:0] rd_ptr_reg = {ADDR_WIDTH + 1{1'b0}};
  logic [ADDR_WIDTH:0] rd_ptr_gray_reg = {ADDR_WIDTH + 1{1'b0}};
  logic [ADDR_WIDTH:0] wr_ptr_conv_reg = {ADDR_WIDTH + 1{1'b0}};
  logic [ADDR_WIDTH:0] rd_ptr_conv_reg = {ADDR_WIDTH + 1{1'b0}};

  // the pointers plus one (Chili.CHIPS: in place of blocking temporaries in the always_ff)
  logic [ADDR_WIDTH:0] wr_ptr_inc;
  assign               wr_ptr_inc = wr_ptr_reg + 1;
  logic [ADDR_WIDTH:0] rd_ptr_inc;
  assign               rd_ptr_inc = rd_ptr_reg + 1;

  (* SHREG_EXTRACT = "NO" *)
  logic [      ADDR_WIDTH:0] wr_ptr_gray_sync1_reg = {ADDR_WIDTH + 1{1'b0}};
  (* SHREG_EXTRACT = "NO" *)
  logic [      ADDR_WIDTH:0] wr_ptr_gray_sync2_reg = {ADDR_WIDTH + 1{1'b0}};
  (* SHREG_EXTRACT = "NO" *)
  logic [      ADDR_WIDTH:0] wr_ptr_commit_sync_reg = {ADDR_WIDTH + 1{1'b0}};
  (* SHREG_EXTRACT = "NO" *)
  logic [      ADDR_WIDTH:0] rd_ptr_gray_sync1_reg = {ADDR_WIDTH + 1{1'b0}};
  (* SHREG_EXTRACT = "NO" *)
  logic [      ADDR_WIDTH:0] rd_ptr_gray_sync2_reg = {ADDR_WIDTH + 1{1'b0}};

  logic                      wr_ptr_update_valid_reg = 1'b0;
  logic                      wr_ptr_update_reg = 1'b0;
  (* SHREG_EXTRACT = "NO" *)
  logic                      wr_ptr_update_sync1_reg = 1'b0;
  (* SHREG_EXTRACT = "NO" *)
  logic                      wr_ptr_update_sync2_reg = 1'b0;
  (* SHREG_EXTRACT = "NO" *)
  logic                      wr_ptr_update_sync3_reg = 1'b0;
  (* SHREG_EXTRACT = "NO" *)
  logic                      wr_ptr_update_ack_sync1_reg = 1'b0;
  (* SHREG_EXTRACT = "NO" *)
  logic                      wr_ptr_update_ack_sync2_reg = 1'b0;

  (* SHREG_EXTRACT = "NO" *)
  logic                      s_rst_sync1_reg = 1'b1;
  (* SHREG_EXTRACT = "NO" *)
  logic                      s_rst_sync2_reg = 1'b1;
  (* SHREG_EXTRACT = "NO" *)
  logic                      s_rst_sync3_reg = 1'b1;
  (* SHREG_EXTRACT = "NO" *)
  logic                      m_rst_sync1_reg = 1'b1;
  (* SHREG_EXTRACT = "NO" *)
  logic                      m_rst_sync2_reg = 1'b1;
  (* SHREG_EXTRACT = "NO" *)
  logic                      m_rst_sync3_reg = 1'b1;

  (* ramstyle = "no_rw_check" *)
  logic [         WIDTH-1:0] mem                                             [(2**ADDR_WIDTH)-1:0];
  logic                      mem_read_data_valid_reg = 1'b0;

  (* shreg_extract = "no" *)
  logic [         WIDTH-1:0] m_axis_pipe_reg                                 [ RAM_PIPELINE+1-1:0];
  logic [RAM_PIPELINE+1-1:0] m_axis_tvalid_pipe_reg = 0;

  // full when first TWO MSBs do NOT match, but rest matches
  // (gray code equivalent of first MSB different but rest same)
  logic  full;
  assign full = wr_ptr_gray_reg == (rd_ptr_gray_sync2_reg ^ {2'b11, {ADDR_WIDTH - 1{1'b0}}});
  // empty when pointers match exactly
  logic  empty;
  assign empty = FRAME_FIFO
             ? (rd_ptr_reg == wr_ptr_commit_sync_reg)
             : (rd_ptr_gray_reg == wr_ptr_gray_sync2_reg);
  // overflow within packet
  logic  full_wr;
  assign full_wr = wr_ptr_reg == (wr_ptr_commit_reg ^ {1'b1, {ADDR_WIDTH{1'b0}}});

  // control signals
  logic                write;
  logic                read;
  logic                store_output;

  logic                s_frame_reg = 1'b0;
  logic                m_frame_reg = 1'b0;

  logic                drop_frame_reg = 1'b0;
  logic                mark_frame_reg = 1'b0;
  logic                send_frame_reg = 1'b0;
  logic                overflow_reg = 1'b0;
  logic                bad_frame_reg = 1'b0;
  logic                good_frame_reg = 1'b0;

  logic                m_drop_frame_reg = 1'b0;
  logic                m_terminate_frame_reg = 1'b0;

  logic [ADDR_WIDTH:0] s_depth_reg = 0;
  logic [ADDR_WIDTH:0] s_depth_commit_reg = 0;
  logic [ADDR_WIDTH:0] m_depth_reg = 0;
  logic [ADDR_WIDTH:0] m_depth_commit_reg = 0;

  logic                overflow_sync1_reg = 1'b0;
  logic                overflow_sync2_reg = 1'b0;
  logic                overflow_sync3_reg = 1'b0;
  logic                overflow_sync4_reg = 1'b0;
  logic                bad_frame_sync1_reg = 1'b0;
  logic                bad_frame_sync2_reg = 1'b0;
  logic                bad_frame_sync3_reg = 1'b0;
  logic                bad_frame_sync4_reg = 1'b0;
  logic                good_frame_sync1_reg = 1'b0;
  logic                good_frame_sync2_reg = 1'b0;
  logic                good_frame_sync3_reg = 1'b0;
  logic                good_frame_sync4_reg = 1'b0;

  // ready by the FIFO's fill, before the reset
  logic                s_axis_ready_fifo;
  assign s_axis_ready_fifo = FRAME_FIFO
                         ? (!full || (full_wr && DROP_OVERSIZE_FRAME) || DROP_WHEN_FULL)
                         : (!full || MARK_WHEN_FULL);
  assign s_axis_tready = s_axis_ready_fifo && !s_rst_sync3_reg;

  logic [WIDTH-1:0] s_axis;

  generate
    assign s_axis[DATA_WIDTH-1:0] = s_axis_tdata;
    // verilator lint_off WIDTHTRUNC
    if (KEEP_ENABLE) begin : g_keep
      assign s_axis[KEEP_OFFSET+:KEEP_WIDTH] = s_axis_tkeep;
    end
    // verilator lint_on WIDTHTRUNC
    if (LAST_ENABLE) begin : g_last
      assign s_axis[LAST_OFFSET] = s_axis_tlast | mark_frame_reg;
    end
    if (ID_ENABLE) begin : g_id
      assign s_axis[ID_OFFSET+:ID_WIDTH] = s_axis_tid;
    end
    if (DEST_ENABLE) begin : g_dest
      assign s_axis[DEST_OFFSET+:DEST_WIDTH] = s_axis_tdest;
    end
    if (USER_ENABLE) begin : g_user
      assign s_axis[USER_OFFSET+:USER_WIDTH] = mark_frame_reg ? USER_BAD_FRAME_VALUE : s_axis_tuser;
    end
  endgenerate

  logic [WIDTH-1:0] m_axis;
  assign            m_axis = m_axis_pipe_reg[RAM_PIPELINE+1-1];

  logic  m_axis_tready_pipe;
  logic  m_axis_tvalid_pipe;
  assign m_axis_tvalid_pipe = m_axis_tvalid_pipe_reg[RAM_PIPELINE+1-1];

  logic [DATA_WIDTH-1:0] m_axis_tdata_pipe;
  assign m_axis_tdata_pipe = m_axis[DATA_WIDTH-1:0];
  // verilator lint_off WIDTHTRUNC
  logic [KEEP_WIDTH-1:0] m_axis_tkeep_pipe;
  assign m_axis_tkeep_pipe = KEEP_ENABLE ? m_axis[KEEP_OFFSET+:KEEP_WIDTH] : {KEEP_WIDTH{1'b1}};
  // verilator lint_on WIDTHTRUNC
  logic m_axis_tlast_pipe;
  assign m_axis_tlast_pipe = LAST_ENABLE ? m_axis[LAST_OFFSET] | m_terminate_frame_reg : 1'b1;
  // verilator lint_off SELRANGE
  logic [ID_WIDTH-1:0] m_axis_tid_pipe;
  assign m_axis_tid_pipe = ID_ENABLE ? m_axis[ID_OFFSET+:ID_WIDTH] : {ID_WIDTH{1'b0}};
  logic [DEST_WIDTH-1:0] m_axis_tdest_pipe;
  assign m_axis_tdest_pipe = DEST_ENABLE ? m_axis[DEST_OFFSET+:DEST_WIDTH] : {DEST_WIDTH{1'b0}};
  // verilator lint_on SELRANGE
  logic [USER_WIDTH-1:0] m_axis_tuser_fifo;  // tuser from the FIFO, or the bad-frame value
  assign m_axis_tuser_fifo = m_terminate_frame_reg
                           ? USER_BAD_FRAME_VALUE
                           : m_axis[USER_OFFSET +: USER_WIDTH];

  logic [USER_WIDTH-1:0] m_axis_tuser_pipe;
  assign                 m_axis_tuser_pipe = USER_ENABLE ? m_axis_tuser_fifo : {USER_WIDTH{1'b0}};

  logic                  m_axis_tready_out;
  logic                  m_axis_tvalid_out;

  logic [DATA_WIDTH-1:0] m_axis_tdata_out;
  logic [KEEP_WIDTH-1:0] m_axis_tkeep_out;
  logic                  m_axis_tlast_out;
  logic [  ID_WIDTH-1:0] m_axis_tid_out;
  logic [DEST_WIDTH-1:0] m_axis_tdest_out;
  logic [USER_WIDTH-1:0] m_axis_tuser_out;

  logic                  pipe_ready;

  // verilator lint_off WIDTHEXPAND
  // verilator lint_off WIDTHTRUNC
  assign s_status_depth = (KEEP_ENABLE && KEEP_WIDTH > 1)
                        ? {s_depth_reg, {CL_KEEP_WDITH{1'b0}}}
                        : s_depth_reg;
  assign s_status_depth_commit = (KEEP_ENABLE && KEEP_WIDTH > 1)
                               ? {s_depth_commit_reg, {CL_KEEP_WDITH{1'b0}}}
                               : s_depth_commit_reg;
  // verilator lint_on WIDTHEXPAND
  // verilator lint_on WIDTHTRUNC
  assign s_status_overflow = overflow_reg;
  assign s_status_bad_frame = bad_frame_reg;
  assign s_status_good_frame = good_frame_reg;

  // verilator lint_off WIDTHEXPAND
  // verilator lint_off WIDTHTRUNC
  assign m_status_depth = (KEEP_ENABLE && KEEP_WIDTH > 1)
                        ? {m_depth_reg, {CL_KEEP_WDITH{1'b0}}}
                        : m_depth_reg;
  assign m_status_depth_commit = (KEEP_ENABLE && KEEP_WIDTH > 1)
                               ? {m_depth_commit_reg, {CL_KEEP_WDITH{1'b0}}}
                               : m_depth_commit_reg;
  // verilator lint_on WIDTHEXPAND
  // verilator lint_on WIDTHTRUNC
  assign m_status_overflow = overflow_sync3_reg ^ overflow_sync4_reg;
  assign m_status_bad_frame = bad_frame_sync3_reg ^ bad_frame_sync4_reg;
  assign m_status_good_frame = good_frame_sync3_reg ^ good_frame_sync4_reg;

  // reset synchronization
  always_ff @(posedge m_clk or posedge m_rst) begin
    if (m_rst) begin
      s_rst_sync1_reg <= 1'b1;
    end
    else begin
      s_rst_sync1_reg <= 1'b0;
    end
  end

  always_ff @(posedge s_clk) begin
    s_rst_sync2_reg <= s_rst_sync1_reg;
    s_rst_sync3_reg <= s_rst_sync2_reg;
  end

  always_ff @(posedge s_clk or posedge s_rst) begin
    if (s_rst) begin
      m_rst_sync1_reg <= 1'b1;
    end
    else begin
      m_rst_sync1_reg <= 1'b0;
    end
  end

  always_ff @(posedge m_clk) begin
    m_rst_sync2_reg <= m_rst_sync1_reg;
    m_rst_sync3_reg <= m_rst_sync2_reg;
  end

  // the tuser of a beat marks a bad frame
  logic s_axis_tuser_bad;
  assign s_axis_tuser_bad =
      DROP_BAD_FRAME && |(USER_BAD_FRAME_MASK & ~(s_axis_tuser ^ USER_BAD_FRAME_VALUE));

  // Write logic
  always_ff @(posedge s_clk) begin
    overflow_reg   <= 1'b0;
    bad_frame_reg  <= 1'b0;
    good_frame_reg <= 1'b0;

    if (FRAME_FIFO && wr_ptr_update_valid_reg) begin
      // have updated pointer to sync
      if (wr_ptr_update_reg == wr_ptr_update_ack_sync2_reg) begin
        // no sync in progress; sync update
        wr_ptr_update_valid_reg <= 1'b0;
        wr_ptr_sync_commit_reg  <= wr_ptr_commit_reg;
        wr_ptr_update_reg       <= !wr_ptr_update_ack_sync2_reg;
      end
    end

    if (s_axis_tready && s_axis_tvalid && LAST_ENABLE) begin
      // track input frame status
      s_frame_reg <= !s_axis_tlast;
    end

    if (s_rst_sync3_reg && LAST_ENABLE) begin
      // if sink side is reset during transfer, drop partial frame
      if (s_frame_reg && !(s_axis_tready && s_axis_tvalid && s_axis_tlast)) begin
        drop_frame_reg <= 1'b1;
      end
      if (s_axis_tready && s_axis_tvalid && !s_axis_tlast) begin
        drop_frame_reg <= 1'b1;
      end
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
            wr_ptr_reg      <= wr_ptr_commit_reg;
            wr_ptr_gray_reg <= bin2gray(wr_ptr_commit_reg);
            drop_frame_reg  <= 1'b0;
            overflow_reg    <= 1'b1;
          end
        end
        else begin
          mem[wr_ptr_reg[ADDR_WIDTH-1:0]] <= s_axis;
          wr_ptr_reg                      <= wr_ptr_inc;
          wr_ptr_gray_reg                 <= bin2gray(wr_ptr_inc);
          if (s_axis_tlast || (!DROP_OVERSIZE_FRAME && (full_wr || send_frame_reg))) begin
            // end of frame or send frame
            send_frame_reg <= !s_axis_tlast;
            if (s_axis_tlast && s_axis_tuser_bad) begin
              // bad packet, reset write pointer
              wr_ptr_reg      <= wr_ptr_commit_reg;
              wr_ptr_gray_reg <= bin2gray(wr_ptr_commit_reg);
              bad_frame_reg   <= 1'b1;
            end
            else begin
              // good packet or packet overflow, update write pointer
              wr_ptr_reg        <= wr_ptr_inc;
              wr_ptr_commit_reg <= wr_ptr_inc;
              wr_ptr_gray_reg   <= bin2gray(wr_ptr_inc);

              if (wr_ptr_update_reg == wr_ptr_update_ack_sync2_reg) begin
                // no sync in progress; sync update
                wr_ptr_update_valid_reg <= 1'b0;
                wr_ptr_sync_commit_reg  <= wr_ptr_inc;
                wr_ptr_update_reg       <= !wr_ptr_update_ack_sync2_reg;
              end
              else begin
                // sync in progress; flag it for later
                wr_ptr_update_valid_reg <= 1'b1;
              end

              good_frame_reg <= s_axis_tlast;
            end
          end
        end
      end
      else if (s_axis_tvalid && full_wr && FRAME_FIFO && !DROP_OVERSIZE_FRAME) begin
        // data valid with packet overflow
        // update write pointer
        send_frame_reg    <= 1'b1;
        wr_ptr_reg        <= wr_ptr_reg;
        wr_ptr_commit_reg <= wr_ptr_reg;
        wr_ptr_gray_reg   <= bin2gray(wr_ptr_reg);

        if (wr_ptr_update_reg == wr_ptr_update_ack_sync2_reg) begin
          // no sync in progress; sync update
          wr_ptr_update_valid_reg <= 1'b0;
          wr_ptr_sync_commit_reg  <= wr_ptr_reg;
          wr_ptr_update_reg       <= !wr_ptr_update_ack_sync2_reg;
        end
        else begin
          // sync in progress; flag it for later
          wr_ptr_update_valid_reg <= 1'b1;
        end
      end
    end
    else begin
      // normal FIFO mode
      if (s_axis_tready && s_axis_tvalid) begin
        if (drop_frame_reg && LAST_ENABLE) begin
          // currently dropping frame
          if (s_axis_tlast) begin
            // end of frame
            if (!full && mark_frame_reg && MARK_WHEN_FULL) begin
              // terminate marked frame
              mark_frame_reg                  <= 1'b0;
              mem[wr_ptr_reg[ADDR_WIDTH-1:0]] <= s_axis;
              wr_ptr_reg                      <= wr_ptr_inc;
              wr_ptr_commit_reg               <= wr_ptr_inc;
              wr_ptr_gray_reg                 <= bin2gray(wr_ptr_inc);
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
          mem[wr_ptr_reg[ADDR_WIDTH-1:0]] <= s_axis;
          wr_ptr_reg                      <= wr_ptr_inc;
          wr_ptr_commit_reg               <= wr_ptr_inc;
          wr_ptr_gray_reg                 <= bin2gray(wr_ptr_inc);
        end
      end
      else if ((!full && !drop_frame_reg && mark_frame_reg) && MARK_WHEN_FULL) begin
        // terminate marked frame
        mark_frame_reg                  <= 1'b0;
        mem[wr_ptr_reg[ADDR_WIDTH-1:0]] <= s_axis;
        wr_ptr_reg                      <= wr_ptr_inc;
        wr_ptr_commit_reg               <= wr_ptr_inc;
        wr_ptr_gray_reg                 <= bin2gray(wr_ptr_inc);
      end
    end

    if (s_rst_sync3_reg) begin
      wr_ptr_reg              <= {ADDR_WIDTH + 1{1'b0}};
      wr_ptr_commit_reg       <= {ADDR_WIDTH + 1{1'b0}};
      wr_ptr_gray_reg         <= {ADDR_WIDTH + 1{1'b0}};
      wr_ptr_sync_commit_reg  <= {ADDR_WIDTH + 1{1'b0}};

      wr_ptr_update_valid_reg <= 1'b0;
      wr_ptr_update_reg       <= 1'b0;
    end

    if (s_rst) begin
      wr_ptr_reg              <= {ADDR_WIDTH + 1{1'b0}};
      wr_ptr_commit_reg       <= {ADDR_WIDTH + 1{1'b0}};
      wr_ptr_gray_reg         <= {ADDR_WIDTH + 1{1'b0}};
      wr_ptr_sync_commit_reg  <= {ADDR_WIDTH + 1{1'b0}};

      wr_ptr_update_valid_reg <= 1'b0;
      wr_ptr_update_reg       <= 1'b0;

      s_frame_reg             <= 1'b0;

      drop_frame_reg          <= 1'b0;
      mark_frame_reg          <= 1'b0;
      send_frame_reg          <= 1'b0;
      overflow_reg            <= 1'b0;
      bad_frame_reg           <= 1'b0;
      good_frame_reg          <= 1'b0;
    end
  end

  // Write-side status
  always_ff @(posedge s_clk) begin
    rd_ptr_conv_reg    <= gray2bin(rd_ptr_gray_sync2_reg);
    s_depth_reg        <= wr_ptr_reg - rd_ptr_conv_reg;
    s_depth_commit_reg <= wr_ptr_commit_reg - rd_ptr_conv_reg;
  end

  // pointer synchronization
  always_ff @(posedge s_clk) begin
    rd_ptr_gray_sync1_reg       <= rd_ptr_gray_reg;
    rd_ptr_gray_sync2_reg       <= rd_ptr_gray_sync1_reg;
    wr_ptr_update_ack_sync1_reg <= wr_ptr_update_sync3_reg;
    wr_ptr_update_ack_sync2_reg <= wr_ptr_update_ack_sync1_reg;

    if (s_rst) begin
      rd_ptr_gray_sync1_reg       <= {ADDR_WIDTH + 1{1'b0}};
      rd_ptr_gray_sync2_reg       <= {ADDR_WIDTH + 1{1'b0}};
      wr_ptr_update_ack_sync1_reg <= 1'b0;
      wr_ptr_update_ack_sync2_reg <= 1'b0;
    end
  end

  always_ff @(posedge m_clk) begin
    wr_ptr_gray_sync1_reg <= wr_ptr_gray_reg;
    wr_ptr_gray_sync2_reg <= wr_ptr_gray_sync1_reg;
    if (FRAME_FIFO && wr_ptr_update_sync2_reg ^ wr_ptr_update_sync3_reg) begin
      wr_ptr_commit_sync_reg <= wr_ptr_sync_commit_reg;
    end
    wr_ptr_update_sync1_reg <= wr_ptr_update_reg;
    wr_ptr_update_sync2_reg <= wr_ptr_update_sync1_reg;
    wr_ptr_update_sync3_reg <= wr_ptr_update_sync2_reg;

    if (FRAME_FIFO && m_rst_sync3_reg) begin
      wr_ptr_gray_sync1_reg <= {ADDR_WIDTH + 1{1'b0}};
    end

    if (m_rst) begin
      wr_ptr_gray_sync1_reg   <= {ADDR_WIDTH + 1{1'b0}};
      wr_ptr_gray_sync2_reg   <= {ADDR_WIDTH + 1{1'b0}};
      wr_ptr_commit_sync_reg  <= {ADDR_WIDTH + 1{1'b0}};
      wr_ptr_update_sync1_reg <= 1'b0;
      wr_ptr_update_sync2_reg <= 1'b0;
      wr_ptr_update_sync3_reg <= 1'b0;
    end
  end

  // status synchronization
  always_ff @(posedge s_clk) begin
    overflow_sync1_reg   <= overflow_sync1_reg ^ overflow_reg;
    bad_frame_sync1_reg  <= bad_frame_sync1_reg ^ bad_frame_reg;
    good_frame_sync1_reg <= good_frame_sync1_reg ^ good_frame_reg;

    if (s_rst) begin
      overflow_sync1_reg   <= 1'b0;
      bad_frame_sync1_reg  <= 1'b0;
      good_frame_sync1_reg <= 1'b0;
    end
  end

  always_ff @(posedge m_clk) begin
    overflow_sync2_reg   <= overflow_sync1_reg;
    overflow_sync3_reg   <= overflow_sync2_reg;
    overflow_sync4_reg   <= overflow_sync3_reg;
    bad_frame_sync2_reg  <= bad_frame_sync1_reg;
    bad_frame_sync3_reg  <= bad_frame_sync2_reg;
    bad_frame_sync4_reg  <= bad_frame_sync3_reg;
    good_frame_sync2_reg <= good_frame_sync1_reg;
    good_frame_sync3_reg <= good_frame_sync2_reg;
    good_frame_sync4_reg <= good_frame_sync3_reg;

    if (m_rst) begin
      overflow_sync2_reg   <= 1'b0;
      overflow_sync3_reg   <= 1'b0;
      overflow_sync4_reg   <= 1'b0;
      bad_frame_sync2_reg  <= 1'b0;
      bad_frame_sync3_reg  <= 1'b0;
      bad_frame_sync4_reg  <= 1'b0;
      good_frame_sync2_reg <= 1'b0;
      good_frame_sync3_reg <= 1'b0;
      good_frame_sync4_reg <= 1'b0;
    end
  end

  // Read logic
  // the output side takes a beat: the output FIFO, or the pipeline's last stage
  logic  m_out_ready;
  assign m_out_ready = OUTPUT_FIFO_ENABLE ? pipe_ready : m_axis_tready_pipe || !m_axis_tvalid_pipe;

  always_ff @(posedge m_clk) begin
    if (m_axis_tready_pipe) begin
      // output ready; invalidate stage
      m_axis_tvalid_pipe_reg[RAM_PIPELINE+1-1] <= 1'b0;
      m_terminate_frame_reg                    <= 1'b0;
    end

    for (int j = RAM_PIPELINE + 1 - 1; j > 0; j = j - 1) begin
      // verilator lint_off WIDTHTRUNC
      if (m_axis_tready_pipe || ((~m_axis_tvalid_pipe_reg) >> j)) begin
        // verilator lint_on WIDTHTRUNC
        // output ready or bubble in pipeline; transfer down pipeline
        m_axis_tvalid_pipe_reg[j]   <= m_axis_tvalid_pipe_reg[j-1];
        m_axis_pipe_reg[j]          <= m_axis_pipe_reg[j-1];
        m_axis_tvalid_pipe_reg[j-1] <= 1'b0;
      end
    end

    // verilator lint_off WIDTHTRUNC
    if (m_axis_tready_pipe || ~m_axis_tvalid_pipe_reg) begin
      // verilator lint_on WIDTHTRUNC
      // output ready or bubble in pipeline; read new data from FIFO
      m_axis_tvalid_pipe_reg[0] <= 1'b0;
      m_axis_pipe_reg[0]        <= mem[rd_ptr_reg[ADDR_WIDTH-1:0]];
      if (!empty && !m_rst_sync3_reg && !m_drop_frame_reg && pipe_ready) begin
        // not empty, increment pointer
        m_axis_tvalid_pipe_reg[0] <= 1'b1;
        rd_ptr_reg                <= rd_ptr_inc;
        rd_ptr_gray_reg           <= rd_ptr_inc ^ (rd_ptr_inc >> 1);
      end
    end

    if (m_axis_tvalid_pipe && LAST_ENABLE) begin
      // track output frame status
      if (m_axis_tlast_pipe && m_axis_tready_pipe) begin
        m_frame_reg <= 1'b0;
      end
      else begin
        m_frame_reg <= 1'b1;
      end
    end

    if (m_drop_frame_reg && m_out_ready && LAST_ENABLE) begin
      // terminate frame
      // (only for frame transfers interrupted by source reset)
      m_axis_tvalid_pipe_reg[RAM_PIPELINE+1-1] <= 1'b1;
      m_terminate_frame_reg                    <= 1'b1;
      m_drop_frame_reg                         <= 1'b0;
    end

    if (m_rst_sync3_reg && LAST_ENABLE) begin
      // if source side is reset during transfer, drop partial frame

      // empty output pipeline, except for last stage
      if (RAM_PIPELINE > 0) begin
        m_axis_tvalid_pipe_reg[RAM_PIPELINE+1-2:0] <= 0;
      end

      if (m_frame_reg && (!m_axis_tvalid_pipe || (m_axis_tvalid_pipe && !m_axis_tlast_pipe)) &&
                !(m_drop_frame_reg || m_terminate_frame_reg)) begin
        // terminate frame
        m_drop_frame_reg <= 1'b1;
      end
    end

    if (m_rst_sync3_reg) begin
      rd_ptr_reg      <= {ADDR_WIDTH + 1{1'b0}};
      rd_ptr_gray_reg <= {ADDR_WIDTH + 1{1'b0}};
    end

    if (m_rst) begin
      rd_ptr_reg             <= {ADDR_WIDTH + 1{1'b0}};
      rd_ptr_gray_reg        <= {ADDR_WIDTH + 1{1'b0}};
      m_axis_tvalid_pipe_reg <= 0;
      m_frame_reg            <= 1'b0;
      m_drop_frame_reg       <= 1'b0;
      m_terminate_frame_reg  <= 1'b0;
    end
  end

  // Read-side status
  always_ff @(posedge m_clk) begin
    wr_ptr_conv_reg <= gray2bin(wr_ptr_gray_sync2_reg);
    m_depth_reg <= wr_ptr_conv_reg - rd_ptr_reg;
    m_depth_commit_reg <= FRAME_FIFO
                        ? wr_ptr_commit_sync_reg - rd_ptr_reg
                        : wr_ptr_conv_reg - rd_ptr_reg;
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
      logic [              DATA_WIDTH-1:0] m_axis_tdata_reg = {DATA_WIDTH{1'b0}};
      logic [              KEEP_WIDTH-1:0] m_axis_tkeep_reg = {KEEP_WIDTH{1'b0}};
      logic                                m_axis_tvalid_reg = 1'b0;
      logic                                m_axis_tlast_reg = 1'b0;
      logic [                ID_WIDTH-1:0] m_axis_tid_reg = {ID_WIDTH{1'b0}};
      logic [              DEST_WIDTH-1:0] m_axis_tdest_reg = {DEST_WIDTH{1'b0}};
      logic [              USER_WIDTH-1:0] m_axis_tuser_reg = {USER_WIDTH{1'b0}};

      logic [OUTPUT_FIFO_ADDR_WIDTH+1-1:0] out_fifo_wr_ptr_reg = 0;
      logic [OUTPUT_FIFO_ADDR_WIDTH+1-1:0] out_fifo_rd_ptr_reg = 0;
      logic                                out_fifo_half_full_reg = 1'b0;

      logic                                out_fifo_full;

      assign out_fifo_full =
          out_fifo_wr_ptr_reg == (out_fifo_rd_ptr_reg ^ {1'b1, {OUTPUT_FIFO_ADDR_WIDTH{1'b0}}});
      logic  out_fifo_empty;
      assign out_fifo_empty = out_fifo_wr_ptr_reg == out_fifo_rd_ptr_reg;

      (* ram_style = "distributed", ramstyle = "no_rw_check, mlab" *)
      logic [DATA_WIDTH-1:0] out_fifo_tdata[2**OUTPUT_FIFO_ADDR_WIDTH-1:0];
      (* ram_style = "distributed", ramstyle = "no_rw_check, mlab" *)
      logic [KEEP_WIDTH-1:0] out_fifo_tkeep[2**OUTPUT_FIFO_ADDR_WIDTH-1:0];
      (* ram_style = "distributed", ramstyle = "no_rw_check, mlab" *)
      logic                  out_fifo_tlast[2**OUTPUT_FIFO_ADDR_WIDTH-1:0];
      (* ram_style = "distributed", ramstyle = "no_rw_check, mlab" *)
      logic [  ID_WIDTH-1:0] out_fifo_tid  [2**OUTPUT_FIFO_ADDR_WIDTH-1:0];
      (* ram_style = "distributed", ramstyle = "no_rw_check, mlab" *)
      logic [DEST_WIDTH-1:0] out_fifo_tdest[2**OUTPUT_FIFO_ADDR_WIDTH-1:0];
      (* ram_style = "distributed", ramstyle = "no_rw_check, mlab" *)
      logic [USER_WIDTH-1:0] out_fifo_tuser[2**OUTPUT_FIFO_ADDR_WIDTH-1:0];

      assign pipe_ready         = !out_fifo_half_full_reg;

      assign m_axis_tready_pipe = 1'b1;

      assign m_axis_tdata_out   = m_axis_tdata_reg;
      assign m_axis_tkeep_out   = KEEP_ENABLE ? m_axis_tkeep_reg : {KEEP_WIDTH{1'b1}};
      assign m_axis_tvalid_out  = m_axis_tvalid_reg;
      assign m_axis_tlast_out   = LAST_ENABLE ? m_axis_tlast_reg : 1'b1;
      assign m_axis_tid_out     = ID_ENABLE   ? m_axis_tid_reg   : {ID_WIDTH{1'b0}};
      assign m_axis_tdest_out   = DEST_ENABLE ? m_axis_tdest_reg : {DEST_WIDTH{1'b0}};
      assign m_axis_tuser_out   = USER_ENABLE ? m_axis_tuser_reg : {USER_WIDTH{1'b0}};

      always_ff @(posedge m_clk) begin
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

        if (m_rst) begin
          out_fifo_wr_ptr_reg <= 0;
          out_fifo_rd_ptr_reg <= 0;
          m_axis_tvalid_reg   <= 1'b0;
        end
      end

    end

    if (PAUSE_ENABLE) begin : pause

      // Pause logic
      logic pause_reg = 1'b0;
      logic pause_frame_reg = 1'b0;

      logic s_pause_req_sync1_reg;
      logic s_pause_req_sync2_reg;
      logic s_pause_req_sync3_reg;
      logic s_pause_ack_sync1_reg;
      logic s_pause_ack_sync2_reg;
      logic s_pause_ack_sync3_reg;

      always_ff @(posedge s_clk) begin
        s_pause_req_sync1_reg <= s_pause_req;
        s_pause_ack_sync2_reg <= s_pause_ack_sync1_reg;
        s_pause_ack_sync3_reg <= s_pause_ack_sync2_reg;
      end

      always_ff @(posedge m_clk) begin
        s_pause_req_sync2_reg <= s_pause_req_sync1_reg;
        s_pause_req_sync3_reg <= s_pause_req_sync2_reg;
        s_pause_ack_sync1_reg <= pause_reg;
      end

      assign m_axis_tready_out = m_axis_tready && !pause_reg;
      assign m_axis_tvalid     = m_axis_tvalid_out && !pause_reg;

      assign m_axis_tdata      = m_axis_tdata_out;
      assign m_axis_tkeep      = m_axis_tkeep_out;
      assign m_axis_tlast      = m_axis_tlast_out;
      assign m_axis_tid        = m_axis_tid_out;
      assign m_axis_tdest      = m_axis_tdest_out;
      assign m_axis_tuser      = m_axis_tuser_out;

      assign s_pause_ack       = s_pause_ack_sync3_reg;
      assign m_pause_ack       = pause_reg;

      always_ff @(posedge m_clk) begin
        if (FRAME_PAUSE) begin
          if (pause_reg) begin
            // paused; update pause status
            pause_reg <= m_pause_req || s_pause_req_sync3_reg;
          end
          else if (m_axis_tvalid_out) begin
            // frame transfer; set frame bit
            pause_frame_reg <= 1'b1;
            if (m_axis_tready && m_axis_tlast) begin
              // end of frame; clear frame bit and update pause status
              pause_frame_reg <= 1'b0;
              pause_reg       <= m_pause_req || s_pause_req_sync3_reg;
            end
          end
          else if (!pause_frame_reg) begin
            // idle; update pause status
            pause_reg <= m_pause_req || s_pause_req_sync3_reg;
          end
        end
        else begin
          pause_reg <= m_pause_req || s_pause_req_sync3_reg;
        end

        if (m_rst) begin
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

      assign s_pause_ack       = 1'b0;
      assign m_pause_ack       = 1'b0;

    end

  endgenerate

endmodule

`resetall
// verilator lint_on GENUNNAMED
// verilator lint_on UNUSED
