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
 * AXI4-Stream asynchronous FIFO
 */
module axis_async_fifo #(
    // FIFO depth in words
    // KEEP_WIDTH words per cycle if KEEP_ENABLE set
    // Rounded up to nearest power of 2 cycles
    parameter int                    DEPTH                = 4096,
    // Width of AXI stream interfaces in bits
    parameter int                    DATA_WIDTH           = 8,
    // Propagate tkeep signal
    // If disabled, tkeep assumed to be 1'b1
    parameter bit                    KEEP_ENABLE          = (DATA_WIDTH > 8),
    // tkeep signal width (words per cycle)
    parameter int                    KEEP_WIDTH           = ((DATA_WIDTH + 7) / 8),
    // Chili.CHIPS: store tkeep as a byte count, $clog2(KEEP_WIDTH+1) bits
    // instead of KEEP_WIDTH (5, not 16: a 128-bit FIFO fits 4 RAMB18, not 5).
    // tkeep must be contiguous from byte 0 (only a last beat partial), as on
    // our Ethernet and DPE streams; SIM_ONLY asserts it
    parameter bit                    KEEP_AS_COUNT        = 0,
    // Propagate tlast signal
    parameter bit                    LAST_ENABLE          = 1,
    // Propagate tuser signal
    parameter bit                    USER_ENABLE          = 1,
    // tuser signal width
    parameter int                    USER_WIDTH           = 1,
    // number of RAM pipeline registers
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
    parameter bit                    DROP_WHEN_FULL       = 0
) (
    /*
     * AXI input
     */
    input  logic                  s_clk,
    input  logic                  s_rst,
    input  logic [DATA_WIDTH-1:0] s_axis_tdata,
    input  logic [KEEP_WIDTH-1:0] s_axis_tkeep,
    input  logic                  s_axis_tvalid,
    output logic                  s_axis_tready,
    input  logic                  s_axis_tlast,
    input  logic [USER_WIDTH-1:0] s_axis_tuser,

    /*
     * AXI output
     */
    input  logic                  m_clk,
    input  logic                  m_rst,
    output logic [DATA_WIDTH-1:0] m_axis_tdata,
    output logic [KEEP_WIDTH-1:0] m_axis_tkeep,
    output logic                  m_axis_tvalid,
    input  logic                  m_axis_tready,
    output logic                  m_axis_tlast,
    output logic [USER_WIDTH-1:0] m_axis_tuser
);

  localparam int ADDR_WIDTH = ((KEEP_ENABLE != 0) & (KEEP_WIDTH > 1)) ? $clog2(
      DEPTH / KEEP_WIDTH
  ) : $clog2(
      DEPTH
  );

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

    if (DROP_BAD_FRAME && (USER_BAD_FRAME_MASK & {USER_WIDTH{1'b1}}) == 0) begin
      $error("Error: Invalid USER_BAD_FRAME_MASK value (instance %m)");
      $finish;
    end

  end

  // KEEP_AS_COUNT: tkeep as a byte count in the FIFO word, and back
  localparam int KEEP_CNT_W = $clog2(KEEP_WIDTH + 1);
  localparam int KEEP_MEM_W = KEEP_AS_COUNT ? KEEP_CNT_W : KEEP_WIDTH;  // tkeep's bits in a word

  function automatic logic [KEEP_CNT_W-1:0] keep2cnt(logic [KEEP_WIDTH-1:0] keep);
    logic [KEEP_CNT_W-1:0] cnt;
    cnt = '0;
    for (int i = 0; i < KEEP_WIDTH; i++) begin
      cnt = cnt + KEEP_CNT_W'(keep[i]);
    end
    return cnt;
  endfunction

  function automatic logic [KEEP_WIDTH-1:0] cnt2keep(logic [KEEP_CNT_W-1:0] cnt);
    logic [KEEP_WIDTH-1:0] keep;
    for (int i = 0; i < KEEP_WIDTH; i++) begin
      keep[i] = KEEP_CNT_W'(i) < cnt;
    end
    return keep;
  endfunction

  localparam int KEEP_OFFSET = DATA_WIDTH;
  localparam int LAST_OFFSET = KEEP_OFFSET + (KEEP_ENABLE ? KEEP_MEM_W : 0);
  localparam int USER_OFFSET = LAST_OFFSET + (LAST_ENABLE ? 1 : 0);
  localparam int WIDTH       = USER_OFFSET + (USER_ENABLE ? USER_WIDTH : 0);

  function automatic [ADDR_WIDTH:0] bin2gray(input logic [ADDR_WIDTH:0] b);
    bin2gray = b ^ (b >> 1);
  endfunction

  function automatic [ADDR_WIDTH:0] gray2bin(input logic [ADDR_WIDTH:0] g);
    integer i;
    for (i = 0; i <= ADDR_WIDTH; i = i + 1) begin
      gray2bin[i] = ^(g >> i);
    end
  endfunction

  logic [ADDR_WIDTH:0] wr_ptr_reg;
  logic [ADDR_WIDTH:0] wr_ptr_commit_reg;
  logic [ADDR_WIDTH:0] wr_ptr_gray_reg;
  logic [ADDR_WIDTH:0] wr_ptr_sync_commit_reg;
  logic [ADDR_WIDTH:0] rd_ptr_reg;
  logic [ADDR_WIDTH:0] rd_ptr_gray_reg;

  // the pointers plus one (Chili.CHIPS: in place of blocking temporaries in the always_ff)
  logic [ADDR_WIDTH:0] wr_ptr_inc;
  assign               wr_ptr_inc = wr_ptr_reg + 1;
  logic [ADDR_WIDTH:0] rd_ptr_inc;
  assign               rd_ptr_inc = rd_ptr_reg + 1;

  (* SHREG_EXTRACT = "NO" *)
  logic [  ADDR_WIDTH:0] wr_ptr_gray_sync1_reg;
  (* SHREG_EXTRACT = "NO" *)
  logic [  ADDR_WIDTH:0] wr_ptr_gray_sync2_reg;
  (* SHREG_EXTRACT = "NO" *)
  logic [  ADDR_WIDTH:0] wr_ptr_commit_sync_reg;
  (* SHREG_EXTRACT = "NO" *)
  logic [  ADDR_WIDTH:0] rd_ptr_gray_sync1_reg;
  (* SHREG_EXTRACT = "NO" *)
  logic [  ADDR_WIDTH:0] rd_ptr_gray_sync2_reg;

  logic                  wr_ptr_update_valid_reg;
  logic                  wr_ptr_update_reg;
  (* SHREG_EXTRACT = "NO" *)
  logic                  wr_ptr_update_sync1_reg;
  (* SHREG_EXTRACT = "NO" *)
  logic                  wr_ptr_update_sync2_reg;
  (* SHREG_EXTRACT = "NO" *)
  logic                  wr_ptr_update_sync3_reg;
  (* SHREG_EXTRACT = "NO" *)
  logic                  wr_ptr_update_ack_sync1_reg;
  (* SHREG_EXTRACT = "NO" *)
  logic                  wr_ptr_update_ack_sync2_reg;

  (* SHREG_EXTRACT = "NO" *)
  logic                  s_rst_sync1_reg;
  (* SHREG_EXTRACT = "NO" *)
  logic                  s_rst_sync2_reg;
  (* SHREG_EXTRACT = "NO" *)
  logic                  s_rst_sync3_reg;
  (* SHREG_EXTRACT = "NO" *)
  logic                  m_rst_sync1_reg;
  (* SHREG_EXTRACT = "NO" *)
  logic                  m_rst_sync2_reg;
  (* SHREG_EXTRACT = "NO" *)
  logic                  m_rst_sync3_reg;

  (* ramstyle = "no_rw_check" *)
  logic [     WIDTH-1:0] mem                         [ 2**ADDR_WIDTH];

  (* shreg_extract = "no" *)
  logic [     WIDTH-1:0] m_axis_pipe_reg             [RAM_PIPELINE+1];
  logic [RAM_PIPELINE:0] m_axis_tvalid_pipe_reg;

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

  logic s_frame_reg;
  logic m_frame_reg;

  logic drop_frame_reg;
  logic send_frame_reg;

  logic m_drop_frame_reg;
  logic m_terminate_frame_reg;

  // ready by the FIFO's fill, before the reset
  logic s_axis_ready_fifo;
  assign s_axis_ready_fifo = FRAME_FIFO
                         ? (~full | (full_wr & (DROP_OVERSIZE_FRAME != 0)) | (DROP_WHEN_FULL != 0))
                         : ~full;
  assign s_axis_tready = s_axis_ready_fifo & ~s_rst_sync3_reg;

  logic [WIDTH-1:0] s_axis;

  generate
    assign s_axis[DATA_WIDTH-1:0] = s_axis_tdata;
    if (KEEP_ENABLE) begin : g_keep
      if (KEEP_AS_COUNT) begin : g_count
        assign s_axis[KEEP_OFFSET+:KEEP_CNT_W] = keep2cnt(s_axis_tkeep);
      end
      else begin : g_mask
        assign s_axis[KEEP_OFFSET+:KEEP_WIDTH] = s_axis_tkeep;
      end
    end
    if (LAST_ENABLE) begin : g_last
      assign s_axis[LAST_OFFSET] = s_axis_tlast;
    end
    if (USER_ENABLE) begin : g_user
      assign s_axis[USER_OFFSET+:USER_WIDTH] = s_axis_tuser;
    end
  endgenerate

  logic [WIDTH-1:0] m_axis;
  assign            m_axis = m_axis_pipe_reg[RAM_PIPELINE+1-1];

  logic  m_axis_tready_pipe;
  logic  m_axis_tvalid_pipe;
  assign m_axis_tvalid_pipe = m_axis_tvalid_pipe_reg[RAM_PIPELINE+1-1];

  logic [DATA_WIDTH-1:0] m_axis_tdata_pipe;
  assign                 m_axis_tdata_pipe = m_axis[DATA_WIDTH-1:0];
  logic [KEEP_WIDTH-1:0] m_axis_tkeep_pipe;
  generate
    if (!KEEP_ENABLE) begin : g_rd_keep_none
      assign m_axis_tkeep_pipe = {KEEP_WIDTH{1'b1}};
    end
    else if (KEEP_AS_COUNT) begin : g_rd_keep_count
      assign m_axis_tkeep_pipe = cnt2keep(m_axis[KEEP_OFFSET+:KEEP_CNT_W]);
    end
    else begin : g_rd_keep_mask
      assign m_axis_tkeep_pipe = m_axis[KEEP_OFFSET+:KEEP_WIDTH];
    end
  endgenerate
  logic m_axis_tlast_pipe;
  assign m_axis_tlast_pipe = LAST_ENABLE ? m_axis[LAST_OFFSET] | m_terminate_frame_reg : 1'b1;
  logic [USER_WIDTH-1:0] m_axis_tuser_fifo;  // tuser from the FIFO, or the bad-frame value
  assign m_axis_tuser_fifo = m_terminate_frame_reg
                           ? USER_BAD_FRAME_VALUE
                           : m_axis[USER_OFFSET +: USER_WIDTH];

  logic [USER_WIDTH-1:0] m_axis_tuser_pipe;
  assign                 m_axis_tuser_pipe = USER_ENABLE ? m_axis_tuser_fifo : {USER_WIDTH{1'b0}};

  // reset synchronization
  always_ff @(posedge m_clk or posedge m_rst) begin
    if (m_rst) begin
      s_rst_sync1_reg <= 1'b1;
    end
    else begin
      s_rst_sync1_reg <= 1'b0;
    end
  end

  always_ff @(posedge s_clk or posedge s_rst) begin
    if (s_rst) begin
      s_rst_sync2_reg <= 1'b1;
      s_rst_sync3_reg <= 1'b1;
    end
    else begin
      s_rst_sync2_reg <= s_rst_sync1_reg;
      s_rst_sync3_reg <= s_rst_sync2_reg;
    end
  end

  always_ff @(posedge s_clk or posedge s_rst) begin
    if (s_rst) begin
      m_rst_sync1_reg <= 1'b1;
    end
    else begin
      m_rst_sync1_reg <= 1'b0;
    end
  end

  always_ff @(posedge m_clk or posedge m_rst) begin
    if (m_rst) begin
      m_rst_sync2_reg <= 1'b1;
      m_rst_sync3_reg <= 1'b1;
    end
    else begin
      m_rst_sync2_reg <= m_rst_sync1_reg;
      m_rst_sync3_reg <= m_rst_sync2_reg;
    end
  end

  // the tuser of a beat marks a bad frame
  logic s_axis_tuser_bad;
  assign s_axis_tuser_bad =
      (DROP_BAD_FRAME != 0) & |(USER_BAD_FRAME_MASK & ~(s_axis_tuser ^ USER_BAD_FRAME_VALUE));

  // Write logic
  always_ff @(posedge s_clk) begin
    if (FRAME_FIFO && wr_ptr_update_valid_reg) begin
      // have updated pointer to sync
      if (wr_ptr_update_reg == wr_ptr_update_ack_sync2_reg) begin
        // no sync in progress; sync update
        wr_ptr_update_valid_reg <= 1'b0;
        wr_ptr_sync_commit_reg  <= wr_ptr_commit_reg;
        wr_ptr_update_reg       <= ~wr_ptr_update_ack_sync2_reg;
      end
    end

    if (s_axis_tready && s_axis_tvalid && LAST_ENABLE) begin
      // track input frame status
      s_frame_reg <= ~s_axis_tlast;
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
          end
        end
        else begin
          mem[wr_ptr_reg[ADDR_WIDTH-1:0]] <= s_axis;
          wr_ptr_reg                      <= wr_ptr_inc;
          wr_ptr_gray_reg                 <= bin2gray(wr_ptr_inc);
          if (s_axis_tlast || (!DROP_OVERSIZE_FRAME && (full_wr || send_frame_reg))) begin
            // end of frame or send frame
            send_frame_reg <= ~s_axis_tlast;
            if (s_axis_tlast && s_axis_tuser_bad) begin
              // bad packet, reset write pointer
              wr_ptr_reg      <= wr_ptr_commit_reg;
              wr_ptr_gray_reg <= bin2gray(wr_ptr_commit_reg);
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
                wr_ptr_update_reg       <= ~wr_ptr_update_ack_sync2_reg;
              end
              else begin
                // sync in progress; flag it for later
                wr_ptr_update_valid_reg <= 1'b1;
              end
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
          wr_ptr_update_reg       <= ~wr_ptr_update_ack_sync2_reg;
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
          // dropping a frame the sink side reset cut: to its end (also in
          // normal mode, unlike upstream, so no half frame reaches the sink)
          if (s_axis_tlast) begin
            drop_frame_reg <= 1'b0;
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
      send_frame_reg          <= 1'b0;
    end
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

  // Read logic
  // the output side takes a beat: the pipeline's last stage is free
  logic  m_out_ready;
  assign m_out_ready = m_axis_tready_pipe | ~m_axis_tvalid_pipe;

  always_ff @(posedge m_clk) begin
    if (m_axis_tready_pipe) begin
      // output ready; invalidate stage
      m_axis_tvalid_pipe_reg[RAM_PIPELINE+1-1] <= 1'b0;
      m_terminate_frame_reg                    <= 1'b0;
    end

    for (int j = RAM_PIPELINE + 1 - 1; j > 0; j = j - 1) begin
      if (m_axis_tready_pipe || |((~m_axis_tvalid_pipe_reg) >> j)) begin
        // output ready or bubble in pipeline; transfer down pipeline
        m_axis_tvalid_pipe_reg[j]   <= m_axis_tvalid_pipe_reg[j-1];
        m_axis_pipe_reg[j]          <= m_axis_pipe_reg[j-1];
        m_axis_tvalid_pipe_reg[j-1] <= 1'b0;
      end
    end

    if (m_axis_tready_pipe || |(~m_axis_tvalid_pipe_reg)) begin
      // output ready or bubble in pipeline; read new data from FIFO
      m_axis_tvalid_pipe_reg[0] <= 1'b0;
      if (!empty && !m_rst_sync3_reg && !m_drop_frame_reg) begin
        // not empty: read a word, increment pointer (a stage loads
        // only a word that is there, so its tlast and tuser are never X)
        m_axis_pipe_reg[0]        <= mem[rd_ptr_reg[ADDR_WIDTH-1:0]];
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
      m_axis_pipe_reg        <= '{default: '0};  // no X out, also before the first word
      m_frame_reg            <= 1'b0;
      m_drop_frame_reg       <= 1'b0;
      m_terminate_frame_reg  <= 1'b0;
    end
  end

  assign m_axis_tready_pipe = m_axis_tready;
  assign m_axis_tvalid      = m_axis_tvalid_pipe;
  assign m_axis_tdata       = m_axis_tdata_pipe;
  assign m_axis_tkeep       = m_axis_tkeep_pipe;
  assign m_axis_tlast       = m_axis_tlast_pipe;
  assign m_axis_tuser       = m_axis_tuser_pipe;

`ifdef SIM_ONLY
  // KEEP_AS_COUNT keeps only a byte count: tkeep must be contiguous from byte 0
  // verilog_format: off
  a_keep_contiguous :
  assert property (@(posedge s_clk) disable iff (s_rst)
      ((KEEP_AS_COUNT != 0) & (KEEP_ENABLE != 0) & s_axis_tvalid & s_axis_tready)
      |-> ((s_axis_tkeep & (s_axis_tkeep + 1'b1)) == '0))
  else begin $error("tkeep %b not contiguous from byte 0 (%m)", s_axis_tkeep); end
  // verilog_format: on
`endif

endmodule

