// SPDX-FileCopyrightText: 2026 Chili.CHIPS
//
// Enhanced by Chili.CHIPS with NLnet-sponsored project
// wireguard-fpga (https://github.com/chili-chips/wireguard-fpga).
// The original header follows.

// Copyright (c) 2013-2023 Alex Forencich
//
// SPDX-License-Identifier: MIT

// Language: Verilog 2001 (ports: SystemVerilog dpe_if, by Chili.CHIPS)

/*
 * AXI4-Stream FIFO
 */
module axis_fifo
  import dpe_pkg::*;
#(
    // FIFO depth in words
    // KEEP_WIDTH words per cycle if KEEP_ENABLE set
    // Rounded up to nearest power of 2 cycles
    parameter int                    DEPTH                = 4096,
    // Propagate tkeep signal
    // If disabled, tkeep assumed to be 1'b1
    parameter bit                    KEEP_ENABLE          = 1,
    // Chili.CHIPS: store tkeep as a byte count, $clog2(KEEP_WIDTH+1) bits
    // instead of KEEP_WIDTH (5, not 16: a 128-bit FIFO fits 4 RAMB18, not 5).
    // tkeep must be contiguous from byte 0 (only a last beat partial), as on
    // our Ethernet and DPE streams; SIM_ONLY asserts it
    parameter bit                    KEEP_AS_COUNT        = 0,
    // Propagate tlast signal
    parameter bit                    LAST_ENABLE          = 1,
    // Propagate tid signal
    // (Chili.CHIPS: on by default, dpe_if carries the peer index in tid)
    parameter bit                    ID_ENABLE            = 1,
    // Propagate tuser signal
    parameter bit                    USER_ENABLE          = 1,
    // number of RAM pipeline registers
    parameter int                    RAM_PIPELINE         = 1,
    // Frame FIFO mode - operate on frames instead of cycles
    // When set, m_axis_tvalid will not be deasserted within a frame
    // Requires LAST_ENABLE set
    parameter bit                    FRAME_FIFO           = 0,
    // tuser value for bad frame marker
    parameter logic [DPE_USER_W-1:0] USER_BAD_FRAME_VALUE = DPE_USER_W'(1),
    // tuser mask for bad frame marker
    parameter logic [DPE_USER_W-1:0] USER_BAD_FRAME_MASK  = DPE_USER_W'(1),
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
    dpe_if.s_axis s_axis,
    dpe_if.m_axis m_axis
);

  // Chili.CHIPS: the widths are dpe_if's, from dpe_pkg; the body below keeps
  // its original port names, bound here to the interface ports
  localparam int DATA_WIDTH = DPE_DATA_W;
  localparam int KEEP_WIDTH = DPE_KEEP_W;
  localparam int ID_WIDTH   = DPE_ID_W;
  localparam int USER_WIDTH = DPE_USER_W;

  logic  clk;
  assign clk = s_axis.clk;
  logic  rst;
  assign rst = s_axis.rst;

  logic [DATA_WIDTH-1:0] s_axis_tdata;
  assign                 s_axis_tdata  = s_axis.tdata;
  logic [KEEP_WIDTH-1:0] s_axis_tkeep;
  assign                 s_axis_tkeep  = s_axis.tkeep;
  logic                  s_axis_tvalid;
  assign                 s_axis_tvalid = s_axis.tvalid;
  logic                  s_axis_tready;
  logic                  s_axis_tlast;
  assign                 s_axis_tlast  = s_axis.tlast;
  logic [ID_WIDTH-1:0]   s_axis_tid;
  assign                 s_axis_tid    = s_axis.tid;
  logic [USER_WIDTH-1:0] s_axis_tuser;
  assign                 s_axis_tuser  = s_axis.tuser;
  assign                 s_axis.tready = s_axis_tready;

  logic [DATA_WIDTH-1:0] m_axis_tdata;
  logic [KEEP_WIDTH-1:0] m_axis_tkeep;
  logic                  m_axis_tvalid;
  logic                  m_axis_tready;
  assign                 m_axis_tready = m_axis.tready;
  logic                  m_axis_tlast;
  logic [ ID_WIDTH-1:0]  m_axis_tid;
  logic [USER_WIDTH-1:0] m_axis_tuser;
  assign                 m_axis.tdata  = m_axis_tdata;
  assign                 m_axis.tkeep  = m_axis_tkeep;
  assign                 m_axis.tvalid = m_axis_tvalid;
  assign                 m_axis.tlast  = m_axis_tlast;
  assign                 m_axis.tid    = m_axis_tid;
  assign                 m_axis.tuser  = m_axis_tuser;

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
  localparam int ID_OFFSET   = LAST_OFFSET + (LAST_ENABLE ? 1 : 0);
  localparam int USER_OFFSET = ID_OFFSET + (ID_ENABLE ? ID_WIDTH : 0);
  localparam int WIDTH       = USER_OFFSET + (USER_ENABLE ? USER_WIDTH : 0);

  logic [  ADDR_WIDTH:0] wr_ptr_reg;
  logic [  ADDR_WIDTH:0] wr_ptr_commit_reg;
  logic [  ADDR_WIDTH:0] rd_ptr_reg;

  (* ramstyle = "no_rw_check" *)
  logic [     WIDTH-1:0] mem                    [ 2**ADDR_WIDTH];

  (* shreg_extract = "no" *)
  logic [     WIDTH-1:0] m_axis_pipe_reg        [RAM_PIPELINE+1];
  logic [RAM_PIPELINE:0] m_axis_tvalid_pipe_reg;

  // full when first MSB different but rest same
  logic  full;
  assign full    = wr_ptr_reg == (rd_ptr_reg ^ {1'b1, {ADDR_WIDTH{1'b0}}});
  // empty when pointers match exactly
  logic  empty;
  assign empty   = wr_ptr_commit_reg == rd_ptr_reg;
  // overflow within packet
  logic  full_wr;
  assign full_wr = wr_ptr_reg == (wr_ptr_commit_reg ^ {1'b1, {ADDR_WIDTH{1'b0}}});

  logic drop_frame_reg;
  logic send_frame_reg;

  assign s_axis_tready = FRAME_FIFO
                       ? (~full | (full_wr & (DROP_OVERSIZE_FRAME != 0)) | (DROP_WHEN_FULL != 0))
                       : ~full;

  logic [WIDTH-1:0] s_axis_word;

  generate
    assign s_axis_word[DATA_WIDTH-1:0] = s_axis_tdata;
    if (KEEP_ENABLE) begin : g_keep
      if (KEEP_AS_COUNT) begin : g_count
        assign s_axis_word[KEEP_OFFSET+:KEEP_CNT_W] = keep2cnt(s_axis_tkeep);
      end
      else begin : g_mask
        assign s_axis_word[KEEP_OFFSET+:KEEP_WIDTH] = s_axis_tkeep;
      end
    end
    if (LAST_ENABLE) begin : g_last
      assign s_axis_word[LAST_OFFSET] = s_axis_tlast;
    end
    if (ID_ENABLE) begin : g_id
      assign s_axis_word[ID_OFFSET+:ID_WIDTH] = s_axis_tid;
    end
    if (USER_ENABLE) begin : g_user
      assign s_axis_word[USER_OFFSET+:USER_WIDTH] = s_axis_tuser;
    end
  endgenerate

  logic [WIDTH-1:0] m_axis_word;
  assign            m_axis_word = m_axis_pipe_reg[RAM_PIPELINE+1-1];

  logic  m_axis_tready_pipe;
  logic  m_axis_tvalid_pipe;
  assign m_axis_tvalid_pipe = m_axis_tvalid_pipe_reg[RAM_PIPELINE+1-1];

  logic [DATA_WIDTH-1:0] m_axis_tdata_pipe;
  assign                 m_axis_tdata_pipe = m_axis_word[DATA_WIDTH-1:0];
  logic [KEEP_WIDTH-1:0] m_axis_tkeep_pipe;
  generate
    if (!KEEP_ENABLE) begin : g_rd_keep_none
      assign m_axis_tkeep_pipe = {KEEP_WIDTH{1'b1}};
    end
    else if (KEEP_AS_COUNT) begin : g_rd_keep_count
      assign m_axis_tkeep_pipe = cnt2keep(m_axis_word[KEEP_OFFSET+:KEEP_CNT_W]);
    end
    else begin : g_rd_keep_mask
      assign m_axis_tkeep_pipe = m_axis_word[KEEP_OFFSET+:KEEP_WIDTH];
    end
  endgenerate
  logic m_axis_tlast_pipe;
  assign m_axis_tlast_pipe = LAST_ENABLE ? m_axis_word[LAST_OFFSET] : 1'b1;
  logic [ID_WIDTH-1:0] m_axis_tid_pipe;
  assign m_axis_tid_pipe = ID_ENABLE ? m_axis_word[ID_OFFSET+:ID_WIDTH] : {ID_WIDTH{1'b0}};
  logic [USER_WIDTH-1:0] m_axis_tuser_pipe;
  assign m_axis_tuser_pipe = USER_ENABLE
                           ? m_axis_word[USER_OFFSET+:USER_WIDTH]
                           : {USER_WIDTH{1'b0}};

  // the tuser of a beat marks a bad frame
  logic s_axis_tuser_bad;
  assign s_axis_tuser_bad =
      (DROP_BAD_FRAME != 0) & |(USER_BAD_FRAME_MASK & ~(s_axis_tuser ^ USER_BAD_FRAME_VALUE));

  // Write logic
  always_ff @(posedge clk) begin

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
          end
        end
        else begin
          // store it
          mem[wr_ptr_reg[ADDR_WIDTH-1:0]] <= s_axis_word;
          wr_ptr_reg                      <= wr_ptr_reg + 1;
          if (s_axis_tlast || (!DROP_OVERSIZE_FRAME && (full_wr || send_frame_reg))) begin
            // end of frame or send frame
            send_frame_reg <= ~s_axis_tlast;
            if (s_axis_tlast && s_axis_tuser_bad) begin
              // bad packet, reset write pointer
              wr_ptr_reg <= wr_ptr_commit_reg;
            end
            else begin
              // good packet or packet overflow, update write pointer
              wr_ptr_commit_reg <= wr_ptr_reg + 1;
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
        mem[wr_ptr_reg[ADDR_WIDTH-1:0]] <= s_axis_word;
        wr_ptr_reg                      <= wr_ptr_reg + 1;
        wr_ptr_commit_reg               <= wr_ptr_reg + 1;
      end
    end

    if (rst) begin
      wr_ptr_reg        <= {ADDR_WIDTH + 1{1'b0}};
      wr_ptr_commit_reg <= {ADDR_WIDTH + 1{1'b0}};

      drop_frame_reg    <= 1'b0;
      send_frame_reg    <= 1'b0;
    end
  end

  // Read logic
  always_ff @(posedge clk) begin
    if (m_axis_tready_pipe) begin
      // output ready; invalidate stage
      m_axis_tvalid_pipe_reg[RAM_PIPELINE+1-1] <= 1'b0;
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
      if (!empty) begin
        // not empty: read a word, increment pointer (a stage loads
        // only a word that is there, so its tlast and tuser are never X)
        m_axis_pipe_reg[0]        <= mem[rd_ptr_reg[ADDR_WIDTH-1:0]];
        m_axis_tvalid_pipe_reg[0] <= 1'b1;
        rd_ptr_reg                <= rd_ptr_reg + 1;
      end
    end

    if (rst) begin
      rd_ptr_reg             <= {ADDR_WIDTH + 1{1'b0}};
      m_axis_tvalid_pipe_reg <= 0;
      m_axis_pipe_reg        <= '{default: '0};  // no X out, also before the first word
    end
  end

  assign m_axis_tready_pipe = m_axis_tready;
  assign m_axis_tvalid      = m_axis_tvalid_pipe;
  assign m_axis_tdata       = m_axis_tdata_pipe;
  assign m_axis_tkeep       = m_axis_tkeep_pipe;
  assign m_axis_tlast       = m_axis_tlast_pipe;
  assign m_axis_tid         = m_axis_tid_pipe;
  assign m_axis_tuser       = m_axis_tuser_pipe;

`ifdef SIM_ONLY
  // KEEP_AS_COUNT keeps only a byte count: tkeep must be contiguous from byte 0
  // verilog_format: off
  a_keep_contiguous :
  assert property (@(posedge clk) disable iff (rst)
      ((KEEP_AS_COUNT != 0) & (KEEP_ENABLE != 0) & s_axis_tvalid & s_axis_tready)
      |-> ((s_axis_tkeep & (s_axis_tkeep + 1'b1)) == '0))
  else begin $error("tkeep %b not contiguous from byte 0 (%m)", s_axis_tkeep); end
  // verilog_format: on
`endif

endmodule

