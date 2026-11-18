// SPDX-FileCopyrightText: 2026 Chili.CHIPS
//
// SPDX-License-Identifier: BSD-3-Clause

//==========================================================================
// Wireguard-1GE FPGA * NLnet-sponsored open-source implementation
//--------------------------------------------------------------------------
// Description:
//   lkup_egress unit bench.
//   1. The CPU's view: all 64 routing-table entries written over the CSR
//      port, then each field of a few read back.
//   2. The data plane: Ethernet/IPv4 frames of several lengths, back to
//      back, with bubbles in and backpressure out (dpe_tb_throttle). Each
//      must come out unchanged, with tuser.dst and tid of the entry its
//      IPv4 destination selects (the first entry that matches, as
//      lkup_route_mem does), and a bypass_all frame with its own.
//   Every output beat is checked: tdata (kept bytes), tkeep, tlast, tuser,
//   tid.
//==========================================================================

module tb;
  import dpe_pkg::*;
  import csr_pkg::*;
  import lkup_pkg::*;

  localparam int ENTRIES = 64;
  localparam int MAX_FRAMES = 16;
  localparam int TIMEOUT_CLKS = 20000;

  logic clk, rst;

  dpe_if from_src (.clk(clk), .rst(rst));
  dpe_if to_dut   (.clk(clk), .rst(rst));
  dpe_if from_dut (.clk(clk), .rst(rst));
  dpe_if to_snk   (.clk(clk), .rst(rst));

  csr_cfg_t csr_cfg;
  csr_sta_t csr_sta;

  dpe_tb_throttle #(.PASS_PCT(60), .SEED(16'hACE1)) stall_in  (.inp(from_src), .outp(to_dut));
  dpe_tb_throttle #(.PASS_PCT(60), .SEED(16'h1D2C)) stall_out (.inp(from_dut), .outp(to_snk));

  lkup_egress #(.ENTRY_COUNT(ENTRIES)) dut (
      .s_axis  (to_dut),
      .m_axis  (from_dut),
      .csr_cfg (csr_cfg),
      .csr_sta (csr_sta)
  );

  // 80 MHz at 1 ns precision: halves of 6, 6, 7, 6 ns, 12.5 ns on average
  initial begin
    clk = 1'b0;
    forever begin
      #6ns clk = 1'b1;
      #6ns clk = 1'b0;
      #7ns clk = 1'b1;
      #6ns clk = 1'b0;
    end
  end

  //------------------------------------------------------------------
  // The routing table, as the bench writes it. Entry 63: the default
  // route; entries 4 to 62: host routes nothing here uses
  //------------------------------------------------------------------
  typedef struct {
    logic [31:0]   ip;
    logic [31:0]   mask;
    dpe_peer_idx_t peer;
    logic          encrypt;  // through the tunnel to peer
    dpe_addr_t     dst;
  } route_t;

  route_t table_m[ENTRIES];

  function automatic logic [31:0] ip4(int a, int b, int c, int d);
    return {8'(a), 8'(b), 8'(c), 8'(d)};
  endfunction

  initial begin
    for (int i = 0; i < ENTRIES; i++)
      table_m[i] = '{ip: ip4(172, 31, 255, i), mask: '1, peer: dpe_peer_idx_t'(8'h40 + i),
                     encrypt: i[0], dst: DPE_ADDR_CPU};
    table_m[0]  = '{ip: ip4(10, 1, 2, 0),    mask: ip4(255, 255, 255, 0), peer: 8'd9, encrypt: 1,
                    dst: DPE_ADDR_ETH_3};
    table_m[1]  = '{ip: ip4(10, 1, 0, 0),    mask: ip4(255, 255, 0, 0),   peer: 8'd5, encrypt: 0,
                    dst: DPE_ADDR_ETH_2};
    table_m[2]  = '{ip: ip4(10, 0, 0, 0),    mask: ip4(255, 0, 0, 0),     peer: 8'd3, encrypt: 1,
                    dst: DPE_ADDR_ETH_1};
    table_m[3]  = '{ip: ip4(192, 168, 1, 0), mask: ip4(255, 255, 255, 0), peer: 8'd7, encrypt: 0,
                    dst: DPE_ADDR_ETH_4};
    table_m[63] = '{ip: '0, mask: '0, peer: 8'd0, encrypt: 0, dst: DPE_ADDR_CPU};
  end

  // the peer_idx register: peer_idx in [7:0], encrypt in bit 8
  function automatic logic [31:0] peer_word(route_t e);
    return {23'd0, e.encrypt, e.peer};
  endfunction

  // the entry lkup_route_mem picks: the first that matches
  function automatic route_t lookup(logic [31:0] ip);
    for (int i = 0; i < ENTRIES; i++)
      if ((ip & table_m[i].mask) == (table_m[i].ip & table_m[i].mask)) return table_m[i];
    return '{ip: '0, mask: '0, peer: '0, encrypt: 0, dst: DPE_ADDR_CPU};  // the defaults
  endfunction

  //------------------------------------------------------------------
  // CSR access: entry[addr[9:4]], field at addr[3:2] (0 ip, 1 mask,
  // 2 peer, 3 dst); the block answers in the request's clock
  //------------------------------------------------------------------
  int errors = 0;

  task automatic csr_write(int idx, int field, logic [31:0] data, logic [31:0] biten = '1);
    @(negedge clk);
    csr_cfg.req       = 1'b1;
    csr_cfg.req_is_wr = 1'b1;
    csr_cfg.addr      = 10'({idx[5:0], field[1:0], 2'b00});
    csr_cfg.wr_data   = data;
    csr_cfg.wr_biten  = biten;
    #3ns;
    if (!csr_sta.wr_ack) begin
      $display("ERROR: CSR write entry %0d field %0d: no wr_ack", idx, field);
      errors++;
    end
    @(negedge clk);
    csr_cfg.req = 1'b0;
  endtask

  task automatic csr_read(int idx, int field, logic [31:0] want);
    @(negedge clk);
    csr_cfg.req       = 1'b1;
    csr_cfg.req_is_wr = 1'b0;
    csr_cfg.addr      = 10'({idx[5:0], field[1:0], 2'b00});
    // a one-clock request, as PeakRDL's external access makes it; the answer
    // (rd_ack with rd_data) may come in that clock or up to 3 later
    for (int t = 0; t < 4; t++) begin
      #3ns;
      if (csr_sta.rd_ack) begin
        if (csr_sta.rd_data !== want) begin
          $display("ERROR: CSR read entry %0d field %0d: data %h, want %h", idx, field,
                   csr_sta.rd_data, want);
          errors++;
        end
        @(negedge clk);
        csr_cfg.req  = 1'b0;
        return;
      end
      @(negedge clk);
      csr_cfg.req  = 1'b0;
      csr_cfg.addr = '1;  // the block must not need it after the request
    end
    $display("ERROR: CSR read entry %0d field %0d: no rd_ack", idx, field);
    errors++;
  endtask

  //------------------------------------------------------------------
  // Frames: Ethernet + IPv4 header (destination at bytes 30 to 33), then a
  // pattern; byte n of a frame goes in tdata[8*(n%16)+:8]
  //------------------------------------------------------------------
  typedef struct {
    int          len;
    logic [31:0] ip_dst;
    logic        bypass_all;
    dpe_addr_t   dst;  // tuser.dst in: kept only by a bypass_all frame
    logic        bypass_stage;
    dpe_peer_idx_t tid;
  } frame_t;

  frame_t frames[MAX_FRAMES];
  int     n_frames;

  function automatic byte_t frame_byte(int f, int n);
    unique case (n)
      12: return 8'h08;  // EtherType IPv4
      13: return 8'h00;
      14: return 8'h45;
      30: return frames[f].ip_dst[31:24];
      31: return frames[f].ip_dst[23:16];
      32: return frames[f].ip_dst[15:8];
      33: return frames[f].ip_dst[7:0];
      default: return 8'((f << 4) ^ n ^ (n >> 8));
    endcase
  endfunction

  function automatic dpe_keep_t keep_of(int f, int beat);
    int left = frames[f].len - 16 * beat;
    for (int b = 0; b < 16; b++) keep_of[b] = b < left;
  endfunction

  // the source: one frame after the other, back to back
  initial begin
    from_src.tvalid = 1'b0;
    from_src.tdata  = '0;
    from_src.tkeep  = '0;
    from_src.tlast  = 1'b0;
    from_src.tuser  = '0;
    from_src.tid    = '0;
    wait (n_frames > 0 && !rst);
    @(negedge clk);
    for (int f = 0; f < n_frames; f++) begin
      automatic int beats = (frames[f].len + 15) / 16;
      for (int k = 0; k < beats; k++) begin
        from_src.tvalid = 1'b1;
        for (int b = 0; b < 16; b++)
          from_src.tdata[8*b+:8] = (16 * k + b < frames[f].len) ? frame_byte(f, 16 * k + b) : 8'h00;
        from_src.tkeep = keep_of(f, k);
        from_src.tlast = (k == beats - 1);
        from_src.tuser = '{bypass_all: frames[f].bypass_all, bypass_stage: frames[f].bypass_stage,
                           src: DPE_ADDR_CPU, dst: frames[f].dst};
        from_src.tid = frames[f].tid;
        do @(posedge clk); while (!from_src.tready);
        @(negedge clk);
      end
    end
    from_src.tvalid = 1'b0;
  end

  // the sink: always ready (stall_out makes the backpressure); checks
  // every beat against the frame it belongs to
  assign to_snk.tready = 1'b1;
  int rx_frame = 0, rx_beat = 0;

  always @(posedge clk) begin
    if (!rst && to_snk.tvalid && to_snk.tready) begin
      if (rx_frame >= n_frames) begin
        $display("ERROR: a beat after the last frame");
        errors++;
      end
      else begin
        automatic int f = rx_frame;
        automatic int beats = (frames[f].len + 15) / 16;
        // a frame shorter than its IPv4 destination: the defaults (CPU, not encrypted)
        automatic route_t r = (frames[f].len >= 34) ? lookup(frames[f].ip_dst) :
            '{ip: '0, mask: '0, peer: '0, encrypt: 0, dst: DPE_ADDR_CPU};
        automatic dpe_tuser_t want_user;
        automatic dpe_peer_idx_t want_tid;
        automatic logic bad = 1'b0;
        if (frames[f].bypass_all) begin
          want_user = '{bypass_all: 1'b1, bypass_stage: frames[f].bypass_stage,
                        src: DPE_ADDR_CPU, dst: frames[f].dst};
          want_tid = frames[f].tid;
        end
        else begin
          // the encryptor next: bypassed unless the route goes through the tunnel
          want_user = '{bypass_all: 1'b0, bypass_stage: ~r.encrypt,
                        src: DPE_ADDR_CPU, dst: r.dst};
          want_tid = r.peer;
        end
        if (to_snk.tkeep !== keep_of(f, rx_beat) || to_snk.tlast !== (rx_beat == beats - 1))
          bad = 1'b1;
        for (int b = 0; b < 16; b++)
          if (16 * rx_beat + b < frames[f].len &&
              to_snk.tdata[8*b+:8] !== frame_byte(f, 16 * rx_beat + b))
            bad = 1'b1;
        // a frame without its full IPv4 destination (under 34 bytes): any route
        if (to_snk.tuser.dst !== want_user.dst || to_snk.tid !== want_tid)
          bad = 1'b1;
        if (to_snk.tuser.bypass_all !== want_user.bypass_all || to_snk.tuser.src !== want_user.src ||
            to_snk.tuser.bypass_stage !== want_user.bypass_stage)
          bad = 1'b1;
        if (bad) begin
          $display("ERROR: frame %0d beat %0d: keep %h last %b tuser %b tid %h; want keep %h last %b tuser %b tid %h",
                   f, rx_beat, to_snk.tkeep, to_snk.tlast, to_snk.tuser, to_snk.tid,
                   keep_of(f, rx_beat), rx_beat == beats - 1, want_user, want_tid);
          errors++;
        end
        if (to_snk.tlast) begin
          rx_frame++;
          rx_beat = 0;
        end
        else rx_beat++;
      end
    end
  end

  //------------------------------------------------------------------
  initial begin
    // dst, peer of each frame: 10.1.2.3 ETH_3 9; 10.1.9.9 ETH_2 5;
    // 10.200.0.1 ETH_1 3; 192.168.1.77 ETH_4 7; 8.8.8.8 the default
    frames[0] = '{len: 60,   ip_dst: ip4(10, 1, 2, 3),     bypass_all: 0, dst: DPE_ADDR_CPU,
                  bypass_stage: 0, tid: 0};
    frames[1] = '{len: 64,   ip_dst: ip4(10, 1, 9, 9),     bypass_all: 0, dst: DPE_ADDR_CPU,
                  bypass_stage: 0, tid: 0};
    frames[2] = '{len: 77,   ip_dst: ip4(10, 200, 0, 1),   bypass_all: 0, dst: DPE_ADDR_CPU,
                  bypass_stage: 1, tid: 0};
    frames[3] = '{len: 128,  ip_dst: ip4(192, 168, 1, 77), bypass_all: 0, dst: DPE_ADDR_CPU,
                  bypass_stage: 0, tid: 0};
    frames[4] = '{len: 48,   ip_dst: ip4(8, 8, 8, 8),      bypass_all: 0, dst: DPE_ADDR_CPU,
                  bypass_stage: 0, tid: 0};
    frames[5] = '{len: 100,  ip_dst: ip4(10, 1, 2, 200),   bypass_all: 1, dst: DPE_ADDR_ETH_2,
                  bypass_stage: 1, tid: 8'h42};
    frames[6] = '{len: 1514, ip_dst: ip4(192, 168, 1, 1),  bypass_all: 0, dst: DPE_ADDR_CPU,
                  bypass_stage: 0, tid: 0};
    frames[7] = '{len: 34,   ip_dst: ip4(10, 1, 2, 4),     bypass_all: 0, dst: DPE_ADDR_CPU,
                  bypass_stage: 0, tid: 0};
    frames[8] = '{len: 20,   ip_dst: ip4(10, 1, 2, 5),     bypass_all: 0, dst: DPE_ADDR_CPU,
                  bypass_stage: 1, tid: 0};
    frames[9] = '{len: 14,   ip_dst: ip4(10, 1, 2, 6),     bypass_all: 0, dst: DPE_ADDR_CPU,
                  bypass_stage: 0, tid: 0};

    csr_cfg = '{req: 1'b0, addr: '0, req_is_wr: 1'b0, wr_data: '0, wr_biten: '0};
    n_frames = 0;
    rst = 1'b1;
    repeat (4) @(negedge clk);
    rst = 1'b0;

    // 1. the table, over the CSR port, then read back
    for (int i = 0; i < ENTRIES; i++) begin
      csr_write(i, 0, table_m[i].ip);
      csr_write(i, 1, table_m[i].mask);
      csr_write(i, 2, peer_word(table_m[i]));
      csr_write(i, 3, 32'(table_m[i].dst));
    end
    for (int i = 0; i < 4; i++) begin
      csr_read(i, 0, table_m[i].ip);
      csr_read(i, 1, table_m[i].mask);
      csr_read(i, 2, peer_word(table_m[i]));
      csr_read(i, 3, 32'(table_m[i].dst));
    end

    // byte lanes: the CPU writes encrypt alone (byte 1), peer_idx stays
    csr_write(60, 2, 32'h0000_0100, 32'h0000_FF00);
    table_m[60].encrypt = 1'b1;
    csr_read(60, 2, peer_word(table_m[60]));

    // 2. the frames
    n_frames = 10;
    for (int t = 0; t < TIMEOUT_CLKS && rx_frame < n_frames; t++) @(negedge clk);
    if (rx_frame < n_frames) begin
      $display("ERROR: %0d of %0d frames out", rx_frame, n_frames);
      errors++;
    end

    if (errors == 0) $display("RESULT: PASS (%0d frames, CSR read-back)", n_frames);
    else $display("RESULT: FAIL (%0d errors)", errors);
    $finish(2);
  end
endmodule

// -----------------------------------------------------------------------------
// Project:     WireGuard-FPGA
// Description: NLnet-funded open-source implementation
// Funding:     https://nlnet.nl/project/KlusterLab-Wireguard (2023-12 to 2025-12)
// -----------------------------------------------------------------------------
