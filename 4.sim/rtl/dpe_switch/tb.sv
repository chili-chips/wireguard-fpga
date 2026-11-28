// SPDX-FileCopyrightText: 2026 Chili.CHIPS
//
// SPDX-License-Identifier: BSD-3-Clause

//==========================================================================
// Wireguard-1GE FPGA * NLnet-sponsored open-source implementation
//--------------------------------------------------------------------------
//                   Copyright (C) 2026 Chili.CHIPS
//
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions
// are met:
//
// 1. Redistributions of source code must retain the above copyright
// notice, this list of conditions and the following disclaimer.
//
// 2. Redistributions in binary form must reproduce the above copyright
// notice, this list of conditions and the following disclaimer in the
// documentation and/or other materials provided with the distribution.
//
// 3. Neither the name of the copyright holder nor the names of its
// contributors may be used to endorse or promote products derived
// from this software without specific prior written permission.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS
// IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED
// TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A
// PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
// HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
// SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
// LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
// DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
// THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
// (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
// OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
//
//              https://opensource.org/license/bsd-3-clause
//--------------------------------------------------------------------------
// Description:
//   dpe_switch system bench: the whole WireGuard data path, the ChaCha20-
//   Poly1305 cores in it.
//   1. Both tables over their CSR ports (routing_table, cryptokey_table),
//      as the firmware writes them; wg_ip:wg_port as csr.dpe gives them.
//   2. Frames from output/sys_in.pcap (sys_check.py gen): plaintext to the
//      peers, WireGuard from them, and frames it must drop or pass on. The
//      links stall on both sides (dpe_tb_throttle), and outp for long
//      during the 2032-byte hairpins.
//   The output goes to output/sys_out.pcap, the tuser of each frame to
//   output/sys_meta.txt; sys_check.py checks both (see the Makefile).
//   3. At the end, over the CSR port: the no-key entry's send_cnt counted
//      its dropped frames.
//   4. The zero-key entry's replay window: still empty, its frames dropped
//      before the core.
//
//   PERF (make perf): the throughput. Every frame waits in a FIFO until the
//   reader is done, then all go back to back, with no stalls (PASS_PCT
//   100); the bench prints the clocks from one frame to the next, in and
//   out.
//==========================================================================

module tb
  import dpe_pkg::*;
  import net_pkg::*;
  import lkup_pkg::*;
#(
    parameter int PASS_PCT = 60,   // the throttles on both sides
    parameter bit PERF     = 1'b0  // the throughput run (see above)
);
  logic clk, rst, rst_src;  // rst_src: the source waits for the tables
  logic pcapfinished, idle;
  logic perf_go;  // PERF: the frames go

  dpe_if from_pcap (.clk(clk), .rst(rst_src));
  dpe_if to_thr    (.clk(clk), .rst(rst));
  dpe_if to_dut    (.clk(clk), .rst(rst));
  dpe_if from_dut  (.clk(clk), .rst(rst));
  dpe_if to_pcap   (.clk(clk), .rst(rst));

  rt_cfg_t rt_cfg;
  rt_sta_t rt_sta;
  ck_cfg_t ck_cfg;
  ck_sta_t ck_sta;

  // this device: csr.dpe.wg_ip, wg_port (sys_check.py: US)
  localparam ipv4_addr_t WG_IP = 32'hC0A8_0162;  // 192.168.1.98
  localparam udp_port_t WG_PORT = 16'd51820;
  localparam logic [47:0] MAC = 48'hCCBA_CACA_0001;

  dpe_pcapreader #(
      .PCAP_FILENAME   ("sys_in.pcap"),  // in output/
      .TUSER_SRC       (DPE_ADDR_ETH_2),
      .TUSER_DST       (DPE_ADDR_CPU)
  ) pcaprd (
      .outp        (from_pcap),
      .pcapfinished(pcapfinished)
  );

  // PERF: the frames wait here (the reader leaves gaps between them)
  if (PERF) begin : g_perf_fifo
    dpe_if fifo_out (.clk(clk), .rst(rst));
    axis_fifo #(.DEPTH(1 << 20), .ID_ENABLE(0)) u_fifo (.s_axis(from_pcap), .m_axis(fifo_out));
    assign to_thr.tvalid   = fifo_out.tvalid & perf_go;
    assign fifo_out.tready = to_thr.tready & perf_go;
    assign to_thr.tdata    = fifo_out.tdata;
    assign to_thr.tkeep    = fifo_out.tkeep;
    assign to_thr.tlast    = fifo_out.tlast;
    assign to_thr.tuser    = fifo_out.tuser;
    assign to_thr.tid      = fifo_out.tid;
  end
  else begin : g_no_fifo
    assign to_thr.tvalid    = from_pcap.tvalid;
    assign from_pcap.tready = to_thr.tready;
    assign to_thr.tdata     = from_pcap.tdata;
    assign to_thr.tkeep     = from_pcap.tkeep;
    assign to_thr.tlast     = from_pcap.tlast;
    assign to_thr.tuser     = from_pcap.tuser;
    assign to_thr.tid       = from_pcap.tid;
  end

  dpe_tb_throttle #(.PASS_PCT(PASS_PCT), .SEED(16'hACE1)) stall_in (.inp(to_thr), .outp(to_dut));

  dpe_switch dut (
      .inp    (to_dut),
      .outp   (from_dut),
      .idle   (idle),
      .wg_ip  (WG_IP),
      .wg_port(WG_PORT),
      .rt_cfg (rt_cfg),
      .rt_sta (rt_sta),
      .ck_cfg (ck_cfg),
      .ck_sta (ck_sta)
  );

  dpe_if throttled (.clk(clk), .rst(rst));
  dpe_tb_throttle #(.PASS_PCT(PASS_PCT), .SEED(16'h1D2C)) stall_out (.inp(from_dut), .outp(throttled));

  // A long outp stall for the largest frames: from the second beat in of a
  // frame whose outer IPv4 is longer than AEAD_MAX_PT_BYTES (only the
  // hairpin of a 2032-byte packet, sys_check.py: hairmax), outp stops for
  // HOLD_CLKS. The stall backs up into the shared core: its decrypt side
  // must wait, then finish, nothing lost and no deadlock
  localparam int HOLD_CLKS = 4000;
  int in_beat, hold_cnt, holds, dec_held;
  logic hold;

  always @(posedge clk) begin
    if (rst) begin
      in_beat  <= 0;
      hold_cnt <= 0;
      holds    <= 0;
      dec_held <= 0;
    end else begin
      if (to_dut.tvalid && to_dut.tready) in_beat <= to_dut.tlast ? 0 : in_beat + 1;
      if (to_dut.tvalid && to_dut.tready && in_beat == 1 &&
          {to_dut.tdata[7:0], to_dut.tdata[15:8]} > AEAD_MAX_PT_BYTES) begin
        hold_cnt <= HOLD_CLKS;
        holds    <= holds + 1;
        $display("%t outp held for %0d clocks: a %0d-byte outer IPv4 coming in", $time,
                 HOLD_CLKS, {to_dut.tdata[7:0], to_dut.tdata[15:8]});
      end else if (hold_cnt != 0) begin
        hold_cnt <= hold_cnt - 1;
      end
      // the core's decrypt output waiting, while outp is held
      if (hold && dut.core_dec_out.tvalid && !dut.core_dec_out.tready) dec_held <= dec_held + 1;
    end
  end
  assign hold = hold_cnt != 0;

  assign to_pcap.tvalid  = throttled.tvalid & ~hold;
  assign throttled.tready = to_pcap.tready & ~hold;
  assign to_pcap.tdata   = throttled.tdata;
  assign to_pcap.tkeep   = throttled.tkeep;
  assign to_pcap.tlast   = throttled.tlast;
  assign to_pcap.tuser   = throttled.tuser;
  assign to_pcap.tid     = throttled.tid;

  // PERF: the clock of each frame's first beat, in and out
  int  perf_clk;
  int  t_in[$], t_out[$];
  logic out_first;
  always @(posedge clk) begin
    if (!perf_go || !PERF) begin
      perf_clk  <= 0;
      out_first <= 1'b1;
    end
    else begin
      perf_clk <= perf_clk + 1;
      if (to_dut.tvalid && to_dut.tready && in_beat == 0) t_in.push_back(perf_clk);
      if (from_dut.tvalid && from_dut.tready) begin
        if (out_first) t_out.push_back(perf_clk);
        out_first <= from_dut.tlast;
      end
    end
  end

  // the steady state: frame k to k+1, after the first 4
  function automatic void perf_report(string side, int t[$]);
    int d, lo, hi, k0;
    if (t.size() < 8) begin
      $display("PERF: %s: %0d frames, too few (at least 8)", side, t.size());
      return;
    end
    lo = 32'h7FFF_FFFF;
    hi = 0;
    for (int k = 5; k < t.size(); k++) begin
      d  = t[k] - t[k-1];
      lo = (d < lo) ? d : lo;
      hi = (d > hi) ? d : hi;
    end
    // from frame k0, an even number of steps: whole pairs when mix alternates
    k0 = 4 + ((t.size() - 5) % 2);
    $display("PERF: %s: %0d frames, %0.1f clocks per frame (%0d to %0d)", side, t.size(),
             real'(t[t.size()-1] - t[k0]) / (t.size() - 1 - k0), lo, hi);
  endfunction

  dpe_pcapwriter #(
      .PCAP_FILENAME("sys_out.pcap")  // in output/
  ) pcapwr (
      .inp(to_pcap)
  );

  // the tuser of each frame out
  int meta_fd;
  initial meta_fd = $fopen("sys_meta.txt", "w");
  always @(posedge clk) begin
    if (!rst && to_pcap.tvalid && to_pcap.tready && to_pcap.tlast) begin
      $fwrite(meta_fd, "%0d %0d\n", to_pcap.tuser.dst, to_pcap.tuser.bypass_all);
    end
  end

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

  // a hang (a stuck link, idle never set) fails instead of running on
  initial begin
    #20ms;
    $display("RESULT: FAIL (timeout: the frames did not get through)");
    $finish;
  end

  //------------------------------------------------------------------
  // CSR writes: one clock of req, acknowledged in that clock
  //------------------------------------------------------------------
  int errors = 0;

  // routing_table: entry[addr[9:4]], field addr[3:2]: 0 ip, 1 mask,
  // 2 peer_idx (encrypt in bit 8), 3 dst
  task automatic rt_write(int e, int field, logic [31:0] data);
    @(negedge clk);
    rt_cfg = '{req: 1'b1, req_is_wr: 1'b1, addr: 10'({6'(e), 2'(field), 2'b00}),
               wr_data: data, wr_biten: '1};
    #3ns;
    if (!rt_sta.wr_ack) begin
      $display("ERROR: routing_table entry %0d field %0d: no wr_ack", e, field);
      errors++;
    end
    @(negedge clk);
    rt_cfg.req = 1'b0;
  endtask

  task automatic route(int e, logic [31:0] prefix, logic [31:0] mask, int peer, logic encrypt,
                       dpe_addr_t dst);
    rt_write(e, 0, prefix);
    rt_write(e, 1, mask);
    rt_write(e, 2, {23'd0, encrypt, 8'(peer)});
    rt_write(e, 3, 32'(dst));
  endtask

  // cryptokey_table: entry[addr[12:7]], word addr[6:2] (lkup_pkg ck_word_t)
  task automatic ck_write(int e, ck_word_t w, logic [31:0] data);
    @(negedge clk);
    ck_cfg = '{req: 1'b1, req_is_wr: 1'b1, addr: 13'({6'(e), w, 2'b00}),
               wr_data: data, wr_biten: '1};
    #3ns;
    if (!ck_sta.wr_ack) begin
      $display("ERROR: cryptokey_table entry %0d word %0d: no wr_ack", e, w);
      errors++;
    end
    @(negedge clk);
    ck_cfg.req = 1'b0;
  endtask

  // a cryptokey_table read: rd_ack and the data one clock after the request
  task automatic ck_read(int e, ck_word_t w, output logic [31:0] data);
    @(negedge clk);
    ck_cfg = '{req: 1'b1, req_is_wr: 1'b0, addr: 13'({6'(e), w, 2'b00}), wr_data: '0,
               wr_biten: '0};
    @(negedge clk);
    ck_cfg.req = 1'b0;
    if (!ck_sta.rd_ack) begin
      $display("ERROR: cryptokey_table entry %0d word %0d: no rd_ack", e, w);
      errors++;
    end
    data = ck_sta.rd_data;
  endtask

  // the peer entry without a session (sys_check.py: nokey): all-zero keys,
  // a route to it; its NOKEY_FRAMES frames are dropped, each still counted
  // in send_cnt (the firmware's demand for a handshake)
  localparam int NOKEY_E = 3;
  localparam logic [63:0] NOKEY_CNT = 64'd7;
  localparam int NOKEY_FRAMES = 3;
  logic [31:0] cnt_hi, cnt_lo;

  // an entry with a local_id but all-zero keys (sys_check.py: zerokey):
  // frames forged under the zero key are dropped, its window stays empty
  localparam int ZEROKEY_E = 6;
  logic [31:0] win_w[4];

  // a peer's entry, numbers as the CPU writes them (sys_check.py: PEERS); tag:
  // its peer tag, the entry its peer's routes point at (local_port[21:16])
  task automatic peer(int e, logic [47:0] mac, logic [31:0] ip, logic [15:0] port,
                      logic [31:0] local_id, logic [31:0] remote_id, logic [255:0] enc_key,
                      logic [255:0] dec_key, logic [63:0] send_cnt, int tag);
    ck_write(e, CK_LOCAL_MAC_HI, 32'(MAC[47:32]));
    ck_write(e, CK_LOCAL_MAC_LO, MAC[31:0]);
    ck_write(e, CK_LOCAL_IP, WG_IP);
    ck_write(e, CK_LOCAL_PORT, {10'd0, 6'(tag), WG_PORT});
    ck_write(e, CK_LOCAL_ID, local_id);
    ck_write(e, CK_REMOTE_MAC_HI, 32'(mac[47:32]));
    ck_write(e, CK_REMOTE_MAC_LO, mac[31:0]);
    ck_write(e, CK_REMOTE_IP, ip);
    ck_write(e, CK_REMOTE_PORT, 32'(port));
    ck_write(e, CK_REMOTE_ID, remote_id);
    for (int k = 0; k < 8; k++) begin
      ck_write(e, ck_word_t'(CK_ENC_KEY_0 + k), enc_key[255-32*k-:32]);
      ck_write(e, ck_word_t'(CK_DEC_KEY_0 + k), dec_key[255-32*k-:32]);
    end
    ck_write(e, CK_SEND_CNT_HI, send_cnt[63:32]);
    ck_write(e, CK_SEND_CNT_LO, send_cnt[31:0]);
    // the replay window: nothing seen yet (the firmware's install)
    ck_write(e, CK_RECV_CNT_HI, '0);
    ck_write(e, CK_RECV_CNT_LO, '0);
    ck_write(e, CK_RECV_WIN_HI, '0);
    ck_write(e, CK_RECV_WIN_LO, '0);
  endtask

  initial begin
    rt_cfg  = '{req: 1'b0, addr: '0, req_is_wr: 1'b0, wr_data: '0, wr_biten: '0};
    ck_cfg  = '{req: 1'b0, addr: '0, req_is_wr: 1'b0, wr_data: '0, wr_biten: '0};
    rst     = 1'b1;
    rst_src = 1'b1;
    perf_go = !PERF;
    @(negedge clk);
    rst = 1'b0;

    // 1. the tables. Routes: first match wins; the unused entries are host
    // routes nothing here uses (the table has no reset)
    route(0, 32'h0A01_0000, 32'hFFFF_0000, 1, 1'b1, DPE_ADDR_ETH_1);  // 10.1/16: peer 1
    route(1, 32'h0A02_0000, 32'hFFFF_0000, 2, 1'b1, DPE_ADDR_ETH_4);  // 10.2/16: peer 2
    route(2, 32'hAC10_0000, 32'hFFF0_0000, 0, 1'b0, DPE_ADDR_ETH_3);  // 172.16/12: LAN
    route(3, 32'hC0A8_0100, 32'hFFFF_FF00, 0, 1'b0, DPE_ADDR_ETH_2);  // 192.168.1/24
    route(4, 32'h0A03_0000, 32'hFFFF_0000, NOKEY_E, 1'b1, DPE_ADDR_ETH_2);  // 10.3/16: no key
    for (int e = 5; e < 64; e++) route(e, {24'hAC1F_FF, 8'(e)}, '1, 0, 1'b0, DPE_ADDR_CPU);

    // peers: our receiver index has the entry in its low 6 bits; the other
    // entries' indexes match no packet here
    for (int e = 0; e < 64; e++) ck_write(e, CK_LOCAL_ID, 32'hDEAD_0000 | 32'(e));
    peer(1, 48'h0200_0000_0099, 32'hC0A8_0163, 16'd51821, 32'h5EED_0041, 32'hAABB_CCDD,
         {4{64'h0123_4567_89AB_CDEF}}, {4{64'hFEDC_BA98_7654_3210}},
         64'h0000_0000_FFFF_FFFE, 1);  // the count crosses into the upper word
    peer(2, 48'h0200_0000_0077, 32'hC0A8_014D, 16'd51822, 32'h7A11_0042, 32'h1122_3344,
         {2{128'h0011_2233_4455_6677_8899_AABB_CCDD_EEFF}},
         {2{128'hA5A5_A5A5_5A5A_5A5A_0F0F_0F0F_F0F0_F0F0}}, 64'd5, 2);
    peer(NOKEY_E, 48'h0200_0000_0033, 32'hC0A8_0133, 16'd51823, 32'h0000_0000, 32'h5555_6666,
         '0, '0, NOKEY_CNT, NOKEY_E);  // a removed session: keys and local_id zeroed
    // the next sessions (#85, sys_check.py: next...): entry 4 of peer 1, entry 5
    // of peer 2, each tagged with its peer's routed entry
    peer(4, 48'h0200_0000_0099, 32'hC0A8_0163, 16'd51821, 32'h5EED_0084, 32'hAABB_0004,
         {2{128'h1111_2222_3333_4444_5555_6666_7777_8888}}, {4{64'h1357_9BDF_2468_ACE0}},
         64'd0, 1);
    peer(5, 48'h0200_0000_0077, 32'hC0A8_014D, 16'd51822, 32'h7A11_0085, 32'h1122_0005,
         {2{128'h9999_0000_AAAA_BBBB_CCCC_DDDD_EEEE_FFFF}}, {4{64'h0F1E_2D3C_4B5A_6978}},
         64'd0, 2);
    peer(ZEROKEY_E, 48'h0200_0000_0099, 32'hC0A8_0163, 16'd51821, 32'h5EED_0086,
         32'hAABB_0006, '0, '0, 64'd0, 1);  // a local_id written, no keys

    // 2. the frames
    @(negedge clk);
    rst_src = 1'b0;
    while (!pcapfinished) @(negedge clk);
    repeat (4) @(negedge clk);  // the last beat into the FIFO
    perf_go = 1'b1;
    do begin
      repeat (64) @(negedge clk);
    end while (!idle || to_dut.tvalid || from_dut.tvalid || to_pcap.tvalid);
    repeat (2) @(negedge clk);
    $fclose(meta_fd);
    $display("outp holds: %0d; the core's decrypt output waited %0d clocks in them", holds,
             dec_held);
    if (PERF) begin
      perf_report("in ", t_in);
      perf_report("out", t_out);
    end
    else if (holds == 0 || dec_held == 0) begin
      $display("RESULT: FAIL (the outp hold did not reach the decrypt side)");
    end
    if (!PERF) begin
      ck_read(NOKEY_E, CK_SEND_CNT_HI, cnt_hi);
      ck_read(NOKEY_E, CK_SEND_CNT_LO, cnt_lo);
      if ({cnt_hi, cnt_lo} != NOKEY_CNT + 64'(NOKEY_FRAMES)) begin
        $display("RESULT: FAIL (no-key entry %0d: send_cnt %0d, want %0d)", NOKEY_E,
                 {cnt_hi, cnt_lo}, NOKEY_CNT + 64'(NOKEY_FRAMES));
      end
      else begin
        $display("no-key entry %0d: send_cnt %0d, its %0d frames counted", NOKEY_E,
                 {cnt_hi, cnt_lo}, NOKEY_FRAMES);
      end
      ck_read(ZEROKEY_E, CK_RECV_CNT_HI, win_w[0]);
      ck_read(ZEROKEY_E, CK_RECV_CNT_LO, win_w[1]);
      ck_read(ZEROKEY_E, CK_RECV_WIN_HI, win_w[2]);
      ck_read(ZEROKEY_E, CK_RECV_WIN_LO, win_w[3]);
      if ({win_w[0], win_w[1], win_w[2], win_w[3]} != '0) begin
        $display("RESULT: FAIL (zero-key entry %0d: recv_cnt %h, recv_win %h, want 0)",
                 ZEROKEY_E, {win_w[0], win_w[1]}, {win_w[2], win_w[3]});
      end
      else begin
        $display("zero-key entry %0d: window unchanged, its frames dropped", ZEROKEY_E);
      end
    end
    if (errors != 0) $display("RESULT: FAIL (%0d CSR errors)", errors);
    $finish;
  end
endmodule

// -----------------------------------------------------------------------------
// Project:     WireGuard-FPGA
// Description: NLnet-funded open-source implementation
// Funding:     https://nlnet.nl/project/KlusterLab-Wireguard (2023-12 to 2025-12)
// -----------------------------------------------------------------------------
