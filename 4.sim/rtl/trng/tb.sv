// SPDX-FileCopyrightText: 2026 Chili.CHIPS
//
// SPDX-License-Identifier: BSD-3-Clause

//==========================================================================
// Wireguard-1GE FPGA * NLnet-sponsored open-source implementation
//--------------------------------------------------------------------------
// Description:
//   TRNG unit bench (1.hw/ip.infra/trng), driving the modules directly, not
//   through the CSR.
//   1. trng_health, directed: stuck-at 0 and 1 trip the RCT at exactly
//      TRNG_RCT_CUTOFF samples and the APT at TRNG_APT_CUTOFF; a window of
//      TRNG_APT_CUTOFF - 1 matches passes, one of TRNG_APT_CUTOFF fails;
//      biased sources (P(1) = 0.9, 0.8) trip the APT; healthy random
//      samples (a xorshift, 300 windows) trip nothing.
//   2. trng_core with the SIM_ONLY bank model: no word before the startup
//      test, ready after TRNG_STARTUP samples, words while read in time,
//      read clears data, ovf when not read, the sample rate, raw mode from
//      enable on, a stuck bank (forced) fails it and stops the words in
//      normal mode but not in raw mode, enable = 0 clears it all.
//==========================================================================

module tb;
  import trng_pkg::*;

  localparam int RCT_C = TRNG_RCT_CUTOFF;
  localparam int APT_C = TRNG_APT_CUTOFF;
  localparam int APT_W = TRNG_APT_WINDOW;

  logic arst_n;
  logic clk;
  int   errors = 0;

  // 80 MHz in whole ns: halves of 6, 6, 7, 6 ns, 12.5 ns on average
  initial begin
    clk = 1'b0;
    forever begin
      #6ns clk = 1'b1;
      #6ns clk = 1'b0;
      #7ns clk = 1'b1;
      #6ns clk = 1'b0;
    end
  end

  task automatic check(input logic ok, input string what);
    if (!ok) begin
      errors++;
      $display("%t ERROR: %s", $time, what);
    end
  endtask

  //==========================================================================
  // 1. trng_health
  //==========================================================================
  logic         h_clr;
  logic         h_vld;
  logic         h_smp;
  trng_health_t h_sta;

  trng_health u_health (
      .arst_n (arst_n),
      .clk    (clk),
      .clr    (h_clr),
      .vld    (h_vld),
      .smp    (h_smp),
      .sta    (h_sta)
  );

  logic [31:0] rng = 32'h1234_5678;  // the bench's own xorshift32

  function automatic logic [31:0] xs(input logic [31:0] v);
    logic [31:0] t;
    t = v ^ (v << 13);
    t = t ^ (t >> 17);
    return t ^ (t << 5);
  endfunction

  // a sample with P(1) = pct / 100
  function automatic logic biased(input int pct);
    rng = xs(rng);
    return (rng % 100) < pct;
  endfunction

  task automatic h_sample(input logic b);
    h_smp <= b;
    h_vld <= 1'b1;
    @(posedge clk);
    h_vld <= 1'b0;
  endtask

  task automatic h_restart();
    h_clr <= 1'b1;
    @(posedge clk);
    h_clr <= 1'b0;
    @(posedge clk);
  endtask

  // n samples equal to b; the RCT must fail with sample RCT_C, not before
  task automatic h_stuck(input logic b);
    h_restart();
    for (int i = 1; i <= APT_W; i++) begin
      h_sample(b);
      @(negedge clk);
      if (i == RCT_C - 1) begin
        check(!h_sta.rct_fail, $sformatf("stuck-at-%0d: RCT failed at %0d samples", b, i));
      end
      if (i == RCT_C) begin
        check(h_sta.rct_fail, $sformatf("stuck-at-%0d: RCT not failed at %0d", b, i));
      end
      if (i == APT_C - 1) begin
        check(!h_sta.apt_fail, $sformatf("stuck-at-%0d: APT failed at %0d samples", b, i));
      end
      if (i == APT_C) begin
        check(h_sta.apt_fail, $sformatf("stuck-at-%0d: APT not failed at %0d", b, i));
      end
    end
    check(h_sta.rct_max == TRNG_RCT_W'(2 ** TRNG_RCT_W - 1), "stuck: rct_max not saturated");
    check(h_sta.apt_max == TRNG_APT_W'(APT_W), "stuck: apt_max not the window");
    $display("%t stuck-at-%0d: RCT at %0d, APT at %0d samples", $time, b, RCT_C, APT_C);
  endtask

  // one window with exactly k samples equal to its first one (a 1), in runs
  // of at most 5: the RCT stays quiet
  task automatic h_window(input int k);
    int ones;
    int zeros;
    int run;
    ones  = 0;
    zeros = 0;
    run   = 0;
    h_restart();
    for (int i = 0; i < APT_W; i++) begin
      if ((ones < k) && ((run < 4) || (zeros == APT_W - k))) begin
        h_sample(1'b1);
        ones++;
        run++;
      end
      else begin
        h_sample(1'b0);
        zeros++;
        run = 0;
      end
    end
    @(negedge clk);
    check(h_sta.apt_fail == (k >= APT_C), $sformatf("window of %0d matches: apt_fail = %0d",
                                                       k, h_sta.apt_fail));
    check(!h_sta.rct_fail, $sformatf("window of %0d matches: RCT failed", k));
    check(h_sta.apt_max == TRNG_APT_W'(k), $sformatf("window of %0d: apt_max %0d", k,
                                                     h_sta.apt_max));
  endtask

  // P(1) = pct %: the APT must fail within max_windows windows
  task automatic h_bias(input int pct, input int max_windows);
    int n;
    n = 0;
    h_restart();
    while (!h_sta.apt_fail && (n < max_windows * APT_W)) begin
      h_sample(biased(pct));
      n++;
    end
    @(negedge clk);
    check(h_sta.apt_fail, $sformatf("P(1) = %0d%%: APT not failed in %0d windows", pct,
                                    max_windows));
    $display("%t P(1) = %0d%%: APT failed after %0d samples (rct_max %0d)", $time, pct, n,
             h_sta.rct_max);
  endtask

  task automatic h_healthy(input int windows);
    h_restart();
    for (int i = 0; i < windows * APT_W; i++) begin
      h_sample(biased(50));
    end
    @(negedge clk);
    check(!h_sta.rct_fail && !h_sta.apt_fail, "healthy samples failed a test");
    check(h_sta.apt_max > TRNG_APT_W'(APT_W / 2), "healthy: apt_max not above half a window");
    $display("%t healthy, %0d windows: rct_max %0d (cutoff %0d), apt_max %0d (cutoff %0d)", $time,
             windows, h_sta.rct_max, RCT_C, h_sta.apt_max, APT_C);
  endtask

  //==========================================================================
  // 2. trng_core with the SIM_ONLY model
  //==========================================================================
  trng_cfg_t cfg;
  logic      rd;
  trng_sta_t sta;

  trng_core u_core (
      .arst_n (arst_n),
      .clk    (clk),
      .cfg    (cfg),
      .rd     (rd),
      .sta    (sta)
  );

  int words;
  int ones;
  int last_word_clk;
  int clks = 0;

  always_ff @(posedge clk) begin
    clks <= clks + 1;
  end

  // read words as they come, for n words; check each
  task automatic c_read(input int n, input int max_clks);
    int t;
    t = 0;
    words = 0;
    while ((words < n) && (t < max_clks)) begin
      @(negedge clk);
      t++;
      if (sta.valid) begin
        ones += $countones(sta.data);
        words++;
        last_word_clk = clks;
        rd <= 1'b1;
        @(posedge clk);
        rd <= 1'b0;
        @(negedge clk);
        check(!sta.valid && (sta.data == '0), "data not cleared after the read");
      end
    end
    check(words == n, $sformatf("%0d of %0d words in %0d clocks", words, n, max_clks));
  endtask

  task automatic c_enable(input logic raw, input logic [TRNG_RATE_W-1:0] rate);
    cfg.enable <= 1'b0;
    @(posedge clk);
    @(posedge clk);
    cfg.raw    <= raw;
    cfg.rate   <= rate;
    cfg.enable <= 1'b1;
    @(posedge clk);
  endtask

  int t0;
  localparam int STARTUP_CLKS = TRNG_STARTUP * TRNG_SAMPLE_CLKS;
  localparam int WORD_CLKS = TRNG_WORD_SAMPLES * TRNG_SAMPLE_CLKS;

  task automatic core_tests();
    // reset state
    @(negedge clk);
    check(!sta.valid && !sta.ready && !sta.ovf, "core: not idle after reset");
    check(sta.impl == 4'd2, "core: impl is not the SIM_ONLY model");

    // normal mode: no word before ready, ready after the startup test
    c_enable(1'b0, '0);
    t0 = clks;
    while (!sta.ready && (clks - t0 < 2 * STARTUP_CLKS)) begin
      @(negedge clk);
      check(!sta.valid, "core: a word before ready");
    end
    check(sta.ready, "core: not ready");
    check((clks - t0 >= STARTUP_CLKS) && (clks - t0 <= STARTUP_CLKS + 4),
          $sformatf("core: ready after %0d clocks, not %0d", clks - t0, STARTUP_CLKS));
    $display("%t core: ready after %0d clocks", $time, clks - t0);

    // 256 words read in time: no ovf, about half the bits 1, no failure
    ones = 0;
    c_read(256, 300 * WORD_CLKS);
    check(!sta.ovf, "core: ovf while read in time");
    check((ones > 256 * 32 * 45 / 100) && (ones < 256 * 32 * 55 / 100),
          $sformatf("core: %0d ones in 256 words", ones));
    check(!sta.bank[0].rct_fail && !sta.bank[0].apt_fail && !sta.bank[1].rct_fail &&
          !sta.bank[1].apt_fail, "core: the SIM_ONLY model failed a health test");
    $display("%t core: 256 words, %0d ones of %0d; A rct_max %0d apt_max %0d, B %0d %0d", $time,
             ones, 256 * 32, sta.bank[0].rct_max, sta.bank[0].apt_max, sta.bank[1].rct_max,
             sta.bank[1].apt_max);

    // not read for 3 word times: ovf, still a word
    repeat (3 * WORD_CLKS) @(posedge clk);
    @(negedge clk);
    check(sta.ovf && sta.valid, "core: no ovf after unread words");

    // rate 2: a word every 4 x WORD_CLKS
    c_enable(1'b0, 4'd2);
    check(!sta.ovf, "core: ovf not cleared by enable = 0");
    c_read(2, 2 * 4 * (STARTUP_CLKS + WORD_CLKS));
    t0 = last_word_clk;
    c_read(1, 2 * 4 * WORD_CLKS);
    check(last_word_clk - t0 == 4 * WORD_CLKS, $sformatf(
          "core: rate 2, a word every %0d clocks, not %0d", last_word_clk - t0, 4 * WORD_CLKS));

    // raw mode: words from enable on, during the startup test
    c_enable(1'b1, '0);
    t0 = clks;
    c_read(4, 8 * WORD_CLKS);
    check(!sta.ready && (last_word_clk - t0 < 5 * WORD_CLKS), "core: raw words not from enable on");

    // a stuck bank A in normal mode: RCT fails, ready and the words stop
    c_enable(1'b0, '0);
    c_read(1, STARTUP_CLKS + 2 * WORD_CLKS);
    force u_core.g_bank[0].u_bank.smp = 1'b0;
    repeat ((RCT_C + 1) * TRNG_SAMPLE_CLKS) @(posedge clk);
    @(negedge clk);
    check(sta.bank[0].rct_fail && !sta.bank[1].rct_fail, "core: stuck bank A, no RCT failure");
    check(!sta.ready && !sta.valid && (sta.data == '0), "core: words after a failure");
    repeat (4 * WORD_CLKS) begin
      @(negedge clk);
      check(!sta.valid, "core: a word after a failure");
    end
    // raw mode: the words go on, the failure shows
    cfg.raw <= 1'b1;
    c_read(2, 3 * WORD_CLKS);
    check(sta.bank[0].rct_fail, "core: raw mode cleared the failure");
    release u_core.g_bank[0].u_bank.smp;

    // enable = 0 clears it all
    c_enable(1'b0, '0);
    @(negedge clk);
    check(!sta.bank[0].rct_fail && (sta.bank[0].rct_max <= 1) && !sta.ready && !sta.valid,
          "core: enable = 0 did not clear");
    c_read(1, STARTUP_CLKS + 2 * WORD_CLKS);
    check(sta.ready, "core: not ready again");
  endtask

  //==========================================================================
  initial begin
    arst_n     = 1'b0;
    h_clr      = 1'b0;
    h_vld      = 1'b0;
    h_smp      = 1'b0;
    cfg.enable = 1'b0;
    cfg.raw    = 1'b0;
    cfg.rate   = '0;
    rd         = 1'b0;
    repeat (4) @(posedge clk);
    arst_n <= 1'b1;
    @(posedge clk);

    h_stuck(1'b0);
    h_stuck(1'b1);
    h_window(APT_C - 1);
    h_window(APT_C);
    h_bias(90, 1);
    h_bias(80, 20);
    h_healthy(300);

    core_tests();

    if (errors == 0) begin
      $display("RESULT: PASS");
    end
    else begin
      $display("RESULT: FAIL (%0d errors)", errors);
    end
    $finish;
  end

endmodule : tb

// -----------------------------------------------------------------------------
// Project:     WireGuard-FPGA
// Description: NLnet-funded open-source implementation
// Funding:     https://nlnet.nl/project/KlusterLab-Wireguard (2023-12 to 2025-12)
// -----------------------------------------------------------------------------
