// SPDX-FileCopyrightText: 2026 Chili.CHIPS
//
// SPDX-License-Identifier: BSD-3-Clause

//==========================================================================
// Wireguard-1GE FPGA * NLnet-sponsored open-source implementation
//--------------------------------------------------------------------------
// Description:
//   The SP 800-90B section 4.4 continuous health tests of one binary noise
//   source, on every sample (vld):
//
//   Repetition Count Test: a run of TRNG_RCT_CUTOFF equal samples fails.
//   Adaptive Proportion Test: windows of TRNG_APT_WINDOW samples; a window
//   in which TRNG_APT_CUTOFF samples (its first one included) equal the
//   first one fails.
//
//   A failure is latched until clr. rct_max and apt_max, the longest run and
//   the highest window count since clr, show the margin to the cutoffs.
//==========================================================================

module trng_health
  import trng_pkg::*;
(
    input  logic         arst_n,
    input  logic         clk,
    input  logic         clr,     // 1: start over (enable = 0)
    input  logic         vld,     // a sample
    input  logic         smp,
    output trng_health_t sta
);

  //--------------------------------------
  // Repetition Count Test
  //--------------------------------------
  logic                  last;  // the previous sample
  logic [TRNG_RCT_W-1:0] run;  // equal samples up to last, 0 after clr; saturates
  logic [TRNG_RCT_W-1:0] run_nxt;

  always_comb begin
    run_nxt = TRNG_RCT_W'(1);
    if ((run != '0) && (smp == last)) begin
      run_nxt = (run == '1) ? run : run + TRNG_RCT_W'(1);
    end
  end

  always_ff @(negedge arst_n or posedge clk) begin
    if (arst_n == 1'b0) begin
      last         <= 1'b0;
      run          <= '0;
      sta.rct_max  <= '0;
      sta.rct_fail <= 1'b0;
    end
    else if (clr == 1'b1) begin
      last         <= 1'b0;
      run          <= '0;
      sta.rct_max  <= '0;
      sta.rct_fail <= 1'b0;
    end
    else if (vld == 1'b1) begin
      last <= smp;
      run  <= run_nxt;
      if (run_nxt > sta.rct_max) begin
        sta.rct_max <= run_nxt;
      end
      if (run_nxt >= TRNG_RCT_W'(TRNG_RCT_CUTOFF)) begin
        sta.rct_fail <= 1'b1;
      end
    end
  end

  //--------------------------------------
  // Adaptive Proportion Test
  //--------------------------------------
  logic [TRNG_APT_W-2:0] idx;  // the sample's place in its window, wraps
  logic                  first;  // the window's first sample
  logic [TRNG_APT_W-1:0] cnt;  // samples of the window equal to first
  logic [TRNG_APT_W-1:0] cnt_nxt;

  always_comb begin
    cnt_nxt = cnt;
    if (idx == '0) begin
      cnt_nxt = TRNG_APT_W'(1);
    end
    else if (smp == first) begin
      cnt_nxt = cnt + TRNG_APT_W'(1);
    end
  end

  always_ff @(negedge arst_n or posedge clk) begin
    if (arst_n == 1'b0) begin
      idx          <= '0;
      first        <= 1'b0;
      cnt          <= '0;
      sta.apt_max  <= '0;
      sta.apt_fail <= 1'b0;
    end
    else if (clr == 1'b1) begin
      idx          <= '0;
      first        <= 1'b0;
      cnt          <= '0;
      sta.apt_max  <= '0;
      sta.apt_fail <= 1'b0;
    end
    else if (vld == 1'b1) begin
      idx <= idx + 1'b1;
      cnt <= cnt_nxt;
      if (idx == '0) begin
        first <= smp;
      end
      if (cnt_nxt > sta.apt_max) begin
        sta.apt_max <= cnt_nxt;
      end
      if (cnt_nxt >= TRNG_APT_W'(TRNG_APT_CUTOFF)) begin
        sta.apt_fail <= 1'b1;
      end
    end
  end

endmodule : trng_health

// -----------------------------------------------------------------------------
// Project:     WireGuard-FPGA
// Description: NLnet-funded open-source implementation
// Funding:     https://nlnet.nl/project/KlusterLab-Wireguard (2023-12 to 2025-12)
// -----------------------------------------------------------------------------
