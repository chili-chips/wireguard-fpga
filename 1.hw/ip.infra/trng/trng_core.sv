// SPDX-FileCopyrightText: 2026 Chili.CHIPS
//
// SPDX-License-Identifier: BSD-3-Clause

//==========================================================================
// Wireguard-1GE FPGA * NLnet-sponsored open-source implementation
//--------------------------------------------------------------------------
// Description:
//   TRNG entropy source: two ring-oscillator banks (trng_bank), sampled
//   together every TRNG_SAMPLE_CLKS << cfg.rate clocks, each with its own
//   SP 800-90B health tests (trng_health), and a data word of 16 raw
//   samples of each bank for the CPU. No conditioning here: the firmware
//   hashes the raw words (2.sw/app/random.c).
//
//   After enable, the startup test: TRNG_STARTUP samples of each bank with
//   no failure, then ready. In normal mode (raw = 0) words come only while
//   ready, so none from the startup or after a failure. Raw mode offers
//   every word from enable on, for offline assessment (SP 800-90B tools).
//
//   Data word: bit 2i bank A, bit 2i+1 bank B, sample i, i = 0 the oldest.
//   A word not read before the next one is complete is replaced: ovf.
//==========================================================================

module trng_core
  import trng_pkg::*;
(
    input  logic      arst_n,
    input  logic      clk,
    input  trng_cfg_t cfg,
    input  logic      rd,      // the CPU read data: take the word
    output trng_sta_t sta
);

  //--------------------------------------
  // Sample tick
  //--------------------------------------
  logic [TRNG_DIV_W-1:0] div;
  logic [TRNG_DIV_W-1:0] period;
  assign                 period = TRNG_DIV_W'(TRNG_SAMPLE_CLKS) << cfg.rate;
  logic                  tick;  // a sample of each bank
  assign                 tick   = (div >= period - TRNG_DIV_W'(1));  // >=: also when rate drops

  always_ff @(negedge arst_n or posedge clk) begin
    if (arst_n == 1'b0) begin
      div <= '0;
    end
    else if ((cfg.enable == 1'b0) || (tick == 1'b1)) begin
      div <= '0;
    end
    else begin
      div <= div + TRNG_DIV_W'(1);
    end
  end

  //--------------------------------------
  // Banks and health tests
  //--------------------------------------
  logic                  clr;  // enable = 0 clears the tests
  assign                 clr = ~cfg.enable;
  logic [TRNG_BANKS-1:0] smp;
  trng_health_t [TRNG_BANKS-1:0] health;
  logic [TRNG_BANKS-1:0] fail;
  assign                 sta.bank = health;

  for (genvar b = 0; b < TRNG_BANKS; b++) begin : g_bank
    trng_bank #(
        .BANK (b)
    ) u_bank (
        .arst_n (arst_n),
        .clk    (clk),
        .en     (cfg.enable),
        .smp    (smp[b])
    );

    trng_health u_health (
        .arst_n (arst_n),
        .clk    (clk),
        .clr    (clr),
        .vld    (tick),
        .smp    (smp[b]),
        .sta    (health[b])
    );

    assign fail[b] = health[b].rct_fail | health[b].apt_fail;
  end

  //--------------------------------------
  // Startup test
  //--------------------------------------
  logic [$clog2(TRNG_STARTUP):0] scnt;  // samples since enable, up to TRNG_STARTUP
  logic                          started;
  logic                          ready;
  assign                         started   = (scnt == ($clog2(TRNG_STARTUP) + 1)'(TRNG_STARTUP));
  assign                         ready     = started & ~|fail;
  assign                         sta.ready = ready;

  always_ff @(negedge arst_n or posedge clk) begin
    if (arst_n == 1'b0) begin
      scnt <= '0;
    end
    else if (cfg.enable == 1'b0) begin
      scnt <= '0;
    end
    else if ((tick == 1'b1) && (started == 1'b0)) begin
      scnt <= scnt + 1'b1;
    end
  end

  //--------------------------------------
  // Data word
  //--------------------------------------
  logic [TRNG_WORD-TRNG_BANKS-1:0]      sh;  // the samples so far of the word being filled
  logic [ TRNG_WORD-1:0]                word;  // sh with this tick's samples
  assign                                word  = {smp, sh};
  logic [$clog2(TRNG_WORD_SAMPLES)-1:0] n;  // samples of each bank in sh
  logic                                 full;  // word is complete
  assign                                full  = tick & (n == '1);
  logic                                 offer;  // words go to the CPU
  assign                                offer = cfg.enable & (cfg.raw | ready);

  always_ff @(negedge arst_n or posedge clk) begin
    if (arst_n == 1'b0) begin
      sh <= '0;
      n  <= '0;
    end
    else if (cfg.enable == 1'b0) begin
      sh <= '0;
      n  <= '0;
    end
    else if (tick == 1'b1) begin
      sh <= word[TRNG_WORD-1:TRNG_BANKS];
      n  <= n + 1'b1;
    end
  end

  logic [TRNG_WORD-1:0] data;  // the word for the CPU
  logic                 valid;  // data not read yet
  logic                 ovf;  // a word was lost
  assign                sta.data  = data;
  assign                sta.valid = valid;
  assign                sta.ovf   = ovf;

  // a word the CPU took or may no longer take is cleared: the UART debug
  // read cannot fetch the samples behind a key afterwards
  always_ff @(negedge arst_n or posedge clk) begin
    if (arst_n == 1'b0) begin
      data  <= '0;
      valid <= 1'b0;
      ovf   <= 1'b0;
    end
    else if (offer == 1'b0) begin
      data  <= '0;
      valid <= 1'b0;
      ovf   <= ovf & cfg.enable;
    end
    else if (full == 1'b1) begin
      data  <= word;
      valid <= 1'b1;
      if ((valid == 1'b1) && (rd == 1'b0)) begin
        ovf <= 1'b1;
      end
    end
    else if (rd == 1'b1) begin
      data  <= '0;
      valid <= 1'b0;
    end
  end

  assign sta.impl = TRNG_IMPL;

endmodule : trng_core

// -----------------------------------------------------------------------------
// Project:     WireGuard-FPGA
// Description: NLnet-funded open-source implementation
// Funding:     https://nlnet.nl/project/KlusterLab-Wireguard (2023-12 to 2025-12)
// -----------------------------------------------------------------------------
