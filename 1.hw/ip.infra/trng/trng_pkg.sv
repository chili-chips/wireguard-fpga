// SPDX-FileCopyrightText: 2026 Chili.CHIPS
//
// SPDX-License-Identifier: BSD-3-Clause

//==========================================================================
// Wireguard-1GE FPGA * NLnet-sponsored open-source implementation
//--------------------------------------------------------------------------
// Description:
//   TRNG constants and types: the ring lengths of the two banks, the sample
//   rate, the SP 800-90B health-test cutoffs (README.md, trng_cutoffs.py)
//==========================================================================

package trng_pkg;

  // two entropy banks, A and B
  localparam int TRNG_BANKS = 2;

  // one sample of each bank every TRNG_SAMPLE_CLKS << ctrl.rate system clocks;
  // the entropy claim is for rate 0: 5 Msample/s per bank at 80 MHz
  localparam int TRNG_SAMPLE_CLKS = 16;
  localparam int TRNG_RATE_W = 4;
  localparam int TRNG_DIV_W = $clog2(TRNG_SAMPLE_CLKS) + 2 ** TRNG_RATE_W;

  // SP 800-90B 4.4, binary samples, claimed min-entropy H = 0.5 bit/sample,
  // alpha = 2^-40 (trng_cutoffs.py 0.5 40):
  //   RCT  C = 1 + ceil(40 / 0.5) = 81 equal samples in a row
  //   APT  C = 1 + CRITBINOM(1024, 2^-0.5, 1 - 2^-40) = 824 samples of a
  //        1024-sample window equal to its first one
  localparam int TRNG_RCT_CUTOFF = 81;
  localparam int TRNG_RCT_W = 8;  // the run counter saturates at 255
  localparam int TRNG_APT_WINDOW = 1024;
  localparam int TRNG_APT_CUTOFF = 824;
  localparam int TRNG_APT_W = $clog2(TRNG_APT_WINDOW) + 1;  // counts up to the window

  // the startup test (SP 800-90B 4.3): one full APT window of each bank, no
  // failure, before the first word
  localparam int TRNG_STARTUP = TRNG_APT_WINDOW;

  // a data word: 16 samples of each bank, interleaved
  localparam int TRNG_WORD = 32;
  localparam int TRNG_WORD_SAMPLES = TRNG_WORD / TRNG_BANKS;

  // ring oscillators: each bank the XOR of TRNG_ROS free-running rings; every
  // length is an odd prime, no two rings alike, so no two lock to each other
  localparam int TRNG_ROS = 8;
  localparam int TRNG_LEN[TRNG_BANKS][TRNG_ROS] = '{
      '{3, 7, 13, 19, 29, 37, 43, 53},  // bank A
      '{5, 11, 17, 23, 31, 41, 47, 59}  // bank B
  };

  // the entropy source; TRNG_IMPL is csr.trng.status.impl
`ifdef SIM_ONLY
  // the SIM_ONLY models, neither random: a xorshift32 per bank (default), or
  // with +trng_rings=1 the rings themselves, each stage a delay with seeded jitter
  localparam logic [3:0] TRNG_IMPL = 4'd2;
  localparam logic [31:0] TRNG_SIM_SEED[TRNG_BANKS] = '{32'h2545_f491, 32'h9e37_79b9};
  localparam int TRNG_SIM_STAGE_PS = 350;  // a LUT and its net
  localparam int TRNG_SIM_SPREAD_PS = 10;  // fixed, per stage: +-
  localparam int TRNG_SIM_JITTER_PS = 10;  // per edge: +-
`else
  localparam logic [3:0] TRNG_IMPL = 4'd1;
`endif

  // csr.trng.ctrl
  typedef struct packed {
    logic [TRNG_RATE_W-1:0] rate;    // [5:2]
    logic                   raw;     // [1]
    logic                   enable;  // [0]
  } trng_cfg_t;

  // the health of one bank, cleared by enable = 0
  typedef struct packed {
    logic [TRNG_APT_W-1:0] apt_max;   // [20:10] highest APT count of a window
    logic [TRNG_RCT_W-1:0] rct_max;   // [9:2]  longest run of equal samples
    logic                  apt_fail;  // [1]    latched
    logic                  rct_fail;  // [0]    latched
  } trng_health_t;

  // csr.trng.status, data, rct_max, apt_max
  typedef struct packed {
    logic [3:0]                    impl;   // [80:77]
    logic                          ovf;    // [76]
    logic                          ready;  // [75]
    logic                          valid;  // [74]
    logic [TRNG_WORD-1:0]          data;   // [73:42]
    trng_health_t [TRNG_BANKS-1:0] bank;   // [41:0] [0] bank A, [1] bank B
  } trng_sta_t;

endpackage : trng_pkg

// -----------------------------------------------------------------------------
// Project:     WireGuard-FPGA
// Description: NLnet-funded open-source implementation
// Funding:     https://nlnet.nl/project/KlusterLab-Wireguard (2023-12 to 2025-12)
// -----------------------------------------------------------------------------
