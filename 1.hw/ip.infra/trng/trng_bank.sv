// SPDX-FileCopyrightText: 2026 Chili.CHIPS
//
// SPDX-License-Identifier: BSD-3-Clause

//==========================================================================
// Wireguard-1GE FPGA * NLnet-sponsored open-source implementation
//--------------------------------------------------------------------------
// Description:
//   One TRNG entropy bank: TRNG_ROS free-running ring oscillators of the
//   lengths TRNG_LEN[BANK], each sampled by the system clock, the samples
//   XORed and registered again: one raw sample a clock.
//
//
//   A ring is a LUT2 NAND (en) and LUT1 inverters, an odd number of
//   inverting stages, KEEP and DONT_TOUCH so no tool shortens or removes it.
//   The loop is on purpose: ALLOW_COMBINATORIAL_LOOPS on the ring net lets
//   Vivado pass DRC LUTLP-1; nextpnr needs --ignore-loops (README.md).
//
//   SIM_ONLY: two models behind the same ports and timing, neither random.
//   - default: a seeded xorshift32 (TRNG_SIM_SEED[BANK]) stands in for the
//     bank, cheap enough for the co-simulation
//   - +trng_rings=1: the rings themselves, each stage a delay of
//     TRNG_SIM_STAGE_PS, a fixed spread and a seeded jitter per edge, into
//     the same sampling flops and XOR as on the chip. Slower: every stage
//     is an event every TRNG_SIM_STAGE_PS
//==========================================================================

module trng_bank
  import trng_pkg::*;
#(
    parameter int BANK = 0  // 0: bank A, 1: bank B (TRNG_LEN, TRNG_SIM_SEED)
) (
    input  logic arst_n,
    input  logic clk,
    input  logic en,      // 1: the rings run
    output logic smp      // a raw sample every clock
);

  logic [TRNG_ROS-1:0] tap;  // the ring outputs: no clock, asynchronous

`ifdef SIM_ONLY
  //------------------------------------------------------------------------
  // the model in use: +trng_rings=1 the rings, else the xorshift32
  logic use_rings;
  logic ring_en;  // the rings run only when they are in use
  initial begin
    int n;
    n         = 0;
    use_rings = 1'b0;
    if ($value$plusargs("trng_rings=%d", n)) begin
      use_rings = (n != 0);
    end
    // the stage delays need 1 ps precision (the TRNG bench: --timescale
    // 1ns/1ps); at 1 ns they round to 0 and the rings would never advance
    if (use_rings == 1'b1) begin
      realtime t0;
      t0 = $realtime;
      #1ps;
      if ($realtime == t0) begin
        $fatal(1, "trng_bank: +trng_rings=1 needs a 1 ps time precision");
      end
    end
  end
  assign ring_en = en & use_rings;

  // xorshift32
  logic [31:0] x;  // xorshift32 state
  logic [31:0] x1;
  logic [31:0] x2;
  logic [31:0] x3;
  logic        smp_x;
  assign       x1 = x ^ (x << 13);
  assign       x2 = x1 ^ (x1 >> 17);
  assign       x3 = x2 ^ (x2 << 5);

  always_ff @(negedge arst_n or posedge clk) begin
    if (arst_n == 1'b0) begin
      x     <= TRNG_SIM_SEED[BANK];
      smp_x <= 1'b0;
    end
    else if (en == 1'b1) begin
      x     <= x3;
      smp_x <= x[31];
    end
  end

  // the rings: stage s of ring r takes TRNG_SIM_STAGE_PS, plus a fixed
  // spread (the stage's own LUT and net) and a jitter drawn per edge. With
  // ring_en = 0 each stage goes to its stopped value (stage 0, the NAND, 1;
  // then alternating) after the longest stage delay, so no edge still on its
  // way can land after it
  function automatic int jitter_ps();
    return int'($urandom_range(2 * TRNG_SIM_JITTER_PS, 0)) - TRNG_SIM_JITTER_PS;
  endfunction

  for (genvar r = 0; r < TRNG_ROS; r++) begin : g_ro
    localparam int L = TRNG_LEN[BANK][r];

    logic [L-1:0] ring;

    for (genvar s = 0; s < L; s++) begin : g_st
      localparam int D = TRNG_SIM_STAGE_PS - TRNG_SIM_SPREAD_PS
                         + (BANK * 59 + r * 31 + s * 17) % (2 * TRNG_SIM_SPREAD_PS + 1);  // ps
      localparam logic STOP = (s % 2 == 0);
      logic q;
      logic d_in;  // the stage's input

      if (s == 0) begin : g_nand
        assign d_in = ring[L-1];
      end
      else begin : g_inv
        assign d_in = ring[s-1];
      end

      // explicit list: Verilator runs always @* with a delay as a loop that
      // never waits, memory grows until it aborts (verilator#9196, #9373)
      always @(d_in or ring_en) begin
        if (ring_en == 1'b1) begin
          q <= #((D + jitter_ps()) * 1ps) ~d_in;
        end
        else begin
          q <= #((D + TRNG_SIM_JITTER_PS) * 1ps) STOP;
        end
      end
      assign ring[s] = q;
    end

    assign tap[r] = ring[0];
  end
`else
  //------------------------------------------------------------------------
  for (genvar r = 0; r < TRNG_ROS; r++) begin : g_ro
    localparam int L = TRNG_LEN[BANK][r];

    (* keep = "true", dont_touch = "true", allow_combinatorial_loops = "true" *)
    logic [L-1:0] ring;

    // stage 0: NAND, a fixed 1 while en = 0, so the ring stops
    (* dont_touch = "true" *)
    LUT2 #(
        .INIT (4'b0111)
    ) u_nand (
        .I0 (ring[L-1]),
        .I1 (en),
        .O  (ring[0])
    );

    for (genvar s = 1; s < L; s++) begin : g_inv
      (* dont_touch = "true" *)
      LUT1 #(
          .INIT (2'b01)
      ) u_inv (
          .I0 (ring[s-1]),
          .O  (ring[s])
      );
    end

    assign tap[r] = ring[0];
  end
`endif  // SIM_ONLY

  //------------------------------------------------------------------------
  // meta: the first flops, which may go metastable (ASYNC_REG: Vivado
  // treats them as synchronizer flops, no retiming); smp_ro the second
  (* async_reg = "true" *)
  logic [TRNG_ROS-1:0] meta;
  logic                smp_ro;

  always_ff @(negedge arst_n or posedge clk) begin
    if (arst_n == 1'b0) begin
      meta   <= '0;
      smp_ro <= 1'b0;
    end
    else begin
      meta   <= tap;
      smp_ro <= ^meta;
    end
  end

`ifdef SIM_ONLY
  always_comb begin
    smp = use_rings ? smp_ro : smp_x;
  end
`else
  always_comb begin
    smp = smp_ro;
  end
`endif

endmodule : trng_bank

// -----------------------------------------------------------------------------
// Project:     WireGuard-FPGA
// Description: NLnet-funded open-source implementation
// Funding:     https://nlnet.nl/project/KlusterLab-Wireguard (2023-12 to 2025-12)
// -----------------------------------------------------------------------------
