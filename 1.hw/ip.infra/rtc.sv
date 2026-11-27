// SPDX-FileCopyrightText: 2026 Chili.CHIPS
//
// SPDX-License-Identifier: BSD-3-Clause

//==========================================================================
// Wireguard-1GE FPGA * NLnet-sponsored open-source implementation
//--------------------------------------------------------------------------
// Description:
//   Real-time clock (#30): 64-bit seconds and nanoseconds, counting on the
//   system clock (PERIOD_PS of soc_pkg: 12.5 ns at 80 MHz, 12 ns a clock
//   plus 1 ns every other clock). 0 at reset; csr.rtc.ctrl.load sets it
//   from csr.rtc.set_*. Its accuracy is the board oscillator's.
//
//   An atomic read: reading csr.rtc.nsec latches the seconds of the same
//   clock into csr.rtc.sec_lo and sec_hi, which the firmware reads after.
//==========================================================================

module rtc
  import csr_pkg::*;
  import soc_pkg::*;
(
    input  logic          arst_n,
    input  logic          clk,

    input  csr__out_t     from_csr,
    output csr__rtc__in_t to_csr
);

  localparam int          NS_STEP  = PERIOD_PS / 1000;   // whole ns per clock
  localparam int          PS_STEP  = PERIOD_PS % 1000;   // and the ps left over
  localparam logic [29:0] NS_PER_S = 30'd1_000_000_000;

  logic [63:0] sec;
  logic [29:0] nsec;
  logic [ 9:0] ps;  // ps below nsec, 0 to 999
  logic [63:0] sec_rd;  // sec at the last read of csr.rtc.nsec

  logic [10:0] ps_sum;
  logic        ps_carry;
  logic [30:0] ns_sum;
  logic        ns_carry;

  assign ps_sum   = 11'(ps) + 11'(PS_STEP);
  assign ps_carry = (ps_sum >= 11'd1000);
  assign ns_sum   = 31'(nsec) + 31'(NS_STEP) + 31'(ps_carry);
  assign ns_carry = (ns_sum >= 31'(NS_PER_S));

  always_ff @(negedge arst_n or posedge clk) begin
    if (arst_n == 1'b0) begin
      sec    <= '0;
      nsec   <= '0;
      ps     <= '0;
      sec_rd <= '0;
    end
    else begin
      if (from_csr.rtc.ctrl.load.value == 1'b1) begin
        sec  <= {from_csr.rtc.set_sec_hi.sec.value, from_csr.rtc.set_sec_lo.sec.value};
        nsec <= from_csr.rtc.set_nsec.nsec.value;
        ps   <= '0;
      end
      else begin
        ps   <= ps_carry ? 10'(ps_sum - 11'd1000) : ps_sum[9:0];
        nsec <= ns_carry ? 30'(ns_sum - 31'(NS_PER_S)) : ns_sum[29:0];
        sec  <= sec + 64'(ns_carry);
      end

      if (from_csr.rtc.nsec.nsec.swacc == 1'b1) begin
        sec_rd <= sec;
      end
    end
  end

  assign to_csr.nsec.nsec.next  = nsec;
  assign to_csr.sec_lo.sec.next = sec_rd[31:0];
  assign to_csr.sec_hi.sec.next = sec_rd[63:32];

endmodule : rtc

// -----------------------------------------------------------------------------
// Project:     WireGuard-FPGA
// Description: NLnet-funded open-source implementation
// Funding:     https://nlnet.nl/project/KlusterLab-Wireguard (2023-12 to 2025-12)
// -----------------------------------------------------------------------------
