// SPDX-FileCopyrightText: 2026 Chili.CHIPS
//
// SPDX-License-Identifier: BSD-3-Clause

//==========================================================================
// Wireguard-1GE FPGA * NLnet-sponsored open-source implementation
//--------------------------------------------------------------------------
// Description:
//   The configuration clock pin (CCLK) for the user design, after
//   configuration: the SPI flash clock (#30). CCLK is a dedicated pin;
//   only STARTUPE2's USRCCLKO reaches it.
//     • Synthesizable variant:
//         - Xilinx STARTUPE2 (UG470, "STARTUPE2"). The first three clock
//           cycles on USRCCLKO after configuration switch the clock source
//           and do not reach CCLK: the user drives a few clocks with the
//           flash deselected before using it
//     • Simulation-only variant (`SIM_ONLY`):
//         - EOS rises 200 ns after time 0; cclk, the pin the bench's flash
//           model takes, drops the first three USRCCLKO cycles after EOS
//==========================================================================

module fpga_startup (
    input  logic usrcclko,  // to the CCLK pin
    output logic eos        // end of start-up: asynchronous
);

`ifdef SIM_ONLY
  // verilator lint_off UNUSEDSIGNAL
  logic cclk;  // the CCLK pin: a bench's flash model reads <...>.u_startup.cclk
  // verilator lint_on UNUSEDSIGNAL
  int   dropped;  // USRCCLKO cycles dropped since EOS

  initial begin
    eos     = 1'b0;
    dropped = 0;
    #200ns;
    eos = 1'b1;
  end

  always @(negedge usrcclko) begin
    if ((eos == 1'b1) && (dropped < 3)) begin
      dropped <= dropped + 1;
    end
  end

  assign cclk = (dropped == 3) ? usrcclko : 1'b0;

`else
  STARTUPE2 u_startupe2 (
      .CFGCLK    (  /*LINT:OK*/),  // the configuration clock is not used
      .CFGMCLK   (  /*LINT:OK*/),  // the internal oscillator is not used
      .EOS       (eos),
      .PREQ      (  /*LINT:OK*/),  // PROG_USR is FALSE: no program requests
      .CLK       (1'b0),
      .GSR       (1'b0),
      .GTS       (1'b0),
      .KEYCLEARB (1'b1),
      .PACK      (1'b0),
      .USRCCLKO  (usrcclko),
      .USRCCLKTS (1'b0),           // drive CCLK
      .USRDONEO  (1'b1),
      .USRDONETS (1'b1)            // leave the DONE pin alone
  );
`endif  // SIM_ONLY

endmodule : fpga_startup

// -----------------------------------------------------------------------------
// Project:     WireGuard-FPGA
// Description: NLnet-funded open-source implementation
// Funding:     https://nlnet.nl/project/KlusterLab-Wireguard (2023-12 to 2025-12)
// -----------------------------------------------------------------------------
