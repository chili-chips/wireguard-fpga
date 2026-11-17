// SPDX-FileCopyrightText: 2026 Chili.CHIPS
//
// SPDX-License-Identifier: BSD-3-Clause

// Icarus (SIM=icarus): a second top that records the bench into wave.fst
// (vvp -fst). Verilator records through versimSV.cpp, JanusHDL through --fst.
module sim_dump;
  initial begin
    $dumpfile("wave.fst");
    $dumpvars(0, tb);
  end
endmodule

// -----------------------------------------------------------------------------
// Project:     WireGuard-FPGA
// Description: NLnet-funded open-source implementation
// Funding:     https://nlnet.nl/project/KlusterLab-Wireguard (2023-12 to 2025-12)
// -----------------------------------------------------------------------------
