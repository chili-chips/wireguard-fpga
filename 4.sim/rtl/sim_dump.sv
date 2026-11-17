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
