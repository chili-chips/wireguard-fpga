// SPDX-FileCopyrightText: 2026 Chili.CHIPS*ba
//
// SPDX-License-Identifier: BSD-3-Clause

//==========================================================================
// Wireguard-1GE FPGA * NLnet-sponsored open-source implementation
//--------------------------------------------------------------------------
//                   Copyright (C) 2026 Chili.CHIPS*ba
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
//   - Package with declaration commonly used across the entire SOC
//==========================================================================

package soc_pkg;

  //-----------------------------------------
  // parameters that can be customized to your SOC
  //-----------------------------------------
  localparam int SOC_ADDRW     = 32;
  localparam int SOC_DATAW     = 32;

  //--------------------------------------
  // Timebase Generator
  //--------------------------------------
  // Clock period in full pico-seconds. Round down to the nearest integer
  localparam int PERIOD_PS     = 12_500;                       // 80 MHz clock

  // number of clocks needed for 1usec period (-1 because we count from 0)
  localparam int NUM_1US_CLKS  = (1_000_000 / PERIOD_PS) - 1;
  localparam int CNT_1US_WIDTH = $clog2(NUM_1US_CLKS);

  typedef logic [CNT_1US_WIDTH-1:0] cnt_1us_t;

  // UART time base, in clocks (-1): the 1us tick in hardware. A simulation
  // build may define UART_SIM_TICK_CLKS for a shorter tick: the UART then
  // runs (NUM_1US_CLKS+1)/(UART_SIM_TICK_CLKS+1) times faster, and the test
  // bench's bfm_uart follows it. The firmware and its register accesses
  // stay the same.
`ifdef UART_SIM_TICK_CLKS
  localparam int UART_TICK_CLKS = `UART_SIM_TICK_CLKS;
`else
  localparam int UART_TICK_CLKS = NUM_1US_CLKS;
`endif

  // Push-button debounce (debounce.sv): clocks between two samples of a key,
  // 4 ms in hardware. A simulation build samples every 16 clocks, so a key the
  // bench sets reaches the CSR in about 50 clocks, not 12 ms.
`ifdef SIM_ONLY
  localparam int KEY_SAMPLE_CLKS = 16;
`else
  localparam int KEY_SAMPLE_CLKS = 4_000 * (NUM_1US_CLKS + 1);
`endif


  //-----------------------------------------
  // derived values. Don't touch anything in this section
  //-----------------------------------------
`ifdef USE_OWN_CLOG2
  function automatic int clog2(input int value);
    int temp;
    temp = value - 1;

    for (clog2 = 0; temp > 0; clog2++) begin
      temp = temp >> 1;
    end
  endfunction : clog2
`endif


  //- - - - - - - - - - - - - - - - - - - - -
  localparam int SOC_BYTES = SOC_DATAW / 8;      // 4 for 32-bit data bus
  localparam int SOC_ADDRL = $clog2(SOC_BYTES);  // 2 for 32-bit data bus

  typedef logic [SOC_ADDRW-1:SOC_ADDRL] soc_addr_t;  // address is in the full data words
  // per-byte Write Enables. They serve as decoded addr LSBs
  typedef logic [SOC_BYTES-1:0] soc_we_t;
  typedef logic [SOC_DATAW-1:0] soc_data_t;  // Write Data

  // a write into the CPU's program memory (IMEM): the UART loader's, while
  // the CPU is held in reset
  typedef struct packed {
    logic      we;
    soc_addr_t addr;  // a word address, [31:2]
    soc_data_t data;
  } imem_wr_t;

  //- - - - - - - - - - - - - - - - - - - - -
  // Memory map of the data bus (soc_fabric): IMEM is on its own port from 0
  localparam logic [SOC_ADDRW-1:0] DMEM_BASE = 32'h1000_0000;  // to 0x1FFF_FFFF
  localparam logic [SOC_ADDRW-1:0] CSR_BASE  = 32'h2000_0000;  // to 0x3FFF_FFFF

  // Decode by the top address bits (the rest is unused); the two never overlap
  // verilator lint_off UNUSEDSIGNAL
  function automatic logic is_dmem(soc_addr_t addr);
    return addr[31:28] == DMEM_BASE[31:28];
  endfunction

  function automatic logic is_csr(soc_addr_t addr);
    return addr[31:29] == CSR_BASE[31:29];
  endfunction
  // verilator lint_on UNUSEDSIGNAL

  typedef enum logic {
    LO = 1'b0,
    HI = 1'b1
  } soc_boolean_t;

  typedef struct packed {
    logic p;  // [1]
    logic n;  // [0]
  } diff_t;  // differential data type

  //   //instruction opcode with corresponding decode
  //   typedef enum logic [6:0] {
  //      ALUREG = 7'b0110011,    //-\ ALU Data
  //      ALUIMM = 7'b0010011,    //-/ instructions
  //
//      BRNCH  = 7'b1100011,    //-\
//      JALR   = 7'b1100111,    // | Code flow
//      JAL    = 7'b1101111,    // | instructions
//      AUIPC  = 7'b0010111,    //-/
//
//      LUI    = 7'b0110111,    //-\ Load/Store
//      LOAD   = 7'b0000011,    // | instructions
//      STORE  = 7'b0100011,    //-/
//
//      SYSTEM = 7'b1110011     //- special
//   } opcode_t;

//   typedef struct packed {
//      logic         imm20;    // [31]
//      logic [10:1]  imm10_1;  // [30:21]
//      logic         imm11;    // [20]
//      logic [19:12] imm19_12; // [19:12]
//      logic [4:0]   rd;       // [11:7]
//   } grp_jump_t;
//
//   //union declaration for variable parts of instruction, [31:7]
//   typedef union packed {
//      grp_reg2reg_t reg2reg;  //[31:7]-InstrGroup#1
//      grp_imm_t     imm;      //[31:7]-InstrGroup#2
//      grp_uimm_t    uimm;     //[31:7]-InstrGroup#3
//      grp_store_t   store;    //[31:7]-InstrGroup#4
//      grp_brnch_t   brnch;    //[31:7]-InstrGroup#5
//      grp_jump_t    jump;     //[31:7]-InstrGroup#6
//   } grp_t;

endpackage : soc_pkg

/*
-----------------------------------------------------------------------------
Version History:
-----------------------------------------------------------------------------
 2023/12/10 JI: initial creation
*/

// -----------------------------------------------------------------------------
// Project:     WireGuard-FPGA
// Description: NLnet-funded open-source implementation
// Funding:     https://nlnet.nl/project/KlusterLab-Wireguard (2023-12 to 2025-12)
// -----------------------------------------------------------------------------
