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
//   WireGuard FPGA top-level module
//==========================================================================

module top
  import csr_pkg::*;
  import soc_pkg::*;
(
    input        clk_p,     //board clock positive
    input        clk_n,     //board clock negative
    input        rst_n,     //reset, low active

    // Ethernet 1
    output       e1_reset,  //phy reset
    output       e1_mdc,    //phy emdio clock
    inout        e1_mdio,   //phy emdio data
    input        e1_rxc,    //125Mhz ethernet gmii rx clock
    input        e1_rxdv,   //GMII recieving data valid
    input        e1_rxer,   //GMII recieving data error
    input  [7:0] e1_rxd,    //GMII recieving data
    input        e1_txc,    //25Mhz ethernet mii tx clock
    output       e1_gtxc,   //125Mhz ethernet gmii tx clock
    output       e1_txen,   //GMII sending data valid
    output       e1_txer,   //GMII sending data error
    output [7:0] e1_txd,    //GMII sending data

    // Ethernet 2
    output       e2_reset,  //phy reset
    output       e2_mdc,    //phy emdio clock
    inout        e2_mdio,   //phy emdio data
    input        e2_rxc,    //125Mhz ethernet gmii rx clock
    input        e2_rxdv,   //GMII recieving data valid
    input        e2_rxer,   //GMII recieving data error
    input  [7:0] e2_rxd,    //GMII recieving data
    input        e2_txc,    //25Mhz ethernet mii tx clock
    output       e2_gtxc,   //125Mhz ethernet gmii tx clock
    output       e2_txen,   //GMII sending data valid
    output       e2_txer,   //GMII sending data error
    output [7:0] e2_txd,    //GMII sending data

    // Ethernet 3
    output       e3_reset,  //phy reset
    output       e3_mdc,    //phy emdio clock
    inout        e3_mdio,   //phy emdio data
    input        e3_rxc,    //125Mhz ethernet gmii rx clock
    input        e3_rxdv,   //GMII recieving data valid
    input        e3_rxer,   //GMII recieving data error
    input  [7:0] e3_rxd,    //GMII recieving data
    input        e3_txc,    //25Mhz ethernet mii tx clock
    output       e3_gtxc,   //125Mhz ethernet gmii tx clock
    output       e3_txen,   //GMII sending data valid
    output       e3_txer,   //GMII sending data error
    output [7:0] e3_txd,    //GMII sending data

    // Ethernet 4
    output       e4_reset,  //phy reset
    output       e4_mdc,    //phy emdio clock
    inout        e4_mdio,   //phy emdio data
    input        e4_rxc,    //125Mhz ethernet gmii rx clock
    input        e4_rxdv,   //GMII recieving data valid
    input        e4_rxer,   //GMII recieving data error
    input  [7:0] e4_rxd,    //GMII recieving data
    input        e4_txc,    //25Mhz ethernet mii tx clock
    output       e4_gtxc,   //125Mhz ethernet gmii tx clock
    output       e4_txen,   //GMII sending data valid
    output       e4_txer,   //GMII sending data error
    output [7:0] e4_txd,    //GMII sending data

    // UART
    input        uart_rx,
    output       uart_tx,

    // Keys
    input  [1:0] key_in,

    // LEDs
    output [1:0] led
);

  //==========================================================================
  // Clock and reset generation
  //==========================================================================
  logic sys_clk;
  logic sys_rst;
  logic sys_rst_n;
  logic eth_gtx_clk;
  logic eth_gtx_rst;

  clk_rst_gen u_clk_rst_gen (
      .clk_p       (clk_p),
      .clk_n       (clk_n),
      .rst_n       (rst_n),
      .sys_clk     (sys_clk),
      .sys_rst     (sys_rst),
      .sys_rst_n   (sys_rst_n),
      .eth_gtx_clk (eth_gtx_clk),
      .eth_gtx_rst (eth_gtx_rst)
  );

  //==========================================================================
  // CPU<->DPE<->Ethernet Interconnect
  //==========================================================================
  dpe_if from_cpu (
      .clk (sys_clk),
      .rst (sys_rst)
  );
  dpe_if from_eth_1 (
      .clk (sys_clk),
      .rst (sys_rst)
  );
  dpe_if from_eth_2 (
      .clk (sys_clk),
      .rst (sys_rst)
  );
  dpe_if from_eth_3 (
      .clk (sys_clk),
      .rst (sys_rst)
  );
  dpe_if from_eth_4 (
      .clk (sys_clk),
      .rst (sys_rst)
  );
  dpe_if to_cpu (
      .clk (sys_clk),
      .rst (sys_rst)
  );
  dpe_if to_eth_1 (
      .clk (sys_clk),
      .rst (sys_rst)
  );
  dpe_if to_eth_2 (
      .clk (sys_clk),
      .rst (sys_rst)
  );
  dpe_if to_eth_3 (
      .clk (sys_clk),
      .rst (sys_rst)
  );
  dpe_if to_eth_4 (
      .clk (sys_clk),
      .rst (sys_rst)
  );
  csr__in_t  to_csr;
  csr__out_t from_csr;

  //=================================
  // CPU Subsystem
  //=================================
  localparam int NUM_WORDS_IMEM = 16384;  //=> 64kB InstructionRAM
  localparam int NUM_WORDS_DMEM = 16384;  //=> 64kB DataRAM

  soc_if bus_cpu (
      .arst_n (sys_rst_n),
      .clk    (sys_clk)
  );
  soc_if bus_uart (
      .arst_n (sys_rst_n),
      .clk    (sys_clk)
  );
  soc_if bus_dmem (
      .arst_n (sys_rst_n),
      .clk    (sys_clk)
  );
  soc_if bus_csr (
      .arst_n (sys_rst_n),
      .clk    (sys_clk)
  );

  logic     imem_cpu_rst_n;
  imem_wr_t imem_wr;  // the UART loader writes the CPU's program memory

  //---------------------------------
  soc_cpu #(
      .ADDR_RESET     (32'h0000_0000),
      .NUM_WORDS_IMEM (NUM_WORDS_IMEM)
  ) u_cpu (
      .bus (bus_cpu),  //MST

      .imem_cpu_rst_n (imem_cpu_rst_n),  //-\ reloading CPU
      .imem_wr        (imem_wr)          //-/ program memory
  );

  //---------------------------------
  soc_fabric u_fabric (
      .cpu  (bus_cpu),  //SLV
      .uart (bus_uart), //SLV

      .dmem (bus_dmem),  //MST
      .csr  (bus_csr)    //MST
  );

  //---------------------------------
  soc_ram #(
      .NUM_WORDS (NUM_WORDS_DMEM)
  ) u_dmem (
      .bus (bus_dmem)  //SLV
  );

  //---------------------------------
  soc_csr u_soc_csr (
      .bus     (bus_csr),  //SLV
      .csr_sta (to_csr),   //i
      .csr_cfg (from_csr)  //o
  );

  //---------------------------------
  uart u_uart (
      .arst_n (sys_rst_n),  //i
      .clk    (sys_clk),    //i

      .uart_rx (uart_rx),  //i
      .uart_tx (uart_tx),  //o

      .from_csr (from_csr),    //i
      .to_csr   (to_csr.uart), //o

      .imem_cpu_rst_n (imem_cpu_rst_n),  //o
      .imem_wr        (imem_wr),         //o

      .bus (bus_uart)  //MST
  );

  //---------------------------------
  cpu_fifo u_cpu_fifo (
      .from_csr (from_csr),         //i
      .to_csr   (to_csr.cpu_fifo),  //o
      .to_cpu   (to_cpu),           //SLV
      .from_cpu (from_cpu)          //MST
  );

  //==========================================================================
  // GPIO
  //==========================================================================
  assign led[1]                  = ~from_csr.gpio.led2.value;
  assign led[0]                  = ~from_csr.gpio.led1.value;
  assign to_csr.gpio.key2.next   = ~key_in[1];  //TODO: Add debounce
  assign to_csr.gpio.key1.next   = ~key_in[0];  //TODO: Add debounce

  // free-running cycle counter (csr.cycle): the firmware's time base
  assign to_csr.cycle.count.incr = 1'b1;

  //==========================================================================
  // DPE
  //==========================================================================
  dpe u_dpe (
      .from_csr               (from_csr),                //i
      .to_csr_dpe             (to_csr.dpe),              //o
      .to_csr_routing_table   (to_csr.routing_table),    //o
      .to_csr_cryptokey_table (to_csr.cryptokey_table),  //o
      .from_cpu               (from_cpu),                //SLV
      .from_eth_1             (from_eth_1),              //SLV
      .from_eth_2             (from_eth_2),              //SLV
      .from_eth_3             (from_eth_3),              //SLV
      .from_eth_4             (from_eth_4),              //SLV
      .to_cpu                 (to_cpu),                  //MST
      .to_eth_1               (to_eth_1),                //MST
      .to_eth_2               (to_eth_2),                //MST
      .to_eth_3               (to_eth_3),                //MST
      .to_eth_4               (to_eth_4)                 //MST
  );

  //==========================================================================
  // Ethernet subsystems
  //==========================================================================
  // the PHYs' GMII pins, one gmii_if each
  gmii_if gmii_1 ();
  gmii_if gmii_2 ();
  gmii_if gmii_3 ();
  gmii_if gmii_4 ();

  assign gmii_1.rx_clk     = e1_rxc;
  assign gmii_1.rxd        = e1_rxd;
  assign gmii_1.rxdv       = e1_rxdv;
  assign gmii_1.rxer       = e1_rxer;
  assign gmii_1.mii_tx_clk = e1_txc;
  assign e1_gtxc           = gmii_1.gtx_clk;
  assign e1_txd            = gmii_1.txd;
  assign e1_txen           = gmii_1.txen;
  assign e1_txer           = gmii_1.txer;

  assign gmii_2.rx_clk     = e2_rxc;
  assign gmii_2.rxd        = e2_rxd;
  assign gmii_2.rxdv       = e2_rxdv;
  assign gmii_2.rxer       = e2_rxer;
  assign gmii_2.mii_tx_clk = e2_txc;
  assign e2_gtxc           = gmii_2.gtx_clk;
  assign e2_txd            = gmii_2.txd;
  assign e2_txen           = gmii_2.txen;
  assign e2_txer           = gmii_2.txer;

  assign gmii_3.rx_clk     = e3_rxc;
  assign gmii_3.rxd        = e3_rxd;
  assign gmii_3.rxdv       = e3_rxdv;
  assign gmii_3.rxer       = e3_rxer;
  assign gmii_3.mii_tx_clk = e3_txc;
  assign e3_gtxc           = gmii_3.gtx_clk;
  assign e3_txd            = gmii_3.txd;
  assign e3_txen           = gmii_3.txen;
  assign e3_txer           = gmii_3.txer;

  assign gmii_4.rx_clk     = e4_rxc;
  assign gmii_4.rxd        = e4_rxd;
  assign gmii_4.rxdv       = e4_rxdv;
  assign gmii_4.rxer       = e4_rxer;
  assign gmii_4.mii_tx_clk = e4_txc;
  assign e4_gtxc           = gmii_4.gtx_clk;
  assign e4_txd            = gmii_4.txd;
  assign e4_txen           = gmii_4.txen;
  assign e4_txer           = gmii_4.txer;

  eth_mac u_eth_1 (
      .gtx_clk (eth_gtx_clk),
      .gtx_rst (eth_gtx_rst),
      .gmii    (gmii_1),
      .speed   (to_csr.ethernet[0].status.speed.next),
      .rx_fifo (from_eth_1),
      .tx_fifo (to_eth_1)
  );

  //--------------------------------------------------------------------------
  eth_mac u_eth_2 (
      .gtx_clk (eth_gtx_clk),
      .gtx_rst (eth_gtx_rst),
      .gmii    (gmii_2),
      .speed   (to_csr.ethernet[1].status.speed.next),
      .rx_fifo (from_eth_2),
      .tx_fifo (to_eth_2)
  );

  //--------------------------------------------------------------------------
  eth_mac u_eth_3 (
      .gtx_clk (eth_gtx_clk),
      .gtx_rst (eth_gtx_rst),
      .gmii    (gmii_3),
      .speed   (to_csr.ethernet[2].status.speed.next),
      .rx_fifo (from_eth_3),
      .tx_fifo (to_eth_3)
  );

  //--------------------------------------------------------------------------
  eth_mac u_eth_4 (
      .gtx_clk (eth_gtx_clk),
      .gtx_rst (eth_gtx_rst),
      .gmii    (gmii_4),
      .speed   (to_csr.ethernet[3].status.speed.next),
      .rx_fifo (from_eth_4),
      .tx_fifo (to_eth_4)
  );

  //--------------------------------------------------------------------------
  // PHY management: none yet. Each PHY out of reset, MDC idle low, MDIO not
  // driven: the PHYs run on their power-up strapping
  assign e1_reset = 1'b1;
  assign e1_mdc   = 1'b0;
  assign e2_reset = 1'b1;
  assign e2_mdc   = 1'b0;
  assign e3_reset = 1'b1;
  assign e3_mdc   = 1'b0;
  assign e4_reset = 1'b1;
  assign e4_mdc   = 1'b0;
endmodule

// -----------------------------------------------------------------------------
// Project:     WireGuard-FPGA
// Description: NLnet-funded open-source implementation
// Funding:     https://nlnet.nl/project/KlusterLab-Wireguard (2023-12 to 2025-12)
// -----------------------------------------------------------------------------
