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
//   Minimal UART BFM, with all serial parameters fixed to:
//     - 115.2kbps (i.e. one bit period is 8.68usec)
//     - 8 Data bits
//     - 1 Stop bit
//     - 0 Parity
//
//  It provides the following Tx tasks:
//     - send_char  (<byte>);
//     - send_string(<string>);
//
//  along with always-on monitoring of Rx wire.
//
//  Use +define+UART_DEBUG for printout of debug messages.
//
//  The bit time follows the UART's time base (soc_pkg::UART_TICK_CLKS):
//  8.68us in hardware, shorter when the simulation build defines
//  UART_SIM_TICK_CLKS.
//==========================================================================

module bfm_uart #(
   parameter bit SOP_TEST     = 1'b0,  // run sop_timeout() after the routes
   parameter int TIMEOUT_LOG2 = 21     // the DUT's UART timeout (top UART_TIMEOUT_LOG2)
) (
   input  logic  uart_rx,
   output logic  uart_tx
);

   // time for one bit in ns: 8.68us at the hardware's 1us tick
   localparam real BITIME_NS = 8_680.0 * (soc_pkg::UART_TICK_CLKS + 1)
                                       / (soc_pkg::NUM_1US_CLKS + 1);

//--------------------------------------
// Send
//--------------------------------------
   task send_char (input byte char);
     //START
      uart_tx = 1'b0;
      #(BITIME_NS * 1ns);

     //D0..7, LSB goes out first
      for (int i=0; i<8; i++) begin
         uart_tx = char[i];
         #(BITIME_NS * 1ns);
      end

     //STOP
      uart_tx = 1'b1;
      #(BITIME_NS * 1ns);
   endtask: send_char

//- - - - - - - - - - - - - - - - - - -
   task send_cmd (input string cmd);
   `ifdef UART_BFM_DEBUG
      $display("\n%t --START-- %m '$%s'\n", $time, cmd);
   `endif

     // Send Start-of-Command character
      send_char (.char("$"));

     // Send Command itself
      for (int i=0; i<cmd.len; i++) begin
         send_char (.char(cmd[i]));
      end

     // Send End-of-Command characters
      send_char (.char("\r"));
      send_char (.char("\n"));

   `ifdef UART_BFM_DEBUG
      $display("\n%t -- END -- %m '$%s'\n", $time, cmd);
   `endif
   endtask: send_cmd


//- - - - - - - - - - - - - - - - - - -
   task send_string (input string text);
   `ifdef UART_BFM_DEBUG
      $display("\n%t --START-- %m '%s'\n", $time, text);
   `endif

      for (int i=0; i<text.len; i++) begin
         send_char (.char(text[i]));
      end

     // Send 'C' End-of-String character
      send_char (.char(8'h0));

   `ifdef UART_BFM_DEBUG
      $display("\n%t -- END -- %m '%s'\n", $time, text);
   `endif
   endtask: send_string

//- - - - - - - - - - - - - - - - - - -
// UART bus master: write one DMEM/CSR word (protocol of 5.test/busw.UART.py)
   task automatic bus_write (input logic [31:0] addr, input logic [31:0] data);
      send_char (.char(8'h12)); // SOP
      send_char (.char(8'h0E)); // BUSW
      for (int i=0; i<4; i++) send_char (.char(addr[i*8 +: 8]));
      for (int i=0; i<4; i++) send_char (.char(data[i*8 +: 8]));
      send_char (.char(8'h0F)); // WE: all bytes
      #(12 * BITIME_NS * 1ns);  // the checksum comes back
      send_char (.char(8'h14)); // EOP
   endtask: bus_write

   // routing_table entry e (csr.rdl: @ 0x400, 16 bytes each): first match wins
   localparam logic [31:0] ROUTING_TABLE = soc_pkg::CSR_BASE + 32'h400;

   task automatic route (input int e, input logic [31:0] prefix, input logic [31:0] mask,
                         input logic [5:0] peer, input logic encrypt, input logic [2:0] dst);
      bus_write (ROUTING_TABLE + 32'(16*e) + 32'h0, prefix);
      bus_write (ROUTING_TABLE + 32'(16*e) + 32'h4, mask);
      bus_write (ROUTING_TABLE + 32'(16*e) + 32'h8, {23'b0, encrypt, 2'b0, peer});
      bus_write (ROUTING_TABLE + 32'(16*e) + 32'hC, {29'b0, dst});
   endtask: route

   // "Routes done" for the UDP senders: a word in the shared mem_model memory
   // (VUserMainUdp.cpp: ROUTES_DONE_ADDR, polled), past the MDIO buffers
   // (tb.sv: MDIO_BUFF_ADDR)
   import "DPI-C" function void MemModelWrite (input int address, input int data, input int be);
   localparam int ROUTES_DONE_ADDR = 32'h5000_1000;

   initial MemModelWrite (ROUTES_DONE_ADDR, 0, 4'hF);

   // The routes of the UDP test (usercode/VUserMainUdp.cpp: node N on eth N),
   // in plain text, by UART bus writes; the table has no reset. The senders
   // go when _init sets ROUTES_DONE_ADDR (after the UART tests), whatever
   // the UART speed
   task automatic program_routes ();
      route (0, 32'hC0A8_9801, '1, 0, 1'b0, 3'd2);  // 192.168.152.1, Node2: eth2
      route (1, 32'hC0A8_0104, '1, 0, 1'b0, 3'd4);  // 192.168.1.4, Node4: eth4
      route (2, '0, '0, 0, 1'b0, 3'd0);              // the rest: the CPU
      $display("%t UART: routing table set (3 routes)", $time);
   endtask: program_routes

`ifdef UART_BUS_STRESS
//- - - - - - - - - - - - - - - - - - -
// #61: UART bus writes while the firmware runs (and stores); chk_uart_bus
// checks the bus, this checks the data landed in DMEM
   int stress_errors = 0;
   int stress_collisions = 0;  // clocks of a CPU store while these writes had the bus

   // The bus writes go to a DMEM window store_stress keeps clear
   // (2.sw/tests/store_stress: its stores start at DMEM_BASE + 0x9000); each
   // word is a tag and its write index
   localparam logic [31:0] BUSW_BASE = soc_pkg::DMEM_BASE + 32'h8000;
   localparam logic [31:0] BUSW_TAG  = 32'hC0DE_0000;

   task automatic bus_stress (input int n);
      logic [31:0] addr, data;
      int c0;
      // Start inside the firmware's store loop, whatever the UART speed
      // (UART_SIM_TICK_CLKS): wait for the CPU's 64th store. Before any other
      // UART bus write (the routes come after), so these are the ones that
      // meet the stores
      repeat (64) @(posedge tb.dut.u_fabric.cpu.clk
                    iff (tb.dut.u_fabric.cpu.vld && tb.dut.u_fabric.cpu.we != '0));
      c0 = tb.chk_uart_bus.collisions;
      for (int k=0; k<n; k++) begin
         addr = BUSW_BASE + 32'(4*k);
         data = BUSW_TAG | 32'(k);
         bus_write (addr, data);
         if (tb.dut.u_dmem.mem[(addr - soc_pkg::DMEM_BASE) >> 2] !== data) begin
            stress_errors++;
            $display("%t UART_BUS_STRESS: DMEM[%h] = %h, expected %h", $time, addr,
                     tb.dut.u_dmem.mem[(addr - soc_pkg::DMEM_BASE) >> 2], data);
         end
      end
      stress_collisions = tb.chk_uart_bus.collisions - c0;
      $display("%t UART_BUS_STRESS: %0d bus writes, %0d data errors, %0d store collisions",
               $time, n, stress_errors, stress_collisions);
   endtask: bus_stress
`endif

//- - - - - - - - - - - - - - - - - - -
// A stray SOP (0x12, a Ctrl-R on the console), then nothing: uart.sv must
// end the session after its timeout (TIMEOUT_LOG2, set low for this test) and
// give the CPU the bus back; while it holds the bus, the CSR block must see
// no access (the address waits at the DMEM base: no read side effects)
   task automatic sop_timeout ();
      int limit, waited, csr_hits;
      limit    = 4 * (2 ** TIMEOUT_LOG2) * (soc_pkg::UART_TICK_CLKS + 1);
      waited   = 0;
      csr_hits = 0;
      send_char (.char(8'h12));  // SOP, and no command
      @(posedge tb.dut.u_fabric.cpu.clk iff tb.dut.u_fabric.uart_busy);
      while (tb.dut.u_fabric.uart_busy && waited < limit) begin
         @(posedge tb.dut.u_fabric.cpu.clk);
         if (tb.dut.u_fabric.csr.vld) csr_hits++;
         waited++;
      end
      if (!tb.dut.u_fabric.uart_busy && csr_hits == 0)
         $display("%t UART_SOP_TEST: PASS (bus back after %0d clocks, no CSR access)",
                  $time, waited);
      else
         $display("%t UART_SOP_TEST: FAIL (bus %s after %0d clocks, %0d CSR accesses)",
                  $time, tb.dut.u_fabric.uart_busy ? "still held" : "back", waited, csr_hits);
   endtask: sop_timeout

//- - - - - - - - - - - - - - - - - - -
// One UART bus read of a CSR (protocol of 5.test/busr.UART.py): the CSR
// block must see exactly one read, or a register with a read side effect
// (uart.rx.data, trng.data) would lose a word. csr.gpio has none.
   localparam logic [31:0] CSR_GPIO = soc_pkg::CSR_BASE + 32'h48;

   task automatic csr_read_once ();
      int csr_hits;
      csr_hits = 0;
      fork
         begin : count
            forever begin
               @(posedge tb.dut.u_fabric.cpu.clk);
               if (tb.dut.u_fabric.uart_busy && tb.dut.u_fabric.csr.vld) csr_hits++;
            end
         end
         begin : read
            send_char (.char(8'h12));  // SOP
            send_char (.char(8'h0F));  // BUSR
            for (int i=0; i<4; i++) send_char (.char(CSR_GPIO[i*8 +: 8]));
            #(60 * BITIME_NS * 1ns);   // 4 data bytes and the checksum come back
            send_char (.char(8'h14));  // EOP
            #(10 * BITIME_NS * 1ns);
         end
      join_any
      disable fork;
      if (csr_hits == 1)
         $display("%t UART_SOP_TEST: CSR read PASS (1 CSR access)", $time);
      else
         $display("%t UART_SOP_TEST: CSR read FAIL (%0d CSR accesses, want 1)", $time, csr_hits);
   endtask: csr_read_once


//--------------------------------------
// Initial greeting
//--------------------------------------
   int recv_byte_cnt; // number of received bytes

   initial begin: _init
      recv_byte_cnt = 0;

      uart_tx = 1'b1; // drive STOP bit
      #(BITIME_NS * 1ns);

     //__for UART test
     send_string ("FPGA raja\r\n");
`ifdef UART_BUS_STRESS
`ifndef UART_BUS_STRESS_N
 `define UART_BUS_STRESS_N 16
`endif
     bus_stress (`UART_BUS_STRESS_N);  // #61 first: it needs no routes
`endif
     program_routes ();
     if (SOP_TEST) begin
        // after the routes: their last bus write left a CSR address (the routing
        // table) in the UART, which the old design kept reading while it hung;
        // before the senders: the run ends soon after the last frame
        sop_timeout ();
        csr_read_once ();
     end
     MemModelWrite (ROUTES_DONE_ADDR, 1, 4'hF);  // the UDP senders go
     //send_string ("Mi nismo mehke koze\n");

     //__for Command parsing and dispatch test
      /* send_cmd ("2,1,1");
       send_cmd ("2 ");
       send_cmd ("2,1,0");
       send_cmd ("2");
       send_cmd ("2,1,1");
       //#(1 * 10us);
       send_cmd ("2,1,0");

       send_cmd ("3,10,5");   // DAC#1
       send_cmd ("4,23,73");  // DAC#2
       //
       //send_cmd ("1,0,0");    // ADC#1.Corner1
       //send_cmd ("2,1,0");    // ADC#2.Corner2
       //
       //send_cmd ("3,100,10"); // DAC#1
       //send_cmd ("4,3,11");   // DAC#2
       //
       send_cmd ("1,3,1");    // ADC#1
       send_cmd ("2,11,1");   // ADC#2*/
   end


//--------------------------------------
// Receive
//--------------------------------------
   byte   recv_data;
   string recv_line = "";

   initial forever begin: receiver

     //___START: Look for the first input negedge
      @(negedge uart_rx);

     // wait till the middle of START bit, then check if valid
      #(BITIME_NS / 2 * 1ns);
      if (uart_rx !== 1'b0) begin
         $display("%t %m RX_ERROR: START bit not 0", $time);
      end

     //___DATA0-7: Collect 8 data bits (LSB comes in first)
      for (int i=0; i<8; i++) begin
         #(BITIME_NS * 1ns);
         recv_data[i] = uart_rx;
      end

     //___STOP: Wait till the middle of STOP bit to check if valid
      #(BITIME_NS * 1ns);
      if (uart_rx !== 1'b1) begin
         $display("%t %m RX_ERROR: STOP bit not 1", $time);
      end

     // ... and report transaction
   `ifdef UART_BFM_DEBUG
      recv_byte_cnt++;
      $display("%t %m Char#%0d \t%0h (%s)", $time,
               recv_byte_cnt, recv_data, string'(recv_data));
   `endif
      // the console: one log line per received text line (CR dropped)
      if (recv_data == 8'h0A) begin
         $display("UART: %s", recv_line);
         recv_line = "";
      end
      else if (recv_data != 8'h0D) begin
         recv_line = {recv_line, string'(recv_data)};
      end
   `ifdef UART_BFM_DEBUG
      recv_data = 'X;
   `endif
   end: receiver

endmodule: bfm_uart


/*
-----------------------------------------------------------------------------
Version History:
-----------------------------------------------------------------------------
 2024/3/3 JI: original creation
*/
