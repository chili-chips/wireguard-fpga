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
//   DPE demultiplexer testbench
//==========================================================================


module tb;
    import dpe_pkg::*;
    import dpe_tb_pkg::*;

    logic clk;
    logic rst;
    logic   all_ready;  // tready of every output, unless stalled
    ports_t stall;      // outputs held not ready on their own (multicast test)
    ports_t out_ready;  // tready of each output
    logic   stall_go;   // starts the stall pattern
    assign out_ready = {5{all_ready}} & ~stall;

    dpe_if from_dpe(.clk(clk), .rst(rst));
    dpe_if to_port[DPE_PORTS] (.clk(clk), .rst(rst));  // CPU, Ethernet 1 to 4

    // One test packet per destination, sent one after the other from the CPU;
    // then multicast and broadcast again while single outputs stall
    typedef struct packed {
       test_pkt_t to_cpu;
       test_pkt_t to_eth_1;
       test_pkt_t to_eth_2;
       test_pkt_t to_eth_3;
       test_pkt_t to_eth_4;
       test_pkt_t to_all;
       test_pkt_t to_13;
       test_pkt_t to_24;
       test_pkt_t to_all_2;
    } packet_data_t;

    const packet_data_t packet_data = '{
        to_cpu:   '{dst: DPE_ADDR_CPU,   len: 6, data: '{8'h01, 8'h02, 8'h03, 8'h04, 8'h05, 8'h06}},
        to_eth_1: '{dst: DPE_ADDR_ETH_1, len: 4, data: '{8'h0B, 8'h0C, 8'h0D, 8'h0E, 8'h00, 8'h00}},
        to_eth_2: '{dst: DPE_ADDR_ETH_2, len: 5, data: '{8'h15, 8'h16, 8'h17, 8'h18, 8'h19, 8'h00}},
        to_eth_3: '{dst: DPE_ADDR_ETH_3, len: 4, data: '{8'h1F, 8'h20, 8'h21, 8'h22, 8'h00, 8'h00}},
        to_eth_4: '{dst: DPE_ADDR_ETH_4, len: 4, data: '{8'h29, 8'h2A, 8'h2B, 8'h2C, 8'h00, 8'h00}},
        to_all:   '{dst: DPE_ADDR_BCAST, len: 5, data: '{8'h33, 8'h34, 8'h35, 8'h36, 8'h37, 8'h00}},
        to_13:    '{dst: DPE_ADDR_MCAST_13, len: 4, data: '{8'h41, 8'h42, 8'h43, 8'h44, 8'h00, 8'h00}},
        to_24:    '{dst: DPE_ADDR_MCAST_24, len: 5, data: '{8'h51, 8'h52, 8'h53, 8'h54, 8'h55, 8'h00}},
        to_all_2: '{dst: DPE_ADDR_BCAST, len: 6, data: '{8'h61, 8'h62, 8'h63, 8'h64, 8'h65, 8'h66}}
    };

    // Clock generation
    // 80 MHz at 1 ns precision: halves of 6, 6, 7, 6 ns, 12.5 ns on average
    initial begin
       clk = 1'b0;
       forever begin
          #6ns clk = 1'b1;
          #6ns clk = 1'b0;
          #7ns clk = 1'b1;
          #6ns clk = 1'b0;
       end
    end

    // DUT instantiation
    dpe_demux DUT (
        .from_dpe(from_dpe),
        .to_port(to_port)
    );

    // The source and the sinks
    dpe_tb_src #(.SRC(DPE_ADDR_CPU)) src (.outp(from_dpe));

    dpe_tb_sink #(.NAME("to_cpu"))   snk_cpu   (.ready(out_ready[0]), .inp(to_port[0]));
    dpe_tb_sink #(.NAME("to_eth_1")) snk_eth_1 (.ready(out_ready[1]), .inp(to_port[1]));
    dpe_tb_sink #(.NAME("to_eth_2")) snk_eth_2 (.ready(out_ready[2]), .inp(to_port[2]));
    dpe_tb_sink #(.NAME("to_eth_3")) snk_eth_3 (.ready(out_ready[3]), .inp(to_port[3]));
    dpe_tb_sink #(.NAME("to_eth_4")) snk_eth_4 (.ready(out_ready[4]), .inp(to_port[4]));

    // Each output must receive p when p's dst selects it
    task automatic expect_on(input test_pkt_t p);
       ports_t ports;
       ports = ports_of(p.dst);
       if (ports[0]) snk_cpu.expect_pkt(p, DPE_ADDR_CPU);
       if (ports[1]) snk_eth_1.expect_pkt(p, DPE_ADDR_CPU);
       if (ports[2]) snk_eth_2.expect_pkt(p, DPE_ADDR_CPU);
       if (ports[3]) snk_eth_3.expect_pkt(p, DPE_ADDR_CPU);
       if (ports[4]) snk_eth_4.expect_pkt(p, DPE_ADDR_CPU);
    endtask

    // Main stimulus process
    initial begin
        int errors;
        rst      = 1;
        stall    = '0;
        stall_go = 0;

        repeat (5) @(negedge clk);
        rst = 0;
        @(negedge clk);

        src.send(packet_data.to_cpu);
        src.send(packet_data.to_eth_1);
        src.send(packet_data.to_eth_2);
        src.send(packet_data.to_eth_3);
        src.send(packet_data.to_eth_4);
        src.send(packet_data.to_all);

        repeat (20) @(negedge clk);  // drain

        // Multicast and broadcast while single outputs stall: each selected
        // output must get every beat once (issue #11)
        stall_go = 1;
        src.send(packet_data.to_13);
        src.send(packet_data.to_24);
        src.send(packet_data.to_all_2);

        repeat (20) @(negedge clk);  // drain

        expect_on(packet_data.to_cpu);
        expect_on(packet_data.to_eth_1);
        expect_on(packet_data.to_eth_2);
        expect_on(packet_data.to_eth_3);
        expect_on(packet_data.to_eth_4);
        expect_on(packet_data.to_all);
        expect_on(packet_data.to_13);
        expect_on(packet_data.to_24);
        expect_on(packet_data.to_all_2);
        snk_cpu.report();
        snk_eth_1.report();
        snk_eth_2.report();
        snk_eth_3.report();
        snk_eth_4.report();
        errors = snk_cpu.errors + snk_eth_1.errors + snk_eth_2.errors + snk_eth_3.errors
               + snk_eth_4.errors;
        if (errors == 0) $display("RESULT: PASS");
        else             $display("RESULT: FAIL (%0d errors)", errors);
        $finish(2);
    end

    // Output back-pressure: tready low now and then
    initial begin
        all_ready = 0;
        @(negedge clk);
        all_ready = 1;
        repeat (7) @(negedge clk);
        all_ready = 0;
        @(negedge clk);
        all_ready = 1;
        repeat (4) @(negedge clk);
        all_ready = 0;
        repeat (3) @(negedge clk);
        all_ready = 1;
        repeat (4) @(negedge clk);
        all_ready = 0;
        repeat (2) @(negedge clk);
        all_ready = 1;
        repeat (6) @(negedge clk);
        all_ready = 0;
        repeat (2) @(negedge clk);
        all_ready = 1;
    end

    // Single outputs stall: ETH 3 for MCAST_13, ETH 2 and ETH 4 in turn for
    // MCAST_24, then the CPU and ETH 1 for the broadcast
    initial begin
        wait (stall_go);
        stall = 5'b01000;
        repeat (10) @(negedge clk);
        for (int i = 0; i < 12; i++) begin
           stall = i[0] ? 5'b10000 : 5'b00100;
           @(negedge clk);
        end
        stall = 5'b00001;
        repeat (6) @(negedge clk);
        stall = 5'b00010;
        repeat (4) @(negedge clk);
        stall = 5'b10101;
        repeat (3) @(negedge clk);
        stall = '0;
    end
endmodule

// -----------------------------------------------------------------------------
// Project:     WireGuard-FPGA
// Description: NLnet-funded open-source implementation
// Funding:     https://nlnet.nl/project/KlusterLab-Wireguard (2023-12 to 2025-12)
// -----------------------------------------------------------------------------
