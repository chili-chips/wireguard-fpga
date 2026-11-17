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
    logic out_ready;  // tready of every output

    dpe_if from_dpe(.clk(clk), .rst(rst));
    dpe_if to_cpu(.clk(clk), .rst(rst));
    dpe_if to_eth_1(.clk(clk), .rst(rst));
    dpe_if to_eth_2(.clk(clk), .rst(rst));
    dpe_if to_eth_3(.clk(clk), .rst(rst));
    dpe_if to_eth_4(.clk(clk), .rst(rst));

    // One test packet per destination, sent one after the other from the CPU
    typedef struct packed {
       test_pkt_t to_cpu;
       test_pkt_t to_eth_1;
       test_pkt_t to_eth_2;
       test_pkt_t to_eth_3;
       test_pkt_t to_eth_4;
       test_pkt_t to_all;
    } packet_data_t;

    packet_data_t packet_data;  // set below: JanusHDL 0.17 has no const variables
    initial packet_data = '{
        to_cpu:   '{dst: DPE_ADDR_CPU,   len: 6, data: '{8'h01, 8'h02, 8'h03, 8'h04, 8'h05, 8'h06}},
        to_eth_1: '{dst: DPE_ADDR_ETH_1, len: 4, data: '{8'h0B, 8'h0C, 8'h0D, 8'h0E, 8'h00, 8'h00}},
        to_eth_2: '{dst: DPE_ADDR_ETH_2, len: 5, data: '{8'h15, 8'h16, 8'h17, 8'h18, 8'h19, 8'h00}},
        to_eth_3: '{dst: DPE_ADDR_ETH_3, len: 4, data: '{8'h1F, 8'h20, 8'h21, 8'h22, 8'h00, 8'h00}},
        to_eth_4: '{dst: DPE_ADDR_ETH_4, len: 4, data: '{8'h29, 8'h2A, 8'h2B, 8'h2C, 8'h00, 8'h00}},
        to_all:   '{dst: DPE_ADDR_BCAST, len: 5, data: '{8'h33, 8'h34, 8'h35, 8'h36, 8'h37, 8'h00}}
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
    dpe_demultiplexer DUT (
        .from_dpe(from_dpe),
        .to_cpu(to_cpu),
        .to_eth_1(to_eth_1),
        .to_eth_2(to_eth_2),
        .to_eth_3(to_eth_3),
        .to_eth_4(to_eth_4)
    );

    // The source and the sinks
    dpe_tb_src #(.SRC(DPE_ADDR_CPU)) src (.outp(from_dpe));

    dpe_tb_sink #(.NAME("to_cpu"))   snk_cpu   (.ready(out_ready), .inp(to_cpu));
    dpe_tb_sink #(.NAME("to_eth_1")) snk_eth_1 (.ready(out_ready), .inp(to_eth_1));
    dpe_tb_sink #(.NAME("to_eth_2")) snk_eth_2 (.ready(out_ready), .inp(to_eth_2));
    dpe_tb_sink #(.NAME("to_eth_3")) snk_eth_3 (.ready(out_ready), .inp(to_eth_3));
    dpe_tb_sink #(.NAME("to_eth_4")) snk_eth_4 (.ready(out_ready), .inp(to_eth_4));

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
        rst = 1;

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

        expect_on(packet_data.to_cpu);
        expect_on(packet_data.to_eth_1);
        expect_on(packet_data.to_eth_2);
        expect_on(packet_data.to_eth_3);
        expect_on(packet_data.to_eth_4);
        expect_on(packet_data.to_all);
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
        out_ready = 0;
        @(negedge clk);
        out_ready = 1;
        repeat (7) @(negedge clk);
        out_ready = 0;
        @(negedge clk);
        out_ready = 1;
        repeat (4) @(negedge clk);
        out_ready = 0;
        repeat (3) @(negedge clk);
        out_ready = 1;
        repeat (4) @(negedge clk);
        out_ready = 0;
        repeat (2) @(negedge clk);
        out_ready = 1;
        repeat (6) @(negedge clk);
        out_ready = 0;
        repeat (2) @(negedge clk);
        out_ready = 1;
    end
endmodule
