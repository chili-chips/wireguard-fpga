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
//   DPE multiplexer testbench
//==========================================================================


module tb;
    import dpe_pkg::*;
    import dpe_tb_pkg::*;

    logic clk;
    logic rst;
    logic pause;
    logic out_ready;  // tready of to_dpe

    dpe_if from_cpu(.clk(clk), .rst(rst));
    dpe_if from_eth_1(.clk(clk), .rst(rst));
    dpe_if from_eth_2(.clk(clk), .rst(rst));
    dpe_if from_eth_3(.clk(clk), .rst(rst));
    dpe_if from_eth_4(.clk(clk), .rst(rst));
    dpe_if to_dpe(.clk(clk), .rst(rst));

    // One test packet per input port. The multiplexer passes dst through
    // and sets tuser_src to the input port.
    typedef struct packed {
       test_pkt_t cpu;
       test_pkt_t eth_1;
       test_pkt_t eth_2;
       test_pkt_t eth_3;
       test_pkt_t eth_4;
    } packet_data_t;

    packet_data_t packet_data;  // set below: JanusHDL 0.17 has no const variables
    initial packet_data = '{
        cpu:   '{dst: DPE_ADDR_ETH_1, len: 6, data: '{8'h01, 8'h02, 8'h03, 8'h04, 8'h05, 8'h06}},
        eth_1: '{dst: DPE_ADDR_CPU,   len: 4, data: '{8'h0B, 8'h0C, 8'h0D, 8'h0E, 8'h00, 8'h00}},
        eth_2: '{dst: DPE_ADDR_ETH_3, len: 5, data: '{8'h15, 8'h16, 8'h17, 8'h18, 8'h19, 8'h00}},
        eth_3: '{dst: DPE_ADDR_ETH_2, len: 4, data: '{8'h1F, 8'h20, 8'h21, 8'h22, 8'h00, 8'h00}},
        eth_4: '{dst: DPE_ADDR_BCAST, len: 4, data: '{8'h29, 8'h2A, 8'h2B, 8'h2C, 8'h00, 8'h00}}
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
    dpe_multiplexer DUT (
        .pause(pause),
        .is_idle(),
        .from_cpu(from_cpu),
        .from_eth_1(from_eth_1),
        .from_eth_2(from_eth_2),
        .from_eth_3(from_eth_3),
        .from_eth_4(from_eth_4),
        .to_dpe(to_dpe)
    );

    // Sources and the sink
    dpe_tb_src #(.SRC(DPE_ADDR_CPU))   src_cpu   (.outp(from_cpu));
    dpe_tb_src #(.SRC(DPE_ADDR_ETH_1)) src_eth_1 (.outp(from_eth_1));
    dpe_tb_src #(.SRC(DPE_ADDR_ETH_2)) src_eth_2 (.outp(from_eth_2));
    dpe_tb_src #(.SRC(DPE_ADDR_ETH_3)) src_eth_3 (.outp(from_eth_3));
    dpe_tb_src #(.SRC(DPE_ADDR_ETH_4)) src_eth_4 (.outp(from_eth_4));

    dpe_tb_sink #(.NAME("to_dpe")) snk (.ready(out_ready), .inp(to_dpe));

    // Main stimulus process
    initial begin
        rst = 1;
        pause = 0;

        repeat (5) @(negedge clk);
        rst = 0;
        @(negedge clk);

        // All inputs at once
        fork
            src_cpu.send(packet_data.cpu);
            src_eth_1.send(packet_data.eth_1);
            src_eth_2.send(packet_data.eth_2);
            src_eth_3.send(packet_data.eth_3);
            src_eth_4.send(packet_data.eth_4);
        join

        repeat (20) @(negedge clk);  // drain

        // Every packet on to_dpe, stamped with its input port
        snk.expect_pkt(packet_data.cpu,   DPE_ADDR_CPU);
        snk.expect_pkt(packet_data.eth_1, DPE_ADDR_ETH_1);
        snk.expect_pkt(packet_data.eth_2, DPE_ADDR_ETH_2);
        snk.expect_pkt(packet_data.eth_3, DPE_ADDR_ETH_3);
        snk.expect_pkt(packet_data.eth_4, DPE_ADDR_ETH_4);
        snk.report();
        if (snk.errors == 0) $display("RESULT: PASS");
        else                 $display("RESULT: FAIL (%0d errors)", snk.errors);
        $finish(2);
    end

    // Output back-pressure, and a pause while packets wait
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
        pause = 1;
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
        pause = 0;
    end
endmodule
