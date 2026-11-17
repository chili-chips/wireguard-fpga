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
    // Constants

    // Clock and reset signals
    logic clk;
    logic rst;
    logic pause;

    // Interfaces
    dpe_if from_cpu(.clk(clk), .rst(rst));
    dpe_if from_eth_1(.clk(clk), .rst(rst));
    dpe_if from_eth_2(.clk(clk), .rst(rst));
    dpe_if from_eth_3(.clk(clk), .rst(rst));
    dpe_if from_eth_4(.clk(clk), .rst(rst));
    dpe_if to_dpe(.clk(clk), .rst(rst));

    // Test data type and constants
    typedef logic [7:0] test_data_t [6];
    typedef test_data_t packet_data_t [5];

    const packet_data_t packet_data = '{
        '{8'h01, 8'h02, 8'h03, 8'h04, 8'h05, 8'h06},  // Input 0
        '{8'h0B, 8'h0C, 8'h0D, 8'h0E, 8'h00, 8'h00},  // Input 1
        '{8'h15, 8'h16, 8'h17, 8'h18, 8'h19, 8'h00},  // Input 2
        '{8'h1F, 8'h20, 8'h21, 8'h22, 8'h00, 8'h00},  // Input 3
        '{8'h29, 8'h2A, 8'h2B, 8'h2C, 8'h00, 8'h00}   // Input 4
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

    // Main stimulus process
    initial begin
        rst = 1;
        pause = 0;
        // Initialize all input interfaces
        from_cpu.tvalid = 0;
        from_cpu.tlast = 0;
        from_cpu.tkeep = '0;
        from_cpu.tdata = '0;

        from_eth_1.tvalid = 0;
        from_eth_1.tlast = 0;
        from_eth_1.tkeep = '0;
        from_eth_1.tdata = '0;

        from_eth_2.tvalid = 0;
        from_eth_2.tlast = 0;
        from_eth_2.tkeep = '0;
        from_eth_2.tdata = '0;

        from_eth_3.tvalid = 0;
        from_eth_3.tlast = 0;
        from_eth_3.tkeep = '0;
        from_eth_3.tdata = '0;

        from_eth_4.tvalid = 0;
        from_eth_4.tlast = 0;
        from_eth_4.tkeep = '0;
        from_eth_4.tdata = '0;

        // Reset assertion
        repeat (4) @(negedge clk);
        @(posedge clk);
        @(negedge clk);
        rst = 0;
        @(negedge clk);

        // Start all stimulus processes in parallel
        fork
            // Input 0 stimulus
            begin
                @(posedge clk);
                @(negedge clk);
                from_cpu.tvalid = 1;
                for (int i = 0; i < 6; i++) begin
                    from_cpu.tdata = '0;
                    from_cpu.tdata[7:0] = packet_data[0][i];
                    from_cpu.tkeep = '1;
                    from_cpu.tlast = (i == 5);
                    @(posedge clk);
                    while (!from_cpu.tready) @(posedge clk);
                    @(negedge clk);
                end
                from_cpu.tvalid = 0;
                from_cpu.tlast = 0;
            end

            // Input 1 stimulus
            begin
                @(posedge clk);
                @(negedge clk);
                from_eth_1.tvalid = 1;
                for (int i = 0; i < 4; i++) begin
                    from_eth_1.tdata = '0;
                    from_eth_1.tdata[7:0] = packet_data[1][i];
                    from_eth_1.tkeep = '1;
                    from_eth_1.tlast = (i == 3);
                    @(posedge clk);
                    while (!from_eth_1.tready) @(posedge clk);
                    @(negedge clk);
                end
                from_eth_1.tvalid = 0;
                from_eth_1.tlast = 0;
            end

            // Input 2 stimulus
            begin
                @(posedge clk);
                @(negedge clk);
                from_eth_2.tvalid = 1;
                for (int i = 0; i < 5; i++) begin
                    from_eth_2.tdata = '0;
                    from_eth_2.tdata[7:0] = packet_data[2][i];
                    from_eth_2.tkeep = '1;
                    from_eth_2.tlast = (i == 4);
                    @(posedge clk);
                    while (!from_eth_2.tready) @(posedge clk);
                    @(negedge clk);
                end
                from_eth_2.tvalid = 0;
                from_eth_2.tlast = 0;
            end

            // Input 3 stimulus
            begin
                @(posedge clk);
                @(negedge clk);
                from_eth_3.tvalid = 1;
                for (int i = 0; i < 4; i++) begin
                    from_eth_3.tdata = '0;
                    from_eth_3.tdata[7:0] = packet_data[3][i];
                    from_eth_3.tkeep = '1;
                    from_eth_3.tlast = (i == 3);
                    @(posedge clk);
                    while (!from_eth_3.tready) @(posedge clk);
                    @(negedge clk);
                end
                from_eth_3.tvalid = 0;
                from_eth_3.tlast = 0;
            end

            // Input 4 stimulus
            begin
                @(posedge clk);
                @(negedge clk);
                from_eth_4.tvalid = 1;
                for (int i = 0; i < 4; i++) begin
                    from_eth_4.tdata = '0;
                    from_eth_4.tdata[7:0] = packet_data[4][i];
                    from_eth_4.tkeep = '1;
                    from_eth_4.tlast = (i == 3);
                    @(posedge clk);
                    while (!from_eth_4.tready) @(posedge clk);
                    @(negedge clk);
                end
                from_eth_4.tvalid = 0;
                from_eth_4.tlast = 0;
            end
        join

        repeat (7) @(negedge clk);
        $display("Stimulus completed successfully");
    $finish(2);
    end

    // Output ready control process
    initial begin
        @(posedge clk);
        @(negedge clk);
        to_dpe.tready = 1;
        repeat (7) @(negedge clk);
        to_dpe.tready = 0;
        @(negedge clk);
        to_dpe.tready = 1;
        repeat (4) @(negedge clk);
        to_dpe.tready = 0;
        pause = 1;
        repeat (3) @(negedge clk);
        to_dpe.tready = 1;
        repeat (4) @(negedge clk);
        to_dpe.tready = 0;
        repeat (2) @(negedge clk);
        to_dpe.tready = 1;
        repeat (6) @(negedge clk);
        to_dpe.tready = 0;
        repeat (2) @(negedge clk);
        to_dpe.tready = 1;
        pause = 0;
    end

    // Monitor process
    int expected_data_count;

    always @(posedge clk) begin
        if (rst) begin
           expected_data_count <= 0;
        end else begin
            if (to_dpe.tvalid && to_dpe.tready) begin
                expected_data_count <= expected_data_count + 1;

                if (to_dpe.tlast) begin
                    $display("Packet received with %0d words", expected_data_count);
                    expected_data_count <= 0;
                end
            end
        end
    end
endmodule
