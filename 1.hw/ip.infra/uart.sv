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
//   Minimal UART, with all serial parameters fixed in hardware:
//     - 115.2kbps (i.e. one bit period is 8.68usec)
//     - 8 Data bits
//     - 1 Stop bit
//     - 0 Parity
//
//   It is designed for the minimal expenditure in hardware resources,
//   yet also with minimal burden for the CPU. It therefore contains
//   16-deep FIFO in each direction. Handshake with SW is based on
//   'tx.busy' and 'rx.valid+overflow' flags:
//     - New Tx data is accepted from SW when tx.busy=0/TxFIFO not full
//     - New Rx data is loaded into RxFIFO only when RxFIFO is not full.
//       Otherwise, 'rx.overflow' is raised
//--------------------------------------------------------------------------
//
//  This module also houses the FSM for loading new CPU program via Rx UART.
//==========================================================================

module uart
  import csr_pkg::*;
  import soc_pkg::*;
(
    input  logic           arst_n,
    input  logic           clk,

    input  logic           uart_rx,
    output logic           uart_tx,

    input  csr__out_t      from_csr,
    output csr__uart__in_t to_csr,

    // IMEM Write port, for live updates of CPU program
    output logic           imem_cpu_rst_n,
    output imem_wr_t       imem_wr,

    // DMEM/CSR bus mastering interface
    soc_if.MST             bus
);

  //--------------------------------------
  // IMEM/BUS FSM states
  //--------------------------------------
  typedef enum logic [5:0] {
    T_STATES_WAIT_SOP,
    T_STATES_WAIT_CMD,
    T_STATES_IMPR_WAIT_LEN_LB,
    T_STATES_IMPR_WAIT_LEN_HB,
    T_STATES_IMPR_WAIT_DATA0,
    T_STATES_IMPR_WAIT_DATA1,
    T_STATES_IMPR_WAIT_DATA2,
    T_STATES_IMPR_WAIT_DATA3,
    T_STATES_IMPR_CHECKSUM,
    T_STATES_IMPR_DONE,
    T_STATES_BUSW_WAIT_ADDR0,
    T_STATES_BUSW_WAIT_ADDR1,
    T_STATES_BUSW_WAIT_ADDR2,
    T_STATES_BUSW_WAIT_ADDR3,
    T_STATES_BUSW_WAIT_DATA0,
    T_STATES_BUSW_WAIT_DATA1,
    T_STATES_BUSW_WAIT_DATA2,
    T_STATES_BUSW_WAIT_DATA3,
    T_STATES_BUSW_WAIT_WE,
    T_STATES_BUSW_CHECKSUM,
    T_STATES_BUSW_DONE,
    T_STATES_BUSR_WAIT_ADDR0,
    T_STATES_BUSR_WAIT_ADDR1,
    T_STATES_BUSR_WAIT_ADDR2,
    T_STATES_BUSR_WAIT_ADDR3,
    T_STATES_BUSR_WAIT_DATA,
    T_STATES_BUSR_DATA0,
    T_STATES_BUSR_DATA1,
    T_STATES_BUSR_DATA2,
    T_STATES_BUSR_DATA3,
    T_STATES_BUSR_CHECKSUM,
    T_STATES_BUSR_DONE,
    T_STATES_IMWR_WAIT_ADDR0,
    T_STATES_IMWR_WAIT_ADDR1,
    T_STATES_IMWR_WAIT_DATA0,
    T_STATES_IMWR_WAIT_DATA1,
    T_STATES_IMWR_WAIT_DATA2,
    T_STATES_IMWR_WAIT_DATA3,
    T_STATES_IMWR_CHECKSUM,
    T_STATES_IMWR_DONE,
    T_STATES_TIMEOUT
  } spec_state_t;

  // the registers: r, and r_next, what they hold in the next clock
  typedef struct packed {
    spec_state_t state;          // [241:236]
    logic        bus_vld;        // [235]
    logic        uart_tx_valid;  // [234]   transmit uart_tx_data (the IMEM FSM)
    logic [7:0]  uart_tx_data;   // [233:226] the byte to transmit (the IMEM FSM)
    logic        cpu_rst_n;      // [225]
    logic [15:0] data_length;    // [224:209]
    logic [15:0] data_cnt;       // [208:193]
    logic        ram_wen;        // [192]
    logic [31:0] ram_data;       // [191:160]
    logic [31:0] ram_addr;       // [159:128]
    logic [3:0]  bus_we;         // [127:124]
    soc_addr_t   bus_addr;       // [123:94] a word address: the host's bits [1:0] are not kept
    logic [31:0] bus_rdat;       // [93:62]
    logic [31:0] bus_wdat;       // [61:30]
    logic [7:0]  checksum;       // [29:22]
    logic [21:0] timeout;        // [21:0]
  } regs_t;
  regs_t r, r_next;

  //--------------------------------------
  // IMEM/BUS commands/responses
  //--------------------------------------
  localparam logic [7:0] C_SOP  = 8'h12;  // Enter special mode
  localparam logic [7:0] C_EOP  = 8'h14;  // Exit special mode
  localparam logic [7:0] C_IMPR = 8'h05;  // Enter IMEM programming mode
  localparam logic [7:0] C_ACK  = 8'h06;  // ACK for IMEM programming mode
  localparam logic [7:0] C_TOUT = 8'h07;  // Timeout in IMEM programming mode
  localparam logic [7:0] C_BUSW = 8'h0E;  // Enter DMEM/CSR write data mode
  localparam logic [7:0] C_BUSR = 8'h0F;  // Enter DMEM/CSR read data mode
  localparam logic [7:0] C_IMWR = 8'h1A;  // Enter IMEM write-single-instruction mode

  //--------------------------------------
  // UART FSM states
  //--------------------------------------
  typedef enum logic [3:0] {
    IDLE = 4'd14,

    START = 4'd15,  // skipped altogether in RxFSM

    D0 = 4'd0,  // LSB first
    D1 = 4'd1,  //  |
    D2 = 4'd2,  //  |
    D3 = 4'd3,  //  |
    D4 = 4'd4,  //  |
    D5 = 4'd5,  //  |
    D6 = 4'd6,  //  V
    D7 = 4'd7,  // MSB last

    STOP = 4'd8  // only one Stop bit

    // Zero Parity bit
  } uart_state_t;

  //--------------------------------------
  // 1us tick generator
  //--------------------------------------
  typedef logic [3:0] cnt1us_t;

  logic     tick_1us;
  cnt_1us_t cnt_1us;

  always_ff @(negedge arst_n or posedge clk) begin
    if (arst_n == 1'b0) begin
      tick_1us <= 1'b0;
      cnt_1us  <= '0;
    end
    else begin
      // number of clocks for 1us time-tick pulse depends
      //   on board, i.e. the period of available clocks
      // (-1 because we count from 0)
      tick_1us <= (cnt_1us == cnt_1us_t'(UART_TICK_CLKS - 1));

      if (tick_1us == 1'b1) begin
        cnt_1us <= '0;
      end
      else begin
        cnt_1us <= cnt_1us + cnt_1us_t'(1);
      end
    end
  end

  //--------------------------------------
  // uart_rx synchronizer
  //--------------------------------------
  logic [1:0] uart_rx_ff;
  logic       uart_rx_sync;
  always_ff @(negedge arst_n or posedge clk) begin
    if (arst_n == 1'b0) begin
      uart_rx_ff <= '1;
    end
    else begin
      uart_rx_ff <= {uart_rx_ff[0], uart_rx};
    end
  end
  assign uart_rx_sync = uart_rx_ff[1];

  //--------------------------------------
  // Rx
  //--------------------------------------
  // To save resources, SOC-level 1us tick is used as time base for
  // Rx sampling. Since one bit period is 8.68us, upon detecting START,
  // the FSM first waits 9+4=13us to skip the START bit and get close to
  // the middle of D0, where it samples it. It then waits 8us or 9us for
  // subsequent data bits. This keep the sampling sufficiently centered,
  // despite 'tick_1us' being completely asynchronous to incoming data:
  //
  // - START+D0center=8.68us+4.34us=13.02us is the ideal D0 sampling point.
  //   Given that 'tick_1us' is async to START, actual D0 sampling can fall
  //   anywhere in (13..14)us window. Max D0 sampling error is thus +0.98us
  //
  // - D1 ideal sampling is (2*8.68)+4.34=21.70us
  //   Actual is (13..14)+8=(21..22)us: Max error: -0.70us
  //
  // - D2 ideal sampling is (3*8.68)+4.34=30.38us
  //   Actual is (21..22)+9=(30..31)us: Max error: +0.62us
  //
  // - D3 ideal sampling is (4*8.68)+4.34=39.06us
  //   Actual is (30..31)+9=(39..40)us: Max error: +0.94us
  //
  // - D4 ideal sampling is (5*8.68)+4.34=47.74us
  //   Actual is (39..40)+8=(47..48)us: Max error: -0.74us
  //
  // - D5 ideal sampling is (6*8.68)+4.34=56.42us
  //   Actual is (47..48)+9=(56..57)us: Max error: +0.58us
  //
  // - D6 ideal sampling is (7*8.68)+4.34=65.10us
  //   Actual is (56..57)+9=(65..66)us: Max error: +0.90us
  //
  // - D7 ideal sampling is (8*8.68)+4.34=73.78us
  //   Actual is (65..66)+8=(73..74)us: Max error: -0.78us
  //
  // - STOP ideal sampling is (9*8.68)+4.34=82.46us
  //   Actual is (73..74)+9=(82..83)us: Max error: +0.54us
  //
  // In other words, sampling error is within +/-1us from the center
  // of +/-4.34us window, thus leaving more than sufficient margin
  // for reliable data reception.
  //--------------------------------------

  localparam bit [3:0] RX_WAIT_D0   = 4'd13;  //=14 ticks: From 13 to 0
  localparam bit [3:0] RX_WAIT_D1   = 4'd7;
  localparam bit [3:0] RX_WAIT_D2   = 4'd8;
  localparam bit [3:0] RX_WAIT_D3   = 4'd8;
  localparam bit [3:0] RX_WAIT_D4   = 4'd7;
  localparam bit [3:0] RX_WAIT_D5   = 4'd8;
  localparam bit [3:0] RX_WAIT_D6   = 4'd8;
  localparam bit [3:0] RX_WAIT_D7   = 4'd7;
  localparam bit [3:0] RX_WAIT_STOP = 4'd8;

  (* fsm_encoding = "none" *)
  uart_state_t       rx_state;

  cnt1us_t           rx_cnt1us;  // counts 1us ticks
  logic              rx_cnt1us_is0;

  logic              rx_nextbit;

  logic        [7:0] rx_shift;
  logic rx_fifo_we, rx_fifo_full, rx_oflow;
  logic       rx_fifo_empty;
  logic [7:0] rx_fifo_dout;

  always_comb begin
    rx_cnt1us_is0 = (rx_cnt1us == '0);
    rx_nextbit    = tick_1us & rx_cnt1us_is0;

    rx_fifo_we    = rx_nextbit & (rx_state == STOP);
  end

  always_ff @(negedge arst_n or posedge clk) begin
    if (arst_n == 1'b0) begin
      rx_state  <= IDLE;
      rx_cnt1us <= '0;
      rx_shift  <= '0;

      rx_oflow  <= 1'b0;
    end
    else begin

      // when not in IDLE, count 1us ticks
      if ((tick_1us == 1'b1) && (rx_state != IDLE)) begin
        rx_cnt1us <= rx_cnt1us - cnt1us_t'(1);
      end

      // latch overflow condition
      if ({rx_fifo_we, rx_fifo_full} == 2'b11) begin
        rx_oflow <= 1'b1;
      end
      // SW Clear-on-Read is async to UART traffic
      //  and with lower priority to HW Set
      //else if (from_csr.uart.rx_trigger.read.value == 1'b1) begin
      else if (from_csr.uart.rx.data.swacc == 1'b1) begin
        rx_oflow <= 1'b0;
      end


      // FSM runs on main clock, with most states gated by 'rx_cnt1us_is0'
      unique case (rx_state)

        //---Wait for 'uart_rx_sync' negedge to start reception
        IDLE: begin
          rx_cnt1us <= RX_WAIT_D0;

          if (uart_rx_sync == 1'b0) begin
            rx_state <= D0;
          end
        end

        //---New Rx data is collected: Push it in the FIFO
        //   (*) while logic within FIFO will prevent overflow,
        //       we capture overflow condition locally
        STOP:
        if (rx_nextbit == 1'b1) begin
          // 'rx_fifo_we' is generated at this moment
          rx_state <= IDLE;

`ifdef UART_DEBUG
          $display("%t %m RX'd %0h (%s)", $time, rx_shift, string'(rx_shift));
`endif
        end

        //---Wait the prescribed amount of time to position sampling
        //   point to Rx bit center, then capture DATA bits
        default:
        if (rx_nextbit == 1'b1) begin
          rx_shift <= {uart_rx_sync, rx_shift[7:1]};  // MSB goes in last

          unique case (rx_state)
            D0: begin
              rx_cnt1us <= RX_WAIT_D1;
              rx_state  <= D1;
            end
            D1: begin
              rx_cnt1us <= RX_WAIT_D2;
              rx_state  <= D2;
            end
            D2: begin
              rx_cnt1us <= RX_WAIT_D3;
              rx_state  <= D3;
            end
            D3: begin
              rx_cnt1us <= RX_WAIT_D4;
              rx_state  <= D4;
            end
            D4: begin
              rx_cnt1us <= RX_WAIT_D5;
              rx_state  <= D5;
            end
            D5: begin
              rx_cnt1us <= RX_WAIT_D6;
              rx_state  <= D6;
            end
            D6: begin
              rx_cnt1us <= RX_WAIT_D7;
              rx_state  <= D7;
            end
            D7: begin
              rx_cnt1us <= RX_WAIT_STOP;
              rx_state  <= STOP;
            end
            default: begin
            end
          endcase  // case (rx_state)
        end
      endcase  // case (rx_state)

    end
  end



  logic  rx_fifo_wr;  // a received byte, while the bus does not read the FIFO
  assign rx_fifo_wr = ~r.bus_vld & rx_fifo_we;

  // synchronous RxFIFO absorbs the variability of CPU reads
  sync_fifo_ram #(
      .DWIDTH (8),
      .AWIDTH (4)   // 16 entries
  ) u_rx_fifo (

      // Inputs
      .arst_n (arst_n),
      .clk    (clk),

      .din (rx_shift),
      .we  (rx_fifo_wr),
      //.re        (from_csr.uart.rx_trigger.read.value), // FIFO internal logic prevents underflow
      .re  (from_csr.uart.rx.data.swacc), // FIFO internal logic prevents underflow

      // Outputs
      .dcount (  /*LINT:OK*/),  // FIFO fill level not needed
      .empty  (rx_fifo_empty),
      .full   (rx_fifo_full),

      .dout_comb (rx_fifo_dout),  // fall-through: Data is available w/o read

      .dout (  /*LINT:OK*/)  // dout_comb (fall-through) is used
  );


  //--------------------------------------
  // Tx
  //--------------------------------------
  // To save resources, SOC-level 1us tick is used as Tx time base.
  // Upon detecting SW request to send, and given 8.68us bit period,
  // the FSM employs the following delay scheme to generate bits:
  // - START ideal end: 1*8.68us= 8.68us. Actual: 9(+9). Error: +0.32us
  // - D0    ideal end: 2*8.68us=17.38us. Actual:17(+8). Error: -0.38us
  // - D1    ideal end: 3*8.68us=26.04us. Actual:26(+9). Error: -0.04us
  // - D2    ideal end: 4*8.68us=34.72us. Actual:35(+9). Error: +0.28us
  // - D3    ideal end: 5*8.68us=43.40us. Actual:43(+8). Error: -0.40us
  // - D4    ideal end: 6*8.68us=52.08us. Actual:52(+9). Error: -0.08us
  // - D5    ideal end: 7*8.68us=60.76us. Actual:61(+9). Error: +0.24us
  // - D6    ideal end: 8*8.68us=69.44us. Actual:69(+8). Error: -0.44us
  // - D7    ideal end: 9*8.68us=78.12us. Actual:78(+9). Error: -0.12us
  // - STOP  ideal end:10*8.68us=86.80us. Actual:87(+9). Error: +0.20us
  //
  // In other words, edge placement error is within +/-0.44us for 8.68us
  // period, i.e. +/-5%, thus leaving sufficient margin for reliable
  // data reception on the other end.
  //--------------------------------------

  localparam bit [3:0] TX_WAIT_START = 4'd9;  //+1 tick for initial sync
  localparam bit [3:0] TX_WAIT_D0    = 4'd7;  //=8 ticks, from 7 to 0
  localparam bit [3:0] TX_WAIT_D1    = 4'd8;
  localparam bit [3:0] TX_WAIT_D2    = 4'd8;
  localparam bit [3:0] TX_WAIT_D3    = 4'd7;
  localparam bit [3:0] TX_WAIT_D4    = 4'd8;
  localparam bit [3:0] TX_WAIT_D5    = 4'd8;
  localparam bit [3:0] TX_WAIT_D6    = 4'd7;
  localparam bit [3:0] TX_WAIT_D7    = 4'd8;
  localparam bit [3:0] TX_WAIT_STOP  = 4'd8;

  (* fsm_encoding = "none" *)
  uart_state_t       tx_state;
  cnt1us_t           tx_cnt1us;  // counts 1us ticks
  logic              tx_cnt1us_is0;

  logic              tx_nextbit;

  logic        [7:0] tx_data;
  logic tx_fifo_re, tx_fifo_empty;

  always_comb begin
    tx_cnt1us_is0 = (tx_cnt1us == '0);
    tx_nextbit    = tick_1us & tx_cnt1us_is0;
    tx_fifo_re    = tx_nextbit & (tx_state == STOP);
  end


  always_ff @(negedge arst_n or posedge clk) begin
    if (arst_n == 1'b0) begin
      tx_state  <= IDLE;
      tx_cnt1us <= '0;

      uart_tx   <= 1'b1;  //STOP
    end
    else begin

      // when not in IDLE, count 1us ticks
      if ((tick_1us == 1'b1) && (tx_state != IDLE)) begin
        tx_cnt1us <= tx_cnt1us - cnt1us_t'(1);
      end

      // FSM runs on main clock, with most states gated by 'tx_cnt1us_is0'
      unique case (tx_state)

        //---Keep sending as long as TxFIFO is not empty
        //   to store SW data that needs to be sent
        IDLE: begin
          uart_tx   <= 1'b1;  //STOP
          tx_cnt1us <= TX_WAIT_START;

          if (tx_fifo_empty == 1'b0) begin
            tx_state <= START;
          end
        end

        //---Wait for next 1us tick to start driving 0 (i.e. sync TX to
        //   the tick), then wait the prescribed amount of time to move on
        START:
        if (tick_1us == 1'b1) begin
          uart_tx <= 1'b0;  //START

          if (tx_cnt1us_is0 == 1'b1) begin
            uart_tx   <= tx_data[0];  //LSB goes out first
            tx_cnt1us <= TX_WAIT_D0;
            tx_state  <= D0;
          end
        end
        //---Wait the prescribed amount of time while driving D0,
        //   then move on. Keep repeating the same, till D7
        D0:
        if (tx_nextbit == 1'b1) begin
          uart_tx   <= tx_data[1];
          tx_cnt1us <= TX_WAIT_D1;
          tx_state  <= D1;
        end
        D1:
        if (tx_nextbit == 1'b1) begin
          uart_tx   <= tx_data[2];
          tx_cnt1us <= TX_WAIT_D2;
          tx_state  <= D2;
        end
        D2:
        if (tx_nextbit == 1'b1) begin
          uart_tx   <= tx_data[3];
          tx_cnt1us <= TX_WAIT_D3;
          tx_state  <= D3;
        end
        D3:
        if (tx_nextbit == 1'b1) begin
          uart_tx   <= tx_data[4];
          tx_cnt1us <= TX_WAIT_D4;
          tx_state  <= D4;
        end
        D4:
        if (tx_nextbit == 1'b1) begin
          uart_tx   <= tx_data[5];
          tx_cnt1us <= TX_WAIT_D5;
          tx_state  <= D5;
        end
        D5:
        if (tx_nextbit == 1'b1) begin
          uart_tx   <= tx_data[6];
          tx_cnt1us <= TX_WAIT_D6;
          tx_state  <= D6;
        end
        D6:
        if (tx_nextbit == 1'b1) begin
          uart_tx   <= tx_data[7];
          tx_cnt1us <= TX_WAIT_D7;
          tx_state  <= D7;
        end
        D7:
        if (tx_nextbit == 1'b1) begin
          uart_tx   <= 1'b1;  // STOP bit
          tx_cnt1us <= TX_WAIT_STOP;
          tx_state  <= STOP;

`ifdef UART_DEBUG
          $display("%t %m TX'd \t\t%0h (%s)", $time, tx_data, string'(tx_data));
`endif
        end

        //---Wait the prescribed amount of time while driving STOP bit
        STOP:
        if (tx_nextbit == 1'b1) begin
          tx_state <= IDLE;
        end

        default: begin
        end
      endcase  // case (tx_state)
    end
  end


  // synchronous TxFIFO offloads CPU write operations
  logic       uart_tx_busy;

  // TX FIFO input: the IMEM loader's bytes on the bus, else the CSR's
  logic [7:0] tx_fifo_din;
  logic       tx_fifo_we;
  assign      tx_fifo_din = r.bus_vld ? r.uart_tx_data  : from_csr.uart.tx.data.value;
  assign      tx_fifo_we  = r.bus_vld ? r.uart_tx_valid : from_csr.uart.tx_trigger.write.value;

  sync_fifo_ram #(
      .DWIDTH (8),
      .AWIDTH (4)   // 16 entries
  ) u_tx_fifo (

      // Inputs
      .arst_n (arst_n),
      .clk    (clk),

      .din (tx_fifo_din),
      //.din       (uart_rx_data),  // loopback test
      .we  (tx_fifo_we),
      //.we        (uart_rx_valid), // loopback test
      .re  (tx_fifo_re),

      // Outputs
      .dcount (  /*LINT:OK*/),  // FIFO fill level not needed
      .empty  (tx_fifo_empty),
      .full   (uart_tx_busy),   // SW write is ignored when FIFO is full

      .dout_comb (tx_data),  // fall-through: Data is available w/o read

      .dout (  /*LINT:OK*/)  // dout_comb (fall-through) is used
  );


  //=========================================
  // FSM for loading IMEM via UART and
  // DMEM/CSR bus mastering via UART
  //=========================================
  logic [7:0] uart_rx_data;
  logic       uart_rx_valid;

  assign uart_rx_data  = rx_shift;
  assign uart_rx_valid = rx_fifo_we;


  always_ff @(negedge arst_n or posedge clk) begin
    if (arst_n == 1'b0) begin
      r.state         <= T_STATES_WAIT_SOP;
      r.cpu_rst_n     <= 1'b1;
      r.data_length   <= '0;
      r.data_cnt      <= '0;
      r.ram_wen       <= 1'b0;
      r.ram_addr      <= '0;
      r.ram_data      <= '0;
      r.bus_vld       <= 1'b0;
      r.bus_we        <= '0;
      r.bus_addr      <= DMEM_BASE[31:2];
      r.bus_rdat      <= '0;
      r.bus_wdat      <= '0;
      r.checksum      <= '0;
      r.timeout       <= '0;
      r.uart_tx_valid <= 1'b0;
      r.uart_tx_data  <= '0;
    end
    else begin
      r <= r_next;
    end
  end

  always_comb begin
    r_next = r;

    unique case (r.state)
      T_STATES_WAIT_SOP: begin
        if ((uart_rx_valid == 1'b1) && (uart_rx_data == C_SOP)) begin
          r_next.bus_vld = 1'b1;
          r_next.state   = T_STATES_WAIT_CMD;
        end
      end

      T_STATES_WAIT_CMD: begin
        if (uart_rx_valid == 1'b1) begin
          unique case (uart_rx_data)
            C_IMPR: begin
              r_next.cpu_rst_n = 1'b0;
              r_next.data_cnt  = '0;
              r_next.checksum  = '0;
              r_next.timeout   = '0;
              r_next.state     = T_STATES_IMPR_WAIT_LEN_LB;
            end
            C_BUSW: begin
              r_next.checksum = '0;
              r_next.timeout  = '0;
              r_next.state    = T_STATES_BUSW_WAIT_ADDR0;
            end
            C_BUSR: begin
              r_next.checksum = '0;
              r_next.timeout  = '0;
              r_next.state    = T_STATES_BUSR_WAIT_ADDR0;
            end
            C_IMWR: begin
              r_next.checksum = '0;
              r_next.timeout  = '0;
              r_next.state    = T_STATES_IMWR_WAIT_ADDR0;
            end
            C_EOP: begin
              r_next.bus_vld = 1'b0;
              r_next.state   = T_STATES_WAIT_SOP;
            end
            default: begin  // not a command: ignored
            end
          endcase
        end
      end

      T_STATES_IMPR_WAIT_LEN_LB: begin
        if (uart_rx_valid == 1'b1) begin
          r_next.data_length[7:0] = uart_rx_data;
          r_next.checksum         = r.checksum + uart_rx_data;
          r_next.timeout          = '0;
          r_next.state            = T_STATES_IMPR_WAIT_LEN_HB;
        end
        else if (r.timeout[21:21] == 1'b1) begin
          r_next.uart_tx_data  = C_TOUT;
          r_next.uart_tx_valid = 1'b1;
          r_next.state         = T_STATES_TIMEOUT;
        end
        else if (tick_1us == 1'b1) begin
          r_next.timeout = r.timeout + 22'd1;
        end
      end

      T_STATES_IMPR_WAIT_LEN_HB: begin
        if (uart_rx_valid == 1'b1) begin
          r_next.data_length[15:8] = uart_rx_data;
          r_next.checksum          = r.checksum + uart_rx_data;
          r_next.timeout           = '0;
          r_next.state             = T_STATES_IMPR_WAIT_DATA0;
        end
        else if (r.timeout[21:21] == 1'b1) begin
          r_next.uart_tx_data  = C_TOUT;
          r_next.uart_tx_valid = 1'b1;
          r_next.state         = T_STATES_TIMEOUT;
        end
        else if (tick_1us == 1'b1) begin
          r_next.timeout = r.timeout + 22'd1;
        end
      end

      T_STATES_IMPR_WAIT_DATA0: begin
        if (uart_rx_valid == 1'b1) begin
          r_next.ram_data[7:0] = uart_rx_data;
          r_next.checksum      = r.checksum + uart_rx_data;
          r_next.timeout       = '0;
          r_next.state         = T_STATES_IMPR_WAIT_DATA1;
        end
        else if (r.timeout[21:21] == 1'b1) begin
          r_next.uart_tx_data  = C_TOUT;
          r_next.uart_tx_valid = 1'b1;
          r_next.state         = T_STATES_TIMEOUT;
        end
        else if (tick_1us == 1'b1) begin
          r_next.timeout = r.timeout + 22'd1;
        end
      end

      T_STATES_IMPR_WAIT_DATA1: begin
        if (uart_rx_valid == 1'b1) begin
          r_next.ram_data[15:8] = uart_rx_data;
          r_next.checksum       = r.checksum + uart_rx_data;
          r_next.timeout        = '0;
          r_next.state          = T_STATES_IMPR_WAIT_DATA2;
        end
        else if (r.timeout[21:21] == 1'b1) begin
          r_next.uart_tx_data  = C_TOUT;
          r_next.uart_tx_valid = 1'b1;
          r_next.state         = T_STATES_TIMEOUT;
        end
        else if (tick_1us == 1'b1) begin
          r_next.timeout = r.timeout + 22'd1;
        end
      end

      T_STATES_IMPR_WAIT_DATA2: begin
        if (uart_rx_valid == 1'b1) begin
          r_next.ram_data[23:16] = uart_rx_data;
          r_next.checksum        = r.checksum + uart_rx_data;
          r_next.timeout         = '0;
          r_next.state           = T_STATES_IMPR_WAIT_DATA3;
        end
        else if (r.timeout[21:21] == 1'b1) begin
          r_next.uart_tx_data  = C_TOUT;
          r_next.uart_tx_valid = 1'b1;
          r_next.state         = T_STATES_TIMEOUT;
        end
        else if (tick_1us == 1'b1) begin
          r_next.timeout = r.timeout + 22'd1;
        end
      end

      T_STATES_IMPR_WAIT_DATA3: begin
        if (uart_rx_valid == 1'b1) begin
          r_next.data_cnt        = r.data_cnt + 1;
          r_next.ram_data[31:24] = uart_rx_data;
          r_next.checksum        = r.checksum + uart_rx_data;
          r_next.ram_addr        = {14'd0, r.data_cnt, 2'd0};
          r_next.ram_wen         = 1'b1;
          r_next.uart_tx_data    = C_ACK;
          r_next.uart_tx_valid   = 1'b1;
          r_next.state           = T_STATES_IMPR_CHECKSUM;
        end
        else if (r.timeout[21:21] == 1'b1) begin
          r_next.uart_tx_data  = C_TOUT;
          r_next.uart_tx_valid = 1'b1;
          r_next.state         = T_STATES_TIMEOUT;
        end
        else if (tick_1us == 1'b1) begin
          r_next.timeout = r.timeout + 22'd1;
        end
      end

      T_STATES_IMPR_CHECKSUM: begin
        if (r.data_cnt == r.data_length) begin
          r_next.ram_wen       = 1'b0;
          r_next.uart_tx_data  = r.checksum;
          r_next.uart_tx_valid = 1'b1;
          r_next.state         = T_STATES_IMPR_DONE;
        end
        else begin
          r_next.ram_wen       = 1'b0;
          r_next.uart_tx_valid = 1'b0;
          r_next.timeout       = '0;
          r_next.state         = T_STATES_IMPR_WAIT_DATA0;
        end
      end

      T_STATES_IMPR_DONE: begin
        r_next.cpu_rst_n     = 1'b1;
        r_next.uart_tx_valid = 1'b0;
        r_next.state         = T_STATES_WAIT_CMD;
      end

      T_STATES_BUSW_WAIT_ADDR0: begin
        if (uart_rx_valid == 1'b1) begin
          r_next.bus_addr[7:2] = uart_rx_data[7:2];
          r_next.checksum      = r.checksum + uart_rx_data;
          r_next.timeout       = '0;
          r_next.state         = T_STATES_BUSW_WAIT_ADDR1;
        end
        else if (r.timeout[21:21] == 1'b1) begin
          r_next.uart_tx_data  = C_TOUT;
          r_next.uart_tx_valid = 1'b1;
          r_next.state         = T_STATES_TIMEOUT;
        end
        else if (tick_1us == 1'b1) begin
          r_next.timeout = r.timeout + 22'd1;
        end
      end

      T_STATES_BUSW_WAIT_ADDR1: begin
        if (uart_rx_valid == 1'b1) begin
          r_next.bus_addr[15:8] = uart_rx_data;
          r_next.checksum       = r.checksum + uart_rx_data;
          r_next.timeout        = '0;
          r_next.state          = T_STATES_BUSW_WAIT_ADDR2;
        end
        else if (r.timeout[21:21] == 1'b1) begin
          r_next.uart_tx_data  = C_TOUT;
          r_next.uart_tx_valid = 1'b1;
          r_next.state         = T_STATES_TIMEOUT;
        end
        else if (tick_1us == 1'b1) begin
          r_next.timeout = r.timeout + 22'd1;
        end
      end

      T_STATES_BUSW_WAIT_ADDR2: begin
        if (uart_rx_valid == 1'b1) begin
          r_next.bus_addr[23:16] = uart_rx_data;
          r_next.checksum        = r.checksum + uart_rx_data;
          r_next.timeout         = '0;
          r_next.state           = T_STATES_BUSW_WAIT_ADDR3;
        end
        else if (r.timeout[21:21] == 1'b1) begin
          r_next.uart_tx_data  = C_TOUT;
          r_next.uart_tx_valid = 1'b1;
          r_next.state         = T_STATES_TIMEOUT;
        end
        else if (tick_1us == 1'b1) begin
          r_next.timeout = r.timeout + 22'd1;
        end
      end

      T_STATES_BUSW_WAIT_ADDR3: begin
        if (uart_rx_valid == 1'b1) begin
          r_next.bus_addr[31:24] = uart_rx_data;
          r_next.checksum        = r.checksum + uart_rx_data;
          r_next.timeout         = '0;
          r_next.state           = T_STATES_BUSW_WAIT_DATA0;
        end
        else if (r.timeout[21:21] == 1'b1) begin
          r_next.uart_tx_data  = C_TOUT;
          r_next.uart_tx_valid = 1'b1;
          r_next.state         = T_STATES_TIMEOUT;
        end
        else if (tick_1us == 1'b1) begin
          r_next.timeout = r.timeout + 22'd1;
        end
      end

      T_STATES_BUSW_WAIT_DATA0: begin
        if (uart_rx_valid == 1'b1) begin
          r_next.bus_wdat[7:0] = uart_rx_data;
          r_next.checksum      = r.checksum + uart_rx_data;
          r_next.timeout       = '0;
          r_next.state         = T_STATES_BUSW_WAIT_DATA1;
        end
        else if (r.timeout[21:21] == 1'b1) begin
          r_next.uart_tx_data  = C_TOUT;
          r_next.uart_tx_valid = 1'b1;
          r_next.state         = T_STATES_TIMEOUT;
        end
        else if (tick_1us == 1'b1) begin
          r_next.timeout = r.timeout + 22'd1;
        end
      end

      T_STATES_BUSW_WAIT_DATA1: begin
        if (uart_rx_valid == 1'b1) begin
          r_next.bus_wdat[15:8] = uart_rx_data;
          r_next.checksum       = r.checksum + uart_rx_data;
          r_next.timeout        = '0;
          r_next.state          = T_STATES_BUSW_WAIT_DATA2;
        end
        else if (r.timeout[21:21] == 1'b1) begin
          r_next.uart_tx_data  = C_TOUT;
          r_next.uart_tx_valid = 1'b1;
          r_next.state         = T_STATES_TIMEOUT;
        end
        else if (tick_1us == 1'b1) begin
          r_next.timeout = r.timeout + 22'd1;
        end
      end

      T_STATES_BUSW_WAIT_DATA2: begin
        if (uart_rx_valid == 1'b1) begin
          r_next.bus_wdat[23:16] = uart_rx_data;
          r_next.checksum        = r.checksum + uart_rx_data;
          r_next.timeout         = '0;
          r_next.state           = T_STATES_BUSW_WAIT_DATA3;
        end
        else if (r.timeout[21:21] == 1'b1) begin
          r_next.uart_tx_data  = C_TOUT;
          r_next.uart_tx_valid = 1'b1;
          r_next.state         = T_STATES_TIMEOUT;
        end
        else if (tick_1us == 1'b1) begin
          r_next.timeout = r.timeout + 22'd1;
        end
      end

      T_STATES_BUSW_WAIT_DATA3: begin
        if (uart_rx_valid == 1'b1) begin
          r_next.bus_wdat[31:24] = uart_rx_data;
          r_next.checksum        = r.checksum + uart_rx_data;
          r_next.timeout         = '0;
          r_next.state           = T_STATES_BUSW_WAIT_WE;
        end
        else if (r.timeout[21:21] == 1'b1) begin
          r_next.uart_tx_data  = C_TOUT;
          r_next.uart_tx_valid = 1'b1;
          r_next.state         = T_STATES_TIMEOUT;
        end
        else if (tick_1us == 1'b1) begin
          r_next.timeout = r.timeout + 22'd1;
        end
      end

      T_STATES_BUSW_WAIT_WE: begin
        if (uart_rx_valid == 1'b1) begin
          r_next.bus_we   = uart_rx_data[3:0];
          r_next.checksum = r.checksum + uart_rx_data;
          r_next.timeout  = '0;
          r_next.state    = T_STATES_BUSW_CHECKSUM;
        end
        else if (r.timeout[21:21] == 1'b1) begin
          r_next.uart_tx_data  = C_TOUT;
          r_next.uart_tx_valid = 1'b1;
          r_next.state         = T_STATES_TIMEOUT;
        end
        else if (tick_1us == 1'b1) begin
          r_next.timeout = r.timeout + 22'd1;
        end
      end

      T_STATES_BUSW_CHECKSUM: begin
        r_next.bus_we        = '0;
        r_next.uart_tx_data  = r.checksum;
        r_next.uart_tx_valid = 1'b1;
        r_next.state         = T_STATES_BUSW_DONE;
      end

      T_STATES_BUSW_DONE: begin
        r_next.uart_tx_valid = 1'b0;
        r_next.state         = T_STATES_WAIT_CMD;
      end

      T_STATES_BUSR_WAIT_ADDR0: begin
        if (uart_rx_valid == 1'b1) begin
          r_next.bus_addr[7:2] = uart_rx_data[7:2];
          r_next.checksum      = r.checksum + uart_rx_data;
          r_next.timeout       = '0;
          r_next.state         = T_STATES_BUSR_WAIT_ADDR1;
        end
        else if (r.timeout[21:21] == 1'b1) begin
          r_next.uart_tx_data  = C_TOUT;
          r_next.uart_tx_valid = 1'b1;
          r_next.state         = T_STATES_TIMEOUT;
        end
        else if (tick_1us == 1'b1) begin
          r_next.timeout = r.timeout + 22'd1;
        end
      end

      T_STATES_BUSR_WAIT_ADDR1: begin
        if (uart_rx_valid == 1'b1) begin
          r_next.bus_addr[15:8] = uart_rx_data;
          r_next.checksum       = r.checksum + uart_rx_data;
          r_next.timeout        = '0;
          r_next.state          = T_STATES_BUSR_WAIT_ADDR2;
        end
        else if (r.timeout[21:21] == 1'b1) begin
          r_next.uart_tx_data  = C_TOUT;
          r_next.uart_tx_valid = 1'b1;
          r_next.state         = T_STATES_TIMEOUT;
        end
        else if (tick_1us == 1'b1) begin
          r_next.timeout = r.timeout + 22'd1;
        end
      end

      T_STATES_BUSR_WAIT_ADDR2: begin
        if (uart_rx_valid == 1'b1) begin
          r_next.bus_addr[23:16] = uart_rx_data;
          r_next.checksum        = r.checksum + uart_rx_data;
          r_next.timeout         = '0;
          r_next.state           = T_STATES_BUSR_WAIT_ADDR3;
        end
        else if (r.timeout[21:21] == 1'b1) begin
          r_next.uart_tx_data  = C_TOUT;
          r_next.uart_tx_valid = 1'b1;
          r_next.state         = T_STATES_TIMEOUT;
        end
        else if (tick_1us == 1'b1) begin
          r_next.timeout = r.timeout + 22'd1;
        end
      end

      T_STATES_BUSR_WAIT_ADDR3: begin
        if (uart_rx_valid == 1'b1) begin
          r_next.bus_addr[31:24] = uart_rx_data;
          r_next.checksum        = r.checksum + uart_rx_data;
          r_next.timeout         = '0;
          r_next.state           = T_STATES_BUSR_WAIT_DATA;
        end
        else if (r.timeout[21:21] == 1'b1) begin
          r_next.uart_tx_data  = C_TOUT;
          r_next.uart_tx_valid = 1'b1;
          r_next.state         = T_STATES_TIMEOUT;
        end
        else if (tick_1us == 1'b1) begin
          r_next.timeout = r.timeout + 22'd1;
        end
      end

      T_STATES_BUSR_WAIT_DATA: begin
        if (bus.rdy == 1'b1) begin
          r_next.bus_rdat = bus.rdat;
          r_next.timeout  = '0;
          r_next.state    = T_STATES_BUSR_DATA0;
        end
        else if (r.timeout[21:21] == 1'b1) begin
          r_next.uart_tx_data  = C_TOUT;
          r_next.uart_tx_valid = 1'b1;
          r_next.state         = T_STATES_TIMEOUT;
        end
        else if (tick_1us == 1'b1) begin
          r_next.timeout = r.timeout + 22'd1;
        end
      end

      T_STATES_BUSR_DATA0: begin
        r_next.uart_tx_data  = r.bus_rdat[7:0];
        r_next.checksum      = r.checksum + r.bus_rdat[7:0];
        r_next.uart_tx_valid = 1'b1;
        r_next.state         = T_STATES_BUSR_DATA1;
      end

      T_STATES_BUSR_DATA1: begin
        r_next.uart_tx_data  = r.bus_rdat[15:8];
        r_next.checksum      = r.checksum + r.bus_rdat[15:8];
        r_next.uart_tx_valid = 1'b1;
        r_next.state         = T_STATES_BUSR_DATA2;
      end

      T_STATES_BUSR_DATA2: begin
        r_next.uart_tx_data  = r.bus_rdat[23:16];
        r_next.checksum      = r.checksum + r.bus_rdat[23:16];
        r_next.uart_tx_valid = 1'b1;
        r_next.state         = T_STATES_BUSR_DATA3;
      end

      T_STATES_BUSR_DATA3: begin
        r_next.uart_tx_data  = r.bus_rdat[31:24];
        r_next.checksum      = r.checksum + r.bus_rdat[31:24];
        r_next.uart_tx_valid = 1'b1;
        r_next.state         = T_STATES_BUSR_CHECKSUM;
      end

      T_STATES_BUSR_CHECKSUM: begin
        r_next.uart_tx_data  = r.checksum;
        r_next.uart_tx_valid = 1'b1;
        r_next.state         = T_STATES_BUSR_DONE;
      end

      T_STATES_BUSR_DONE: begin
        r_next.uart_tx_valid = 1'b0;
        r_next.state         = T_STATES_WAIT_CMD;
      end

      T_STATES_IMWR_WAIT_ADDR0: begin
        if (uart_rx_valid == 1'b1) begin
          r_next.ram_addr[7:0] = uart_rx_data;
          r_next.checksum      = r.checksum + uart_rx_data;
          r_next.timeout       = '0;
          r_next.state         = T_STATES_IMWR_WAIT_ADDR1;
        end
        else if (r.timeout[21:21] == 1'b1) begin
          r_next.uart_tx_data  = C_TOUT;
          r_next.uart_tx_valid = 1'b1;
          r_next.state         = T_STATES_TIMEOUT;
        end
        else if (tick_1us == 1'b1) begin
          r_next.timeout = r.timeout + 22'd1;
        end
      end

      T_STATES_IMWR_WAIT_ADDR1: begin
        if (uart_rx_valid == 1'b1) begin
          r_next.ram_addr[15:8] = uart_rx_data;
          r_next.checksum       = r.checksum + uart_rx_data;
          r_next.timeout        = '0;
          r_next.state          = T_STATES_IMWR_WAIT_DATA0;
        end
        else if (r.timeout[21:21] == 1'b1) begin
          r_next.uart_tx_data  = C_TOUT;
          r_next.uart_tx_valid = 1'b1;
          r_next.state         = T_STATES_TIMEOUT;
        end
        else if (tick_1us == 1'b1) begin
          r_next.timeout = r.timeout + 22'd1;
        end
      end

      T_STATES_IMWR_WAIT_DATA0: begin
        if (uart_rx_valid == 1'b1) begin
          r_next.ram_data[7:0] = uart_rx_data;
          r_next.checksum      = r.checksum + uart_rx_data;
          r_next.timeout       = '0;
          r_next.state         = T_STATES_IMWR_WAIT_DATA1;
        end
        else if (r.timeout[21:21] == 1'b1) begin
          r_next.uart_tx_data  = C_TOUT;
          r_next.uart_tx_valid = 1'b1;
          r_next.state         = T_STATES_TIMEOUT;
        end
        else if (tick_1us == 1'b1) begin
          r_next.timeout = r.timeout + 22'd1;
        end
      end

      T_STATES_IMWR_WAIT_DATA1: begin
        if (uart_rx_valid == 1'b1) begin
          r_next.ram_data[15:8] = uart_rx_data;
          r_next.checksum       = r.checksum + uart_rx_data;
          r_next.timeout        = '0;
          r_next.state          = T_STATES_IMWR_WAIT_DATA2;
        end
        else if (r.timeout[21:21] == 1'b1) begin
          r_next.uart_tx_data  = C_TOUT;
          r_next.uart_tx_valid = 1'b1;
          r_next.state         = T_STATES_TIMEOUT;
        end
        else if (tick_1us == 1'b1) begin
          r_next.timeout = r.timeout + 22'd1;
        end
      end

      T_STATES_IMWR_WAIT_DATA2: begin
        if (uart_rx_valid == 1'b1) begin
          r_next.ram_data[23:16] = uart_rx_data;
          r_next.checksum        = r.checksum + uart_rx_data;
          r_next.timeout         = '0;
          r_next.state           = T_STATES_IMWR_WAIT_DATA3;
        end
        else if (r.timeout[21:21] == 1'b1) begin
          r_next.uart_tx_data  = C_TOUT;
          r_next.uart_tx_valid = 1'b1;
          r_next.state         = T_STATES_TIMEOUT;
        end
        else if (tick_1us == 1'b1) begin
          r_next.timeout = r.timeout + 22'd1;
        end
      end

      T_STATES_IMWR_WAIT_DATA3: begin
        if (uart_rx_valid == 1'b1) begin
          r_next.ram_data[31:24] = uart_rx_data;
          r_next.ram_wen         = 1'b1;
          r_next.checksum        = r.checksum + uart_rx_data;
          r_next.timeout         = '0;
          r_next.state           = T_STATES_IMWR_CHECKSUM;
        end
        else if (r.timeout[21:21] == 1'b1) begin
          r_next.uart_tx_data  = C_TOUT;
          r_next.uart_tx_valid = 1'b1;
          r_next.state         = T_STATES_TIMEOUT;
        end
        else if (tick_1us == 1'b1) begin
          r_next.timeout = r.timeout + 22'd1;
        end
      end

      T_STATES_IMWR_CHECKSUM: begin
        r_next.ram_wen       = 1'b0;
        r_next.uart_tx_data  = r.checksum;
        r_next.uart_tx_valid = 1'b1;
        r_next.state         = T_STATES_IMWR_DONE;
      end

      T_STATES_IMWR_DONE: begin
        r_next.uart_tx_valid = 1'b0;
        r_next.state         = T_STATES_WAIT_CMD;
      end

      T_STATES_TIMEOUT: begin
        r_next.uart_tx_valid = 1'b0;
        r_next.ram_wen       = 1'b0;
        r_next.cpu_rst_n     = 1'b1;
        r_next.bus_vld       = 1'b0;
        r_next.state         = T_STATES_WAIT_SOP;
      end

      default: begin
      end
    endcase
  end

  assign imem_cpu_rst_n = r.cpu_rst_n;
  assign imem_wr        = '{we: r.ram_wen, addr: r.ram_addr[31:2], data: r.ram_data};

  assign bus.vld        = r.bus_vld;
  assign bus.we         = r.bus_we;
  assign bus.addr       = r.bus_addr;
  assign bus.wdat       = r.bus_wdat;

  // CSR status, in one process
  always_comb begin
    to_csr.rx.data.next  = rx_fifo_dout;
    to_csr.rx.oflow.next = rx_oflow;
    to_csr.rx.valid.next = ~rx_fifo_empty;
    to_csr.tx.busy.next  = uart_tx_busy;
  end
endmodule : uart

// -----------------------------------------------------------------------------
// Project:     WireGuard-FPGA
// Description: NLnet-funded open-source implementation
// Funding:     https://nlnet.nl/project/KlusterLab-Wireguard (2023-12 to 2025-12)
// -----------------------------------------------------------------------------
