// SPDX-FileCopyrightText: 2026 Chili.CHIPS
//
// SPDX-License-Identifier: BSD-3-Clause

//==========================================================================
// Wireguard-1GE FPGA * NLnet-sponsored open-source implementation
//--------------------------------------------------------------------------
// Description:
//   SPI (x1) access to the configuration flash (#30): the CPU drives chip
//   select (csr.flash.ctrl.cs) and sends one byte at a time (csr.flash.tx);
//   each transfer reads one byte back (csr.flash.status). The firmware
//   speaks the flash's commands (2.sw/app/flash.c). SPI mode 0, MSB first,
//   SCK = clk / (2 * HALF_CLKS): 10 MHz at 80 MHz.
//
//   SCK reaches the CCLK pin through STARTUPE2 (fpga_startup). After the
//   end of start-up (EOS) the controller first drives 8 clocks (16 edges,
//   like a byte) with the flash deselected: STARTUPE2 swallows the first
//   three (UG470); then it sets status.ready. Until then chip select
//   stays off.
//
//   MOSI and MISO each have a flop of their own at the pin (miso_q,
//   mosi_q), so both can be IOB flops (#78). MOSI follows the falling SCK
//   edge one clk later, 37.5 ns before the flash samples it; MISO is taken
//   from miso_q on the clk edge on which SCK rises, so it was sampled one
//   clk before that edge, 37.5 ns after the flash changed it on the falling
//   edge: room for the STARTUPE2-to-CCLK and the pad delays.
//==========================================================================

module flash_spi
  import csr_pkg::*;
#(
    parameter int HALF_CLKS = 4  // clk cycles per half SCK period
) (
    input  logic            arst_n,
    input  logic            clk,

    input  csr__out_t       from_csr,
    output csr__flash__in_t to_csr,

    output logic            cs_n,      // FCS_B
    output logic            mosi,      // D00
    input  logic            miso       // D01
);

  localparam int DIV_W = $clog2(HALF_CLKS);

  typedef enum logic [1:0] {
    S_EOS,    // wait for the end of start-up
    S_START,  // the start-up clocks, deselected
    S_IDLE,
    S_XFER    // one byte
  } state_t;

  (* ASYNC_REG = "TRUE" *)logic   [      1:0] eos_sync;  // EOS, synchronized

  state_t             state;
  logic               eos;
  logic   [DIV_W-1:0] div;  // clk cycles in this half SCK period
  logic               tick;  // the last of them
  logic   [      3:0] edges;  // SCK edges so far, 16 per byte
  logic               sck;
  logic               pending;  // a byte written, not yet started
  logic   [      7:0] shreg;  // out MSB first, in at the LSB
  logic               rx_bit;  // MISO at the rising edge
  logic               miso_q;  // the MISO pin, every clk (IOB flop)
  logic               mosi_q;  // the MOSI pin (IOB flop)

  assign tick = (div == DIV_W'(HALF_CLKS - 1));

  fpga_startup u_startup (
      .usrcclko (sck),  //i
      .eos      (eos)   //o
  );

  always_ff @(negedge arst_n or posedge clk) begin
    if (arst_n == 1'b0) begin
      eos_sync <= '0;
      state    <= S_EOS;
      div      <= '0;
      edges    <= '0;
      sck      <= 1'b0;
      pending  <= 1'b0;
      shreg    <= '0;
      rx_bit   <= 1'b0;
      miso_q   <= 1'b0;
      mosi_q   <= 1'b0;
      cs_n     <= 1'b1;
    end
    else begin
      eos_sync <= {eos_sync[0], eos};
      miso_q   <= miso;
      mosi_q   <= shreg[7];
      cs_n     <= ~(from_csr.flash.ctrl.cs.value & ((state == S_IDLE) | (state == S_XFER)));

      // the tx register takes the byte on the clock of the write: start one later
      if (from_csr.flash.tx.data.swmod == 1'b1) begin
        pending <= 1'b1;
      end

      unique case (state)
        S_EOS: begin
          if (eos_sync[1] == 1'b1) begin
            state <= S_START;
          end
        end

        S_START, S_XFER: begin
          div <= tick ? '0 : div + 1'b1;
          if (tick == 1'b1) begin
            sck   <= ~sck;
            edges <= edges + 1'b1;
            if (sck == 1'b0) begin  // rising edge
              rx_bit <= miso_q;
            end
            else if (state == S_XFER) begin  // falling edge: next bit out
              shreg <= {shreg[6:0], rx_bit};
            end
            if (edges == 4'hF) begin
              state <= S_IDLE;
            end
          end
        end

        S_IDLE: begin
          if (pending == 1'b1) begin
            pending <= 1'b0;
            shreg   <= from_csr.flash.tx.data.value;
            state   <= S_XFER;
          end
        end

        default: begin
          state <= S_EOS;
        end
      endcase
    end
  end

  assign mosi                     = mosi_q;

  assign to_csr.status.ready.next = (state == S_IDLE) | (state == S_XFER);
  assign to_csr.status.busy.next  = pending | (state == S_XFER);
  assign to_csr.status.data.next  = shreg;

endmodule : flash_spi

// -----------------------------------------------------------------------------
// Project:     WireGuard-FPGA
// Description: NLnet-funded open-source implementation
// Funding:     https://nlnet.nl/project/KlusterLab-Wireguard (2023-12 to 2025-12)
// -----------------------------------------------------------------------------
