// SPDX-FileCopyrightText: 2026 Chili.CHIPS
//
// SPDX-License-Identifier: BSD-3-Clause

//==========================================================================
// Wireguard-1GE FPGA * NLnet-sponsored open-source implementation
//--------------------------------------------------------------------------
// Description:
//   Behavioural model of the AX7201's configuration flash (N25Q128, 16 MiB)
//   in x1 SPI, mode 0, 3-byte addresses: the commands 2.sw/app/flash.c
//   uses.
//     9F  READ ID        20 BA 18 (JEDEC_ID)
//     05  READ STATUS    bit 1 WEL, bit 0 WIP
//     06  WRITE ENABLE   04 WRITE DISABLE
//     03  READ           any length, wraps at the end of the array
//     02  PAGE PROGRAM   1 to 256 bytes, wraps inside the 256-byte page,
//                        clears bits only (AND), WIP for PROG_NS
//     20  4 KiB ERASE    D8 64 KiB ERASE: to FF, WIP for ERASE_NS
//   Program and erase need WEL and clear it; while WIP, only 05 answers.
//   The array has no reset: it keeps its contents across a reset of the
//   design, like the flash across a reboot. start_clks counts the SCK
//   rising edges while the flash is deselected (the controller's start-up
//   clocks); errors counts protocol violations the model saw.
//==========================================================================

module spi_flash_model #(
    parameter int          ADDR_BITS = 24,
    parameter logic [23:0] JEDEC_ID  = 24'h20_BA_18,
    parameter int          PROG_NS   = 5_000,
    parameter int          ERASE_NS  = 20_000
) (
    input  logic sck,
    input  logic cs_n,
    input  logic mosi,
    output logic miso
);

  localparam int SIZE = 1 << ADDR_BITS;

  logic [7:0] mem[SIZE];
  logic [7:0] page[256];
  logic       wel;
  logic       wip;
  logic [7:0] cmd;
  logic [23:0] addr;
  logic [23:0] pp_addr;  // where a page program starts
  logic [7:0] sh_in;  // bits in
  logic [7:0] obuf;  // bits out, MSB next
  int         nbits;  // bits of this byte
  int         nbytes;  // whole bytes since chip select
  int         start_clks;
  int         errors;

  initial begin
    for (int i = 0; i < SIZE; i++) begin
      mem[i] = 8'hFF;
    end
    wel        = 1'b0;
    wip        = 1'b0;
    miso       = 1'bz;
    nbits      = 0;
    nbytes     = 0;
    start_clks = 0;
    errors     = 0;
  end

  function automatic logic [ADDR_BITS-1:0] a_of(logic [23:0] a);
    return a[ADDR_BITS-1:0];
  endfunction

  task automatic busy_for(logic erase);
    wip = 1'b1;
    fork
      begin
        if (erase == 1'b1) begin
          #(ERASE_NS * 1ns);
        end
        else begin
          #(PROG_NS * 1ns);
        end
        wip = 1'b0;
        wel = 1'b0;
      end
    join_none
  endtask

  // one byte in: decode it, and set up the byte that goes out next
  task automatic byte_in(logic [7:0] b);
    logic [7:0] r;
    r = 8'hFF;
    if (nbytes == 0) begin
      cmd = b;
    end
    else if (nbytes <= 3) begin
      addr    = {addr[15:0], b};
      pp_addr = addr;
    end
    else if (cmd == 8'h02) begin
      if (nbytes - 4 < 256) begin
        page[nbytes-4] = b;
      end
      else begin
        $display("%t spi_flash_model: page program of more than 256 bytes", $time);
        errors = errors + 1;
      end
    end

    if ((wip == 1'b1) && (cmd != 8'h05)) begin
      r = 8'hFF;  // busy: only READ STATUS answers
    end
    else begin
      unique case (cmd)
        8'h9F: begin
          r = (nbytes == 0) ? JEDEC_ID[23:16] : (nbytes == 1) ? JEDEC_ID[15:8] :
              (nbytes == 2) ? JEDEC_ID[7:0] : 8'h00;
        end
        8'h05: begin
          r = {6'b0, wel, wip};
        end
        8'h03: begin
          if (nbytes >= 3) begin
            r    = mem[a_of(addr)];
            addr = addr + 1'b1;
          end
        end
        default: begin
          r = 8'hFF;
        end
      endcase
    end
    nbytes = nbytes + 1;
    obuf   = r;
  endtask

  always @(negedge cs_n) begin
    nbits  = 0;
    nbytes = 0;
    cmd    = 8'h00;
    obuf   = 8'hFF;
  end

  // chip select off: the command takes effect
  always @(posedge cs_n) begin
    miso = 1'bz;
    if (nbits != 0) begin
      $display("%t spi_flash_model: chip select off after %0d bits of a byte", $time, nbits);
      errors = errors + 1;
    end
    else if ((wip == 1'b0) && (nbytes != 0)) begin
      unique case (cmd)
        8'h06: begin
          wel = 1'b1;
        end
        8'h04: begin
          wel = 1'b0;
        end
        8'h02: begin
          if ((wel == 1'b1) && (nbytes >= 5)) begin
            for (int i = 0; i < nbytes - 4; i++) begin
              logic [23:0] a;
              a           = {pp_addr[23:8], pp_addr[7:0] + 8'(i)};  // wraps in the page
              mem[a_of(a)] = mem[a_of(a)] & page[i];
            end
            busy_for(1'b0);
          end
        end
        8'h20, 8'hD8: begin
          if ((wel == 1'b1) && (nbytes == 4)) begin
            logic [23:0] base;
            int          len;
            len  = (cmd == 8'h20) ? 4096 : 65536;
            base = addr & ~24'(len - 1);
            for (int i = 0; i < len; i++) begin
              mem[a_of(base+24'(i))] = 8'hFF;
            end
            busy_for(1'b1);
          end
        end
        default: begin
        end
      endcase
    end
  end

  always @(posedge sck) begin
    if (cs_n == 1'b1) begin
      start_clks = start_clks + 1;
    end
    else begin
      sh_in = {sh_in[6:0], mosi};
      nbits = nbits + 1;
      if (nbits == 8) begin
        nbits = 0;
        byte_in(sh_in);
      end
    end
  end

  always @(negedge sck) begin
    if (cs_n == 1'b0) begin
      miso = obuf[7];
      obuf = {obuf[6:0], 1'b1};
    end
  end

endmodule : spi_flash_model

// -----------------------------------------------------------------------------
// Project:     WireGuard-FPGA
// Description: NLnet-funded open-source implementation
// Funding:     https://nlnet.nl/project/KlusterLab-Wireguard (2023-12 to 2025-12)
// -----------------------------------------------------------------------------
