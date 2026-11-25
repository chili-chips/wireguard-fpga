// SPDX-FileCopyrightText: 2026 Chili.CHIPS
//
// SPDX-License-Identifier: BSD-3-Clause

//==========================================================================
// Block-level DPE benches: one AXI-Stream sink, with its scoreboard.
// It takes each beat (tready = ready) and records each packet: bytes,
// length, tuser_src and tuser_dst of its first beat. Every beat must have
// tkeep 0x0001 (one byte). At the end the bench calls expect_pkt() once
// per packet this output must have received, then report(): each expected
// packet must be there once, with the same bytes, src and dst, and nothing
// else. Order is not checked (the multiplexer arbitrates).
//==========================================================================

module dpe_tb_sink
  import dpe_pkg::*;
  import dpe_tb_pkg::*;
#(
    parameter string NAME   = "sink",
    parameter int    MAX_RX = 8
) (
    input logic   ready,
    dpe_if.s_axis inp
);
  test_pkt_t        rx_pkt  [MAX_RX];
  logic      [ 2:0] rx_src  [MAX_RX];
  logic             rx_used [MAX_RX];
  int               n_rx;
  int               errors;

  test_pkt_t        cur;
  logic      [8*MAX_BYTES-1:0] cur_bytes;  // cur.data as one vector (Icarus 14, #66)
  logic      [ 2:0] cur_src;
  int               n_byte;

  assign inp.tready = ready;

  initial begin
    n_rx   = 0;
    errors = 0;
    n_byte = 0;
    cur    = '0;
  end

  // Procedural, not a flop: the record is built with blocking assignments
  initial forever begin
    @(posedge inp.clk);
    if (!inp.rst && inp.tvalid && inp.tready) begin
      if (n_byte == 0) begin
        cur     = '0;
        cur_bytes = '0;
        cur.dst = inp.tuser.dst;
        cur_src = inp.tuser.src;
      end
      if (inp.tkeep !== 16'h0001) begin
        errors++;
        $display("%t %s: FAIL tkeep %h on byte %0d, expected 0001", $time, NAME, inp.tkeep,
                 n_byte);
      end
      if (n_byte < MAX_BYTES) cur_bytes[8*(MAX_BYTES-1-n_byte)+:8] = inp.tdata[7:0];
      n_byte++;
      if (inp.tlast) begin
        cur.data = cur_bytes;
        cur.len = len_t'(n_byte);
        $display("%t %s: packet from src %0d, dst %0d, %0d bytes", $time, NAME, cur_src, cur.dst,
                 n_byte);
        if (n_byte > MAX_BYTES) begin
          errors++;
          $display("%t %s: FAIL packet of %0d bytes, at most %0d", $time, NAME, n_byte, MAX_BYTES);
        end else if (n_rx == MAX_RX) begin
          errors++;
          $display("%t %s: FAIL more than %0d packets", $time, NAME, MAX_RX);
        end else begin
          rx_pkt[n_rx]  = cur;
          rx_src[n_rx]  = cur_src;
          rx_used[n_rx] = 1'b0;
          n_rx++;
        end
        n_byte = 0;
      end
    end
  end

  // This output must have received p, sent by src: once, intact
  task automatic expect_pkt(input test_pkt_t p, input dpe_addr_t src);
    for (int i = 0; i < n_rx; i++) begin
      if (!rx_used[i] && rx_pkt[i] == p && rx_src[i] == src) begin
        rx_used[i] = 1'b1;
        return;
      end
    end
    errors++;
    $display("%t %s: FAIL missing packet from src %0d, dst %0d, %0d bytes: %h", $time, NAME, src,
             p.dst, p.len, p.data);
  endtask

  // Packets nobody expected, and a packet cut short at the end
  task automatic report();
    for (int i = 0; i < n_rx; i++) begin
      if (!rx_used[i]) begin
        errors++;
        $display("%t %s: FAIL unexpected packet from src %0d, dst %0d, %0d bytes: %h", $time,
                 NAME, rx_src[i], rx_pkt[i].dst, rx_pkt[i].len, rx_pkt[i].data);
      end
    end
    if (n_byte != 0) begin
      errors++;
      $display("%t %s: FAIL a packet without tlast (%0d bytes)", $time, NAME, n_byte);
    end
  endtask
endmodule

// -----------------------------------------------------------------------------
// Project:     WireGuard-FPGA
// Description: NLnet-funded open-source implementation
// Funding:     https://nlnet.nl/project/KlusterLab-Wireguard (2023-12 to 2025-12)
// -----------------------------------------------------------------------------
