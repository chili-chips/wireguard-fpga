// SPDX-FileCopyrightText: 2026 Chili.CHIPS
//
// SPDX-License-Identifier: BSD-3-Clause

//==========================================================================
// Wireguard-1GE FPGA * NLnet-sponsored open-source implementation
//--------------------------------------------------------------------------
// Description:
//   flash_spi + rtc unit bench (#30), through the real CSR block (soc_csr)
//   with the bus accesses the firmware makes:
//   1. After EOS the controller gives the start-up clocks (STARTUPE2 drops
//      three of them) with the flash deselected, then sets ready.
//   2. Flash: READ ID; WRITE ENABLE and its WEL; erase the 4 KiB sector at
//      0xFFF000; a page program without WRITE ENABLE changes nothing; one
//      with it writes 32 bytes; read them back.
//   3. RTC: counts 12.5 ns a clock, exactly; a read is atomic (nsec latches
//      the seconds), also when the carry into the next second falls
//      between the reads; set it just before a carry into sec_hi.
//   4. "Reboot": reset the design, the flash model keeps its array. The
//      RTC is back at 0, the controller ready again, the 32 bytes there.
//==========================================================================

module tb;
  import soc_pkg::*;
  import csr_pkg::*;

  localparam logic [31:0] RTC   = 32'h2000_0100;
  localparam logic [31:0] FLASH = 32'h2000_0140;
  localparam logic [23:0] SECTOR = 24'hFF_F000;
  localparam int NBYTES = 32;

  logic clk, arst_n;
  int   fails;

  soc_if bus (
      .arst_n (arst_n),
      .clk    (clk)
  );

  csr__in_t  csr_sta;
  csr__out_t csr_cfg;
  logic      cs_n, mosi, miso;

  // the external tables are not here: their acks stay 0
  assign csr_sta.routing_table.rd_ack    = 1'b0;
  assign csr_sta.routing_table.wr_ack    = 1'b0;
  assign csr_sta.routing_table.rd_data   = '0;
  assign csr_sta.cryptokey_table.rd_ack  = 1'b0;
  assign csr_sta.cryptokey_table.wr_ack  = 1'b0;
  assign csr_sta.cryptokey_table.rd_data = '0;

  soc_csr u_csr (
      .bus     (bus),
      .csr_sta (csr_sta),
      .csr_cfg (csr_cfg)
  );

  rtc u_rtc (
      .arst_n   (arst_n),
      .clk      (clk),
      .from_csr (csr_cfg),
      .to_csr   (csr_sta.rtc)
  );

  flash_spi u_flash (
      .arst_n   (arst_n),
      .clk      (clk),
      .from_csr (csr_cfg),
      .to_csr   (csr_sta.flash),
      .cs_n     (cs_n),
      .mosi     (mosi),
      .miso     (miso)
  );

  spi_flash_model u_mem (
      .sck  (u_flash.u_startup.cclk),  // the CCLK pin
      .cs_n (cs_n),
      .mosi (mosi),
      .miso (miso)
  );

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

  //------------------------------------------------------------------
  // the bus: drive after a falling edge, take rdat before the rising one
  //------------------------------------------------------------------
  task automatic bus_acc(input logic [31:0] a, input logic [3:0] we, input logic [31:0] d,
                         output logic [31:0] q);
    @(negedge clk);
    bus.vld  = 1'b1;
    bus.addr = a[31:2];
    bus.we   = we;
    bus.wdat = d;
    #1ns;
    while (bus.rdy != 1'b1) begin
      @(negedge clk);
      #1ns;
    end
    q = bus.rdat;
    @(negedge clk);
    bus.vld = 1'b0;
    bus.we  = '0;
  endtask

  task automatic wr(input logic [31:0] a, input logic [31:0] d);
    logic [31:0] q;
    bus_acc(a, 4'hF, d, q);
  endtask

  task automatic rd(input logic [31:0] a, output logic [31:0] q);
    bus_acc(a, 4'h0, '0, q);
  endtask

  task automatic check(input string what, input logic [31:0] got, input logic [31:0] exp);
    if (got !== exp) begin
      $display("%t FAIL %s: 0x%08x, expected 0x%08x", $time, what, got, exp);
      fails++;
    end
  endtask

  //------------------------------------------------------------------
  // the firmware's flash primitives (2.sw/app/flash.c)
  //------------------------------------------------------------------
  task automatic wait_ready();
    logic [31:0] s;
    int n;
    n = 0;
    do begin
      rd(FLASH + 8, s);
      n++;
    end while ((s[31] != 1'b1) && (n < 1000));
    check("flash ready", 32'(s[31]), 1);
  endtask

  task automatic xfer(input logic [7:0] b, output logic [7:0] r);
    logic [31:0] s;
    wr(FLASH + 4, 32'(b));
    do begin
      rd(FLASH + 8, s);
    end while (s[30] == 1'b1);
    r = s[7:0];
  endtask

  task automatic sel(input logic on);
    wr(FLASH + 0, 32'(on));
  endtask

  task automatic cmd1(input logic [7:0] c);
    logic [7:0] r;
    sel(1'b1);
    xfer(c, r);
    sel(1'b0);
  endtask

  task automatic rdsr(output logic [7:0] r);
    logic [7:0] x;
    sel(1'b1);
    xfer(8'h05, x);
    xfer(8'h00, r);
    sel(1'b0);
  endtask

  task automatic wait_wip();
    logic [7:0] r;
    do begin
      rdsr(r);
    end while (r[0] == 1'b1);
  endtask

  task automatic cmd_addr(input logic [7:0] c, input logic [23:0] a);
    logic [7:0] r;
    xfer(c, r);
    xfer(a[23:16], r);
    xfer(a[15:8], r);
    xfer(a[7:0], r);
  endtask

  task automatic read_bytes(input logic [23:0] a, input int n, output logic [7:0] d[NBYTES]);
    sel(1'b1);
    cmd_addr(8'h03, a);
    for (int i = 0; i < n; i++) begin
      xfer(8'h00, d[i]);
    end
    sel(1'b0);
  endtask

  task automatic page_prog(input logic [23:0] a, input logic [7:0] d[NBYTES]);
    logic [7:0] r;
    sel(1'b1);
    cmd_addr(8'h02, a);
    for (int i = 0; i < NBYTES; i++) begin
      xfer(d[i], r);
    end
    sel(1'b0);
    wait_wip();
  endtask

  task automatic check_bytes(input string what, input logic [7:0] d[NBYTES],
                             input logic [7:0] exp[NBYTES]);
    for (int i = 0; i < NBYTES; i++) begin
      check($sformatf("%s byte %0d", what, i), 32'(d[i]), 32'(exp[i]));
    end
  endtask

  //------------------------------------------------------------------
  // the RTC, read as the firmware does: nsec first
  //------------------------------------------------------------------
  // a clock count, to time the RTC reads
  longint cyc = 0;
  always @(posedge clk) cyc <= cyc + 1;

  // as rtc_get() in rtc.c; at: the clock count when the nsec read ended
  task automatic rtc_get(output logic [63:0] sec, output logic [31:0] nsec);
    longint at;
    rtc_get_at(sec, nsec, at);
  endtask

  task automatic rtc_get_at(output logic [63:0] sec, output logic [31:0] nsec, output longint at);
    logic [31:0] lo, hi;
    rd(RTC + 0, nsec);
    at = cyc;
    rd(RTC + 4, lo);
    rd(RTC + 8, hi);
    sec = {hi, lo};
  endtask

  task automatic rtc_set(input logic [63:0] sec, input logic [31:0] nsec);
    wr(RTC + 12, nsec);
    wr(RTC + 16, sec[31:0]);
    wr(RTC + 20, sec[63:32]);
    wr(RTC + 24, 32'h1);
  endtask

  //------------------------------------------------------------------
  initial begin
    logic [7:0] id[NBYTES], d[NBYTES], pat[NBYTES], ff[NBYTES];
    logic [7:0] r;
    logic [63:0] s0, s1;
    logic [31:0] n0, n1;
    longint t0, t1;
    int clks, straddled;

    fails    = 0;
    bus.vld  = 1'b0;
    bus.we   = '0;
    bus.addr = '0;
    bus.wdat = '0;
    for (int i = 0; i < NBYTES; i++) begin
      pat[i] = 8'(i * 7 + 3);
      ff[i]  = 8'hFF;
    end

    arst_n = 1'b0;
    #100ns;
    arst_n = 1'b1;

    // 1. start-up clocks, then ready
    wait_ready();
    // 8 driven, the first 3 dropped by STARTUPE2
    check("start-up clocks at the flash", 32'(u_mem.start_clks), 5);

    // 2. the flash
    sel(1'b1);
    xfer(8'h9F, r);
    for (int i = 0; i < 3; i++) begin
      xfer(8'h00, id[i]);
    end
    sel(1'b0);
    check("JEDEC ID", {8'h00, id[0], id[1], id[2]}, 32'h0020_BA18);

    rdsr(r);
    check("status after start", 32'(r), 0);
    cmd1(8'h06);
    rdsr(r);
    check("status after WRITE ENABLE", 32'(r), 2);

    sel(1'b1);
    cmd_addr(8'h20, SECTOR);
    sel(1'b0);
    wait_wip();
    rdsr(r);
    check("status after erase", 32'(r), 0);
    read_bytes(SECTOR, NBYTES, d);
    check_bytes("erased", d, ff);

    page_prog(SECTOR, pat);  // no WRITE ENABLE: ignored
    read_bytes(SECTOR, NBYTES, d);
    check_bytes("program without WREN", d, ff);

    cmd1(8'h06);
    page_prog(SECTOR, pat);
    read_bytes(SECTOR, NBYTES, d);
    check_bytes("programmed", d, pat);

    // 3. the RTC: 12.5 ns a clock, exactly (12 and 13 ns in turn)
    rtc_get_at(s0, n0, t0);
    repeat (800) @(posedge clk);  // 10 us
    rtc_get_at(s1, n1, t1);
    check("rtc seconds", s1[31:0], 0);
    if ((longint'(n1 - n0) * 2 < (t1 - t0) * 25 - 2) || (longint'(n1 - n0) * 2 > (t1 - t0) * 25 + 2)) begin
      $display("%t FAIL rtc: %0d ns over %0d clocks", $time, n1 - n0, t1 - t0);
      fails++;
    end

    // a read is atomic: nsec latches the seconds. Start ever closer to the
    // carry into second 6, so that in some tries it falls between the nsec
    // read and the seconds reads: the seconds must still be those of nsec
    straddled = 0;
    for (int i = 0; i < 40; i++) begin
      rtc_set(64'd5, 999_999_500 + 12 * i);
      rtc_get_at(s1, n1, t0);
      t1 = cyc;  // the seconds reads are done
      if (n1 >= 999_999_000) begin
        check("rtc sec with an nsec before the carry", s1[31:0], 5);
        // the live clock passed the carry before the seconds reads ended
        if (longint'(n1) * 2 + (t1 - t0) * 25 >= 64'd2_000_000_000) straddled++;
      end
      else begin
        check("rtc sec with an nsec after the carry", s1[31:0], 6);
      end
    end
    if (straddled == 0) begin
      $display("%t FAIL rtc: no try had the carry between the reads", $time);
      fails++;
    end

    rtc_set(64'h0000_0001_FFFF_FFFF, 999_995_000);
    repeat (800) @(posedge clk);
    rtc_get(s1, n1);
    check("rtc sec_hi after the carry", s1[63:32], 2);
    check("rtc sec_lo after the carry", s1[31:0], 0);
    if ((n1 < 4_900) || (n1 > 5_000 + 2_000)) begin  // 800 clocks from the load
      $display("%t FAIL rtc: nsec %0d after the carry", $time, n1);
      fails++;
    end

    // 4. reboot: the design resets, the flash keeps its contents
    clks = u_mem.start_clks;
    arst_n = 1'b0;
    #200ns;
    arst_n = 1'b1;
    wait_ready();
    // EOS stays high over a reset of the design: no clock dropped
    check("start-up clocks after the reboot", 32'(u_mem.start_clks - clks), 8);
    rtc_get(s1, n1);
    check("rtc seconds after the reboot", s1[31:0], 0);
    read_bytes(SECTOR, NBYTES, d);
    check_bytes("after the reboot", d, pat);

    if (u_mem.errors != 0) begin
      $display("FAIL: the flash model saw %0d protocol errors", u_mem.errors);
      fails++;
    end
    $display("RESULT: %s (%0d failure(s))", (fails == 0) ? "PASS" : "FAIL", fails);
    $finish;
  end

  initial begin
    #5ms;
    $display("RESULT: FAIL (timeout)");
    $finish;
  end

endmodule : tb

// -----------------------------------------------------------------------------
// Project:     WireGuard-FPGA
// Description: NLnet-funded open-source implementation
// Funding:     https://nlnet.nl/project/KlusterLab-Wireguard (2023-12 to 2025-12)
// -----------------------------------------------------------------------------
