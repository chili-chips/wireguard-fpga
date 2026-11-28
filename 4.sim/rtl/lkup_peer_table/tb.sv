// SPDX-FileCopyrightText: 2026 Chili.CHIPS
//
// SPDX-License-Identifier: BSD-3-Clause

//==========================================================================
// Wireguard-1GE FPGA * NLnet-sponsored open-source implementation
//--------------------------------------------------------------------------
// Description:
//   lkup_peer_table unit bench.
//   1. The CPU's view: every word of all 64 entries written over the CSR
//      port; a few entries read back in full; a write with byte enables.
//   2. The encryptor's and the decryptor's entry for several indices, two
//      clocks after the index: every field, MAC/IP/port byte-swapped to bus
//      order, the key words in order; the decryptor's entry holds its key
//      and its replay window (recv_cnt, recv_win), and the peer tag
//      (local_port[21:16], read at the decryptor's entry while the encryptor
//      reads the port at its own; bits 23:22 set, not part of it).
//   3. The disassembler's lookup: each entry's local_id matches and gives
//      its entry; with other upper bits it does not, nor does index 0 on an
//      entry whose local_id is 0 (unwritten or cleared).
//   4. The send_cnt write-back, seen by the encryptor and by the CPU; a CPU
//      write in the same clock wins.
//   5. The decryptor's write-back of its replay window (recv_cnt, recv_win),
//      seen by the decryptor a clock later and by the CPU; a CPU write in
//      the same clock wins; both write-backs and a CPU write in one clock.
//   6. The peer tag written alone (its byte, as the firmware moves it): the
//      decryptor and the CPU see it, the port stays.
//==========================================================================

module tb;
  import dpe_pkg::*;
  import net_pkg::*;
  import lkup_pkg::*;

  logic clk, rst;

  ck_cfg_t       csr_cfg;
  ck_sta_t       csr_sta;
  peer_req_t     enc_req;
  wg_dec_req_t   dec_req;
  rcv_rsp_t      rcv_rsp;
  wg_peer_cfg_t  enc_peer;
  wg_dec_peer_t  dec_peer;
  wg_receiver_t  rcv;

  lkup_peer_table dut (.*);

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

  int errors = 0;

  // the bench's table: a distinct value for every word; local_id carries
  // its entry in [5:0]
  function automatic logic [31:0] word_of(int e, int w);
    if (w == int'(CK_LOCAL_ID)) return {26'(32'h0123457 * (e + 1)), 6'(e)};
    // the tag (63 - e: not its own entry) under reserved bits 23:22 set
    if (w == int'(CK_LOCAL_PORT)) return {8'(e), 2'b11, 6'(63 - e), 8'(e * 7 + w), 8'hA5};
    return {8'(e), 8'(w), 8'(e * 7 + w), 8'hA5};
  endfunction

  logic [31:0] model[CK_ENTRIES][32];

  function automatic wg_peer_cfg_t enc_want(int e);
    wg_key_t key;
    for (int k = 0; k < 8; k++) key[255-32*k-:32] = model[e][int'(CK_ENC_KEY_0)+k];
    return '{
        local_mac: bswap48({model[e][CK_LOCAL_MAC_HI][15:0], model[e][CK_LOCAL_MAC_LO]}),
        local_ip: bswap32(model[e][CK_LOCAL_IP]),
        local_port: bswap16(model[e][CK_LOCAL_PORT][15:0]),
        remote_mac: bswap48({model[e][CK_REMOTE_MAC_HI][15:0], model[e][CK_REMOTE_MAC_LO]}),
        remote_ip: bswap32(model[e][CK_REMOTE_IP]),
        remote_port: bswap16(model[e][CK_REMOTE_PORT][15:0]),
        remote_id: model[e][CK_REMOTE_ID],
        key: key,
        send_cnt: {model[e][CK_SEND_CNT_HI], model[e][CK_SEND_CNT_LO]}
    };
  endfunction

  function automatic wg_dec_peer_t dec_want(int e);
    wg_key_t key;
    for (int k = 0; k < 8; k++) key[255-32*k-:32] = model[e][int'(CK_DEC_KEY_0)+k];
    return '{
        peer: dpe_peer_idx_t'(model[e][CK_LOCAL_PORT][CK_TAG_LSB+:CK_ENTRY_W]),
        key: key,
        recv_cnt: {model[e][CK_RECV_CNT_HI], model[e][CK_RECV_CNT_LO]},
        recv_win: {model[e][CK_RECV_WIN_HI], model[e][CK_RECV_WIN_LO]}
    };
  endfunction

  //------------------------------------------------------------------
  // CSR access: {entry, word, 2'b00}; writes acknowledged in the
  // request's clock, reads one clock later
  //------------------------------------------------------------------
  task automatic csr_write(int e, int w, logic [31:0] data, logic [31:0] biten = '1);
    @(negedge clk);
    csr_cfg = '{req: 1'b1, req_is_wr: 1'b1, addr: 13'({6'(e), 5'(w), 2'b00}),
                wr_data: data, wr_biten: biten};
    #3ns;
    if (!csr_sta.wr_ack) begin
      $display("ERROR: CSR write entry %0d word %0d: no wr_ack", e, w);
      errors++;
    end
    @(negedge clk);
    csr_cfg.req = 1'b0;
  endtask

  task automatic csr_read(int e, int w, logic [31:0] want);
    @(negedge clk);
    csr_cfg = '{req: 1'b1, req_is_wr: 1'b0, addr: 13'({6'(e), 5'(w), 2'b00}),
                wr_data: '0, wr_biten: '0};
    @(negedge clk);
    csr_cfg.req  = 1'b0;
    csr_cfg.addr = '1;  // not needed after the request
    if (!csr_sta.rd_ack) begin
      $display("ERROR: CSR read entry %0d word %0d: no rd_ack", e, w);
      errors++;
    end
    else if (csr_sta.rd_data !== want) begin
      $display("ERROR: CSR read entry %0d word %0d: %h, want %h", e, w, csr_sta.rd_data, want);
      errors++;
    end
  endtask

  // the encryptor's and the decryptor's entries: registered on the first
  // clock after the index (the blocks take them on the 2nd)
  task automatic check_peer(int e_enc, int e_dec);
    @(negedge clk);
    enc_req.idx = dpe_peer_idx_t'(e_enc);
    dec_req.idx = dpe_peer_idx_t'(e_dec);
    @(negedge clk);
    if (enc_peer !== enc_want(e_enc)) begin
      $display("ERROR: encryptor entry %0d: %h", e_enc, enc_peer);
      errors++;
    end
    if (dec_peer !== dec_want(e_dec)) begin
      $display("ERROR: decryptor entry %0d: %h", e_dec, dec_peer);
      errors++;
    end
  endtask

  task automatic check_rcv(wg_receiver_t r, logic want_match, int want_e);
    @(negedge clk);
    rcv = r;
    #3ns;
    if (rcv_rsp.match !== want_match || (want_match && rcv_rsp.idx !== dpe_peer_idx_t'(want_e))) begin
      $display("ERROR: receiver %h: match %b entry %0d, want %b %0d", r, rcv_rsp.match, rcv_rsp.idx,
               want_match, want_e);
      errors++;
    end
  endtask

  initial begin
    csr_cfg = '{req: 1'b0, req_is_wr: 1'b0, addr: '0, wr_data: '0, wr_biten: '0};
    enc_req.idx = '0;
    dec_req = '0;
    rcv = '0;
    enc_req.new_send_cnt = '0;
    enc_req.update_send_cnt = 1'b0;
    rst = 1'b1;
    repeat (4) @(negedge clk);
    rst = 1'b0;

    // 1. the CPU writes every word, then reads some back
    for (int e = 0; e < CK_ENTRIES; e++) begin
      for (int w = 0; w < 32; w++) begin
        model[e][w] = (w < CK_WORDS) ? word_of(e, w) : '0;
        if (w < CK_WORDS) csr_write(e, w, model[e][w]);
      end
    end
    foreach (model[e]) begin
      if (e inside {0, 1, 37, 63}) begin
        for (int w = 0; w < 32; w++) csr_read(e, w, model[e][w]);
      end
    end
    csr_write(5, int'(CK_REMOTE_IP), 32'hDEADBEEF, 32'h0000FFFF);  // the low half only
    model[5][CK_REMOTE_IP][15:0] = 16'hBEEF;
    csr_read(5, int'(CK_REMOTE_IP), model[5][CK_REMOTE_IP]);

    // 2. the encryptor's and the decryptor's entries
    check_peer(0, 63);
    check_peer(5, 5);
    check_peer(37, 1);
    check_peer(63, 0);

    // 3. the receiver index
    foreach (model[e]) check_rcv(model[e][CK_LOCAL_ID], 1'b1, e);
    check_rcv(model[9][CK_LOCAL_ID] ^ 32'h0100_0000, 1'b0, 9);  // other upper bits
    check_rcv(model[9][CK_LOCAL_ID] ^ 32'h0000_0001, 1'b0, 9);  // another entry's index
    // an unwritten (or cleared) entry holds local_id 0: index 0 must not match
    csr_write(0, int'(CK_LOCAL_ID), 32'h0);
    check_rcv(32'h0, 1'b0, 0);
    csr_write(0, int'(CK_LOCAL_ID), model[0][CK_LOCAL_ID]);

    // 4. the send_cnt write-back
    @(negedge clk);
    enc_req.idx = 8'd37;
    enc_req.new_send_cnt = 64'h0000_0001_8000_0002;
    enc_req.update_send_cnt = 1'b1;
    @(negedge clk);
    enc_req.update_send_cnt = 1'b0;
    {model[37][CK_SEND_CNT_HI], model[37][CK_SEND_CNT_LO]} = 64'h0000_0001_8000_0002;
    check_peer(37, 2);
    csr_read(37, int'(CK_SEND_CNT_HI), 32'h0000_0001);
    csr_read(37, int'(CK_SEND_CNT_LO), 32'h8000_0002);
    // a CPU write in the write-back's clock wins (send_cnt low word)
    @(negedge clk);
    enc_req.idx = 8'd37;
    enc_req.new_send_cnt = 64'h0000_0001_8000_0003;
    enc_req.update_send_cnt = 1'b1;
    csr_cfg = '{req: 1'b1, req_is_wr: 1'b1, addr: 13'({6'd37, 5'(CK_SEND_CNT_LO), 2'b00}),
                wr_data: 32'h5555_5555, wr_biten: '1};
    @(negedge clk);
    enc_req.update_send_cnt = 1'b0;
    csr_cfg.req = 1'b0;
    csr_read(37, int'(CK_SEND_CNT_LO), 32'h5555_5555);
    csr_read(37, int'(CK_SEND_CNT_HI), 32'h0000_0001);  // the write-back's (unchanged)
    // a CPU write to another entry's send_cnt in the write-back's clock: both land
    @(negedge clk);
    enc_req.idx = 8'd37;
    enc_req.new_send_cnt = 64'h0000_0002_8000_0004;
    enc_req.update_send_cnt = 1'b1;
    csr_cfg = '{req: 1'b1, req_is_wr: 1'b1, addr: 13'({6'd5, 5'(CK_SEND_CNT_LO), 2'b00}),
                wr_data: 32'hAAAA_0005, wr_biten: '1};
    @(negedge clk);
    enc_req.update_send_cnt = 1'b0;
    csr_cfg.req = 1'b0;
    // then another counter write, a clock later (CPU requests are clocks
    // apart: the RTL asserts it)
    @(negedge clk);
    csr_cfg = '{req: 1'b1, req_is_wr: 1'b1, addr: 13'({6'd6, 5'(CK_SEND_CNT_HI), 2'b00}),
                wr_data: 32'hBBBB_0006, wr_biten: '1};
    @(negedge clk);
    csr_cfg.req = 1'b0;
    csr_read(37, int'(CK_SEND_CNT_HI), 32'h0000_0002);
    csr_read(37, int'(CK_SEND_CNT_LO), 32'h8000_0004);
    csr_read(5, int'(CK_SEND_CNT_LO), 32'hAAAA_0005);
    csr_read(6, int'(CK_SEND_CNT_HI), 32'hBBBB_0006);
    // a write-back meeting a CPU write to the same word of another entry:
    // the encryptor's next read, a clock later, sees the new count
    @(negedge clk);
    enc_req.idx = 8'd37;
    enc_req.new_send_cnt = 64'h0000_0003_0000_0007;
    enc_req.update_send_cnt = 1'b1;
    csr_cfg = '{req: 1'b1, req_is_wr: 1'b1, addr: 13'({6'd9, 5'(CK_SEND_CNT_LO), 2'b00}),
                wr_data: 32'hCCCC_0009, wr_biten: '1};
    @(negedge clk);
    enc_req.update_send_cnt = 1'b0;
    csr_cfg.req = 1'b0;
    @(negedge clk);
    if (enc_peer.send_cnt !== 64'h0000_0003_0000_0007) begin
      $display("ERROR: send_cnt %h a clock after its write-back", enc_peer.send_cnt);
      errors++;
    end
    csr_read(9, int'(CK_SEND_CNT_LO), 32'hCCCC_0009);
    // byte enables: one byte of a word
    csr_write(7, int'(CK_LOCAL_IP), 32'h1122_3344, 32'h00FF_0000);
    model[7][CK_LOCAL_IP][23:16] = 8'h22;
    csr_read(7, int'(CK_LOCAL_IP), model[7][CK_LOCAL_IP]);

    // 5. the replay window write-back
    @(negedge clk);
    dec_req = '{idx: 8'd37, new_recv_cnt: 64'h0000_0004_0000_0010,
                new_recv_win: 64'h8000_0000_0000_0003, update_recv: 1'b1};
    @(negedge clk);
    dec_req.update_recv = 1'b0;
    @(negedge clk);
    if (dec_peer.recv_cnt !== 64'h0000_0004_0000_0010 ||
        dec_peer.recv_win !== 64'h8000_0000_0000_0003) begin
      $display("ERROR: recv_cnt %h recv_win %h a clock after the write-back", dec_peer.recv_cnt,
               dec_peer.recv_win);
      errors++;
    end
    {model[37][CK_RECV_CNT_HI], model[37][CK_RECV_CNT_LO]} = 64'h0000_0004_0000_0010;
    {model[37][CK_RECV_WIN_HI], model[37][CK_RECV_WIN_LO]} = 64'h8000_0000_0000_0003;
    check_peer(2, 37);
    for (int w = int'(CK_RECV_CNT_HI); w <= int'(CK_RECV_WIN_LO); w++) csr_read(37, w, model[37][w]);
    // a CPU write in the write-back's clock wins (recv_win low word)
    @(negedge clk);
    dec_req = '{idx: 8'd37, new_recv_cnt: 64'h0000_0004_0000_0011,
                new_recv_win: 64'h0000_0000_0000_0007, update_recv: 1'b1};
    csr_cfg = '{req: 1'b1, req_is_wr: 1'b1, addr: 13'({6'd37, 5'(CK_RECV_WIN_LO), 2'b00}),
                wr_data: 32'h1234_5678, wr_biten: '1};
    @(negedge clk);
    dec_req.update_recv = 1'b0;
    csr_cfg.req = 1'b0;
    {model[37][CK_RECV_CNT_HI], model[37][CK_RECV_CNT_LO]} = 64'h0000_0004_0000_0011;
    {model[37][CK_RECV_WIN_HI], model[37][CK_RECV_WIN_LO]} = 64'h0000_0000_1234_5678;
    for (int w = int'(CK_RECV_CNT_HI); w <= int'(CK_RECV_WIN_LO); w++) csr_read(37, w, model[37][w]);
    // both write-backs in one clock (encryptor entry 5, decryptor entry 6)
    // and a CPU write to entry 9's recv_cnt: all three land
    @(negedge clk);
    enc_req.idx = 8'd5;
    enc_req.new_send_cnt = 64'h0000_0005_0000_0055;
    enc_req.update_send_cnt = 1'b1;
    dec_req = '{idx: 8'd6, new_recv_cnt: 64'h0000_0006_0000_0066,
                new_recv_win: 64'hFFFF_0000_0000_FFFF, update_recv: 1'b1};
    csr_cfg = '{req: 1'b1, req_is_wr: 1'b1, addr: 13'({6'd9, 5'(CK_RECV_CNT_HI), 2'b00}),
                wr_data: 32'h9999_0009, wr_biten: '1};
    @(negedge clk);
    enc_req.update_send_cnt = 1'b0;
    dec_req.update_recv = 1'b0;
    csr_cfg.req = 1'b0;
    {model[5][CK_SEND_CNT_HI], model[5][CK_SEND_CNT_LO]} = 64'h0000_0005_0000_0055;
    {model[6][CK_RECV_CNT_HI], model[6][CK_RECV_CNT_LO]} = 64'h0000_0006_0000_0066;
    {model[6][CK_RECV_WIN_HI], model[6][CK_RECV_WIN_LO]} = 64'hFFFF_0000_0000_FFFF;
    model[9][CK_RECV_CNT_HI] = 32'h9999_0009;
    check_peer(5, 6);
    check_peer(2, 9);
    csr_read(9, int'(CK_RECV_CNT_HI), 32'h9999_0009);
    csr_read(6, int'(CK_RECV_WIN_HI), 32'hFFFF_0000);

    // 6. the peer tag alone, a byte write (entry 5: tag 58 to 9)
    csr_write(5, int'(CK_LOCAL_PORT), 32'h0009_0000, 32'h00FF_0000);
    model[5][CK_LOCAL_PORT][23:16] = 8'h09;
    csr_read(5, int'(CK_LOCAL_PORT), model[5][CK_LOCAL_PORT]);
    check_peer(5, 5);
    check_peer(2, 5);  // the encryptor at another entry: its port
    if (dec_peer.peer !== 8'd9) begin
      $display("ERROR: peer tag %0d, want 9", dec_peer.peer);
      errors++;
    end

    if (errors == 0) begin
      $display("RESULT: PASS (64 entries, read-back, peers, tag, receiver index, write-backs)");
    end
    else begin
      $display("RESULT: FAIL (%0d errors)", errors);
    end
    $finish(2);
  end
endmodule

// -----------------------------------------------------------------------------
// Project:     WireGuard-FPGA
// Description: NLnet-funded open-source implementation
// Funding:     https://nlnet.nl/project/KlusterLab-Wireguard (2023-12 to 2025-12)
// -----------------------------------------------------------------------------
