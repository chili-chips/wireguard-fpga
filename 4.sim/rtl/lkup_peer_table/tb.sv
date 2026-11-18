// SPDX-FileCopyrightText: 2026 Chili.CHIPS
//
// SPDX-License-Identifier: BSD-3-Clause

//==========================================================================
// Wireguard-1GE FPGA * NLnet-sponsored open-source implementation
//--------------------------------------------------------------------------
// Description:
//   lkup_peer_table unit bench.
//   1. The CPU's view: every word of all 64 entries written over the CSR
//      port; a few entries read back in full (the padding words 30, 31
//      read 0); a write with byte enables.
//   2. The encryptor's and the decryptor's entry for several indices, two
//      clocks after the index: every field, MAC/IP/port byte-swapped to bus
//      order, the key words in order; the decryptor's entry holds its key
//      only.
//   3. The disassembler's lookup: each entry's local_id matches and gives
//      its entry; with other upper bits it does not.
//   4. The send_cnt write-back, seen by the encryptor and by the CPU; a CPU
//      write in the same clock wins.
//==========================================================================

module tb;
  import dpe_pkg::*;
  import net_pkg::*;
  import lkup_pkg::*;

  logic clk, rst;

  ck_cfg_t       csr_cfg;
  ck_sta_t       csr_sta;
  dpe_peer_idx_t enc_idx, dec_idx, rcv_idx;
  wg_peer_cfg_t  enc_peer, dec_peer;
  wg_counter_t   enc_new_send_cnt;
  logic          enc_update_send_cnt, rcv_match;
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

  function automatic wg_peer_cfg_t dec_want(int e);
    wg_key_t key;
    for (int k = 0; k < 8; k++) key[255-32*k-:32] = model[e][int'(CK_DEC_KEY_0)+k];
    return '{key: key, default: '0};
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
    enc_idx = dpe_peer_idx_t'(e_enc);
    dec_idx = dpe_peer_idx_t'(e_dec);
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
    if (rcv_match !== want_match || (want_match && rcv_idx !== dpe_peer_idx_t'(want_e))) begin
      $display("ERROR: receiver %h: match %b entry %0d, want %b %0d", r, rcv_match, rcv_idx,
               want_match, want_e);
      errors++;
    end
  endtask

  initial begin
    csr_cfg = '{req: 1'b0, req_is_wr: 1'b0, addr: '0, wr_data: '0, wr_biten: '0};
    enc_idx = '0;
    dec_idx = '0;
    rcv = '0;
    enc_new_send_cnt = '0;
    enc_update_send_cnt = 1'b0;
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

    // 4. the send_cnt write-back
    @(negedge clk);
    enc_idx = 8'd37;
    enc_new_send_cnt = 64'h0000_0001_8000_0002;
    enc_update_send_cnt = 1'b1;
    @(negedge clk);
    enc_update_send_cnt = 1'b0;
    {model[37][CK_SEND_CNT_HI], model[37][CK_SEND_CNT_LO]} = 64'h0000_0001_8000_0002;
    check_peer(37, 2);
    csr_read(37, int'(CK_SEND_CNT_HI), 32'h0000_0001);
    csr_read(37, int'(CK_SEND_CNT_LO), 32'h8000_0002);
    // a CPU write in the write-back's clock wins (send_cnt low word)
    @(negedge clk);
    enc_idx = 8'd37;
    enc_new_send_cnt = 64'h0000_0001_8000_0003;
    enc_update_send_cnt = 1'b1;
    csr_cfg = '{req: 1'b1, req_is_wr: 1'b1, addr: 13'({6'd37, 5'(CK_SEND_CNT_LO), 2'b00}),
                wr_data: 32'h5555_5555, wr_biten: '1};
    @(negedge clk);
    enc_update_send_cnt = 1'b0;
    csr_cfg.req = 1'b0;
    csr_read(37, int'(CK_SEND_CNT_LO), 32'h5555_5555);
    csr_read(37, int'(CK_SEND_CNT_HI), 32'h0000_0001);  // the write-back cancelled
    // a CPU write to another entry's send_cnt in the write-back's clock: both land
    @(negedge clk);
    enc_idx = 8'd37;
    enc_new_send_cnt = 64'h0000_0002_8000_0004;
    enc_update_send_cnt = 1'b1;
    csr_cfg = '{req: 1'b1, req_is_wr: 1'b1, addr: 13'({6'd5, 5'(CK_SEND_CNT_LO), 2'b00}),
                wr_data: 32'hAAAA_0005, wr_biten: '1};
    @(negedge clk);
    enc_update_send_cnt = 1'b0;
    // and in the next clock too: the write-back waits for it
    csr_cfg = '{req: 1'b1, req_is_wr: 1'b1, addr: 13'({6'd6, 5'(CK_SEND_CNT_HI), 2'b00}),
                wr_data: 32'hBBBB_0006, wr_biten: '1};
    @(negedge clk);
    csr_cfg.req = 1'b0;
    csr_read(37, int'(CK_SEND_CNT_HI), 32'h0000_0002);
    csr_read(37, int'(CK_SEND_CNT_LO), 32'h8000_0004);
    csr_read(5, int'(CK_SEND_CNT_LO), 32'hAAAA_0005);
    csr_read(6, int'(CK_SEND_CNT_HI), 32'hBBBB_0006);
    // byte enables: one byte of a word
    csr_write(7, int'(CK_LOCAL_IP), 32'h1122_3344, 32'h00FF_0000);
    model[7][CK_LOCAL_IP][23:16] = 8'h22;
    csr_read(7, int'(CK_LOCAL_IP), model[7][CK_LOCAL_IP]);

    if (errors == 0) $display("RESULT: PASS (64 entries, CSR read-back, peers, receiver index)");
    else $display("RESULT: FAIL (%0d errors)", errors);
    $finish(2);
  end
endmodule

// -----------------------------------------------------------------------------
// Project:     WireGuard-FPGA
// Description: NLnet-funded open-source implementation
// Funding:     https://nlnet.nl/project/KlusterLab-Wireguard (2023-12 to 2025-12)
// -----------------------------------------------------------------------------
