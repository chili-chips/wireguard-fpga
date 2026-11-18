// SPDX-FileCopyrightText: 2026 Chili.CHIPS
//
// SPDX-License-Identifier: BSD-3-Clause

//==========================================================================
// Wireguard-1GE FPGA * NLnet-sponsored open-source implementation
//--------------------------------------------------------------------------
// Description: the peer table, the data plane's side of the CSR
//  cryptokey_table (1.hw/README.md: "Receiver Index: From a WireGuard
//  Packet to Its Peer"). 64 entries of 30 words; each word is a 64-entry
//  distributed RAM (LUTRAM), stored once and read where it is used:
//   - the encryptor: addresses, remote_id, encrypt_key, send_cnt; its entry
//     (wg_peer_cfg_t) is valid from the 2nd clock after enc_idx, and it
//     writes send_cnt back (enc_update_send_cnt, for entry enc_idx)
//   - the decryptor: decrypt_key, in dec_peer.key (the rest of dec_peer is
//     0), valid from the 2nd clock after dec_idx
//   - the disassembler: local_id, combinationally: rcv_idx is the receiver
//     index's low 6 bits (the entry), rcv_match whether that entry's
//     local_id is the whole receiver index
//  The CPU writes every word, byte by byte (byte enables), and reads it back
//  one clock after its request. The send_cnt write-back lands a clock later
//  and waits while the CPU writes a send_cnt word; a CPU write to the same
//  entry's send_cnt cancels it.
//  MAC, IP and port are natural values in the CSR (byte 0 of the address
//  in the top bits) and in bus byte order in wg_peer_cfg_t (byte 0 in
//  [7:0]); the key is {key_255_224, ..., key_31_0}.
//==========================================================================

module lkup_peer_table
  import dpe_pkg::*;
  import net_pkg::*;
  import lkup_pkg::*;
(
    input  logic          clk,
    input  logic          rst,

    // the CSR cryptokey_table regfile (csr.rdl)
    input  ck_cfg_t       csr_cfg,
    output ck_sta_t       csr_sta,

    // the encryptor
    input  dpe_peer_idx_t enc_idx,
    output wg_peer_cfg_t  enc_peer,
    input  wg_counter_t   enc_new_send_cnt,
    input  logic          enc_update_send_cnt,

    // the decryptor
    input  dpe_peer_idx_t dec_idx,
    output wg_peer_cfg_t  dec_peer,

    // the disassembler
    input  wg_receiver_t  rcv,
    output dpe_peer_idx_t rcv_idx,
    output logic          rcv_match
);

  typedef logic [CK_ENTRY_W-1:0] entry_t;
  typedef logic [31:0] word_t;

  // the CPU's request: {entry, word, 2'b00}
  entry_t                 csr_entry;
  logic [CK_WORD_W-1:0] csr_word;
  logic                 csr_wr, csr_rd;
  assign                csr_entry = csr_cfg.addr[CK_ENTRY_W+CK_WORD_W+1:CK_WORD_W+2];
  assign                csr_word  = csr_cfg.addr[CK_WORD_W+1:2];
  assign                csr_wr    = csr_cfg.req & csr_cfg.req_is_wr;
  assign                csr_rd    = csr_cfg.req & ~csr_cfg.req_is_wr;

  // the data-plane readers' entries (a peer index, tid, has 8 bits: the
  // table holds 64 peers)
  entry_t enc_e, dec_e, rcv_e;
  logic [3:0] NC_idx_hi;
  assign      enc_e     = enc_idx[CK_ENTRY_W-1:0];
  assign      dec_e     = dec_idx[CK_ENTRY_W-1:0];
  assign      rcv_e     = rcv[CK_ENTRY_W-1:0];
  assign      NC_idx_hi = {enc_idx[7:CK_ENTRY_W], dec_idx[7:CK_ENTRY_W]};

  word_t       dp_rd    [CK_WORDS];  // each word at its reader's entry
  word_t       cpu_rd   [CK_WORDS];  // each word at the CPU's entry

  // The encryptor's send_cnt write-back, a clock later. Each word has one
  // write port: while the CPU writes a send_cnt word, the write-back waits
  // (so a CPU write to another entry cannot drop it, which would reuse a
  // nonce); a CPU write to the same entry's send_cnt cancels it (the CPU's
  // value wins).
  logic        wb_valid;
  entry_t      wb_e;
  wg_counter_t wb_cnt;
  logic cpu_cnt_wr, wb_go;
  assign cpu_cnt_wr = csr_wr &
      ((csr_word == CK_WORD_W'(CK_SEND_CNT_HI)) | (csr_word == CK_WORD_W'(CK_SEND_CNT_LO)));
  assign wb_go = wb_valid & ~cpu_cnt_wr;
  always_ff @(posedge clk) begin
    if (rst) begin
      wb_valid <= 1'b0;
      wb_e     <= '0;
      wb_cnt   <= '0;
    end
    else if (enc_update_send_cnt) begin
      wb_valid <= ~(cpu_cnt_wr & (csr_entry == enc_e));  // the CPU's write wins
      wb_e     <= enc_e;
      wb_cnt   <= enc_new_send_cnt;
    end
    else if (wb_go | (cpu_cnt_wr & (csr_entry == wb_e))) begin
      wb_valid <= 1'b0;
    end
  end

  for (genvar w = 0; w < CK_WORDS; w++) begin : g_word
    entry_t rd_e;  // its data-plane reader's entry
    logic   dp_we;  // the encryptor's send_cnt write-back
    word_t  dp_wdata;

    if (w == int'(CK_LOCAL_ID)) begin : g_rcv
      assign rd_e = rcv_e;
    end
    else if ((w >= int'(CK_DEC_KEY_0)) && (w < int'(CK_DEC_KEY_0) + 8)) begin : g_dec
      assign rd_e = dec_e;
    end
    else begin : g_enc
      assign rd_e = enc_e;
    end

    if (w == int'(CK_SEND_CNT_HI)) begin : g_cnt_hi
      assign dp_we    = wb_go;
      assign dp_wdata = wb_cnt[63:32];
    end
    else if (w == int'(CK_SEND_CNT_LO)) begin : g_cnt_lo
      assign dp_we    = wb_go;
      assign dp_wdata = wb_cnt[31:0];
    end
    else begin : g_no_wb
      assign dp_we    = 1'b0;
      assign dp_wdata = '0;
    end

    // a RAM per byte, written when its byte enable is set (the CPU writes
    // bytes, halves and words: bit 8b of wr_biten stands for byte b)
    for (genvar b = 0; b < 4; b++) begin : g_byte
      logic [7:0] mem[CK_ENTRIES];
      always_ff @(posedge clk) begin
        if (csr_wr & (csr_word == CK_WORD_W'(w)) & csr_cfg.wr_biten[8*b]) begin
          mem[csr_entry] <= csr_cfg.wr_data[8*b+:8];
        end
        else if (dp_we) begin
          mem[wb_e] <= dp_wdata[8*b+:8];
        end
      end
      assign dp_rd[w][8*b+:8]  = mem[rd_e];
      assign cpu_rd[w][8*b+:8] = mem[csr_entry];
    end
  end

  // CPU: write acknowledged at once, read data one clock after the request
  logic  rd_ack;
  word_t rd_data;
  always_ff @(posedge clk) begin
    if (rst) begin
      rd_ack  <= 1'b0;
      rd_data <= '0;
    end
    else begin
      rd_ack  <= csr_rd;
      rd_data <= (csr_word < CK_WORD_W'(CK_WORDS)) ? cpu_rd[csr_word] : '0;  // 30, 31: padding
    end
  end
  assign csr_sta.rd_ack  = rd_ack;
  assign csr_sta.rd_data = rd_data;
  assign csr_sta.wr_ack  = csr_wr;

  // the keys: word CK_*_KEY_0 holds bits 255:224
  wg_key_t enc_key, dec_key;
  always_comb begin
    for (int k = 0; k < 8; k++) begin
      enc_key[255-32*k-:32] = dp_rd[int'(CK_ENC_KEY_0)+k];
      dec_key[255-32*k-:32] = dp_rd[int'(CK_DEC_KEY_0)+k];
    end
  end

  // the encryptor's and the decryptor's entry, a clock after their index
  always_ff @(posedge clk) begin
    enc_peer <= '{
        local_mac: bswap48({dp_rd[CK_LOCAL_MAC_HI][15:0], dp_rd[CK_LOCAL_MAC_LO]}),
        local_ip: bswap32(dp_rd[CK_LOCAL_IP]),
        local_port: bswap16(dp_rd[CK_LOCAL_PORT][15:0]),
        remote_mac: bswap48({dp_rd[CK_REMOTE_MAC_HI][15:0], dp_rd[CK_REMOTE_MAC_LO]}),
        remote_ip: bswap32(dp_rd[CK_REMOTE_IP]),
        remote_port: bswap16(dp_rd[CK_REMOTE_PORT][15:0]),
        remote_id: dp_rd[CK_REMOTE_ID],
        key: enc_key,
        send_cnt: {dp_rd[CK_SEND_CNT_HI], dp_rd[CK_SEND_CNT_LO]}
    };
    dec_peer <= '{key: dec_key, default: '0};
  end

  // the disassembler: the entry from the receiver index, checked in full
  assign rcv_idx   = dpe_peer_idx_t'(rcv_e);
  assign rcv_match = dp_rd[CK_LOCAL_ID] == rcv;

endmodule

// -----------------------------------------------------------------------------
// Project:     WireGuard-FPGA
// Description: NLnet-funded open-source implementation
// Funding:     https://nlnet.nl/project/KlusterLab-Wireguard (2023-12 to 2025-12)
// -----------------------------------------------------------------------------
