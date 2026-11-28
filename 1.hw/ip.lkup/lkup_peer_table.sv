// SPDX-FileCopyrightText: 2026 Chili.CHIPS
//
// SPDX-License-Identifier: BSD-3-Clause

//==========================================================================
// Wireguard-1GE FPGA * NLnet-sponsored open-source implementation
//--------------------------------------------------------------------------
// Description: the peer table, the data plane's side of the CSR
//  cryptokey_table (1.hw/README.md: "Receiver Index: From a WireGuard
//  Packet to Its Peer"). 64 entries of 32 words; each word is a 64-entry
//  distributed RAM (LUTRAM), stored once and read where it is used:
//   - the encryptor: addresses, remote_id, encrypt_key, send_cnt; its entry
//     (wg_peer_cfg_t) is valid from the 2nd clock after enc_req.idx, and it
//     writes send_cnt back (enc_req.update_send_cnt, for entry enc_req.idx)
//   - the decryptor: decrypt_key, the replay window (recv_cnt and
//     recv_win) and the peer tag (local_port's upper bits, on a read port
//     of its own: the encryptor reads that word for the port)
//     (wg_dec_peer_t), valid from the 2nd clock after dec_req.idx;
//     it writes the window back (dec_req.update_recv, for entry dec_req.idx)
//   - the disassembler: local_id, combinationally: rcv_rsp.idx is the receiver
//     index's low 6 bits (the entry), rcv_rsp.match whether that entry's
//     local_id is the whole receiver index (never for index 0)
//  The CPU writes every word, byte by byte (byte enables), and reads it back
//  one clock after its request. The write-backs (send_cnt; recv_cnt and
//  recv_win) go in at once; a CPU write to one of their words in the
//  write-back's clock is posted to the next (and wins on the same entry).
//  CPU requests are clocks apart, so a posted write never meets the next
//  one.
//  The posted write orders only the same clock. A packet in flight on an
//  entry read it at PEER_RSP and writes its window (words 28 to 31) back
//  after its tag check, clocks later (send_cnt likewise, after its frame):
//  that write-back overwrites a CPU write made between the two. So the CPU
//  installs or rewrites an entry only under the pause/drain handshake
//  (CLAUDE.md: csr.dpe.fcr.pause, wait for csr.dpe.fcr.idle, write, clear
//  pause), when no packet is in flight.
//  MAC, IP and port are natural values in the CSR (byte 0 of the address
//  in the top bits) and in bus byte order in wg_peer_cfg_t (byte 0 in
//  [7:0]); the key is {key_255_224, ..., key_31_0}.
//==========================================================================

module lkup_peer_table
  import dpe_pkg::*;
  import net_pkg::*;
  import lkup_pkg::*;
(
    input  logic         clk,
    input  logic         rst,

    // the CSR cryptokey_table regfile (csr.rdl)
    input  ck_cfg_t      csr_cfg,
    output ck_sta_t      csr_sta,

    // the encryptor
    input  peer_req_t    enc_req,
    output wg_peer_cfg_t enc_peer,

    // the decryptor
    input  wg_dec_req_t  dec_req,
    output wg_dec_peer_t dec_peer,

    // the disassembler
    input  wg_receiver_t rcv,
    output rcv_rsp_t     rcv_rsp
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
  assign      enc_e     = enc_req.idx[CK_ENTRY_W-1:0];
  assign      dec_e     = dec_req.idx[CK_ENTRY_W-1:0];
  assign      rcv_e     = rcv[CK_ENTRY_W-1:0];
  assign      NC_idx_hi = {enc_req.idx[7:CK_ENTRY_W], dec_req.idx[7:CK_ENTRY_W]};

  word_t dp_rd [CK_WORDS];  // each word at its reader's entry
  word_t cpu_rd[CK_WORDS];  // each word at the CPU's entry

  // Each word has one write port. The encryptor's send_cnt write-back and
  // the decryptor's recv_cnt/recv_win one always go in at once, so the next
  // packet of that peer reads the new value (a stale or lost count would
  // reuse a nonce, a stale window let a replay through). A CPU write to one
  // of their words in the same clock as its write-back is posted:
  // acknowledged at once, written in the next clock (each write-back pulses
  // once a packet), so it lands after the write-back and wins on the same
  // entry.
  logic cpu_send_wr, cpu_recv_wr;  // the CPU writes a send_cnt word; a recv_cnt or recv_win one
  assign cpu_send_wr = csr_wr &
      ((csr_word == CK_WORD_W'(CK_SEND_CNT_HI)) | (csr_word == CK_WORD_W'(CK_SEND_CNT_LO)));
  assign cpu_recv_wr = csr_wr & (csr_word >= CK_WORD_W'(CK_RECV_CNT_HI));  // words 28 to 31

  logic                   pw_valid;  // a posted CPU write
  entry_t                 pw_e;
  logic   [CK_WORD_W-1:0] pw_word;
  word_t                  pw_data;
  logic   [          3:0] pw_be;  // its byte enables (wr_biten bit 8b: byte b)
  always_ff @(posedge clk) begin
    if (rst) begin
      pw_valid <= 1'b0;
      pw_e     <= '0;
      pw_word  <= '0;
      pw_data  <= '0;
      pw_be    <= '0;
    end
    else begin
      pw_valid <= (cpu_send_wr & enc_req.update_send_cnt) | (cpu_recv_wr & dec_req.update_recv);
      pw_e <= csr_entry;
      pw_word <= csr_word;
      pw_data <= csr_cfg.wr_data;
      pw_be <= {
        csr_cfg.wr_biten[24], csr_cfg.wr_biten[16], csr_cfg.wr_biten[8], csr_cfg.wr_biten[0]
      };
    end
  end

`ifdef SIM_ONLY
  // the posted write assumes CPU requests are clocks apart (eduBOS5,
  // PicoRV32 and the UART path give that); one in its clock would be lost
  always_ff @(posedge clk) begin
    if (!rst) begin
      assert (!(pw_valid & csr_cfg.req))
      else begin
        $error("lkup_peer_table: a CSR request in a posted write's clock");
      end
    end
  end
`endif

  // the peer tag: local_port's byte CK_TAG_LSB / 8 at the decryptor's entry
  logic [7:0] tag_rd;
  logic [1:0] NC_tag_hi;  // reserved bits 23:22
  assign      NC_tag_hi = tag_rd[7:CK_ENTRY_W];

  for (genvar w = 0; w < CK_WORDS; w++) begin : g_word
    entry_t rd_e;  // its data-plane reader's entry
    logic   dp_we;  // its write-back: the encryptor's send_cnt, the decryptor's window
    entry_t wb_e;  // the write-back's entry
    word_t  dp_wdata;

    if (w == int'(CK_LOCAL_ID)) begin : g_rcv
      assign rd_e = rcv_e;
    end
    else if (((w >= int'(CK_DEC_KEY_0)) && (w < int'(CK_DEC_KEY_0) + 8)) ||
             (w >= int'(CK_RECV_CNT_HI))) begin : g_dec
      assign rd_e = dec_e;
    end
    else begin : g_enc
      assign rd_e = enc_e;
    end

    if (w == int'(CK_SEND_CNT_HI)) begin : g_cnt_hi
      assign dp_we    = enc_req.update_send_cnt;
      assign wb_e     = enc_e;
      assign dp_wdata = enc_req.new_send_cnt[63:32];
    end
    else if (w == int'(CK_SEND_CNT_LO)) begin : g_cnt_lo
      assign dp_we    = enc_req.update_send_cnt;
      assign wb_e     = enc_e;
      assign dp_wdata = enc_req.new_send_cnt[31:0];
    end
    else if (w == int'(CK_RECV_CNT_HI)) begin : g_recv_cnt_hi
      assign dp_we    = dec_req.update_recv;
      assign wb_e     = dec_e;
      assign dp_wdata = dec_req.new_recv_cnt[63:32];
    end
    else if (w == int'(CK_RECV_CNT_LO)) begin : g_recv_cnt_lo
      assign dp_we    = dec_req.update_recv;
      assign wb_e     = dec_e;
      assign dp_wdata = dec_req.new_recv_cnt[31:0];
    end
    else if (w == int'(CK_RECV_WIN_HI)) begin : g_recv_win_hi
      assign dp_we    = dec_req.update_recv;
      assign wb_e     = dec_e;
      assign dp_wdata = dec_req.new_recv_win[63:32];
    end
    else if (w == int'(CK_RECV_WIN_LO)) begin : g_recv_win_lo
      assign dp_we    = dec_req.update_recv;
      assign wb_e     = dec_e;
      assign dp_wdata = dec_req.new_recv_win[31:0];
    end
    else begin : g_no_wb
      assign dp_we    = 1'b0;
      assign wb_e     = '0;
      assign dp_wdata = '0;
    end

    // a RAM per byte, written when its byte enable is set (the CPU writes
    // bytes, halves and words: bit 8b of wr_biten stands for byte b)
    for (genvar b = 0; b < 4; b++) begin : g_byte
      logic [7:0] mem[CK_ENTRIES];
      always_ff @(posedge clk) begin
        if (dp_we) begin
          mem[wb_e] <= dp_wdata[8*b+:8];
        end
        else if (pw_valid & (pw_word == CK_WORD_W'(w))) begin
          if (pw_be[b]) begin
            mem[pw_e] <= pw_data[8*b+:8];
          end
        end
        else if (csr_wr & (csr_word == CK_WORD_W'(w)) & csr_cfg.wr_biten[8*b]) begin
          mem[csr_entry] <= csr_cfg.wr_data[8*b+:8];
        end
      end
      assign dp_rd[w][8*b+:8]  = mem[rd_e];
      assign cpu_rd[w][8*b+:8] = mem[csr_entry];
      if ((w == int'(CK_LOCAL_PORT)) && (b == CK_TAG_LSB / 8)) begin : g_tag
        assign tag_rd = mem[dec_e];
      end
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
      rd_data <= cpu_rd[csr_word];  // CK_WORDS: every word is used
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
    dec_peer <= '{
        peer: dpe_peer_idx_t'(tag_rd[CK_ENTRY_W-1:0]),
        key: dec_key,
        recv_cnt: {dp_rd[CK_RECV_CNT_HI], dp_rd[CK_RECV_CNT_LO]},
        recv_win: {dp_rd[CK_RECV_WIN_HI], dp_rd[CK_RECV_WIN_LO]}
    };
  end

  // the disassembler: the entry from the receiver index, checked in full. An
  // unwritten or cleared entry holds local_id 0 (and an all-zero key), and
  // entry 0 is never used: a receiver index of 0 never matches. The firmware's
  // indices carry their entry (1 to 63) in the low bits, so are never 0
  assign rcv_rsp = '{
          idx: dpe_peer_idx_t'(rcv_e),
          match: (dp_rd[CK_LOCAL_ID] == rcv) & (rcv != '0)
      };

endmodule

// -----------------------------------------------------------------------------
// Project:     WireGuard-FPGA
// Description: NLnet-funded open-source implementation
// Funding:     https://nlnet.nl/project/KlusterLab-Wireguard (2023-12 to 2025-12)
// -----------------------------------------------------------------------------
