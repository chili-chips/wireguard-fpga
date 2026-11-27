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
//     (wg_peer_cfg_t) is valid from the 2nd clock after enc_req.idx, and it
//     writes send_cnt back (enc_req.update_send_cnt, for entry enc_req.idx)
//   - the decryptor: decrypt_key, in dec_peer.key (the rest of dec_peer is
//     0), valid from the 2nd clock after dec_req.idx
//   - the disassembler: local_id, combinationally: rcv_rsp.idx is the receiver
//     index's low 6 bits (the entry), rcv_rsp.match whether that entry's
//     local_id is the whole receiver index (never for index 0)
//  The CPU writes every word, byte by byte (byte enables), and reads it back
//  one clock after its request. The send_cnt write-back goes in at once; a
//  CPU send_cnt write in its clock is posted to the next (and wins on the
//  same entry). CPU requests are clocks apart, so a posted write never
//  meets the next one.
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
    input  peer_req_t    dec_req,
    output wg_peer_cfg_t dec_peer,

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
  logic        [3:0] NC_idx_hi;
  wg_counter_t       NC_dec_cnt;  // the decryptor writes no counter back
  logic  NC_dec_upd;
  assign enc_e      = enc_req.idx[CK_ENTRY_W-1:0];
  assign dec_e      = dec_req.idx[CK_ENTRY_W-1:0];
  assign rcv_e      = rcv[CK_ENTRY_W-1:0];
  assign NC_idx_hi  = {enc_req.idx[7:CK_ENTRY_W], dec_req.idx[7:CK_ENTRY_W]};
  assign NC_dec_cnt = dec_req.new_send_cnt;
  assign NC_dec_upd = dec_req.update_send_cnt;

  word_t dp_rd[CK_WORDS];  // each word at its reader's entry
  word_t cpu_rd[CK_WORDS];  // each word at the CPU's entry

  // Each word has one write port. The encryptor's send_cnt write-back always
  // goes in at once, so the next packet to that peer reads the new count (a
  // stale or lost count would reuse a nonce). A CPU write to a send_cnt word
  // in the same clock is posted: acknowledged at once, written in the next
  // clock (the write-back pulses once a packet), so it lands after the
  // write-back and wins on the same entry.
  logic cpu_cnt_wr;  // the CPU writes a send_cnt word
  assign cpu_cnt_wr = csr_wr &
      ((csr_word == CK_WORD_W'(CK_SEND_CNT_HI)) | (csr_word == CK_WORD_W'(CK_SEND_CNT_LO)));

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
      pw_valid <= cpu_cnt_wr & enc_req.update_send_cnt;
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
      assign dp_we    = enc_req.update_send_cnt;
      assign dp_wdata = enc_req.new_send_cnt[63:32];
    end
    else if (w == int'(CK_SEND_CNT_LO)) begin : g_cnt_lo
      assign dp_we    = enc_req.update_send_cnt;
      assign dp_wdata = enc_req.new_send_cnt[31:0];
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
        if (dp_we) begin
          mem[enc_e] <= dp_wdata[8*b+:8];
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
