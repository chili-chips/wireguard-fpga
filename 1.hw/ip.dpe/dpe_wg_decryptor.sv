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
//   DPE WireGuard Decryptor. In: a WireGuard transport-data frame
//   (Ethernet, IPv4, UDP, WireGuard headers: 58 bytes, then the encrypted
//   IPv4 packet in 16-byte blocks, then its 16-byte tag), tid = its peer.
//   Out: the outer Ethernet header, then the decrypted IPv4 packet, cut to
//   its own total length. A frame whose tag does not check out (or too
//   short to hold one block and a tag, or with an implausible IPv4 length
//   inside) is dropped whole: the core holds the plaintext until its tag is
//   checked (wait_to_verify), then flags it with decrypt_m_verified.
//
//   One packet at a time: the core's key and nonce stay put until the
//   packet's plaintext has left. Inside a packet, two FSMs run side by side:
//   - feed: frame beats into the core. The headers end 10 bytes into frame
//     beat 3, so a core beat is 6 bytes of one frame beat and 10 of the
//     next; the nonce counter comes from the WireGuard header (beat 3).
//   - emit: the outer Ethernet header (14 bytes) with the plaintext's first
//     2 bytes, then the plaintext shifted by 2, up to the IPv4 total length;
//     the zero padding and anything after is dropped.
//   Every beat moves on its own handshake, so stalls on either side change
//   only the timing.
//
//   The peer table answers a synchronous read: ram_peer is valid from the
//   2nd clock after ram_peer_idx. The receiver does not advance the send
//   counter; ram_new_send_cnt and ram_update_send_cnt stay 0.
//   TODO: the receive key (wg_peer_cfg_t has one key for both directions),
//   the replay window on the counter.
//==========================================================================

module dpe_wg_decryptor
  import dpe_pkg::*;
  import net_pkg::*;
(
    dpe_if.s_axis         inp,
    dpe_if.m_axis         outp,

    output logic          fcr_idle,

    output dpe_peer_idx_t ram_peer_idx,
    input  wg_peer_cfg_t  ram_peer,
    output wg_counter_t   ram_new_send_cnt,
    output logic          ram_update_send_cnt
);

  typedef enum logic [2:0] {
    IDLE,      // wait for a frame; a bypass frame passes at once
    BYPASS,    // the rest of a bypass frame
    RAM_ADDR,  // ram_peer_idx is out
    RAM_DATA,  // ram_peer is valid: take it
    PACKET     // feed and emit run
  } state_t;

  typedef enum logic [2:0] {
    FEED_HDR,   // frame beats 0 to 2: headers only (keep the Ethernet one)
    FEED_WG,    // frame beat 3: the counter, then the first 6 payload bytes
    FEED_DATA,  // one core beat per frame beat
    FEED_TAIL,  // the frame's last 6 bytes, when its last beat had more than 10
    FEED_DONE
  } feed_t;

  typedef enum logic [2:0] {
    EMIT_FIRST,  // Ethernet header and plaintext bytes 0, 1; or drop it all
    EMIT_BODY,   // the plaintext, shifted by 2
    EMIT_DROP,   // the rest of the core's beats: padding, or a bad packet
    EMIT_DONE
  } emit_t;

  // a core beat: the frame beat before's last CARRY_BYTES bytes, then
  // WG_HDR_TAIL_BYTES of this one
  localparam int CARRY_BYTES = BEAT_BYTES - WG_HDR_TAIL_BYTES;  // 6
  localparam int CARRY_W = 8 * CARRY_BYTES;
  localparam int HEAD_W = 8 * WG_HDR_TAIL_BYTES;  // 80
  // the output's first beat: the Ethernet header, then plaintext bytes
  localparam int ETH_W = 8 * ETH_HDR_LEN;  // 112
  localparam int PT_HEAD_W = DPE_DATA_W - ETH_W;  // 16
  localparam int PT_HEAD_BYTES = PT_HEAD_W / 8;  // 2
  localparam int WG_HDR_BEATS = WG_FRAME_HDR_LEN / BEAT_BYTES;  // 3: then the beat with the counter

  state_t state, state_next;
  feed_t feed, feed_next;
  emit_t emit, emit_next;
  dpe_addr_t tuser_dst, tuser_dst_next;
  dpe_addr_t tuser_src, tuser_src_next;
  dpe_peer_idx_t peer_idx, peer_idx_next;
  wg_peer_cfg_t peer, peer_next;  // the packet's peer, from the routing table
  logic [1:0] hdr_k, hdr_k_next;  // header beats in so far
  logic [ETH_W-1:0] eth_hdr, eth_hdr_next;  // the outer Ethernet header
  wg_counter_t wg_cnt, wg_cnt_next;  // the packet's counter: the nonce
  logic [CARRY_W-1:0] carry, carry_next;  // the frame beat before: its last bytes
  len16_t ip_len, ip_len_next;  // the plaintext IPv4 total length
  len16_t sent, sent_next;  // IPv4 bytes out so far
  logic core_done, core_done_next;  // the core's last beat is in
  beat_t held, held_next;  // the plaintext beat before

  dpe_tuser_t tuser_out;
  assign tuser_out = '{bypass_all: 1'b0, bypass_stage: 1'b0, src: tuser_src, dst: tuser_dst};

  // Internal signals
  dpe_if to_decrypt (
      .clk (inp.clk),
      .rst (inp.rst)
  );
  dpe_if from_decrypt (
      .clk (inp.clk),
      .rst (inp.rst)
  );
  dpe_if piped (
      .clk (inp.clk),
      .rst (inp.rst)
  );
  dpe_if muxed (
      .clk (inp.clk),
      .rst (inp.rst)
  );
  logic verified;  // the core's plaintext beats are of a packet whose tag checked out

  logic  piped_hs, dec_in_hs, dec_out_hs, muxed_hs;
  assign piped_hs   = piped.tvalid & piped.tready;
  assign dec_in_hs  = to_decrypt.tvalid & to_decrypt.tready;
  assign dec_out_hs = from_decrypt.tvalid & from_decrypt.tready;
  assign muxed_hs   = muxed.tvalid & muxed.tready;

  // the plaintext's IPv4 total length, in its first beat
  len16_t ip_len_first;
  assign ip_len_first = be16(from_decrypt.tdata, 2);

  len16_t rem;  // IPv4 bytes still to go out
  assign rem = ip_len - sent;

  // FSM registers
  always_ff @(posedge inp.clk) begin
    if (inp.rst) begin
      state     <= IDLE;
      feed      <= FEED_HDR;
      emit      <= EMIT_FIRST;
      tuser_dst <= DPE_ADDR_CPU;
      tuser_src <= DPE_ADDR_CPU;
      peer_idx  <= '0;
      peer      <= '0;
      hdr_k     <= '0;
      eth_hdr   <= '0;
      wg_cnt    <= '0;
      carry     <= '0;
      ip_len    <= '0;
      sent      <= '0;
      core_done <= 1'b0;
      held      <= '0;
    end
    else begin
      state     <= state_next;
      feed      <= feed_next;
      emit      <= emit_next;
      tuser_dst <= tuser_dst_next;
      tuser_src <= tuser_src_next;
      peer_idx  <= peer_idx_next;
      peer      <= peer_next;
      hdr_k     <= hdr_k_next;
      eth_hdr   <= eth_hdr_next;
      wg_cnt    <= wg_cnt_next;
      carry     <= carry_next;
      ip_len    <= ip_len_next;
      sent      <= sent_next;
      core_done <= core_done_next;
      held      <= held_next;
    end
  end

  // The FSMs: next state and the handshake signals
  always_comb begin
    state_next          = state;
    feed_next           = feed;
    emit_next           = emit;
    tuser_dst_next      = tuser_dst;
    tuser_src_next      = tuser_src;
    peer_idx_next       = peer_idx;
    peer_next           = peer;
    hdr_k_next          = hdr_k;
    eth_hdr_next        = eth_hdr;
    wg_cnt_next         = wg_cnt;
    carry_next          = carry;
    ip_len_next         = ip_len;
    sent_next           = sent;
    core_done_next      = core_done;
    held_next           = held;

    piped.tready        = 1'b0;

    to_decrypt.tvalid   = 1'b0;
    to_decrypt.tdata    = '0;
    to_decrypt.tkeep    = '1;
    to_decrypt.tlast    = 1'b0;
    to_decrypt.tuser    = '0;
    to_decrypt.tid      = '0;

    from_decrypt.tready = 1'b0;

    muxed.tvalid        = 1'b0;
    muxed.tdata         = '0;
    muxed.tkeep         = '1;
    muxed.tlast         = 1'b0;
    muxed.tuser         = tuser_out;
    muxed.tid           = peer_idx;

    unique case (state)
      IDLE: begin
        if (piped.tvalid) begin
          if (piped.tuser.bypass_stage || piped.tuser.bypass_all) begin
            muxed.tvalid = 1'b1;
            muxed.tdata  = piped.tdata;
            muxed.tkeep  = piped.tkeep;
            muxed.tlast  = piped.tlast;
            muxed.tuser  = piped.tuser;
            muxed.tid    = piped.tid;
            piped.tready = muxed.tready;
            if (piped_hs && !piped.tlast) begin
              state_next = BYPASS;
            end
          end
          else begin
            // the frame stays in piped until feed takes it
            tuser_dst_next = piped.tuser.dst;
            tuser_src_next = piped.tuser.src;
            peer_idx_next  = piped.tid;
            state_next     = RAM_ADDR;
          end
        end
      end

      BYPASS: begin
        muxed.tvalid = piped.tvalid;
        muxed.tdata  = piped.tdata;
        muxed.tkeep  = piped.tkeep;
        muxed.tlast  = piped.tlast;
        muxed.tuser  = piped.tuser;
        muxed.tid    = piped.tid;
        piped.tready = muxed.tready;
        if (piped_hs && piped.tlast) begin
          state_next = IDLE;
        end
      end

      RAM_ADDR: state_next = RAM_DATA;

      RAM_DATA: begin
        peer_next  = ram_peer;
        feed_next  = FEED_HDR;
        emit_next  = EMIT_FIRST;
        hdr_k_next = '0;
        state_next = PACKET;
      end

      PACKET: begin
        // feed: frame beats into the core
        unique case (feed)
          FEED_HDR: begin
            piped.tready = 1'b1;
            if (piped_hs) begin
              if (hdr_k == 2'd0) begin
                eth_hdr_next = piped.tdata[ETH_W-1:0];
              end
              hdr_k_next = hdr_k + 2'd1;
              if (piped.tlast) begin
                // too short: nothing for the core, nothing out
                feed_next = FEED_DONE;
                emit_next = EMIT_DONE;
              end
              else if (hdr_k == 2'(WG_HDR_BEATS - 1)) begin
                feed_next = FEED_WG;
              end
            end
          end

          FEED_WG: begin
            piped.tready = 1'b1;
            if (piped_hs) begin
              wg_cnt_next = le64(piped.tdata, WG_COUNTER_OFFSET);
              carry_next  = piped.tdata[DPE_DATA_W-1-:CARRY_W];
              if (piped.tlast) begin
                feed_next = FEED_DONE;
                emit_next = EMIT_DONE;
              end
              else begin
                feed_next = FEED_DATA;
              end
            end
          end

          FEED_DATA: begin
            // the frame's next 16 payload bytes
            to_decrypt.tvalid = piped.tvalid;
            to_decrypt.tdata  = {piped.tdata[HEAD_W-1:0], carry};
            to_decrypt.tlast  = piped.tlast & ~piped.tkeep[WG_HDR_TAIL_BYTES];
            piped.tready      = to_decrypt.tready;
            if (dec_in_hs) begin
              carry_next = piped.tdata[DPE_DATA_W-1-:CARRY_W];
              if (piped.tlast) begin
                feed_next = piped.tkeep[WG_HDR_TAIL_BYTES] ? FEED_TAIL : FEED_DONE;
              end
            end
          end

          FEED_TAIL: begin
            to_decrypt.tvalid = 1'b1;
            to_decrypt.tdata  = beat_t'(carry);
            to_decrypt.tlast  = 1'b1;
            if (dec_in_hs) begin
              feed_next = FEED_DONE;
            end
          end

          default: ;  // FEED_DONE
        endcase

        // emit: the plaintext, once the core has checked its tag
        unique case (emit)
          EMIT_FIRST: begin
            if (!verified || ip_len_first < len16_t'(IPV4_HDR_LEN)) begin
              from_decrypt.tready = 1'b1;
              if (dec_out_hs) begin
                emit_next = from_decrypt.tlast ? EMIT_DONE : EMIT_DROP;
              end
            end
            else begin
              muxed.tvalid        = from_decrypt.tvalid;
              muxed.tdata         = {from_decrypt.tdata[PT_HEAD_W-1:0], eth_hdr};
              from_decrypt.tready = muxed.tready;
              if (dec_out_hs) begin
                held_next      = from_decrypt.tdata;
                ip_len_next    = ip_len_first;
                sent_next      = len16_t'(PT_HEAD_BYTES);
                core_done_next = from_decrypt.tlast;
                emit_next      = EMIT_BODY;
              end
            end
          end

          EMIT_BODY: begin
            if (rem <= len16_t'(BEAT_BYTES - PT_HEAD_BYTES) || core_done) begin
              // the rest is in held (or the core has no more: cut there)
              muxed.tvalid = 1'b1;
              muxed.tdata  = beat_t'(held[DPE_DATA_W-1:PT_HEAD_W]);
              muxed.tkeep  = keep_first(rem) & keep_first(len16_t'(BEAT_BYTES - PT_HEAD_BYTES));
              muxed.tlast  = 1'b1;
              if (muxed_hs) begin
                emit_next = core_done ? EMIT_DONE : EMIT_DROP;
              end
            end
            else begin
              muxed.tvalid = from_decrypt.tvalid;
              muxed.tdata = {from_decrypt.tdata[PT_HEAD_W-1:0], held[DPE_DATA_W-1:PT_HEAD_W]};
              muxed.tkeep = keep_first(rem);
              muxed.tlast = rem <= len16_t'(BEAT_BYTES);
              from_decrypt.tready = muxed.tready;
              if (dec_out_hs) begin
                held_next      = from_decrypt.tdata;
                sent_next      = sent + len16_t'(BEAT_BYTES);
                core_done_next = from_decrypt.tlast;
                if (muxed.tlast) begin
                  emit_next = from_decrypt.tlast ? EMIT_DONE : EMIT_DROP;
                end
              end
            end
          end

          EMIT_DROP: begin
            from_decrypt.tready = 1'b1;
            if (dec_out_hs && from_decrypt.tlast) begin
              emit_next = EMIT_DONE;
            end
          end

          default: ;  // EMIT_DONE
        endcase

        if (feed == FEED_DONE && emit == EMIT_DONE) begin
          state_next = IDLE;
        end
      end

      default: state_next = IDLE;
    endcase
  end

  assign fcr_idle            = (state == IDLE) & ~outp.tvalid;
  assign ram_peer_idx        = peer_idx;
  assign ram_new_send_cnt    = '0;
  assign ram_update_send_cnt = 1'b0;

  // Decryptor core. The nonce: 4 zero bytes, then the counter
  // (little-endian; byte 0 in [7:0])
  chacha20poly1305_decrypt u_chacha20poly1305_decrypt (
      .clk_80p0              (inp.clk),
      .decrypt_key           (peer.key),
      .decrypt_nonce         ({wg_cnt, 32'd0}),
      .decrypt_aad           (256'd0),
      .decrypt_aad_len       (8'd0),
      .decrypt_s_axis_tdata  (to_decrypt.tdata),
      .decrypt_s_axis_tkeep  (to_decrypt.tkeep),
      .decrypt_s_axis_tlast  (to_decrypt.tlast),
      .decrypt_s_axis_tvalid (to_decrypt.tvalid),
      .decrypt_m_axis_tready (from_decrypt.tready),
      .decrypt_s_axis_tready (to_decrypt.tready),
      .decrypt_m_axis_tdata  (from_decrypt.tdata),
      .decrypt_m_axis_tkeep  (from_decrypt.tkeep),
      .decrypt_m_axis_tlast  (from_decrypt.tlast),
      .decrypt_m_axis_tvalid (from_decrypt.tvalid),
      .decrypt_m_verified    (verified)
  );

  // Input pipeline
  dpe_if_pipeline #(
      .LENGTH (1)
  ) u_dpe_if_pipeline_input (
      .inp  (inp),
      .outp (piped)
  );

  // Output skid buffer
  dpe_if_skid_buffer u_dpe_if_skid_buffer_output (
      .inp  (muxed),
      .outp (outp)
  );
endmodule
