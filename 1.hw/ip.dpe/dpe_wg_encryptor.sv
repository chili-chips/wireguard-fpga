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
//   DPE WireGuard Encryptor. In: an Ethernet frame that carries an IPv4
//   packet, tid = its peer. Out: the WireGuard transport-data frame to that
//   peer: Ethernet, IPv4, UDP and WireGuard headers (58 bytes), then the
//   IPv4 packet, zero-padded to 16-byte blocks and ChaCha20-Poly1305
//   encrypted, then its 16-byte tag.
//
//   One packet at a time: the core's key and nonce stay put until the
//   packet's tag has left. Inside a packet, two FSMs run side by side:
//   - feed: frame beats into the core. A core beat is the IPv4 packet's
//     next 16 bytes: 2 from the frame beat before, 14 from this one
//     (the Ethernet header is 14 bytes). Bytes past the IPv4 total length
//     go in as zero; frame beats past the last block are dropped.
//   - emit: 3 header beats, then the header tail (10 bytes) with the
//     ciphertext's first 6 bytes, then the ciphertext and tag shifted by 6.
//   Every beat moves on its own handshake, so stalls on either side
//   change only the timing.
//
//   The peer table answers a synchronous read: ram_peer is valid from the
//   2nd clock after ram_peer_idx.
//==========================================================================

module dpe_wg_encryptor
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

  typedef enum logic [1:0] {
    FEED_ETH,    // frame beat 0: keep its last 2 bytes (IPv4 bytes 0, 1)
    FEED_DATA,   // one core beat per frame beat, then zero-padding beats
    FEED_DRAIN,  // frame beats past the last block
    FEED_DONE
  } feed_t;

  typedef enum logic [2:0] {
    EMIT_HDR_0,
    EMIT_HDR_1,  // needs the IPv4 length: from the first core beat on
    EMIT_HDR_2,
    EMIT_TAIL,   // header tail, then the ciphertext's first bytes
    EMIT_BODY,   // the ciphertext and the tag, shifted by 6 bytes
    EMIT_LAST,   // the tag's last 10 bytes
    EMIT_DONE
  } emit_t;

  // The last header beat holds the headers' last WG_HDR_TAIL_BYTES bytes,
  // then the first bytes of the encrypted payload
  localparam int PAYLOAD_HEAD_W = 8 * (BEAT_BYTES - WG_HDR_TAIL_BYTES);  // 48
  // a core beat takes this many bytes from the frame beat before
  localparam int CARRY_BYTES    = BEAT_BYTES - ETH_HDR_LEN;              // 2
  localparam int CARRY_W        = 8 * CARRY_BYTES;

  state_t state, state_next;
  feed_t feed, feed_next;
  emit_t emit, emit_next;
  dpe_addr_t tuser_dst, tuser_dst_next;
  dpe_addr_t tuser_src, tuser_src_next;
  dpe_peer_idx_t peer_idx, peer_idx_next;
  wg_peer_cfg_t peer, peer_next;  // the packet's peer, from the routing table
  wg_counter_t new_send_cnt, new_send_cnt_next;
  logic update_send_cnt, update_send_cnt_next;
  logic [CARRY_W-1:0] carry, carry_next;  // the frame beat before: its last bytes
  logic in_done, in_done_next;  // the frame's last beat is in
  logic have_len, have_len_next;  // ip_len holds the IPv4 total length
  len16_t ip_len, ip_len_next;
  len16_t fed, fed_next;  // IPv4 bytes into the core so far
  beat_t held, held_next;  // the core beat out before this one

  // The headers of the outgoing frame. The routing table holds MAC, IP and
  // UDP port in bus byte order (wire byte 0 in [7:0]): bswap*() gives their
  // natural values
  wg_frame_bytes_t hdr;
  assign hdr = wg_frame_bytes(
      '{
          eth: '{
              dst: bswap48(peer.remote_mac),
              src: bswap48(peer.local_mac),
              ethertype: ETHERTYPE_IPV4
          },
          ipv4: '{
              version: IPV4_VERSION,
              ihl: IPV4_IHL,
              dscp_ecn: '0,
              total_len: wg_padded_len(ip_len) + WG_IPV4_OVERHEAD,
              id: '0,
              flags_frag: '0,
              ttl: IPV4_TTL,
              proto: IP_PROTO_UDP,
              checksum: '0,
              src: bswap32(peer.local_ip),
              dst: bswap32(peer.remote_ip)
          },
          udp: '{
              src_port: bswap16(peer.local_port),
              dst_port: bswap16(peer.remote_port),
              len: wg_padded_len(ip_len) + WG_UDP_OVERHEAD,
              checksum: '0
          },
          wg: '{msg_type: WG_TYPE_DATA, receiver: peer.remote_id, counter: peer.send_cnt}
      }
  );

  // the headers' last WG_HDR_TAIL_BYTES bytes, in bus order: the low bytes of the
  // last header beat
  typedef logic [8*WG_HDR_TAIL_BYTES-1:0] hdr_tail_t;
  hdr_tail_t hdr_tail;
  assign hdr_tail = hdr_tail_t'(hdr_beat(hdr, WG_FRAME_HDR_LEN / BEAT_BYTES));

  dpe_tuser_t tuser_out;
  assign tuser_out = '{bypass_all: 1'b0, bypass_stage: 1'b0, src: tuser_src, dst: tuser_dst};

  // Internal signals
  dpe_if to_encrypt (
      .clk (inp.clk),
      .rst (inp.rst)
  );
  dpe_if from_encrypt (
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

  logic  piped_hs, enc_in_hs, enc_out_hs, muxed_hs;
  assign piped_hs   = piped.tvalid & piped.tready;
  assign enc_in_hs  = to_encrypt.tvalid & to_encrypt.tready;
  assign enc_out_hs = from_encrypt.tvalid & from_encrypt.tready;
  assign muxed_hs   = muxed.tvalid & muxed.tready;

  // the IPv4 total length, as soon as the frame beat with it is here (an
  // implausible frame of 16 bytes or less: 0)
  len16_t ip_len_now;
  assign ip_len_now = have_len ? ip_len : in_done ? '0 : be16(piped.tdata, IPV4_TOTAL_LEN_OFFSET);

  len16_t ip_padded;  // the bytes into the core
  assign ip_padded = wg_padded_len(ip_len_now);

  // FSM registers
  always_ff @(posedge inp.clk) begin
    if (inp.rst) begin
      state           <= IDLE;
      feed            <= FEED_ETH;
      emit            <= EMIT_HDR_0;
      tuser_dst       <= DPE_ADDR_CPU;
      tuser_src       <= DPE_ADDR_CPU;
      peer_idx        <= '0;
      peer            <= '0;
      new_send_cnt    <= '0;
      update_send_cnt <= 1'b0;
      carry           <= '0;
      in_done         <= 1'b0;
      have_len        <= 1'b0;
      ip_len          <= '0;
      fed             <= '0;
      held            <= '0;
    end
    else begin
      state           <= state_next;
      feed            <= feed_next;
      emit            <= emit_next;
      tuser_dst       <= tuser_dst_next;
      tuser_src       <= tuser_src_next;
      peer_idx        <= peer_idx_next;
      peer            <= peer_next;
      new_send_cnt    <= new_send_cnt_next;
      update_send_cnt <= update_send_cnt_next;
      carry           <= carry_next;
      in_done         <= in_done_next;
      have_len        <= have_len_next;
      ip_len          <= ip_len_next;
      fed             <= fed_next;
      held            <= held_next;
    end
  end

  // The FSMs: next state and the handshake signals
  always_comb begin
    state_next           = state;
    feed_next            = feed;
    emit_next            = emit;
    tuser_dst_next       = tuser_dst;
    tuser_src_next       = tuser_src;
    peer_idx_next        = peer_idx;
    peer_next            = peer;
    new_send_cnt_next    = new_send_cnt;
    update_send_cnt_next = 1'b0;
    carry_next           = carry;
    in_done_next         = in_done;
    have_len_next        = have_len;
    ip_len_next          = ip_len;
    fed_next             = fed;
    held_next            = held;

    piped.tready         = 1'b0;

    to_encrypt.tvalid    = 1'b0;
    to_encrypt.tdata     = '0;
    to_encrypt.tkeep     = '1;
    to_encrypt.tlast     = 1'b0;
    to_encrypt.tuser     = '0;
    to_encrypt.tid       = '0;

    from_encrypt.tready  = 1'b0;

    muxed.tvalid         = 1'b0;
    muxed.tdata          = '0;
    muxed.tkeep          = '1;
    muxed.tlast          = 1'b0;
    muxed.tuser          = tuser_out;
    muxed.tid            = peer_idx;

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
        peer_next     = ram_peer;
        feed_next     = FEED_ETH;
        emit_next     = EMIT_HDR_0;
        in_done_next  = 1'b0;
        have_len_next = 1'b0;
        fed_next      = '0;
        state_next    = PACKET;
      end

      PACKET: begin
        // feed: frame beats into the core
        unique case (feed)
          FEED_ETH: begin
            piped.tready = 1'b1;
            if (piped_hs) begin
              carry_next   = piped.tdata[DPE_DATA_W-1-:CARRY_W];
              in_done_next = piped.tlast;
              feed_next    = FEED_DATA;
            end
          end

          FEED_DATA: begin
            // the IPv4 packet's next 16 bytes; past its end, zeros
            to_encrypt.tvalid = in_done | piped.tvalid;
            to_encrypt.tdata = keep_bytes(
              in_done ? beat_t'(carry) : {piped.tdata[DPE_DATA_W-CARRY_W-1:0], carry},
              keep_first(
                ip_len_now - fed)
            );
            to_encrypt.tlast = (fed + len16_t'(BEAT_BYTES)) >= ip_padded;
            piped.tready = ~in_done & to_encrypt.tready;
            if (enc_in_hs) begin
              fed_next      = fed + len16_t'(BEAT_BYTES);
              ip_len_next   = ip_len_now;
              have_len_next = 1'b1;
              carry_next    = in_done ? '0 : piped.tdata[DPE_DATA_W-1-:CARRY_W];
              in_done_next  = in_done | piped.tlast;
              if (to_encrypt.tlast) begin
                feed_next = in_done_next ? FEED_DONE : FEED_DRAIN;
              end
            end
          end

          FEED_DRAIN: begin
            piped.tready = 1'b1;
            if (piped_hs && piped.tlast) begin
              feed_next = FEED_DONE;
            end
          end

          default: ;  // FEED_DONE
        endcase

        // emit: the headers, then the core's beats
        unique case (emit)
          EMIT_HDR_0: begin
            muxed.tvalid = 1'b1;
            muxed.tdata  = hdr_beat(hdr, 0);
            if (muxed_hs) begin
              emit_next = EMIT_HDR_1;
            end
          end

          EMIT_HDR_1: begin
            muxed.tvalid = have_len;
            muxed.tdata  = hdr_beat(hdr, 1);
            if (muxed_hs) begin
              emit_next = EMIT_HDR_2;
            end
          end

          EMIT_HDR_2: begin
            muxed.tvalid = 1'b1;
            muxed.tdata  = hdr_beat(hdr, 2);
            if (muxed_hs) begin
              emit_next = EMIT_TAIL;
            end
          end

          EMIT_TAIL, EMIT_BODY: begin
            muxed.tvalid = from_encrypt.tvalid;
            muxed.tdata = {
              from_encrypt.tdata[PAYLOAD_HEAD_W-1:0],
              (emit == EMIT_TAIL) ? hdr_tail : held[DPE_DATA_W-1:PAYLOAD_HEAD_W]
            };
            from_encrypt.tready = muxed.tready;
            if (enc_out_hs) begin
              held_next = from_encrypt.tdata;
              emit_next = from_encrypt.tlast ? EMIT_LAST : EMIT_BODY;
            end
          end

          EMIT_LAST: begin
            muxed.tvalid = 1'b1;
            muxed.tdata  = beat_t'(held[DPE_DATA_W-1:PAYLOAD_HEAD_W]);
            muxed.tkeep  = keep_first(len16_t'(WG_HDR_TAIL_BYTES));
            muxed.tlast  = 1'b1;
            if (muxed_hs) begin
              new_send_cnt_next    = peer.send_cnt + 1;
              update_send_cnt_next = 1'b1;
              emit_next            = EMIT_DONE;
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
  assign ram_new_send_cnt    = new_send_cnt;
  assign ram_update_send_cnt = update_send_cnt;

  // Encryptor core. The nonce: 4 zero bytes, then the counter
  // (little-endian; byte 0 in [7:0])
  chacha20poly1305_encrypt u_chacha20poly1305_encrypt (
      .clk_80p0              (inp.clk),
      .encrypt_key           (peer.key),
      .encrypt_nonce         ({peer.send_cnt, 32'd0}),
      .encrypt_aad           (256'd0),
      .encrypt_aad_len       (8'd0),
      .encrypt_s_axis_tdata  (to_encrypt.tdata),
      .encrypt_s_axis_tkeep  (to_encrypt.tkeep),
      .encrypt_s_axis_tlast  (to_encrypt.tlast),
      .encrypt_s_axis_tvalid (to_encrypt.tvalid),
      .encrypt_m_axis_tready (from_encrypt.tready),
      .encrypt_s_axis_tready (to_encrypt.tready),
      .encrypt_m_axis_tdata  (from_encrypt.tdata),
      .encrypt_m_axis_tkeep  (from_encrypt.tkeep),
      .encrypt_m_axis_tlast  (from_encrypt.tlast),
      .encrypt_m_axis_tvalid (from_encrypt.tvalid)
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

// -----------------------------------------------------------------------------
// Project:     WireGuard-FPGA
// Description: NLnet-funded open-source implementation
// Funding:     https://nlnet.nl/project/KlusterLab-Wireguard (2023-12 to 2025-12)
// -----------------------------------------------------------------------------
