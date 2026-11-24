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
//     go in as zero; frame beats past the last block are dropped. A frame
//     whose IPv4 total length is under 20, or too long for the core once
//     padded (AEAD_MAX_PT_BYTES or more), is dropped whole, nothing out.
//   - emit: 3 header beats (from when the IPv4 length is in), then the
//     header tail (10 bytes) with the ciphertext's first 6 bytes, then the
//     ciphertext and tag shifted by 6.
//   Every beat moves on its own handshake, so stalls on either side
//   change only the timing.
//
//   The peer table answers a synchronous read: peer_rsp is valid from the
//   2nd clock after peer_req.idx.
//==========================================================================

module dpe_wg_encryptor
  import dpe_pkg::*;
  import net_pkg::*;
(
    dpe_if.s_axis        inp,
    dpe_if.m_axis        outp,

    output logic         idle,

    // the peer table: the packet's peer, from the 2nd clock after the request
    output peer_req_t    peer_req,
    input  wg_peer_cfg_t peer_rsp
);

  typedef enum logic [2:0] {
    IDLE,      // wait for a frame; a bypass frame passes at once
    PASS,      // the rest of a bypass frame
    PEER_REQ,  // peer_req.idx is out
    PEER_RSP,  // peer_rsp is valid: take it
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

  // the registers: r, and r_next, what they hold in the next clock
  typedef struct packed {
    state_t             state;            // [808:806]
    feed_t              feed;             // [805:804]
    emit_t              emit;             // [803:801]
    dpe_addr_t          tuser_dst;        // [800:798]
    dpe_addr_t          tuser_src;        // [797:795]
    dpe_peer_idx_t      peer_idx;         // [794:787]
    wg_peer_cfg_t       peer_cfg;         // [786:243] the packet's peer, from the peer table
    wg_counter_t        new_send_cnt;     // [242:179]
    logic               update_send_cnt;  // [178]
    logic [CARRY_W-1:0] carry;            // [177:162] the frame beat before: its last bytes
    logic               in_done;          // [161]   the frame's last beat is in
    logic               have_len;         // [160]   ip_len holds the IPv4 total length
    len16_t             ip_len;           // [159:144]
    len16_t             fed;              // [143:128] IPv4 bytes into the core so far
    beat_t              held;             // [127:0] the core beat out before this one
  } regs_t;
  regs_t r, r_next;

  // The headers of the outgoing frame. The routing table holds MAC, IP and
  // UDP port in bus byte order (wire byte 0 in [7:0]): bswap*() gives their
  // natural values
  wg_frame_bytes_t hdr;
  assign hdr = wg_frame_bytes(
      '{
          eth: '{
              dst: bswap48(r.peer_cfg.remote_mac),
              src: bswap48(r.peer_cfg.local_mac),
              ethertype: ETHERTYPE_IPV4
          },
          ipv4: '{
              version: IPV4_VERSION,
              ihl: IPV4_IHL,
              dscp_ecn: '0,
              total_len: wg_padded_len(r.ip_len) + WG_IPV4_OVERHEAD,
              id: '0,
              flags_frag: '0,
              ttl: IPV4_TTL,
              proto: IP_PROTO_UDP,
              checksum: '0,
              src: bswap32(r.peer_cfg.local_ip),
              dst: bswap32(r.peer_cfg.remote_ip)
          },
          udp: '{
              src_port: bswap16(r.peer_cfg.local_port),
              dst_port: bswap16(r.peer_cfg.remote_port),
              len: wg_padded_len(r.ip_len) + WG_UDP_OVERHEAD,
              checksum: '0
          },
          wg: '{
              msg_type: WG_TYPE_DATA,
              receiver: r.peer_cfg.remote_id,
              counter: r.peer_cfg.send_cnt
          }
      }
  );

  // the headers' last WG_HDR_TAIL_BYTES bytes, in bus order: the low bytes of the
  // last header beat
  typedef logic [8*WG_HDR_TAIL_BYTES-1:0] hdr_tail_t;
  hdr_tail_t hdr_tail;
  assign hdr_tail = hdr_tail_t'(hdr_beat(hdr, WG_FRAME_HDR_LEN / BEAT_BYTES));

  dpe_tuser_t tuser_out;
  assign tuser_out = '{
          bypass_all: 1'b0,
          bypass_stage: 1'b0,
          src: r.tuser_src,
          dst: r.tuser_dst
      };

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
  assign ip_len_now = r.have_len ? r.ip_len : r.in_done ? '0 : be16(
      piped.tdata, IPV4_TOTAL_LEN_OFFSET
  );

  len16_t ip_padded;  // the bytes into the core
  assign ip_padded = wg_padded_len(ip_len_now);

  // FSM registers
  always_ff @(posedge inp.clk) begin
    if (inp.rst) begin
      r.state           <= IDLE;
      r.feed            <= FEED_ETH;
      r.emit            <= EMIT_HDR_0;
      r.tuser_dst       <= DPE_ADDR_CPU;
      r.tuser_src       <= DPE_ADDR_CPU;
      r.peer_idx        <= '0;
      r.peer_cfg        <= '0;
      r.new_send_cnt    <= '0;
      r.update_send_cnt <= 1'b0;
      r.carry           <= '0;
      r.in_done         <= 1'b0;
      r.have_len        <= 1'b0;
      r.ip_len          <= '0;
      r.fed             <= '0;
      r.held            <= '0;
    end
    else begin
      r <= r_next;
    end
  end

  // The FSMs: next state and the handshake signals
  always_comb begin
    r_next                 = r;
    r_next.update_send_cnt = 1'b0;

    piped.tready           = 1'b0;

    to_encrypt.tvalid      = 1'b0;
    to_encrypt.tdata       = '0;
    to_encrypt.tkeep       = '1;
    to_encrypt.tlast       = 1'b0;
    to_encrypt.tuser       = '0;
    to_encrypt.tid         = '0;

    from_encrypt.tready    = 1'b0;

    muxed.tvalid           = 1'b0;
    muxed.tdata            = '0;
    muxed.tkeep            = '1;
    muxed.tlast            = 1'b0;
    muxed.tuser            = tuser_out;
    muxed.tid              = r.peer_idx;

    unique case (r.state)
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
              r_next.state = PASS;
            end
          end
          else begin
            // the frame stays in piped until feed takes it
            r_next.tuser_dst = piped.tuser.dst;
            r_next.tuser_src = piped.tuser.src;
            r_next.peer_idx  = piped.tid;
            r_next.state     = PEER_REQ;
          end
        end
      end

      PASS: begin
        muxed.tvalid = piped.tvalid;
        muxed.tdata  = piped.tdata;
        muxed.tkeep  = piped.tkeep;
        muxed.tlast  = piped.tlast;
        muxed.tuser  = piped.tuser;
        muxed.tid    = piped.tid;
        piped.tready = muxed.tready;
        if (piped_hs && piped.tlast) begin
          r_next.state = IDLE;
        end
      end

      PEER_REQ: r_next.state = PEER_RSP;

      PEER_RSP: begin
        r_next.peer_cfg = peer_rsp;
        r_next.feed     = FEED_ETH;
        r_next.emit     = EMIT_HDR_0;
        r_next.in_done  = 1'b0;
        r_next.have_len = 1'b0;
        r_next.fed      = '0;
        r_next.state    = PACKET;
      end

      PACKET: begin
        // feed: frame beats into the core
        unique case (r.feed)
          FEED_ETH: begin
            piped.tready = 1'b1;
            if (piped_hs) begin
              r_next.carry   = piped.tdata[DPE_DATA_W-1-:CARRY_W];
              r_next.in_done = piped.tlast;
              r_next.feed    = FEED_DATA;
            end
          end

          FEED_DATA: begin
            if (~r.have_len & (r.in_done | piped.tvalid) &
                ((ip_len_now < len16_t'(IPV4_HDR_LEN)) | (ip_len_now >= AEAD_MAX_PT_BYTES))) begin
              // implausible, or more than the core takes: drop it, nothing out
              // (emit has sent nothing yet: it waits for the length)
              r_next.emit = EMIT_DONE;
              r_next.feed = r.in_done ? FEED_DONE : FEED_DRAIN;
            end
            else begin
              // the IPv4 packet's next 16 bytes; past its end, zeros
              to_encrypt.tvalid = r.in_done | piped.tvalid;
              to_encrypt.tdata = keep_bytes(
                r.in_done ? beat_t'(r.carry) : {piped.tdata[DPE_DATA_W-CARRY_W-1:0], r.carry},
                keep_first(
                  ip_len_now - r.fed)
              );
              to_encrypt.tlast = (r.fed + len16_t'(BEAT_BYTES)) >= ip_padded;
              piped.tready = ~r.in_done & to_encrypt.tready;
              if (enc_in_hs) begin
                r_next.fed      = r.fed + len16_t'(BEAT_BYTES);
                r_next.ip_len   = ip_len_now;
                r_next.have_len = 1'b1;
                r_next.carry    = r.in_done ? '0 : piped.tdata[DPE_DATA_W-1-:CARRY_W];
                r_next.in_done  = r.in_done | piped.tlast;
                if (to_encrypt.tlast) begin
                  r_next.feed = r_next.in_done ? FEED_DONE : FEED_DRAIN;
                end
              end
            end
          end

          FEED_DRAIN: begin
            piped.tready = 1'b1;
            if (piped_hs && piped.tlast) begin
              r_next.feed = FEED_DONE;
            end
          end

          default: ;  // FEED_DONE
        endcase

        // emit: the headers, then the core's beats
        unique case (r.emit)
          EMIT_HDR_0: begin
            muxed.tvalid = r.have_len;  // not before the frame is known good
            muxed.tdata  = hdr_beat(hdr, 0);
            if (muxed_hs) begin
              r_next.emit = EMIT_HDR_1;
            end
          end

          EMIT_HDR_1: begin
            muxed.tvalid = r.have_len;
            muxed.tdata  = hdr_beat(hdr, 1);
            if (muxed_hs) begin
              r_next.emit = EMIT_HDR_2;
            end
          end

          EMIT_HDR_2: begin
            muxed.tvalid = 1'b1;
            muxed.tdata  = hdr_beat(hdr, 2);
            if (muxed_hs) begin
              r_next.emit = EMIT_TAIL;
            end
          end

          EMIT_TAIL, EMIT_BODY: begin
            muxed.tvalid = from_encrypt.tvalid;
            muxed.tdata = {
              from_encrypt.tdata[PAYLOAD_HEAD_W-1:0],
              (r.emit == EMIT_TAIL) ? hdr_tail : r.held[DPE_DATA_W-1:PAYLOAD_HEAD_W]
            };
            from_encrypt.tready = muxed.tready;
            if (enc_out_hs) begin
              r_next.held = from_encrypt.tdata;
              r_next.emit = from_encrypt.tlast ? EMIT_LAST : EMIT_BODY;
            end
          end

          EMIT_LAST: begin
            muxed.tvalid = 1'b1;
            muxed.tdata  = beat_t'(r.held[DPE_DATA_W-1:PAYLOAD_HEAD_W]);
            muxed.tkeep  = keep_first(len16_t'(WG_HDR_TAIL_BYTES));
            muxed.tlast  = 1'b1;
            if (muxed_hs) begin
              r_next.new_send_cnt    = r.peer_cfg.send_cnt + 1;
              r_next.update_send_cnt = 1'b1;
              r_next.emit            = EMIT_DONE;
            end
          end

          default: ;  // EMIT_DONE
        endcase

        if (r.feed == FEED_DONE && r.emit == EMIT_DONE) begin
          r_next.state = IDLE;
        end
      end

      default: r_next.state = IDLE;
    endcase
  end

  assign idle = (r.state == IDLE) & ~piped.tvalid & ~outp.tvalid;
  assign peer_req = '{
          idx: r.peer_idx,
          new_send_cnt: r.new_send_cnt,
          update_send_cnt: r.update_send_cnt
      };

  // Encryptor core. The nonce: 4 zero bytes, then the counter
  // (little-endian; byte 0 in [7:0])
  chacha20poly1305_encrypt u_chacha20poly1305_encrypt (
      .clk_80p0              (inp.clk),
      .encrypt_key           (r.peer_cfg.key),
      .encrypt_nonce         ({r.peer_cfg.send_cnt, 32'd0}),
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
