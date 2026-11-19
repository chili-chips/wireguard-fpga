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
//   its own total length. Dropped whole:
//   - a frame whose tag does not check out: the core holds the plaintext
//     until its tag is checked (wait_to_verify), then flags it with
//     decrypt_m_verified;
//   - one too short to hold a block and a tag, a WireGuard keepalive (an
//     empty payload: the tag alone) among them: the core would give no
//     plaintext for it, so it never reaches the core;
//   - one whose outer IPv4 length says more than the core takes
//     (AEAD_MAX_PT_BYTES of plaintext): skipped before the core;
//   - one whose plaintext IPv4 length is under 20, or over the plaintext.
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
//   The peer table answers a synchronous read: peer_rsp is valid from the
//   2nd clock after peer_req.idx. The receiver does not advance the send
//   counter; peer_req.new_send_cnt and update_send_cnt stay 0.
//   TODO: the replay window on the counter (#4).
//==========================================================================

module dpe_wg_decryptor
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

  typedef enum logic [2:0] {
    FEED_HDR,   // frame beats 0 to 2: headers only (keep the Ethernet one)
    FEED_WG,    // frame beat 3: the counter, then the first 6 payload bytes
    FEED_DATA,  // one core beat per frame beat
    FEED_TAIL,  // the frame's last 6 bytes, when its last beat had more than 10
    FEED_SKIP,  // the rest of a frame too long for the core: not fed
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
  localparam int     CARRY_BYTES   = BEAT_BYTES - WG_HDR_TAIL_BYTES;        // 6
  localparam int     CARRY_W       = 8 * CARRY_BYTES;
  localparam int     HEAD_W        = 8 * WG_HDR_TAIL_BYTES;                 // 80
  // the output's first beat: the Ethernet header, then plaintext bytes
  localparam int     ETH_W         = 8 * ETH_HDR_LEN;                       // 112
  localparam int     PT_HEAD_W     = DPE_DATA_W - ETH_W;                    // 16
  localparam int     PT_HEAD_BYTES = PT_HEAD_W / 8;                         // 2
  // header-only beats: the payload (and the counter) start in the next
  localparam int     WG_HDR_BEATS  = WG_PAYLOAD_OFFSET / BEAT_BYTES;        // 3
  // the outer IPv4 total length: its header beat, and the most the core takes
  localparam int     IP_LEN_BEAT   = beat_of(IPV4_TOTAL_LEN_OFFSET);        // 1
  localparam len16_t IP_LEN_MAX    = WG_IPV4_OVERHEAD + AEAD_MAX_PT_BYTES;

  // the registers: r, and r_next, what they hold in the next clock
  typedef struct packed {
    state_t             state;
    feed_t              feed;
    emit_t              emit;
    dpe_addr_t          tuser_dst;
    dpe_addr_t          tuser_src;
    dpe_peer_idx_t      peer_idx;
    wg_peer_cfg_t       peer_cfg;    // the packet's peer, from the peer table
    logic [1:0]         hdr_k;       // header beats in so far
    logic [ETH_W-1:0]   eth_hdr;     // the outer Ethernet header
    wg_counter_t        counter;     // the packet's counter: the nonce
    logic [CARRY_W-1:0] carry;       // the frame beat before: its last bytes
    len16_t             ip_len;      // the plaintext IPv4 total length
    len16_t             sent;        // IPv4 bytes out so far
    logic               core_done;   // the core's last beat is in
    beat_t              held;        // the plaintext beat before
    len16_t             core_bytes;  // bytes fed to the core: ciphertext and tag
  } regs_t;
  regs_t r, r_next;

  dpe_tuser_t tuser_out;
  assign tuser_out = '{
          bypass_all: 1'b0,
          bypass_stage: 1'b0,
          src: r.tuser_src,
          dst: r.tuser_dst
      };

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
  assign rem = r.ip_len - r.sent;

  // FSM registers
  always_ff @(posedge inp.clk) begin
    if (inp.rst) begin
      r.state      <= IDLE;
      r.feed       <= FEED_HDR;
      r.emit       <= EMIT_FIRST;
      r.tuser_dst  <= DPE_ADDR_CPU;
      r.tuser_src  <= DPE_ADDR_CPU;
      r.peer_idx   <= '0;
      r.peer_cfg   <= '0;
      r.hdr_k      <= '0;
      r.eth_hdr    <= '0;
      r.counter    <= '0;
      r.carry      <= '0;
      r.ip_len     <= '0;
      r.sent       <= '0;
      r.core_done  <= 1'b0;
      r.held       <= '0;
      r.core_bytes <= '0;
    end
    else begin
      r <= r_next;
    end
  end

  // The FSMs: next state and the handshake signals
  always_comb begin
    r_next              = r;

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
    muxed.tid           = r.peer_idx;

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
        r_next.feed     = FEED_HDR;
        r_next.emit     = EMIT_FIRST;
        r_next.hdr_k    = '0;
        r_next.state    = PACKET;
      end

      PACKET: begin
        // feed: frame beats into the core
        unique case (r.feed)
          FEED_HDR: begin
            piped.tready = 1'b1;
            if (piped_hs) begin
              if (r.hdr_k == 2'd0) begin
                r_next.eth_hdr = piped.tdata[ETH_W-1:0];
              end
              r_next.hdr_k = r.hdr_k + 2'd1;
              if (piped.tlast) begin
                // too short: nothing for the core, nothing out
                r_next.feed = FEED_DONE;
                r_next.emit = EMIT_DONE;
              end
              else if ((r.hdr_k == 2'(IP_LEN_BEAT)) & (be16(
                      piped.tdata, IPV4_TOTAL_LEN_OFFSET % BEAT_BYTES
                  ) > IP_LEN_MAX)) begin
                // more than the core takes: skip it, nothing out
                r_next.feed = FEED_SKIP;
                r_next.emit = EMIT_DONE;
              end
              else if (r.hdr_k == 2'(WG_HDR_BEATS - 1)) begin
                r_next.feed = FEED_WG;
              end
            end
          end

          FEED_WG: begin
            piped.tready = 1'b1;
            if (piped_hs) begin
              r_next.counter    = le64(piped.tdata, WG_COUNTER_OFFSET);
              r_next.carry      = piped.tdata[DPE_DATA_W-1-:CARRY_W];
              r_next.core_bytes = '0;
              if (piped.tlast) begin
                r_next.feed = FEED_DONE;
                r_next.emit = EMIT_DONE;
              end
              else begin
                r_next.feed = FEED_DATA;
              end
            end
          end

          FEED_DATA: begin
            if ((r.core_bytes == '0) & piped.tlast & ~piped.tkeep[WG_HDR_TAIL_BYTES]) begin
              // one core beat in all, the tag alone (a keepalive): the core
              // would give no plaintext, so the frame never reaches it
              piped.tready = 1'b1;
              if (piped_hs) begin
                r_next.feed = FEED_DONE;
                r_next.emit = EMIT_DONE;
              end
            end
            else begin
              // the frame's next 16 payload bytes
              to_decrypt.tvalid = piped.tvalid;
              to_decrypt.tdata  = {piped.tdata[HEAD_W-1:0], r.carry};
              to_decrypt.tlast  = piped.tlast & ~piped.tkeep[WG_HDR_TAIL_BYTES];
              piped.tready      = to_decrypt.tready;
              if (dec_in_hs) begin
                r_next.carry      = piped.tdata[DPE_DATA_W-1-:CARRY_W];
                r_next.core_bytes = r.core_bytes + len16_t'(BEAT_BYTES);
                if (piped.tlast) begin
                  r_next.feed = piped.tkeep[WG_HDR_TAIL_BYTES] ? FEED_TAIL : FEED_DONE;
                end
              end
            end
          end

          FEED_TAIL: begin
            to_decrypt.tvalid = 1'b1;
            to_decrypt.tdata  = beat_t'(r.carry);
            to_decrypt.tlast  = 1'b1;
            if (dec_in_hs) begin
              r_next.core_bytes = r.core_bytes + len16_t'(BEAT_BYTES);
              r_next.feed       = FEED_DONE;
            end
          end

          FEED_SKIP: begin
            piped.tready = 1'b1;
            if (piped_hs && piped.tlast) begin
              r_next.feed = FEED_DONE;
            end
          end

          default: ;  // FEED_DONE
        endcase

        // emit: the plaintext, once the core has checked its tag
        unique case (r.emit)
          EMIT_FIRST: begin
            // the feed is done by now: the core keeps the plaintext until the tag
            if (!verified || ip_len_first < len16_t'(IPV4_HDR_LEN) ||
                ip_len_first > r.core_bytes - len16_t'(POLY1305_TAG_LEN)) begin
              from_decrypt.tready = 1'b1;
              if (dec_out_hs) begin
                r_next.emit = from_decrypt.tlast ? EMIT_DONE : EMIT_DROP;
              end
            end
            else begin
              muxed.tvalid        = from_decrypt.tvalid;
              muxed.tdata         = {from_decrypt.tdata[PT_HEAD_W-1:0], r.eth_hdr};
              from_decrypt.tready = muxed.tready;
              if (dec_out_hs) begin
                r_next.held      = from_decrypt.tdata;
                r_next.ip_len    = ip_len_first;
                r_next.sent      = len16_t'(PT_HEAD_BYTES);
                r_next.core_done = from_decrypt.tlast;
                r_next.emit      = EMIT_BODY;
              end
            end
          end

          EMIT_BODY: begin
            if (rem <= len16_t'(BEAT_BYTES - PT_HEAD_BYTES) || r.core_done) begin
              // the rest is in held (or the core has no more: cut there)
              muxed.tvalid = 1'b1;
              muxed.tdata  = beat_t'(r.held[DPE_DATA_W-1:PT_HEAD_W]);
              muxed.tkeep  = keep_first(rem) & keep_first(len16_t'(BEAT_BYTES - PT_HEAD_BYTES));
              muxed.tlast  = 1'b1;
              if (muxed_hs) begin
                r_next.emit = r.core_done ? EMIT_DONE : EMIT_DROP;
              end
            end
            else begin
              muxed.tvalid = from_decrypt.tvalid;
              muxed.tdata = {from_decrypt.tdata[PT_HEAD_W-1:0], r.held[DPE_DATA_W-1:PT_HEAD_W]};
              muxed.tkeep = keep_first(rem);
              muxed.tlast = rem <= len16_t'(BEAT_BYTES);
              from_decrypt.tready = muxed.tready;
              if (dec_out_hs) begin
                r_next.held      = from_decrypt.tdata;
                r_next.sent      = r.sent + len16_t'(BEAT_BYTES);
                r_next.core_done = from_decrypt.tlast;
                if (muxed.tlast) begin
                  r_next.emit = from_decrypt.tlast ? EMIT_DONE : EMIT_DROP;
                end
              end
            end
          end

          EMIT_DROP: begin
            from_decrypt.tready = 1'b1;
            if (dec_out_hs && from_decrypt.tlast) begin
              r_next.emit = EMIT_DONE;
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

  assign idle     = (r.state == IDLE) & ~piped.tvalid & ~outp.tvalid;
  // the receiver does not advance the send counter
  assign peer_req = '{idx: r.peer_idx, new_send_cnt: '0, update_send_cnt: 1'b0};

  // Decryptor core. The nonce: 4 zero bytes, then the counter
  // (little-endian; byte 0 in [7:0])
  chacha20poly1305_decrypt u_chacha20poly1305_decrypt (
      .clk_80p0              (inp.clk),
      .decrypt_key           (r.peer_cfg.key),
      .decrypt_nonce         ({r.counter, 32'd0}),
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

// -----------------------------------------------------------------------------
// Project:     WireGuard-FPGA
// Description: NLnet-funded open-source implementation
// Funding:     https://nlnet.nl/project/KlusterLab-Wireguard (2023-12 to 2025-12)
// -----------------------------------------------------------------------------
