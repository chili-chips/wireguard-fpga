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
//   DPE WireGuard Encryptor
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

  typedef enum logic [3:0] {
    IDLE,
    BYPASS,
    WAIT_RAM,
    HEADER_1,
    HEADER_2,
    HEADER_3,
    HEADER_4,
    PAYLOAD,
    PAYLOAD_LAST
  } state_t;

  // Internal states
  state_t state, state_next;
  dpe_addr_t tuser_dst, tuser_dst_next;
  dpe_addr_t tuser_src, tuser_src_next;
  dpe_peer_idx_t peer_idx, peer_idx_next;
  wg_peer_cfg_t peer, peer_next;  // the packet's peer, from the routing table
  wg_counter_t new_send_cnt, new_send_cnt_next;
  logic update_send_cnt, update_send_cnt_next;
  logic [DPE_DATA_W-1:0] plaintext_data, plaintext_data_next;
  logic plaintext_valid, plaintext_valid_next;
  logic [DPE_DATA_W-1:0] encrypted_data, encrypted_data_next;
  logic input_finished, input_finished_next;
  len16_t packet_ip_len, packet_ip_len_next;
  len16_t packet_udp_len, packet_udp_len_next;

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
              total_len: packet_ip_len,
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
              len: packet_udp_len,
              checksum: '0
          },
          wg: '{msg_type: WG_TYPE_DATA, receiver: peer.remote_id, counter: peer.send_cnt}
      }
  );

  // The last header beat holds the headers' last WG_HDR_TAIL_BYTES bytes,
  // then the first bytes of the encrypted payload
  localparam int PAYLOAD_HEAD_W = 8 * (BEAT_BYTES - WG_HDR_TAIL_BYTES);  // 48
  beat_t hdr_tail;
  assign hdr_tail = hdr_beat(hdr, WG_FRAME_HDR_LEN / BEAT_BYTES);

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

  // FSM registers
  always_ff @(posedge inp.clk) begin
    if (inp.rst) begin
      state           <= IDLE;
      tuser_dst       <= DPE_ADDR_CPU;
      tuser_src       <= DPE_ADDR_CPU;
      peer_idx        <= '0;
      peer            <= '0;
      new_send_cnt    <= '0;
      update_send_cnt <= '0;
      plaintext_data  <= '0;
      plaintext_valid <= 1'b0;
      encrypted_data  <= '0;
      input_finished  <= 1'b0;
      packet_ip_len   <= '0;
      packet_udp_len  <= '0;
    end
    else begin
      state           <= state_next;
      tuser_dst       <= tuser_dst_next;
      tuser_src       <= tuser_src_next;
      peer_idx        <= peer_idx_next;
      peer            <= peer_next;
      new_send_cnt    <= new_send_cnt_next;
      update_send_cnt <= update_send_cnt_next;
      plaintext_data  <= plaintext_data_next;
      plaintext_valid <= plaintext_valid_next;
      encrypted_data  <= encrypted_data_next;
      input_finished  <= input_finished_next;
      packet_ip_len   <= packet_ip_len_next;
      packet_udp_len  <= packet_udp_len_next;
    end
  end

  // FSM transition logic
  always_comb begin
    state_next           = state;
    tuser_dst_next       = tuser_dst;
    tuser_src_next       = tuser_src;
    peer_idx_next        = peer_idx;
    peer_next            = peer;
    new_send_cnt_next    = new_send_cnt;
    update_send_cnt_next = update_send_cnt;
    plaintext_data_next  = plaintext_data;
    plaintext_valid_next = plaintext_valid;
    encrypted_data_next  = encrypted_data;
    input_finished_next  = input_finished;
    packet_ip_len_next   = packet_ip_len;
    packet_udp_len_next  = packet_udp_len;

    unique case (state)
      IDLE: begin
        if (inp.tvalid && inp.tready) begin
          if (inp.tuser.bypass_stage || inp.tuser.bypass_all) begin
            state_next = BYPASS;
          end
          else begin
            tuser_dst_next = inp.tuser.dst;
            tuser_src_next = inp.tuser.src;
            peer_idx_next  = inp.tid;
            state_next     = WAIT_RAM;
          end
        end
      end

      BYPASS: begin
        if (inp.tlast && inp.tvalid) begin
          state_next = IDLE;
        end
      end

      WAIT_RAM: begin
        peer_next = ram_peer;

        if (piped.tvalid && piped.tready) begin
          plaintext_data_next = piped.tdata;
        end
        plaintext_valid_next = piped.tvalid;

        if (muxed.tready) begin
          state_next = HEADER_1;
        end
      end

      HEADER_1: begin
        if (piped.tvalid && piped.tready) begin
          plaintext_data_next = piped.tdata;
          packet_ip_len_next = wg_padded_len(be16(piped.tdata, IPV4_TOTAL_LEN_OFFSET)) +
              WG_IPV4_OVERHEAD;
          packet_udp_len_next = wg_padded_len(be16(piped.tdata, IPV4_TOTAL_LEN_OFFSET)) +
              WG_UDP_OVERHEAD;
          state_next = HEADER_2;
        end
        plaintext_valid_next = piped.tvalid;
      end

      HEADER_2: begin
        if (piped.tvalid && piped.tready) begin
          plaintext_data_next = piped.tdata;
          if (piped.tlast) begin
            input_finished_next = 1'b1;
          end
          state_next = HEADER_3;
        end
        plaintext_valid_next = piped.tvalid;
      end

      HEADER_3: begin
        if (piped.tvalid && piped.tready) begin
          plaintext_data_next = piped.tdata;
          if (piped.tlast) begin
            input_finished_next = 1'b1;
          end
          state_next = HEADER_4;
        end
        plaintext_valid_next = piped.tvalid;
      end

      HEADER_4: begin
        if (piped.tvalid && piped.tready) begin
          plaintext_data_next = piped.tdata;
          if (piped.tlast) begin
            input_finished_next = 1'b1;
          end
        end
        plaintext_valid_next = piped.tvalid;

        if (muxed.tready && from_encrypt.tvalid) begin
          encrypted_data_next = from_encrypt.tdata;
          state_next          = PAYLOAD;
        end
      end

      PAYLOAD: begin
        if (piped.tvalid && piped.tready) begin
          plaintext_data_next = piped.tdata;
          if (piped.tlast) begin
            input_finished_next = 1'b1;
          end
        end
        plaintext_valid_next = piped.tvalid;

        if (muxed.tready && from_encrypt.tvalid) begin
          encrypted_data_next = from_encrypt.tdata;
          if (from_encrypt.tlast) begin
            new_send_cnt_next    = peer.send_cnt + 1;
            update_send_cnt_next = 1'b1;
            state_next           = PAYLOAD_LAST;
          end
        end
      end

      PAYLOAD_LAST: begin
        update_send_cnt_next = 1'b0;
        if (muxed.tready) begin
          input_finished_next = 1'b0;
          state_next          = IDLE;
        end
      end

      default: state_next = IDLE;
    endcase
  end

  // Outputs logic
  always_comb begin
    to_encrypt.tvalid = 1'b0;
    to_encrypt.tdata  = '0;
    to_encrypt.tlast  = 1'b0;
    to_encrypt.tkeep  = '0;

    muxed.tvalid      = 1'b0;
    muxed.tdata       = '0;
    muxed.tlast       = 1'b0;
    muxed.tkeep       = '0;
    muxed.tuser       = '0;
    muxed.tid         = '0;

    unique case (state)
      IDLE, BYPASS: begin
        muxed.tvalid = piped.tvalid;
        muxed.tdata  = piped.tdata;
        muxed.tlast  = piped.tlast;
        muxed.tkeep  = piped.tkeep;
        muxed.tuser  = piped.tuser;
        muxed.tid    = piped.tid;
      end

      WAIT_RAM: begin
        //NOP
      end

      HEADER_1: begin
        to_encrypt.tvalid        = piped.tvalid;
        to_encrypt.tdata         = {piped.tdata[111:0], plaintext_data[127:112]};
        to_encrypt.tlast         = 1'b0;
        to_encrypt.tkeep         = 16'hFFFF;

        muxed.tvalid             = 1'b1;
        muxed.tdata              = hdr_beat(hdr, 0);
        muxed.tlast              = 1'b0;
        muxed.tkeep              = 16'hFFFF;
        muxed.tuser.bypass_all   = 1'b0;
        muxed.tuser.bypass_stage = 1'b0;
        muxed.tuser.dst          = tuser_dst;
        muxed.tuser.src          = tuser_src;
        muxed.tid                = peer_idx;
      end

      HEADER_2: begin
        to_encrypt.tvalid        = piped.tvalid;
        to_encrypt.tdata         = {piped.tdata[111:0], plaintext_data[127:112]};
        to_encrypt.tlast         = 1'b0;
        to_encrypt.tkeep         = 16'hFFFF;

        muxed.tvalid             = 1'b1;
        muxed.tdata              = hdr_beat(hdr, 1);
        muxed.tlast              = 1'b0;
        muxed.tkeep              = 16'hFFFF;
        muxed.tuser.bypass_all   = 1'b0;
        muxed.tuser.bypass_stage = 1'b0;
        muxed.tuser.dst          = tuser_dst;
        muxed.tuser.src          = tuser_src;
        muxed.tid                = peer_idx;
      end

      HEADER_3: begin
        to_encrypt.tvalid        = (piped.tkeep[15:14] == 2'b00) ? plaintext_valid : piped.tvalid;
        to_encrypt.tdata         = {piped.tdata[111:0], plaintext_data[127:112]};
        to_encrypt.tlast         = (piped.tkeep[15:14] == 2'b00) ? 1'b1 : 1'b0;
        to_encrypt.tkeep         = 16'hFFFF;

        muxed.tvalid             = 1'b1;
        muxed.tdata              = hdr_beat(hdr, 2);
        muxed.tlast              = 1'b0;
        muxed.tkeep              = 16'hFFFF;
        muxed.tuser.bypass_all   = 1'b0;
        muxed.tuser.bypass_stage = 1'b0;
        muxed.tuser.dst          = tuser_dst;
        muxed.tuser.src          = tuser_src;
        muxed.tid                = peer_idx;
      end

      HEADER_4: begin
        to_encrypt.tvalid = (piped.tkeep[15:14] == 2'b00) ? plaintext_valid : piped.tvalid;
        to_encrypt.tdata = {piped.tdata[111:0], plaintext_data[127:112]};
        to_encrypt.tlast = (piped.tkeep[15:14] == 2'b00) ? 1'b1 : 1'b0;
        to_encrypt.tkeep = 16'hFFFF;

        muxed.tvalid = from_encrypt.tvalid;
        // the headers' tail, then the payload's first bytes
        muxed.tdata = {from_encrypt.tdata[PAYLOAD_HEAD_W-1:0], hdr_tail[8*WG_HDR_TAIL_BYTES-1:0]};
        muxed.tlast = 1'b0;
        muxed.tkeep = 16'hFFFF;
        muxed.tuser.bypass_all = 1'b0;
        muxed.tuser.bypass_stage = 1'b0;
        muxed.tuser.dst = tuser_dst;
        muxed.tuser.src = tuser_src;
        muxed.tid = peer_idx;
      end

      PAYLOAD: begin
        to_encrypt.tvalid = (piped.tkeep[15:14] == 2'b00) ? plaintext_valid : piped.tvalid;
        to_encrypt.tdata = {piped.tdata[111:0], plaintext_data[127:112]};
        to_encrypt.tlast = (piped.tkeep[15:14] == 2'b00) ? 1'b1 : 1'b0;
        to_encrypt.tkeep = 16'hFFFF;

        muxed.tvalid = from_encrypt.tvalid;
        // the encrypted payload
        muxed.tdata = {
          from_encrypt.tdata[PAYLOAD_HEAD_W-1:0], encrypted_data[DPE_DATA_W-1:PAYLOAD_HEAD_W]
        };
        muxed.tlast = 1'b0;
        muxed.tkeep = 16'hFFFF;
        muxed.tuser.bypass_all = 1'b0;
        muxed.tuser.bypass_stage = 1'b0;
        muxed.tuser.dst = tuser_dst;
        muxed.tuser.src = tuser_src;
        muxed.tid = peer_idx;
      end

      PAYLOAD_LAST: begin
        muxed.tvalid             = 1'b1;
        // the encrypted payload
        muxed.tdata              = beat_t'(encrypted_data[DPE_DATA_W-1:PAYLOAD_HEAD_W]);
        muxed.tlast              = 1'b1;
        muxed.tkeep              = 16'h03FF;
        muxed.tuser.bypass_all   = 1'b0;
        muxed.tuser.bypass_stage = 1'b0;
        muxed.tuser.dst          = tuser_dst;
        muxed.tuser.src          = tuser_src;
        muxed.tid                = peer_idx;
      end

      default: begin
        to_encrypt.tdata  = '0;
        to_encrypt.tkeep  = '0;
        to_encrypt.tlast  = '0;
        to_encrypt.tvalid = '0;

        muxed.tdata       = '0;
        muxed.tkeep       = '0;
        muxed.tlast       = '0;
        muxed.tvalid      = '0;
        muxed.tuser       = '0;
        muxed.tid         = '0;
      end
    endcase
  end
  assign piped.tready        = muxed.tready & to_encrypt.tready & ~input_finished;
  assign from_encrypt.tready = muxed.tready;
  assign fcr_idle            = ((state == IDLE) ? 1'b1 : 1'b0) & ~outp.tvalid;
  assign ram_peer_idx        = peer_idx;
  assign ram_new_send_cnt    = new_send_cnt;
  assign ram_update_send_cnt = update_send_cnt;

  // Encryptor core
  chacha20poly1305_encrypt u_chacha20poly1305_encrypt (
      .clk_80p0              (inp.clk),
      .encrypt_key           (peer.key),
      .encrypt_nonce         ({32'd0, peer.send_cnt}),
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
