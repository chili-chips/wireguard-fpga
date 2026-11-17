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
//    DPE WireGuard Decryptor with Verification Gate & Ethernet Re-wrap
//==========================================================================

// ============================================================================
// Module: sync_fifo
// Description: Internal buffer to hold decrypted data until verified.
// ============================================================================

module sync_fifo #(
    parameter int WIDTH = 159,
    parameter int DEPTH = 512
) (
    input  logic             clk,
    input  logic             rst,
    input  logic [WIDTH-1:0] data_in,
    input  logic             wr_en,
    output logic             full,
    output logic [WIDTH-1:0] data_out,
    input  logic             rd_en,
    output logic             empty
);
  localparam int ADDR_W = $clog2(DEPTH);
  logic [WIDTH-1:0] mem[DEPTH];
  logic [ADDR_W:0] wr_ptr, rd_ptr;

  assign full  = (wr_ptr[ADDR_W] != rd_ptr[ADDR_W]) && (wr_ptr[ADDR_W-1:0] == rd_ptr[ADDR_W-1:0]);
  assign empty = (wr_ptr == rd_ptr);

  always_ff @(posedge clk) begin
    if (rst) begin
      wr_ptr <= '0;
      rd_ptr <= '0;
    end
    else begin
      if (wr_en && !full) begin
        mem[wr_ptr[ADDR_W-1:0]] <= data_in;
        wr_ptr                  <= wr_ptr + 1;
      end
      if (rd_en && !empty) begin
        rd_ptr <= rd_ptr + 1;
      end
    end
  end
  assign data_out = mem[rd_ptr[ADDR_W-1:0]];
endmodule

// ============================================================================
// Module: dpe_wg_decryptor
// Description: Main decryptor with FIFO-based verification gating.
// ============================================================================

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

  typedef enum logic [3:0] {
    IDLE,
    BYPASS,
    WAIT_RAM,
    HEADER_1,
    HEADER_2,
    HEADER_3,
    HEADER_4,
    PAYLOAD,
    PAYLOAD_LAST,
    DROP_PACKET
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
  logic [DPE_DATA_W-1:0] decrypted_data, decrypted_data_next;
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
  // then the first bytes of the decrypted payload
  localparam int PAYLOAD_HEAD_W = 8 * (BEAT_BYTES - WG_HDR_TAIL_BYTES);  // 48
  beat_t hdr_tail;
  assign hdr_tail = hdr_beat(hdr, WG_FRAME_HDR_LEN / BEAT_BYTES);

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
  logic is_verified;

  // FIFO & Gate Logic Signals
  logic packet_authorized;
  logic fifo_full, fifo_empty, fifo_clear;

  // FIFO Data Packing (tdata + tkeep + tlast + tuser signals)
  localparam int FIFO_W = DPE_ID_W + 2 * $bits(dpe_addr_t) + 1 + DPE_KEEP_W + DPE_DATA_W;
  logic [FIFO_W-1:0] fifo_din, fifo_dout;

  assign fifo_din = {
    muxed.tid,  // [158:151]
    muxed.tuser.src,  // [150:148]
    muxed.tuser.dst,  // [147:145]
    muxed.tlast,  // [144]
    muxed.tkeep,  // [143:128]
    muxed.tdata  // [127:0]
  };

  // Output Logic mapping from FIFO
  logic      fifo_out_tlast;
  dpe_keep_t fifo_out_tkeep;
  dpe_data_t fifo_out_tdata;
  dpe_addr_t fifo_out_tuser_dst, fifo_out_tuser_src;
  dpe_peer_idx_t fifo_out_tid;

  assign {fifo_out_tid, fifo_out_tuser_src, fifo_out_tuser_dst,
           fifo_out_tlast, fifo_out_tkeep, fifo_out_tdata} = fifo_dout;

  // FIFO Instantiation
  sync_fifo #(
      .WIDTH (FIFO_W),
      .DEPTH (512)
  ) out_fifo (
      .clk      (inp.clk),
      .rst      (inp.rst || fifo_clear),
      .data_in  (fifo_din),
      .wr_en    (muxed.tvalid && !fifo_full),
      .full     (fifo_full),
      .data_out (fifo_dout),
      .rd_en    (outp.tready && packet_authorized),
      .empty    (fifo_empty)
  );

  // Verification Gate: Opens only if is_verified is true at the end of packet
  always_ff @(posedge inp.clk) begin
    if (inp.rst || fifo_clear) begin
      packet_authorized <= 1'b0;
    end
    else if (state == PAYLOAD_LAST && is_verified) begin
      packet_authorized <= 1'b1;
    end
    else if (outp.tlast && outp.tready) begin
      packet_authorized <= 1'b0;
    end
  end

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
      decrypted_data  <= '0;
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
      decrypted_data  <= decrypted_data_next;
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
    decrypted_data_next  = decrypted_data;
    input_finished_next  = input_finished;
    packet_ip_len_next   = packet_ip_len;
    packet_udp_len_next  = packet_udp_len;
    fifo_clear           = 1'b0;

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

      BYPASS:
      if (inp.tlast && inp.tvalid) begin
        state_next = IDLE;
      end

      WAIT_RAM: begin
        peer_next = ram_peer;
        if (piped.tvalid && piped.tready) begin
          plaintext_data_next = piped.tdata;
        end
        plaintext_valid_next = piped.tvalid;
        if (!fifo_full) begin
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
        if (!fifo_full && from_decrypt.tvalid) begin
          decrypted_data_next = from_decrypt.tdata;
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
        if (!fifo_full && from_decrypt.tvalid) begin
          decrypted_data_next = from_decrypt.tdata;
          if (from_decrypt.tlast) begin
            new_send_cnt_next    = peer.send_cnt + 1;
            update_send_cnt_next = 1'b1;
            state_next           = PAYLOAD_LAST;
          end
        end
      end

      PAYLOAD_LAST: begin
        update_send_cnt_next = 1'b0;
        if (!fifo_full) begin
          if (is_verified) begin
            input_finished_next = 1'b0;
            state_next          = IDLE;
          end
          else begin
            state_next = DROP_PACKET;
          end
        end
      end


      DROP_PACKET: begin
        fifo_clear          = 1'b1;
        input_finished_next = 1'b0;
        state_next          = IDLE;
      end


      default: state_next = IDLE;
    endcase
  end

  // Outputs logic (Muxing and Data Generation)

  always_comb begin
    to_decrypt.tvalid        = 1'b0;
    to_decrypt.tdata         = '0;
    to_decrypt.tlast         = 1'b0;
    to_decrypt.tkeep         = '0;
    muxed.tvalid             = 1'b0;
    muxed.tdata              = '0;
    muxed.tlast              = 1'b0;
    muxed.tkeep              = '0;
    muxed.tuser.bypass_all   = 1'b0;
    muxed.tuser.bypass_stage = 1'b0;
    muxed.tuser.src          = tuser_src;
    muxed.tuser.dst          = tuser_dst;
    muxed.tid                = peer_idx;


    unique case (state)

      IDLE, BYPASS: begin
        muxed.tvalid = piped.tvalid;
        muxed.tdata  = piped.tdata;
        muxed.tlast  = piped.tlast;
        muxed.tkeep  = piped.tkeep;
        muxed.tuser  = piped.tuser;
        muxed.tid    = piped.tid;
      end


      HEADER_1: begin
        to_decrypt.tvalid = piped.tvalid;
        to_decrypt.tdata  = {piped.tdata[111:0], plaintext_data[127:112]};
        to_decrypt.tkeep  = 16'hFFFF;
        muxed.tvalid      = !fifo_full;
        muxed.tdata       = hdr_beat(hdr, 0);
        muxed.tkeep       = 16'hFFFF;
      end


      HEADER_2: begin
        to_decrypt.tvalid = piped.tvalid;
        to_decrypt.tdata  = {piped.tdata[111:0], plaintext_data[127:112]};
        to_decrypt.tkeep  = 16'hFFFF;
        muxed.tvalid      = !fifo_full;
        muxed.tdata       = hdr_beat(hdr, 1);
        muxed.tkeep       = 16'hFFFF;
      end


      HEADER_3: begin
        to_decrypt.tvalid = (piped.tkeep[15:14] == 2'b00) ? plaintext_valid : piped.tvalid;
        to_decrypt.tdata  = {piped.tdata[111:0], plaintext_data[127:112]};
        to_decrypt.tlast  = (piped.tkeep[15:14] == 2'b00) ? 1'b1 : 1'b0;
        to_decrypt.tkeep  = 16'hFFFF;
        muxed.tvalid      = !fifo_full;
        muxed.tdata       = hdr_beat(hdr, 2);
        muxed.tkeep       = 16'hFFFF;
      end


      HEADER_4: begin
        to_decrypt.tvalid = (piped.tkeep[15:14] == 2'b00) ? plaintext_valid : piped.tvalid;
        to_decrypt.tdata = {piped.tdata[111:0], plaintext_data[127:112]};
        to_decrypt.tlast = (piped.tkeep[15:14] == 2'b00) ? 1'b1 : 1'b0;
        to_decrypt.tkeep = 16'hFFFF;
        muxed.tvalid = !fifo_full && from_decrypt.tvalid;
        muxed.tdata = {from_decrypt.tdata[PAYLOAD_HEAD_W-1:0], hdr_tail[8*WG_HDR_TAIL_BYTES-1:0]};
        muxed.tkeep = 16'hFFFF;
      end


      PAYLOAD: begin
        to_decrypt.tvalid = (piped.tkeep[15:14] == 2'b00) ? plaintext_valid : piped.tvalid;
        to_decrypt.tdata = {piped.tdata[111:0], plaintext_data[127:112]};
        to_decrypt.tlast = (piped.tkeep[15:14] == 2'b00) ? 1'b1 : 1'b0;
        to_decrypt.tkeep = 16'hFFFF;
        muxed.tvalid = !fifo_full && from_decrypt.tvalid;
        muxed.tdata = {
          from_decrypt.tdata[PAYLOAD_HEAD_W-1:0], decrypted_data[DPE_DATA_W-1:PAYLOAD_HEAD_W]
        };
        muxed.tkeep = 16'hFFFF;
      end


      PAYLOAD_LAST: begin
        muxed.tvalid = !fifo_full;
        muxed.tdata  = beat_t'(decrypted_data[DPE_DATA_W-1:PAYLOAD_HEAD_W]);
        muxed.tlast  = 1'b1;
        muxed.tkeep  = 16'h03FF;
      end
      default: ;
    endcase
  end


  // Handshaking and interface assignments
  assign piped.tready        = !fifo_full && to_decrypt.tready && !input_finished;
  assign from_decrypt.tready = !fifo_full;
  assign fcr_idle            = ((state == IDLE) ? 1'b1 : 1'b0) && !outp.tvalid;
  assign ram_peer_idx        = peer_idx;
  assign ram_new_send_cnt    = new_send_cnt;
  assign ram_update_send_cnt = update_send_cnt;


  // Drive the external interface from FIFO outputs
  assign outp.tvalid         = !fifo_empty && packet_authorized;
  assign outp.tlast          = fifo_out_tlast;
  assign outp.tkeep          = fifo_out_tkeep;
  assign outp.tdata          = fifo_out_tdata;
  assign outp.tid            = fifo_out_tid;
  assign outp.tuser.dst      = fifo_out_tuser_dst;
  assign outp.tuser.src      = fifo_out_tuser_src;

  // Sub-module instantiations

  chacha20poly1305_decrypt decrypt (
      .clk_80p0              (inp.clk),
      .decrypt_key           (peer.key),
      .decrypt_nonce         ({32'd0, peer.send_cnt}),
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
      .decrypt_m_verified    (is_verified)
  );

  dpe_if_pipeline #(
      .LENGTH (1)
  ) input_pipe (
      .inp  (inp),
      .outp (piped)
  );
endmodule
