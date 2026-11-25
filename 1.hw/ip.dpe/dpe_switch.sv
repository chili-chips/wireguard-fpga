// SPDX-FileCopyrightText: 2026 Chili.CHIPS
//
// SPDX-License-Identifier: BSD-3-Clause

//==========================================================================
// Wireguard-1GE FPGA * NLnet-sponsored open-source implementation
//--------------------------------------------------------------------------
//                   Copyright (C) 2026 Chili.CHIPS
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
//   DPE switch: the WireGuard data path. Pin-compatible with the fixed
//   crossbar of dpe_switch.DUMMY.sv; top.filelist picks one.
//
//   inp --> disassembler --> decryptor --> egress lookup --> encryptor --> out
//               |  ^             |  ^         (routing      |  ^
//         wg_rcv|  |rcv_rsp       peer_req     table, CSR)  peer_req
//               v  |             v  |                       v  |
//            +-------------------------------------------------------+
//            |   peer table (cryptokey table, CSR): lkup_peer_table   |
//            +-------------------------------------------------------+
//
//   - the disassembler finds WireGuard data packets of a known receiver
//     index and gives them their peer; others pass the decryptor
//     (bypass_stage);
//   - the decryptor decrypts them with the peer's decrypt_key;
//   - the egress lookup routes every packet by its IPv4 destination: port,
//     peer, and whether it goes through the tunnel (the route's encrypt
//     flag, as bypass_stage clear for the encryptor);
//   - the encryptor encrypts those for their peer (encrypt_key, send_cnt).
//   idle: no stage holds a packet (the pause/drain handshake, fcr.idle)
//
//   The decryptor and the encryptor share one ChaCha20-Poly1305 core
//   (chacha20poly1305_encrypt_decrypt_shared, 3.build/pypeline_build
//   build.py --shared --soc): one ChaCha20 and one Poly1305 serve both
//   directions, so the design fits the xc7a200t (two standalone cores: about
//   134%, #40). Both directions run at once; they share the core's throughput.
//   A register slice (axis_register, skid) sits on each of the core's four
//   streams, so no path runs from the block FSMs into the core's logic or
//   back (#67): one cycle more each way. Key and nonce need none: each block
//   holds them until its packet has left the core. The decrypt output's
//   decrypt_m_verified (valid with every beat) rides its slice in tuser.
//==========================================================================

module dpe_switch
  import dpe_pkg::*;
  import net_pkg::*;
  import lkup_pkg::*;
(
    dpe_if.s_axis      inp,
    dpe_if.m_axis      outp,
    output logic       idle,
    input  ipv4_addr_t wg_ip,    // this device's WireGuard address (csr.dpe.wg_ip)
    input  udp_port_t  wg_port,  // the WireGuard listen port (csr.dpe.wg_port)

    // the CSR routing_table and cryptokey_table regfiles (csr.rdl)
    input  rt_cfg_t    rt_cfg,
    output rt_sta_t    rt_sta,
    input  ck_cfg_t    ck_cfg,
    output ck_sta_t    ck_sta
);

  dpe_if disassembled (
      .clk (inp.clk),
      .rst (inp.rst)
  );
  dpe_if decrypted (
      .clk (inp.clk),
      .rst (inp.rst)
  );
  dpe_if routed (
      .clk (inp.clk),
      .rst (inp.rst)
  );

  // the shared core's two sides
  dpe_if to_decrypt (
      .clk (inp.clk),
      .rst (inp.rst)
  );
  dpe_if from_decrypt (
      .clk (inp.clk),
      .rst (inp.rst)
  );
  dpe_if to_encrypt (
      .clk (inp.clk),
      .rst (inp.rst)
  );
  dpe_if from_encrypt (
      .clk (inp.clk),
      .rst (inp.rst)
  );
  // the same four streams at the core's ports, behind the register slices
  dpe_if core_dec_in (
      .clk (inp.clk),
      .rst (inp.rst)
  );
  dpe_if core_dec_out (
      .clk (inp.clk),
      .rst (inp.rst)
  );
  dpe_if core_enc_in (
      .clk (inp.clk),
      .rst (inp.rst)
  );
  dpe_if core_enc_out (
      .clk (inp.clk),
      .rst (inp.rst)
  );
  logic [255:0] dec_key, enc_key;
  logic [95:0] dec_nonce, enc_nonce;
  logic dec_verified, core_verified;

  wg_receiver_t wg_rcv;
  rcv_rsp_t     rcv_rsp;
  peer_req_t dec_req, enc_req;
  wg_peer_cfg_t dec_peer, enc_peer;
  logic dis_idle, dec_idle, lkup_idle, enc_idle;

  dpe_wg_disassembler u_disassembler (
      .idle    (dis_idle),
      .wg_rcv  (wg_rcv),
      .rcv_rsp (rcv_rsp),
      .wg_ip   (wg_ip),
      .wg_port (wg_port),
      .inp     (inp),
      .outp    (disassembled)
  );

  dpe_wg_decryptor u_decryptor (
      .inp           (disassembled),
      .outp          (decrypted),
      .idle          (dec_idle),
      .peer_req      (dec_req),
      .peer_rsp      (dec_peer),
      .core_key      (dec_key),
      .core_nonce    (dec_nonce),
      .to_decrypt    (to_decrypt),
      .from_decrypt  (from_decrypt),
      .core_verified (dec_verified)
  );

  lkup_egress #(
      .ENTRY_COUNT (64)
  ) u_egress (
      .inp     (decrypted),
      .outp    (routed),
      .idle    (lkup_idle),
      .csr_cfg (rt_cfg),
      .csr_sta (rt_sta)
  );

  dpe_wg_encryptor u_encryptor (
      .inp          (routed),
      .outp         (outp),
      .idle         (enc_idle),
      .peer_req     (enc_req),
      .peer_rsp     (enc_peer),
      .core_key     (enc_key),
      .core_nonce   (enc_nonce),
      .to_encrypt   (to_encrypt),
      .from_encrypt (from_encrypt)
  );

  // register slices on the core's streams; tuser and tid carry nothing,
  // but the decrypt output's tuser.bypass_stage: the tag did not check out
  axis_register #(
      .ID_ENABLE   (0),
      .USER_ENABLE (0)
  ) u_enc_in_reg (
      .s_axis (to_encrypt),
      .m_axis (core_enc_in)
  );
  axis_register #(
      .ID_ENABLE   (0),
      .USER_ENABLE (0)
  ) u_enc_out_reg (
      .s_axis (core_enc_out),
      .m_axis (from_encrypt)
  );
  axis_register #(
      .ID_ENABLE   (0),
      .USER_ENABLE (0)
  ) u_dec_in_reg (
      .s_axis (to_decrypt),
      .m_axis (core_dec_in)
  );
  axis_register #(
      .ID_ENABLE   (0),
      .USER_ENABLE (1)
  ) u_dec_out_reg (
      .s_axis (core_dec_out),
      .m_axis (from_decrypt)
  );

  assign core_enc_out.tuser = '0;
  assign core_enc_out.tid = '0;
  assign core_dec_out.tuser = '{
          bypass_all: 1'b0,
          bypass_stage: ~core_verified,
          src: DPE_ADDR_CPU,
          dst: DPE_ADDR_CPU
      };
  assign core_dec_out.tid = '0;
  assign dec_verified = ~from_decrypt.tuser.bypass_stage;

  // the shared ChaCha20-Poly1305 core (AAD: none, today)
  chacha20poly1305_encrypt_decrypt_shared u_aead (
      .clk_80p0              (inp.clk),
      .encrypt_key           (enc_key),
      .encrypt_nonce         (enc_nonce),
      .encrypt_aad           (256'd0),
      .encrypt_aad_len       (8'd0),
      .encrypt_s_axis_tdata  (core_enc_in.tdata),
      .encrypt_s_axis_tkeep  (core_enc_in.tkeep),
      .encrypt_s_axis_tlast  (core_enc_in.tlast),
      .encrypt_s_axis_tvalid (core_enc_in.tvalid),
      .encrypt_s_axis_tready (core_enc_in.tready),
      .encrypt_m_axis_tdata  (core_enc_out.tdata),
      .encrypt_m_axis_tkeep  (core_enc_out.tkeep),
      .encrypt_m_axis_tlast  (core_enc_out.tlast),
      .encrypt_m_axis_tvalid (core_enc_out.tvalid),
      .encrypt_m_axis_tready (core_enc_out.tready),
      .decrypt_key           (dec_key),
      .decrypt_nonce         (dec_nonce),
      .decrypt_aad           (256'd0),
      .decrypt_aad_len       (8'd0),
      .decrypt_s_axis_tdata  (core_dec_in.tdata),
      .decrypt_s_axis_tkeep  (core_dec_in.tkeep),
      .decrypt_s_axis_tlast  (core_dec_in.tlast),
      .decrypt_s_axis_tvalid (core_dec_in.tvalid),
      .decrypt_s_axis_tready (core_dec_in.tready),
      .decrypt_m_axis_tdata  (core_dec_out.tdata),
      .decrypt_m_axis_tkeep  (core_dec_out.tkeep),
      .decrypt_m_axis_tlast  (core_dec_out.tlast),
      .decrypt_m_axis_tvalid (core_dec_out.tvalid),
      .decrypt_m_axis_tready (core_dec_out.tready),
      .decrypt_m_verified    (core_verified)
  );

  lkup_peer_table u_peers (
      .clk      (inp.clk),
      .rst      (inp.rst),
      .csr_cfg  (ck_cfg),
      .csr_sta  (ck_sta),
      .enc_req  (enc_req),
      .enc_peer (enc_peer),
      .dec_req  (dec_req),
      .dec_peer (dec_peer),
      .rcv      (wg_rcv),
      .rcv_rsp  (rcv_rsp)
  );

  assign idle = dis_idle & dec_idle & lkup_idle & enc_idle;
endmodule

// -----------------------------------------------------------------------------
// Project:     WireGuard-FPGA
// Description: NLnet-funded open-source implementation
// Funding:     https://nlnet.nl/project/KlusterLab-Wireguard (2023-12 to 2025-12)
// -----------------------------------------------------------------------------
