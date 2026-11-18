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
//         wg_rcv|  |wg_peer       peer_req     table, CSR)  peer_req
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
//==========================================================================

module dpe_switch
  import dpe_pkg::*;
  import net_pkg::*;
  import lkup_pkg::*;
(
    dpe_if.s_axis    inp,
    dpe_if.m_axis    out,
    output logic     idle,

    // the CSR routing_table and cryptokey_table regfiles (csr.rdl)
    input  csr_cfg_t rt_cfg,
    output csr_sta_t rt_sta,
    input  ck_cfg_t  ck_cfg,
    output ck_sta_t  ck_sta
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

  wg_receiver_t wg_rcv;
  rcv_rsp_t     wg_peer;
  peer_req_t dec_req, enc_req;
  wg_peer_cfg_t dec_peer, enc_peer;
  logic dis_idle, dec_idle, lkup_idle, enc_idle;

  dpe_wg_disassembler u_disassembler (
      .fcr_idle (dis_idle),
      .wg_rcv   (wg_rcv),
      .wg_peer  (wg_peer),
      .inp      (inp),
      .outp     (disassembled)
  );

  dpe_wg_decryptor u_decryptor (
      .inp      (disassembled),
      .outp     (decrypted),
      .fcr_idle (dec_idle),
      .peer_req (dec_req),
      .peer_rsp (dec_peer)
  );

  lkup_egress #(
      .ENTRY_COUNT (64)
  ) u_egress (
      .s_axis   (decrypted),
      .m_axis   (routed),
      .fcr_idle (lkup_idle),
      .csr_cfg  (rt_cfg),
      .csr_sta  (rt_sta)
  );

  dpe_wg_encryptor u_encryptor (
      .inp      (routed),
      .outp     (out),
      .fcr_idle (enc_idle),
      .peer_req (enc_req),
      .peer_rsp (enc_peer)
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
      .rcv_rsp  (wg_peer)
  );

  assign idle = dis_idle & dec_idle & lkup_idle & enc_idle;
endmodule

// -----------------------------------------------------------------------------
// Project:     WireGuard-FPGA
// Description: NLnet-funded open-source implementation
// Funding:     https://nlnet.nl/project/KlusterLab-Wireguard (2023-12 to 2025-12)
// -----------------------------------------------------------------------------
