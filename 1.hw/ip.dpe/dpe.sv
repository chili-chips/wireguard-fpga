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
//   Data Plane Engine
//==========================================================================

module dpe
  import csr_pkg::*;
  import dpe_pkg::*;
(
    input  csr__out_t                           from_csr,
    output csr__dpe__in_t                       to_csr_dpe,
    output csr__routing_table__external__in_t   to_csr_routing_table,
    output csr__cryptokey_table__external__in_t to_csr_cryptokey_table,
    dpe_if.s_axis                               from_cpu,
    dpe_if.s_axis                               from_eth_1,
    dpe_if.s_axis                               from_eth_2,
    dpe_if.s_axis                               from_eth_3,
    dpe_if.s_axis                               from_eth_4,
    dpe_if.m_axis                               to_cpu,
    dpe_if.m_axis                               to_eth_1,
    dpe_if.m_axis                               to_eth_2,
    dpe_if.m_axis                               to_eth_3,
    dpe_if.m_axis                               to_eth_4
);

  dpe_if muxed_1 (
      .clk (from_cpu.clk),
      .rst (from_cpu.rst)
  );
  dpe_if muxed_2 (
      .clk (from_cpu.clk),
      .rst (from_cpu.rst)
  );

  // fcr.idle: the multiplexer stopped (pause) and the switch holds no packet
  logic  mux_idle, switch_idle;
  assign to_csr_dpe.fcr.idle.next = mux_idle & switch_idle;

  // DPE multiplexer
  dpe_mux u_dpe_mux (
      .pause      (from_csr.dpe.fcr.pause.value),
      .idle       (mux_idle),
      .from_cpu   (from_cpu),
      .from_eth_1 (from_eth_1),
      .from_eth_2 (from_eth_2),
      .from_eth_3 (from_eth_3),
      .from_eth_4 (from_eth_4),
      .to_dpe     (muxed_1)
  );

  // DPE switch: the fixed crossbar (dpe_switch.DUMMY.sv) or the WireGuard
  // data path (dpe_switch.sv), as top.filelist lists; each owns both tables
  dpe_switch u_dpe_switch (
      .inp     (muxed_1),
      .outp    (muxed_2),
      .idle    (switch_idle),
      .wg_ip   (from_csr.dpe.wg_ip.ip.value),
      .wg_port (from_csr.dpe.wg_port.port.value),
      .rt_cfg  (from_csr.routing_table),
      .rt_sta  (to_csr_routing_table),
      .ck_cfg  (from_csr.cryptokey_table),
      .ck_sta  (to_csr_cryptokey_table)
  );

  // DPE demultiplexer
  dpe_demux u_dpe_demux (
      .from_dpe (muxed_2),
      .to_cpu   (to_cpu),
      .to_eth_1 (to_eth_1),
      .to_eth_2 (to_eth_2),
      .to_eth_3 (to_eth_3),
      .to_eth_4 (to_eth_4)
  );

endmodule

// -----------------------------------------------------------------------------
// Project:     WireGuard-FPGA
// Description: NLnet-funded open-source implementation
// Funding:     https://nlnet.nl/project/KlusterLab-Wireguard (2023-12 to 2025-12)
// -----------------------------------------------------------------------------
