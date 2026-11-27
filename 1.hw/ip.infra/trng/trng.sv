// SPDX-FileCopyrightText: 2026 Chili.CHIPS
//
// SPDX-License-Identifier: BSD-3-Clause

//==========================================================================
// Wireguard-1GE FPGA * NLnet-sponsored open-source implementation
//--------------------------------------------------------------------------
// Description:
//   TRNG, the CSR client: csr.trng (INTEGRATION.md) to trng_core. Reading
//   csr.trng.data takes the word (swacc).
//==========================================================================

module trng
  import csr_pkg::*;
  import trng_pkg::*;
(
    input  logic           arst_n,
    input  logic           clk,
    input  csr__out_t      from_csr,
    output csr__trng__in_t to_csr
);

  trng_cfg_t cfg;
  trng_sta_t sta;
  assign cfg.enable = from_csr.trng.ctrl.enable.value;
  assign cfg.raw    = from_csr.trng.ctrl.raw.value;
  assign cfg.rate   = from_csr.trng.ctrl.rate.value;

  trng_core u_core (
      .arst_n (arst_n),
      .clk    (clk),
      .cfg    (cfg),
      .rd     (from_csr.trng.data.data.swacc),
      .sta    (sta)
  );

  assign to_csr.status.impl.next       = sta.impl;
  assign to_csr.status.ovf.next        = sta.ovf;
  assign to_csr.status.apt_fail_b.next = sta.bank[1].apt_fail;
  assign to_csr.status.rct_fail_b.next = sta.bank[1].rct_fail;
  assign to_csr.status.apt_fail_a.next = sta.bank[0].apt_fail;
  assign to_csr.status.rct_fail_a.next = sta.bank[0].rct_fail;
  assign to_csr.status.valid.next      = sta.valid;
  assign to_csr.status.ready.next      = sta.ready;
  assign to_csr.data.data.next         = sta.data;
  assign to_csr.rct_max.b.next         = sta.bank[1].rct_max;
  assign to_csr.rct_max.a.next         = sta.bank[0].rct_max;
  assign to_csr.apt_max.b.next         = sta.bank[1].apt_max;
  assign to_csr.apt_max.a.next         = sta.bank[0].apt_max;

endmodule : trng

// -----------------------------------------------------------------------------
// Project:     WireGuard-FPGA
// Description: NLnet-funded open-source implementation
// Funding:     https://nlnet.nl/project/KlusterLab-Wireguard (2023-12 to 2025-12)
// -----------------------------------------------------------------------------
