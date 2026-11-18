// SPDX-FileCopyrightText: 2026 Chili.CHIPS
//
// SPDX-License-Identifier: BSD-3-Clause

//==========================================================================
// Wireguard-1GE FPGA * NLnet-sponsored open-source implementation
//--------------------------------------------------------------------------
// Description: the IP lookup engine's (ip.lkup) types. Its CSR port is the
//  routing_table regfile of csr.rdl (external): the generated structs by
//  short names, named from the lookup's side
//   - csr_cfg_t: CPU to table: request, write, address, data
//   - csr_sta_t: table to CPU: write and read acknowledge, read data
//==========================================================================

package lkup_pkg;
  import csr_pkg::*;

  typedef csr__routing_table__external__out_t csr_cfg_t;
  typedef csr__routing_table__external__in_t csr_sta_t;

endpackage

// -----------------------------------------------------------------------------
// Project:     WireGuard-FPGA
// Description: NLnet-funded open-source implementation
// Funding:     https://nlnet.nl/project/KlusterLab-Wireguard (2023-12 to 2025-12)
// -----------------------------------------------------------------------------
