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
//  GMII: the signals between the MAC (FPGA) and one PHY, its clocks
//  included. RX runs on the PHY's rx_clk; TX on gtx_clk from the MAC at
//  1000 Mb/s, on the PHY's mii_tx_clk at 10/100 Mb/s (MII)
//==========================================================================

interface gmii_if;

  logic       rx_clk;  // from the PHY: 125 MHz, or 2.5/25 MHz (MII)
  logic [7:0] rxd;
  logic       rxdv;
  logic       rxer;

  logic       mii_tx_clk;  // from the PHY: the MII TX clock, 2.5/25 MHz
  logic       gtx_clk;  // to the PHY: the GMII TX clock, 125 MHz
  logic [7:0] txd;
  logic       txen;
  logic       txer;

  //----------------------------------------
  // the MAC
  //----------------------------------------
  modport MST(input rx_clk, rxd, rxdv, rxer, mii_tx_clk, output gtx_clk, txd, txen, txer);

  //----------------------------------------
  // the PHY
  //----------------------------------------
  modport SLV(output rx_clk, rxd, rxdv, rxer, mii_tx_clk, input gtx_clk, txd, txen, txer);

endinterface : gmii_if

// -----------------------------------------------------------------------------
// Project:     WireGuard-FPGA
// Description: NLnet-funded open-source implementation
// Funding:     https://nlnet.nl/project/KlusterLab-Wireguard (2023-12 to 2025-12)
// -----------------------------------------------------------------------------
