// SPDX-License-Identifier: GPL-3.0-or-later

// =============================================================
//
// VProc user code for WireGuard test bench udpPgIp BFM nodes
//
// Copyright (c) 2025 Simon Southwell. Confidential
//
// This file is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// The file is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this file. If not, see <http://www.gnu.org/licenses/>.
//
// =============================================================

#include <cstdio>
#include <cstdint>
#include "VProcClass.h"
#include "udpIpPg.h"

extern "C" {
#include "mem.h"
}

// ----------------------------------------------------------------------------
// Node definitions: MAC/IP/UDP ports
// ----------------------------------------------------------------------------
#define NODE1_MAC_ADDR   0xd89ef3887ec3ULL  // D8:9E:F3:88:7E:C3
#define NODE1_IPV4_ADDR  0xc0a81908        // 192.168.25.8
#define NODE1_UDP_PORT   0x0400            // UDP port 1024

#define NODE2_MAC_ADDR   0x90324b070bd1ULL  // 90:32:4B:07:0B:D1
#define NODE2_IPV4_ADDR  0xc0a89801        // 192.168.152.1
#define NODE2_UDP_PORT   0x0401            // UDP port 1025

#define NODE3_MAC_ADDR   0xAABBCCDDEEFFULL  // example MAC for Node3
#define NODE3_IPV4_ADDR  0xc0a80103        // 192.168.1.3
#define NODE3_UDP_PORT   0x0500            // UDP port 1280

#define NODE4_MAC_ADDR   0x112233445566ULL  // example MAC for Node4
#define NODE4_IPV4_ADDR  0xc0a80104        // 192.168.1.4
#define NODE4_UDP_PORT   0x0501            // UDP port 1281

#define PAYLOAD_LEN      64
#define PKT_BUF_SIZE     (2*1024)

// One buffer per sender (0: Node1, 1: Node3): both build their frame at
// the same time, once the routes are in
static uint8_t  payload[2][PKT_BUF_SIZE];
static uint32_t frmBuf[2][PKT_BUF_SIZE];

// The test is done when both receivers (nodes 2 and 4) have their own frame
// (bit 0: node 2, bit 1: node 4): a frame on the wrong node, or a second
// one, does not count
static unsigned rx_seen = 0;

// A receiving node, for its callback
struct rxNode {
    udpIpPg* pg;
    unsigned node;  // 2 or 4
    unsigned bit;   // its bit in rx_seen
    uint16_t port;  // the UDP destination port its sender uses
};

// Set to 1 in the shared mem_model memory by models/bfm_uart.sv once its
// UART bus writes have filled the routing table (its ROUTES_DONE_ADDR). The
// HDL's MemModelWrite goes to node 0's space, the one the models share
#define ROUTES_DONE_ADDR 0x50001000ULL
#define SHARED_MEM_NODE  0

// Idle until the routes are in, whatever the UART speed (UART_SIM_TICK_CLKS)
static void waitRoutes(udpIpPg& pUdp, uint32_t node) {
    VPrint("Node%u: waiting for the routes (models/bfm_uart.sv)...\n", node);
    while (ReadRamWord(ROUTES_DONE_ADDR, 1, SHARED_MEM_NODE) == 0) pUdp.UdpVpSendIdle(100);
    VPrint("Node%u: routes in\n", node);
}

// ----------------------------------------------------------------------------
// Generic RX callback: print packet info. hdl is the receiving node; the
// last frame asks tb.sv to end the run (udpIpPg halt).
// ----------------------------------------------------------------------------
static void rxCallback(udpIpPg::rxInfo_t info, void* hdl) {
    rxNode* rx = static_cast<rxNode*>(hdl);
    VPrint("\n=== Received packet on node %u ===\n", rx->node);
    VPrint("  MAC src      = %012lX\n", (unsigned long)info.mac_src_addr);
    VPrint("  IPv4 src     = %08X\n", info.ipv4_src_addr);
    VPrint("  UDP src port = %04X\n", info.udp_src_port);
    VPrint("  UDP dst port = %04X\n", info.udp_dst_port);
    VPrint("  Payload (%u bytes):\n", info.rx_len);
    for (uint32_t i = 0; i < info.rx_len; ++i) {
        VPrint(" %02X", info.rx_payload[i]);
        if ((i & 0xF) == 0xF) VPrint("\n");
    }
    VPrint("\n=== End receive ===\n");

    if (info.udp_dst_port != rx->port) {
        VPrint("ERROR: node %u got a frame for UDP port %04X, not %04X: not counted\n", rx->node,
               info.udp_dst_port, rx->port);
        return;
    }
    rx_seen |= rx->bit;
    if (rx_seen == 3u) {
        VPrint("\n=== All frames received: test done ===\n");
        rx->pg->UdpVpSetHalt(1);
    }
}

// ----------------------------------------------------------------------------
// VUserMain1: Node1 sends to Node2
// ----------------------------------------------------------------------------
extern "C" void VUserMain1(void) {
    VPrint("Node1: initializing packet generator\n");
    udpIpPg pUdp(1, NODE1_IPV4_ADDR, NODE1_MAC_ADDR, NODE1_UDP_PORT);

    waitRoutes(pUdp, 1);

    for (uint32_t i = 0; i < PAYLOAD_LEN; ++i) payload[0][i] = uint8_t(i);

    udpIpPg::udpConfig_t cfg;
    cfg.mac_dst_addr = NODE2_MAC_ADDR;
    cfg.ip_dst_addr  = NODE2_IPV4_ADDR;
    cfg.dst_port     = NODE2_UDP_PORT;

    uint32_t frameLen = pUdp.genUdpIpPkt(cfg, frmBuf[0], reinterpret_cast<uint32_t*>(payload[0]), PAYLOAD_LEN);
    VPrint("Node1: frameLen = %u bytes\n", frameLen);
    pUdp.UdpVpSendRawEthFrame(frmBuf[0], frameLen);
    VPrint("Node1: frame sent to Node2\n");

    while (true) pUdp.UdpVpSendIdle(1);
}

// ----------------------------------------------------------------------------
// VUserMain2: Node2 receives
// ----------------------------------------------------------------------------
extern "C" void VUserMain2(void) {
    VPrint("Node2: initializing receiver\n");
    udpIpPg pUdp(2, NODE2_IPV4_ADDR, NODE2_MAC_ADDR, NODE2_UDP_PORT);
    static rxNode rx = {&pUdp, 2, 1u, NODE2_UDP_PORT};
    pUdp.registerUsrRxCbFunc(rxCallback, &rx);
    while (true) pUdp.UdpVpSendIdle(1);
}

// ----------------------------------------------------------------------------
// VUserMain3: Node3 sends to Node4
// ----------------------------------------------------------------------------
extern "C" void VUserMain3(void) {
    VPrint("Node3: initializing packet generator\n");
    udpIpPg pUdp(3, NODE3_IPV4_ADDR, NODE3_MAC_ADDR, NODE3_UDP_PORT);

    waitRoutes(pUdp, 3);

    for (uint32_t i = 0; i < PAYLOAD_LEN; ++i) payload[1][i] = uint8_t(i);

    udpIpPg::udpConfig_t cfg;
    cfg.mac_dst_addr = NODE4_MAC_ADDR;
    cfg.ip_dst_addr  = NODE4_IPV4_ADDR;
    cfg.dst_port     = NODE4_UDP_PORT;

    uint32_t frameLen = pUdp.genUdpIpPkt(cfg, frmBuf[1], reinterpret_cast<uint32_t*>(payload[1]), PAYLOAD_LEN);
    VPrint("Node3: frameLen = %u bytes\n", frameLen);
    pUdp.UdpVpSendRawEthFrame(frmBuf[1], frameLen);
    VPrint("Node3: frame sent to Node4\n");

    while (true) pUdp.UdpVpSendIdle(1);
}

// ----------------------------------------------------------------------------
// VUserMain4: Node4 receives
// ----------------------------------------------------------------------------
extern "C" void VUserMain4(void) {
    VPrint("Node4: initializing receiver\n");
    udpIpPg pUdp(4, NODE4_IPV4_ADDR, NODE4_MAC_ADDR, NODE4_UDP_PORT);
    static rxNode rx = {&pUdp, 4, 2u, NODE4_UDP_PORT};
    pUdp.registerUsrRxCbFunc(rxCallback, &rx);
    while (true) pUdp.UdpVpSendIdle(1);
}
