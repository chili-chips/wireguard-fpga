// SPDX-FileCopyrightText: 2026 Chili.CHIPS
//
// SPDX-License-Identifier: BSD-3-Clause

//==========================================================================
// Wireguard-1GE FPGA * NLnet-sponsored open-source implementation
//--------------------------------------------------------------------------
// Description:
//   The network headers the DPE reads and writes: Ethernet II, IPv4, UDP
//   and the WireGuard data message (transport data, type 4). Header sizes,
//   field offsets in the frame, protocol constants, and the byte order.
//
//   Byte order, in one place. dpe_if carries a frame little-endian: frame
//   byte k is in beat k / BEAT_BYTES, at tdata[8*(k % BEAT_BYTES) +: 8].
//   Ethernet, IPv4 and UDP fields are big-endian (network order), WireGuard
//   fields little-endian: be16()/be32() and le32()/le64() read a field
//   from the beat that holds it, by the field's frame offset, and give its
//   natural value (EtherType 0x0800, not 0x0008).
//==========================================================================

`ifndef _NET_PKG
`define _NET_PKG
package net_pkg;

  localparam int BEAT_BYTES = dpe_pkg::DPE_DATA_BYTES;  // dpe_if tdata: 128 bits
  typedef logic [8*BEAT_BYTES-1:0] beat_t;

  //------------------------------------------------------------------
  // Header sizes (bytes)
  localparam int ETH_HDR_LEN = 14;  // dst MAC, src MAC, EtherType
  localparam int IPV4_HDR_LEN = 20;  // IHL 5: no options
  localparam int UDP_HDR_LEN = 8;
  localparam int WG_DATA_HDR_LEN = 16;  // type, receiver, counter
  localparam int POLY1305_TAG_LEN = 16;

  // Where each header starts in the frame
  localparam int IPV4_OFFSET = ETH_HDR_LEN;  // 14
  localparam int UDP_OFFSET = IPV4_OFFSET + IPV4_HDR_LEN;  // 34
  localparam int WG_OFFSET = UDP_OFFSET + UDP_HDR_LEN;  // 42
  localparam int WG_PAYLOAD_OFFSET = WG_OFFSET + WG_DATA_HDR_LEN;  // 58

  //------------------------------------------------------------------
  // Field offsets in the frame
  localparam int ETH_TYPE_OFFSET = 12;  // 2 bytes, big-endian
  localparam int IPV4_VER_IHL_OFFSET = IPV4_OFFSET;  // version in [7:4]
  localparam int IPV4_TOTAL_LEN_OFFSET = IPV4_OFFSET + 2;  // 2 bytes, big-endian
  localparam int IPV4_PROTO_OFFSET = IPV4_OFFSET + 9;
  localparam int IPV4_SRC_OFFSET = IPV4_OFFSET + 12;  // 4 bytes, big-endian
  localparam int IPV4_DST_OFFSET = IPV4_OFFSET + 16;  // 4 bytes, big-endian
  localparam int UDP_SRC_PORT_OFFSET = UDP_OFFSET;  // 2 bytes, big-endian
  localparam int UDP_DST_PORT_OFFSET = UDP_OFFSET + 2;
  localparam int UDP_LEN_OFFSET = UDP_OFFSET + 4;
  localparam int WG_TYPE_OFFSET = WG_OFFSET;  // 4 bytes, little-endian
  localparam int WG_RECEIVER_OFFSET = WG_OFFSET + 4;  // 4 bytes, little-endian
  localparam int WG_COUNTER_OFFSET = WG_OFFSET + 8;  // 8 bytes, little-endian

  //------------------------------------------------------------------
  // Field types
  typedef logic [47:0] mac_addr_t;
  typedef logic [31:0] ipv4_addr_t;
  typedef logic [15:0] udp_port_t;
  typedef logic [15:0] len16_t;  // an IPv4 or UDP length
  typedef logic [31:0] wg_receiver_t;  // WireGuard receiver (and sender) index
  typedef logic [63:0] wg_counter_t;  // WireGuard nonce counter
  typedef logic [255:0] wg_key_t;  // ChaCha20-Poly1305 key

  //------------------------------------------------------------------
  // Protocol constants (natural values)
  localparam logic [15:0] ETHERTYPE_IPV4 = 16'h0800;
  localparam logic [ 3:0] IPV4_VERSION   = 4'd4;
  localparam logic [ 7:0] IP_PROTO_UDP   = 8'd17;
  localparam logic [31:0] WG_TYPE_DATA   = 32'd4;     // transport data message

  //------------------------------------------------------------------
  // Which beat holds frame byte `offset`, and where in it
  function automatic int beat_of(int offset);
    return offset / BEAT_BYTES;
  endfunction

  function automatic logic [7:0] byte_at(beat_t beat, int offset);
    return beat[8*(offset%BEAT_BYTES)+:8];
  endfunction

  // A field that starts at frame byte `offset`, read from the beat holding
  // its first byte (it must not cross into the next beat)
  function automatic logic [15:0] be16(beat_t beat, int offset);
    return {byte_at(beat, offset), byte_at(beat, offset + 1)};
  endfunction

  function automatic logic [31:0] be32(beat_t beat, int offset);
    return {be16(beat, offset), be16(beat, offset + 2)};
  endfunction

  function automatic logic [15:0] le16(beat_t beat, int offset);
    return {byte_at(beat, offset + 1), byte_at(beat, offset)};
  endfunction

  function automatic logic [31:0] le32(beat_t beat, int offset);
    return {le16(beat, offset + 2), le16(beat, offset)};
  endfunction

  function automatic logic [63:0] le64(beat_t beat, int offset);
    return {le32(beat, offset + 4), le32(beat, offset)};
  endfunction

endpackage : net_pkg
`endif
