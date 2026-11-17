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
  import dpe_pkg::*;

  localparam int BEAT_BYTES = DPE_DATA_BYTES;  // dpe_if tdata: 128 bits
  typedef dpe_data_t beat_t;

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
  localparam int IPV4_DST_OFFSET = IPV4_OFFSET + 16;  // 4 bytes, big-endian
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
  localparam logic [ 3:0] IPV4_IHL       = 4'd5;      // 5 words: no options
  localparam logic [ 7:0] IPV4_TTL       = 8'd64;

  //------------------------------------------------------------------
  // Headers, natural values. A packed struct puts its first member in the
  // top bits, which is also the first byte on the wire: the Ethernet, IPv4
  // and UDP members read as their big-endian wire bytes. Comments give the
  // true bit positions in the struct.
  typedef struct packed {
    mac_addr_t   dst;        // [111:64]
    mac_addr_t   src;        // [ 63:16]
    logic [15:0] ethertype;  // [ 15: 0]
  } eth_hdr_t;

  typedef struct packed {
    logic [3:0]  version;     // [159:156]
    logic [3:0]  ihl;         // [155:152] header length in 32-bit words
    logic [7:0]  dscp_ecn;    // [151:144]
    len16_t      total_len;   // [143:128] IPv4 header + payload, bytes
    logic [15:0] id;          // [127:112]
    logic [15:0] flags_frag;  // [111: 96] flags, fragment offset
    logic [7:0]  ttl;         // [ 95: 88]
    logic [7:0]  proto;       // [ 87: 80]
    logic [15:0] checksum;    // [ 79: 64]
    ipv4_addr_t  src;         // [ 63: 32]
    ipv4_addr_t  dst;         // [ 31:  0]
  } ipv4_hdr_t;

  typedef struct packed {
    udp_port_t   src_port;  // [63:48]
    udp_port_t   dst_port;  // [47:32]
    len16_t      len;       // [31:16] UDP header + payload, bytes
    logic [15:0] checksum;  // [15: 0]
  } udp_hdr_t;

  // WireGuard fields are little-endian on the wire: wg_frame_bytes() swaps
  // them, so they too hold natural values here
  typedef struct packed {
    logic [31:0]  msg_type;  // [127:96] WG_TYPE_DATA
    wg_receiver_t receiver;  // [ 95:64]
    wg_counter_t  counter;   // [ 63: 0]
  } wg_data_hdr_t;

  // The headers of an outgoing WireGuard data frame, in wire order
  typedef struct packed {
    eth_hdr_t     eth;   // [463:352] frame bytes  0-13
    ipv4_hdr_t    ipv4;  // [351:192] frame bytes 14-33
    udp_hdr_t     udp;   // [191:128] frame bytes 34-41
    wg_data_hdr_t wg;    // [127:  0] frame bytes 42-57
  } wg_frame_hdr_t;

  localparam int WG_FRAME_HDR_LEN = $bits(wg_frame_hdr_t) / 8;  // 58 = WG_PAYLOAD_OFFSET
  typedef logic [8*WG_FRAME_HDR_LEN-1:0] wg_frame_bytes_t;  // frame byte 0 in the top bits
  localparam int WG_HDR_TAIL_BYTES = WG_FRAME_HDR_LEN % BEAT_BYTES;  // 10, in the last header beat

  // What a WireGuard data frame adds to its padded plaintext: the UDP
  // length and the IPv4 total length are the padded plaintext plus these
  // (40 and 60 bytes)
  localparam len16_t WG_UDP_OVERHEAD = len16_t'(UDP_HDR_LEN + WG_DATA_HDR_LEN + POLY1305_TAG_LEN);
  localparam len16_t WG_IPV4_OVERHEAD = len16_t'(IPV4_HDR_LEN) + WG_UDP_OVERHEAD;

  // A peer's entry in the routing table: what the encryptor and the
  // decryptor need to build its frames. MAC, IP and UDP port are in bus byte
  // order (wire byte 0 in [7:0]), the others natural values.
  typedef struct packed {
    mac_addr_t    local_mac;    // [543:496]
    ipv4_addr_t   local_ip;     // [495:464]
    udp_port_t    local_port;   // [463:448]
    mac_addr_t    remote_mac;   // [447:400]
    ipv4_addr_t   remote_ip;    // [399:368]
    udp_port_t    remote_port;  // [367:352]
    wg_receiver_t remote_id;    // [351:320] the peer's receiver index
    wg_key_t      key;          // [319: 64]
    wg_counter_t  send_cnt;     // [ 63:  0]
  } wg_peer_cfg_t;

  //------------------------------------------------------------------
  // Byte order, in one place

  // Reverse the bytes of a field
  function automatic logic [15:0] bswap16(logic [15:0] x);
    return {x[7:0], x[15:8]};
  endfunction

  function automatic logic [31:0] bswap32(logic [31:0] x);
    return {bswap16(x[15:0]), bswap16(x[31:16])};
  endfunction

  function automatic logic [47:0] bswap48(logic [47:0] x);
    return {bswap16(x[15:0]), bswap16(x[31:16]), bswap16(x[47:32])};
  endfunction

  function automatic logic [63:0] bswap64(logic [63:0] x);
    return {bswap32(x[31:0]), bswap32(x[63:32])};
  endfunction

  // The frame bytes of the headers: WireGuard fields little-endian
  function automatic wg_frame_bytes_t wg_frame_bytes(wg_frame_hdr_t h);
    h.wg.msg_type = bswap32(h.wg.msg_type);
    h.wg.receiver = bswap32(h.wg.receiver);
    h.wg.counter  = bswap64(h.wg.counter);
    return h;
  endfunction

  // Beat k of a frame whose first bytes are `bytes`: frame byte n goes to
  // beat n / BEAT_BYTES at tdata[8*(n % BEAT_BYTES) +: 8]; bytes past the
  // headers are 0
  function automatic beat_t hdr_beat(wg_frame_bytes_t bytes, int k);
    beat_t b = '0;
    for (int i = 0; i < BEAT_BYTES; i++) begin
      if (k * BEAT_BYTES + i < WG_FRAME_HDR_LEN) begin
        b[8*i+:8] = bytes[8*(WG_FRAME_HDR_LEN-1-(k*BEAT_BYTES+i))+:8];
      end
    end
    return b;
  endfunction

  localparam int WG_PAD_BLOCK = 16;

  // WireGuard pads the plaintext to a multiple of 16 bytes. This gives the
  // next multiple ABOVE len: one block too many when len already is one
  // (the DPE's behaviour so far; to be fixed on its own)
  function automatic len16_t wg_padded_len(len16_t len);
    return (len | len16_t'(WG_PAD_BLOCK - 1)) + len16_t'(1);
  endfunction

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

  //------------------------------------------------------------------
  // The tkeep of a beat that holds its first n bytes (n of 0 to BEAT_BYTES:
  // a larger n keeps them all)
  function automatic dpe_keep_t keep_first(len16_t n);
    dpe_keep_t k;
    for (int b = 0; b < BEAT_BYTES; b++) begin
      k[b] = len16_t'(b) < n;
    end
    return k;
  endfunction

  // The beat with the bytes that keep does not hold set to zero
  function automatic beat_t keep_bytes(beat_t beat, dpe_keep_t keep);
    beat_t m;
    for (int b = 0; b < BEAT_BYTES; b++) begin
      m[8*b+:8] = keep[b] ? beat[8*b+:8] : 8'h00;
    end
    return m;
  endfunction

endpackage : net_pkg
`endif
