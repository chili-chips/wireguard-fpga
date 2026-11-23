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
//   Main program for WireGuard FPGA
//==========================================================================

#include <stdint.h>
#include "csr_regs.h"
#include "string_bare.h"
#include "uart.h"
#include "ethernet.h"
#include "network.h"
#include "chacha20poly1305.h"
#include "poly1305.h"
#include "blake2s.h"
#include "curve25519.h"
#include "hkdf.h"
#include "random.h"
#include "timer.h"

// TEST CODE

// RFC 8439 2.5.2: Poly1305 over "Cryptographic Forum Research Group"
static const uint8_t rfc_poly_key[32] = {
   0x85, 0xd6, 0xbe, 0x78, 0x57, 0x55, 0x6d, 0x33,
   0x7f, 0x44, 0x52, 0xfe, 0x42, 0xd5, 0x06, 0xa8,
   0x01, 0x03, 0x80, 0x8a, 0xfb, 0x0d, 0xb2, 0xfd,
   0x4a, 0xbf, 0xf6, 0xaf, 0x41, 0x49, 0xf5, 0x1b};

static const uint8_t rfc_poly_tag[16] = {
   0xa8, 0x06, 0x1d, 0xc1, 0x30, 0x51, 0x36, 0xc6,
   0xc2, 0x2b, 0x8b, 0xaf, 0x0c, 0x01, 0x27, 0xa9};

// RFC 8439 2.8.2: AEAD encryption of the "sunscreen" text
static const uint8_t rfc_aead_key[32] = {
   0x80, 0x81, 0x82, 0x83, 0x84, 0x85, 0x86, 0x87,
   0x88, 0x89, 0x8a, 0x8b, 0x8c, 0x8d, 0x8e, 0x8f,
   0x90, 0x91, 0x92, 0x93, 0x94, 0x95, 0x96, 0x97,
   0x98, 0x99, 0x9a, 0x9b, 0x9c, 0x9d, 0x9e, 0x9f};

static const uint8_t rfc_aead_nonce[12] = {
   0x07, 0x00, 0x00, 0x00, 0x40, 0x41, 0x42, 0x43,
   0x44, 0x45, 0x46, 0x47};

static const uint8_t rfc_aead_aad[12] = {
   0x50, 0x51, 0x52, 0x53, 0xc0, 0xc1, 0xc2, 0xc3,
   0xc4, 0xc5, 0xc6, 0xc7};

static const uint8_t rfc_aead_ct[114] = {
   0xd3, 0x1a, 0x8d, 0x34, 0x64, 0x8e, 0x60, 0xdb, 0x7b, 0x86, 0xaf, 0xbc, 0x53, 0xef, 0x7e, 0xc2,
   0xa4, 0xad, 0xed, 0x51, 0x29, 0x6e, 0x08, 0xfe, 0xa9, 0xe2, 0xb5, 0xa7, 0x36, 0xee, 0x62, 0xd6,
   0x3d, 0xbe, 0xa4, 0x5e, 0x8c, 0xa9, 0x67, 0x12, 0x82, 0xfa, 0xfb, 0x69, 0xda, 0x92, 0x72, 0x8b,
   0x1a, 0x71, 0xde, 0x0a, 0x9e, 0x06, 0x0b, 0x29, 0x05, 0xd6, 0xa5, 0xb6, 0x7e, 0xcd, 0x3b, 0x36,
   0x92, 0xdd, 0xbd, 0x7f, 0x2d, 0x77, 0x8b, 0x8c, 0x98, 0x03, 0xae, 0xe3, 0x28, 0x09, 0x1b, 0x58,
   0xfa, 0xb3, 0x24, 0xe4, 0xfa, 0xd6, 0x75, 0x94, 0x55, 0x85, 0x80, 0x8b, 0x48, 0x31, 0xd7, 0xbc,
   0x3f, 0xf4, 0xde, 0xf0, 0x8e, 0x4b, 0x7a, 0x9d, 0xe5, 0x76, 0xd2, 0x65, 0x86, 0xce, 0xc6, 0x4b,
   0x61, 0x16};

static const uint8_t rfc_aead_tag[16] = {
   0x1a, 0xe1, 0x0b, 0x59, 0x4f, 0x09, 0xe2, 0x6a,
   0x7e, 0x90, 0x2e, 0xcb, 0xd0, 0x60, 0x06, 0x91};

static void test_result(const char *name, int ok, int *pass) {
   uart_send(name);
   uart_send(ok ? ": PASS\r\n" : ": FAIL\r\n");
   if (!ok) {
      *pass = 0;
   }
}

static int test_chacha20poly1305(void) {
   const char *poly_msg = "Cryptographic Forum Research Group";
   const char *aead_pt  = "Ladies and Gentlemen of the class of '99: If I could offer you "
                          "only one tip for the future, sunscreen would be it.";
   const size_t pt_len  = sizeof(rfc_aead_ct);

   uint8_t tag[16];
   uint8_t buf[sizeof(rfc_aead_ct)];
   int pass = 1;

   // Poly1305 alone, RFC 8439 2.5.2
   poly1305_mac(tag, rfc_poly_key, (const uint8_t *)poly_msg, bare_strlen(poly_msg));
   test_result("Poly1305 RFC 8439 2.5.2", memcmp(tag, rfc_poly_tag, 16) == 0, &pass);

   // AEAD encrypt, RFC 8439 2.8.2: exact ciphertext and tag
   int ret = chacha20poly1305_encrypt(
      buf, tag, rfc_aead_key, rfc_aead_nonce,
      (const uint8_t *)aead_pt, pt_len, rfc_aead_aad, sizeof(rfc_aead_aad));
   test_result("AEAD encrypt RFC 8439 2.8.2", ret == 0 && bare_strlen(aead_pt) == pt_len
               && memcmp(buf, rfc_aead_ct, pt_len) == 0
               && memcmp(tag, rfc_aead_tag, 16) == 0, &pass);

   // AEAD decrypt of the RFC ciphertext
   ret = chacha20poly1305_decrypt(
      buf, rfc_aead_key, rfc_aead_nonce, rfc_aead_ct, pt_len,
      rfc_aead_tag, rfc_aead_aad, sizeof(rfc_aead_aad));
   test_result("AEAD decrypt RFC 8439 2.8.2", ret == 0
               && memcmp(buf, aead_pt, pt_len) == 0, &pass);

   // A flipped tag bit must be rejected
   for (int i = 0; i < 16; i++) {
      tag[i] = rfc_aead_tag[i];
   }
   tag[15] ^= 0x80;
   ret = chacha20poly1305_decrypt(
      buf, rfc_aead_key, rfc_aead_nonce, rfc_aead_ct, pt_len,
      tag, rfc_aead_aad, sizeof(rfc_aead_aad));
   test_result("AEAD bad tag rejected", ret != 0, &pass);

   uart_send(pass ? "ChaCha20-Poly1305 test passed!\r\n"
                  : "ChaCha20-Poly1305 test failed!\r\n");
   return pass ? 0 : -1;
}

static int test_blake2s(void) {
   uint8_t out[32];
   int pass = 1;

   struct {
      const char *input;
      const uint8_t expected[32];
   } tests[] = {
      // RFC 7693 official test vectors (BLAKE2s-256)
      {
         "", // empty string
         {0x69, 0x21, 0x7a, 0x30, 0x79, 0x90, 0x80, 0x94,
         0xe1, 0x11, 0x21, 0xd0, 0x42, 0x35, 0x4a, 0x7c,
         0x1f, 0x55, 0xb6, 0x48, 0x2c, 0xa1, 0xa5, 0x1e,
         0x1b, 0x25, 0x0d, 0xfd, 0x1e, 0xd0, 0xee, 0xf9}
      },
      {
         "abc",
         {0x50, 0x8c, 0x5e, 0x8c, 0x32, 0x7c, 0x14, 0xe2,
         0xe1, 0xa7, 0x2b, 0xa3, 0x4e, 0xeb, 0x45, 0x2f,
         0x37, 0x45, 0x8b, 0x20, 0x9e, 0xd6, 0x3a, 0x29,
         0x4d, 0x99, 0x9b, 0x4c, 0x86, 0x67, 0x59, 0x82}
      }
   };

   size_t num_tests = sizeof(tests) / sizeof(tests[0]);

   for (size_t i = 0; i < num_tests; i++) {
      const char *msg = tests[i].input;
      const uint8_t *expected = tests[i].expected;

      // Compute hash
      hash(out, 32, NULL, 0, msg, bare_strlen(msg));

      // Compare
      int ok = 1;
      for (int j = 0; j < 32; j++) {
         if (out[j] != expected[j]) {
               ok = 0;
               break;
         }
      }

      if (!ok) pass = 0;
   }

   if (pass) {
      uart_send("BLAKE2s test passed!\r\n");
   } else {
      uart_send("BLAKE2s test failed!\r\n");
      return -1;
   }

   return 0;
}

static void test_curve25519(void) {
   /* Simulate Alice and Bob doing a complete key exchange */
   uint8_t alice_private[32], bob_private[32];
   uint8_t alice_public[32], bob_public[32];
   uint8_t alice_shared[32], bob_shared[32];

   // Generate private keys
   random_32bytes(alice_private);
   random_32bytes(bob_private);

   // Generate public keys
   int alice_keygen = curve25519_generate_public_key(alice_public, alice_private);
   int bob_keygen = curve25519_generate_public_key(bob_public, bob_private);

   // Exchange public keys and compute shared secrets
   int alice_shared_result = curve25519_compute_shared_secret(alice_shared, alice_private, bob_public);
   int bob_shared_result = curve25519_compute_shared_secret(bob_shared, bob_private, alice_public);

   // Verify shared secrets match
   int secrets_match = memcmp(alice_shared, bob_shared, 32) == 0;

   if (secrets_match) {
      uart_send("Key exchange successful! Alice and Bob have the same shared secret\r\n");
   } else {
      uart_send("Key exchange failed! Shared secrets don't match.\r\n");
   }
}

static int test_rng(void)
{
   uint8_t random_bytes[32];
   uint32_t rand_num;

   for (uint8_t i = 0; i < 10; i++) {
      uart_send("Generating random 32 bytes: ");
      random_32bytes(random_bytes);
      uart_send_hex_bytes(random_bytes, 32);
      uart_send("\r\n");

      uart_send("Generating random number between 10 and 1000: ");
      rand_num = random_range(10, 1000);
      uart_send_dec(rand_num);
      uart_send("\r\n");
   }

   return 0;
}

static int test_timer(void)
{
   for (uint8_t i = 0; i < 10; i++) {
      delay_ms(1000u); // 1 second pause
      uart_send(".");
   }
   uart_send("\r\nTest passed!\r\n");

   return 0;
}

// APP CODE

eth_raw_packet_t  eth_packet_rx;
eth_raw_packet_t  eth_packet_tx;
net_config_t      net_config;
net_arp_cache_t   net_arp_cache = {0};

#define DPE_PAUSE_TIMEOUT_MS 100

// Pause the DPE and wait until it holds no packet (pause/drain), before a
// table or wg_ip/wg_port write. An Ethernet port that does not send (no
// link) back-pressures the DPE, so it may never drain: after
// DPE_PAUSE_TIMEOUT_MS the pause ends and the caller writes nothing (false)
bool dpe_pause(void) {
   CSR_RMW(dpe.fcr, CSR__DPE__FCR__PAUSE, 1);
   uint32_t start = cycles();
   while (!CSR_GET(dpe.fcr, CSR__DPE__FCR__IDLE)) {
      if (cycles() - start > DPE_PAUSE_TIMEOUT_MS * CYCLES_PER_MS) {
         CSR_RMW(dpe.fcr, CSR__DPE__FCR__PAUSE, 0);
         uart_send("Error: the data plane did not drain; nothing written.\r\n");
         return false;
      }
   }
   return true;
}

void dpe_resume(void) {
   CSR_RMW(dpe.fcr, CSR__DPE__FCR__PAUSE, 0);
}

// The data plane takes IPv4 UDP to wg_ip:wg_port as WireGuard for this device:
// the device's own address and its WireGuard listen port
// The DPE pauses while they change: no packet sees half of them. False: the
// DPE did not drain, nothing written
bool set_wg_addr(const net_config_t* config) {
   if (!dpe_pause()) return false;
   CSR_REG32(dpe.wg_ip) = ((uint32_t)config->ip[0] << 24) | ((uint32_t)config->ip[1] << 16) |
                          ((uint32_t)config->ip[2] << 8) | (uint32_t)config->ip[3];
   CSR_SET(dpe.wg_port, CSR__DPE__WG_PORT__PORT, config->wg_port);
   dpe_resume();
   return true;
}

void init_network(net_config_t* config) {
   if (config->ip[0] == 0 && config->ip[1] == 0 && config->ip[2] == 0 && config->ip[3] == 0) {
      config->ip[0] = 192;
      config->ip[1] = 168;
      config->ip[2] = 1;
      config->ip[3] = 98;

      config->sub_mask[0] = 255;
      config->sub_mask[1] = 255;
      config->sub_mask[2] = 255;
      config->sub_mask[3] = 0;

      config->mac[0] = 0xCC;
      config->mac[1] = 0xBA;
      config->mac[2] = 0xCA;
      config->mac[3] = 0xCA;
      config->mac[4] = 0x00;
      config->mac[5] = 0x01;

      config->def_gw[0] = 192;
      config->def_gw[1] = 168;
      config->def_gw[2] = 1;
      config->def_gw[3] = 254;

      config->def_if = 1;
   }
   if (config->wg_port == 0) {
      config->wg_port = 51820;
   }
   set_wg_addr(config);
}

void show_network(net_config_t* config) {
   uart_send("Network configuration:\r\n");
   uart_send("  IP address:        ");
   uart_send_ip(config->ip);
   uart_send("\r\n  Subnet mask:       ");
   uart_send_ip(config->sub_mask);
   uart_send("\r\n  MAC address:       ");
   uart_send_mac(config->mac);
   uart_send("\r\n  Default gateway:   ");
   uart_send_ip(config->def_gw);
   uart_send("\r\n  Default interface: ");
   uart_send_dec(config->def_if);
   switch (config->def_if) {
      case 0:
         uart_send(" [0....]");
         break;
      case 1:
         uart_send(" [.1...]");
         break;
      case 2:
         uart_send(" [..2..]");
         break;
      case 3:
         uart_send(" [...3.]");
         break;
      case 4:
         uart_send(" [....4]");
         break;
      case 5:
         uart_send(" [.1.3.]");
         break;
      case 6:
         uart_send(" [..2.4]");
         break;
      case 7:
         uart_send(" [.1234]");
         break;
   }
   uart_send("\r\n  WireGuard port:    ");
   uart_send_dec(config->wg_port);
   uart_send("\r\n");
}

void config_network(net_config_t* config) {
   char uart_rx_data[UART_RXBUF_SIZE];
   const net_config_t old = *config;  // the IP and port the DPE has

   uart_send("Enter new network configuration:\r\n");

   uart_send("  IP address [");
   uart_send_ip(config->ip);
   uart_send("]: ");
   while (!uart_recv(uart_rx_data));
   net_str_parse_ip(uart_rx_data, &config->ip);

   uart_send("  Subnet mask [");
   uart_send_ip(config->sub_mask);
   uart_send("]: ");
   while (!uart_recv(uart_rx_data));
   net_str_parse_ip(uart_rx_data, &config->sub_mask);

   uart_send("  Generate new MAC address? (y/n) [n]: ");
   while (!uart_recv(uart_rx_data));
   if (uart_rx_data[0] == 'y' || uart_rx_data[0] == 'Y') {
      uint8_t random_bytes[32];  // random_32bytes() writes 32 bytes
      random_32bytes(random_bytes);
      config->mac[4] = random_bytes[0]; // Use random byte for MAC suffix
      config->mac[5] = random_bytes[1]; // Use random byte for MAC suffix
      // a made-up MAC is locally administered (bit 1) and unicast (bit 0)
      config->mac[0] = (uint8_t)((config->mac[0] | 0x02) & ~0x01);
   }

   uart_send("  Default gateway [");
   uart_send_ip(config->def_gw);
   uart_send("]: ");
   while (!uart_recv(uart_rx_data));
   net_str_parse_ip(uart_rx_data, &config->def_gw);

   uart_send("  Default interface (0-7) [");
   uart_send_dec(config->def_if);
   uart_send("]: ");
   while (!uart_recv(uart_rx_data));
   str_parse_uint8(uart_rx_data, &config->def_if, 0, 7);

   uart_send("  WireGuard port (1-65535) [");
   uart_send_dec(config->wg_port);
   uart_send("]: ");
   while (!uart_recv(uart_rx_data));
   uint32_t wg_port = config->wg_port;
   str_parse_uint32(uart_rx_data, &wg_port, 1, 65535);
   config->wg_port = (uint16_t)wg_port;
   if (set_wg_addr(config)) {
      uart_send("Network configuration updated.\r\n");
   } else {
      // the firmware keeps what the data plane uses
      for (int i = 0; i < 4; i++) config->ip[i] = old.ip[i];
      config->wg_port = old.wg_port;
      uart_send("Network configuration updated, but not the IP address and WireGuard port.\r\n");
   }

   show_network(config);
}

void show_routes_entry(int i) {
   uart_send("  (");
   uart_send_dec(i);

   uint32_t uip = CSR_REG32(routing_table.entry[i].ip);
   ip_t ip = {(uint8_t)((uip >> 24) & 0xFF), (uint8_t)((uip >> 16) & 0xFF), (uint8_t)((uip >> 8) & 0xFF), (uint8_t)(uip & 0xFF)};
   uart_send(") IP: ");
   uart_send_ip(ip);

   uint32_t umask = CSR_REG32(routing_table.entry[i].mask);
   ip_t mask = {(uint8_t)((umask >> 24) & 0xFF), (uint8_t)((umask >> 16) & 0xFF), (uint8_t)((umask >> 8) & 0xFF), (uint8_t)(umask & 0xFF)};
   uart_send(", Mask: ");
   uart_send_ip(mask);

   uint32_t peer_idx = CSR_GET(routing_table.entry[i].peer_idx, CSR__ROUTING_TABLE__ENTRY__PEER_IDX__PEER_IDX);
   uart_send(", Peer index: ");
   uart_send_dec(peer_idx);

   uint32_t encrypt = CSR_GET(routing_table.entry[i].peer_idx, CSR__ROUTING_TABLE__ENTRY__PEER_IDX__ENCRYPT);
   uart_send(", Encrypt: ");
   uart_send_dec(encrypt);

   uint32_t dst = CSR_GET(routing_table.entry[i].dst, CSR__ROUTING_TABLE__ENTRY__DST__DST);
   uart_send(", Destination interface: ");
   uart_send_dec(dst);
   switch (dst) {
      case 0:
         uart_send(" [0....]");
         break;
      case 1:
         uart_send(" [.1...]");
         break;
      case 2:
         uart_send(" [..2..]");
         break;
      case 3:
         uart_send(" [...3.]");
         break;
      case 4:
         uart_send(" [....4]");
         break;
      case 5:
         uart_send(" [.1.3.]");
         break;
      case 6:
         uart_send(" [..2.4]");
         break;
      case 7:
         uart_send(" [.1234]");
         break;
   }

   uart_send("\r\n");
}

// The CPU reads the tables on a port of their own: no pause for reading
void show_routes(void) {
   uart_send("Routing table:\r\n");
   for (int i = 0; i < 64; i++) {
      show_routes_entry(i);
   }
}

// The prompts run with the DPE running; it pauses only for the writes
void config_routes(void) {
   char uart_rx_data[UART_RXBUF_SIZE];

   uart_send("Enter new routing table entry:\r\n");
   uart_send("  Entry index (0-63) [0]: ");
   while (!uart_recv(uart_rx_data));
   uint32_t entry_idx = 0;
   str_parse_uint32(uart_rx_data, &entry_idx, 0, 63);

   uart_send("  Destination IP address [");
   uint32_t uip = CSR_REG32(routing_table.entry[entry_idx].ip);
   ip_t ip = {(uint8_t)((uip >> 24) & 0xFF), (uint8_t)((uip >> 16) & 0xFF), (uint8_t)((uip >> 8) & 0xFF), (uint8_t)(uip & 0xFF)};
   uart_send_ip(ip);
   uart_send("]: ");
   while (!uart_recv(uart_rx_data));
   net_str_parse_ip(uart_rx_data, &ip);

   uart_send("  Subnet mask [");
   uint32_t umask = CSR_REG32(routing_table.entry[entry_idx].mask);
   ip_t mask = {(uint8_t)((umask >> 24) & 0xFF), (uint8_t)((umask >> 16) & 0xFF), (uint8_t)((umask >> 8) & 0xFF), (uint8_t)(umask & 0xFF)};
   uart_send_ip(mask);
   uart_send("]: ");
   while (!uart_recv(uart_rx_data));
   net_str_parse_ip(uart_rx_data, &mask);

   uart_send("  Peer index (0-63) [");
   uint32_t peer_idx = CSR_GET(routing_table.entry[entry_idx].peer_idx, CSR__ROUTING_TABLE__ENTRY__PEER_IDX__PEER_IDX);
   uart_send_dec(peer_idx);
   uart_send("]: ");
   while (!uart_recv(uart_rx_data));
   str_parse_uint32(uart_rx_data, &peer_idx, 0, 63);

   uart_send("  Encrypt (0/1: through the tunnel to the peer) [");
   uint32_t encrypt = CSR_GET(routing_table.entry[entry_idx].peer_idx, CSR__ROUTING_TABLE__ENTRY__PEER_IDX__ENCRYPT);
   uart_send_dec(encrypt);
   uart_send("]: ");
   while (!uart_recv(uart_rx_data));
   str_parse_uint32(uart_rx_data, &encrypt, 0, 1);

   uart_send("  Destination interface (0-7) [");
   uint32_t dst = CSR_GET(routing_table.entry[entry_idx].dst, CSR__ROUTING_TABLE__ENTRY__DST__DST);
   uart_send_dec(dst);
   uart_send("]: ");
   while (!uart_recv(uart_rx_data));
   str_parse_uint32(uart_rx_data, &dst, 0, 7);

   // Update routing table entry
   uip = ((uint32_t)ip[0] << 24) | ((uint32_t)ip[1] << 16) | ((uint32_t)ip[2] << 8) | (uint32_t)ip[3];
   umask = ((uint32_t)mask[0] << 24) | ((uint32_t)mask[1] << 16) | ((uint32_t)mask[2] << 8) | (uint32_t)mask[3];
   if (!dpe_pause()) return;
   CSR_REG32(routing_table.entry[entry_idx].ip) = uip;
   CSR_REG32(routing_table.entry[entry_idx].mask) = umask;
   // peer_idx and encrypt in one word write: a byte store reaches every lane on
   // this bus, and the DUMMY switch's table ignores byte enables
   CSR_REG32(routing_table.entry[entry_idx].peer_idx) =
      ((peer_idx << CSR__ROUTING_TABLE__ENTRY__PEER_IDX__PEER_IDX_bp) & CSR__ROUTING_TABLE__ENTRY__PEER_IDX__PEER_IDX_bm) |
      ((encrypt << CSR__ROUTING_TABLE__ENTRY__PEER_IDX__ENCRYPT_bp) & CSR__ROUTING_TABLE__ENTRY__PEER_IDX__ENCRYPT_bm);
   CSR_SET(routing_table.entry[entry_idx].dst, CSR__ROUTING_TABLE__ENTRY__DST__DST, dst);
   dpe_resume();

   uart_send("Routing table entry updated.\r\n");

   show_routes_entry(entry_idx);
}

void show_cryptokeys_entry(int i) {
   uart_send("  (");
   uart_send_dec(i);

   uart_send(") Local MAC: ");
   uart_send_hex(CSR_GET(cryptokey_table.entry[i].local_mac_47_32, CSR__CRYPTOKEY_TABLE__ENTRY__LOCAL_MAC_47_32__MAC), 4);
   uart_send_hex(CSR_REG32(cryptokey_table.entry[i].local_mac_31_0), 8);

   uart_send(", Local IP: ");
   uint32_t ulocal_ip = CSR_REG32(cryptokey_table.entry[i].local_ip);
   ip_t local_ip = {(uint8_t)((ulocal_ip >> 24) & 0xFF), (uint8_t)((ulocal_ip >> 16) & 0xFF), (uint8_t)((ulocal_ip >> 8) & 0xFF), (uint8_t)(ulocal_ip & 0xFF)};
   uart_send_ip(local_ip);

   uart_send(", Local port: ");
   uart_send_dec(CSR_GET(cryptokey_table.entry[i].local_port, CSR__CRYPTOKEY_TABLE__ENTRY__LOCAL_PORT__PORT));

   uart_send(", Local ID: 0x");
   uart_send_hex(CSR_REG32(cryptokey_table.entry[i].local_id), 8);

   uart_send("\r\n    Remote MAC: ");
   uart_send_hex(CSR_GET(cryptokey_table.entry[i].remote_mac_47_32, CSR__CRYPTOKEY_TABLE__ENTRY__REMOTE_MAC_47_32__MAC), 4);
   uart_send_hex(CSR_REG32(cryptokey_table.entry[i].remote_mac_31_0), 8);

   uart_send(", Remote IP: ");
   uint32_t uremote_ip = CSR_REG32(cryptokey_table.entry[i].remote_ip);
   ip_t remote_ip = {(uint8_t)((uremote_ip >> 24) & 0xFF), (uint8_t)((uremote_ip >> 16) & 0xFF), (uint8_t)((uremote_ip >> 8) & 0xFF), (uint8_t)(uremote_ip & 0xFF)};
   uart_send_ip(remote_ip);

   uart_send(", Remote port: ");
   uart_send_dec(CSR_GET(cryptokey_table.entry[i].remote_port, CSR__CRYPTOKEY_TABLE__ENTRY__REMOTE_PORT__PORT));

   uart_send(", Remote ID: 0x");
   uart_send_hex(CSR_REG32(cryptokey_table.entry[i].remote_id), 8);

   uart_send("\r\n    Encryption key: 0x");
   uart_send_hex(CSR_REG32(cryptokey_table.entry[i].encrypt_key_255_224), 8);
   uart_send_hex(CSR_REG32(cryptokey_table.entry[i].encrypt_key_223_192), 8);
   uart_send_hex(CSR_REG32(cryptokey_table.entry[i].encrypt_key_191_160), 8);
   uart_send_hex(CSR_REG32(cryptokey_table.entry[i].encrypt_key_159_128), 8);
   uart_send_hex(CSR_REG32(cryptokey_table.entry[i].encrypt_key_127_96), 8);
   uart_send_hex(CSR_REG32(cryptokey_table.entry[i].encrypt_key_95_64), 8);
   uart_send_hex(CSR_REG32(cryptokey_table.entry[i].encrypt_key_63_32), 8);
   uart_send_hex(CSR_REG32(cryptokey_table.entry[i].encrypt_key_31_0), 8);

   uart_send("\r\n    Decryption key: 0x");
   uart_send_hex(CSR_REG32(cryptokey_table.entry[i].decrypt_key_255_224), 8);
   uart_send_hex(CSR_REG32(cryptokey_table.entry[i].decrypt_key_223_192), 8);
   uart_send_hex(CSR_REG32(cryptokey_table.entry[i].decrypt_key_191_160), 8);
   uart_send_hex(CSR_REG32(cryptokey_table.entry[i].decrypt_key_159_128), 8);
   uart_send_hex(CSR_REG32(cryptokey_table.entry[i].decrypt_key_127_96), 8);
   uart_send_hex(CSR_REG32(cryptokey_table.entry[i].decrypt_key_95_64), 8);
   uart_send_hex(CSR_REG32(cryptokey_table.entry[i].decrypt_key_63_32), 8);
   uart_send_hex(CSR_REG32(cryptokey_table.entry[i].decrypt_key_31_0), 8);

   uart_send("\r\n    Send counter: 0x");
   uart_send_hex(CSR_REG32(cryptokey_table.entry[i].send_cnt_63_32), 8);
   uart_send_hex(CSR_REG32(cryptokey_table.entry[i].send_cnt_31_0), 8);

   uart_send("\r\n    Recv counter: 0x");
   uart_send_hex(CSR_REG32(cryptokey_table.entry[i].recv_cnt_63_32), 8);
   uart_send_hex(CSR_REG32(cryptokey_table.entry[i].recv_cnt_31_0), 8);

   uart_send("\r\n");
}

void show_cryptokeys(void) {
   uart_send("Cryptokey table:\r\n");
   for (int i = 1; i < 64; i++) {
      show_cryptokeys_entry(i);
   }
}

// A 32-byte key in base64 (44 characters, as WireGuard tools print it),
// followed by <LF> or the end of the string: true and the key bytes, else false
static bool base64_key(const char* s, uint8_t key[32]) {
   uint32_t acc = 0;
   int      bits = 0, n = 0;
   for (int i = 0; i < 43; i++) {
      char c = s[i];
      int  v = (c >= 'A' && c <= 'Z') ? c - 'A' :
               (c >= 'a' && c <= 'z') ? c - 'a' + 26 :
               (c >= '0' && c <= '9') ? c - '0' + 52 :
               (c == '+') ? 62 : (c == '/') ? 63 : -1;
      if (v < 0) return false;
      if (i == 42 && (v & 3)) return false;  // its 2 low bits pad: 0, as WireGuard checks
      acc = (acc << 6) | (uint32_t)v;
      bits += 6;
      if (bits >= 8) {
         bits -= 8;
         if (n < 32) key[n++] = (uint8_t)(acc >> bits);
      }
   }
   return n == 32 && s[43] == '=' && (s[44] == '\n' || s[44] == '\0');
}

// Ask for a key: base64, or Enter for 8 hex words from bits 255:224 (key
// byte 31 first; Enter keeps a word). w: the current words in, the new out.
// The CSR words hold the key as one little-endian 256-bit number (csr.rdl)
static void read_key(const char* name, uint32_t w[8], char* buf) {
   static const char* const nth[8] = {"1st", "2nd", "3rd", "4th", "5th", "6th", "7th", "8th"};
   uint8_t key[32];

   uart_send("  ");
   uart_send(name);
   uart_send(" key, base64 (Enter: 8 hex words): ");
   while (!uart_recv(buf));
   if (buf[0] != '\n' && buf[0] != '\0') {
      if (base64_key(buf, key)) {
         for (int k = 0; k < 8; k++) {
            w[k] = ((uint32_t)key[31 - 4 * k] << 24) | ((uint32_t)key[30 - 4 * k] << 16) |
                   ((uint32_t)key[29 - 4 * k] << 8) | (uint32_t)key[28 - 4 * k];
         }
         return;
      }
      uart_send("  Not a base64 key (44 characters); as 8 hex words:\r\n");
   }
   for (int k = 0; k < 8; k++) {
      uart_send("  ");
      uart_send(name);
      uart_send(" key (");
      uart_send(nth[k]);
      uart_send(" 8 hex digits) [");
      uart_send_hex(w[k], 8);
      uart_send("]: ");
      while (!uart_recv(buf));
      str_parse_hex(buf, &w[k], 0, 0xFFFFFFFF);
   }
}

// As config_routes: the DPE pauses only for the writes
void config_cryptokeys(void) {
   char uart_rx_data[UART_RXBUF_SIZE];

   uart_send("Enter new cryptokey table entry:\r\n");
   uart_send("  Entry index (1-63) [1]: ");
   while (!uart_recv(uart_rx_data));
   uint32_t entry_idx = 1;
   str_parse_uint32(uart_rx_data, &entry_idx, 1, 63);

   uart_send("  Local MAC address [");
   uint32_t local_mac_47_32 = CSR_GET(cryptokey_table.entry[entry_idx].local_mac_47_32, CSR__CRYPTOKEY_TABLE__ENTRY__LOCAL_MAC_47_32__MAC);
   uart_send_hex(local_mac_47_32, 4);
   uint32_t local_mac_31_0 = CSR_REG32(cryptokey_table.entry[entry_idx].local_mac_31_0);
   uart_send_hex(local_mac_31_0, 8);
   uart_send("]: ");
   while (!uart_recv(uart_rx_data));
   if (bare_strlen(uart_rx_data) == 13) {
      str_parse_hex(uart_rx_data + 4, &local_mac_31_0, 0, 0xFFFFFFFF);
      uart_rx_data[4] = '\n';
      str_parse_hex(uart_rx_data, &local_mac_47_32, 0, 0xFFFF);
   }

   uart_send("  Local IP address [");
   uint32_t ulocal_ip = CSR_REG32(cryptokey_table.entry[entry_idx].local_ip);
   ip_t local_ip = {(uint8_t)((ulocal_ip >> 24) & 0xFF), (uint8_t)((ulocal_ip >> 16) & 0xFF), (uint8_t)((ulocal_ip >> 8) & 0xFF), (uint8_t)(ulocal_ip & 0xFF)};
   uart_send_ip(local_ip);
   uart_send("]: ");
   while (!uart_recv(uart_rx_data));
   net_str_parse_ip(uart_rx_data, &local_ip);
   ulocal_ip = ((uint32_t)local_ip[0] << 24) | ((uint32_t)local_ip[1] << 16) | ((uint32_t)local_ip[2] << 8) | (uint32_t)local_ip[3];

   uart_send("  Local port (0-65535) [");
   uint32_t local_port = CSR_GET(cryptokey_table.entry[entry_idx].local_port, CSR__CRYPTOKEY_TABLE__ENTRY__LOCAL_PORT__PORT);
   uart_send_dec(local_port);
   uart_send("]: ");
   while (!uart_recv(uart_rx_data));
   str_parse_uint32(uart_rx_data, &local_port, 0, 65535);

   uart_send("  Local ID (8 hex digits) [");
   uint32_t local_id = CSR_REG32(cryptokey_table.entry[entry_idx].local_id);
   uart_send_hex(local_id, 8);
   uart_send("]: ");
   while (!uart_recv(uart_rx_data));
   str_parse_hex(uart_rx_data, &local_id, 0, 0xFFFFFFFF);

   uart_send("  Remote MAC address [");
   uint32_t remote_mac_47_32 = CSR_GET(cryptokey_table.entry[entry_idx].remote_mac_47_32, CSR__CRYPTOKEY_TABLE__ENTRY__REMOTE_MAC_47_32__MAC);
   uart_send_hex(remote_mac_47_32, 4);
   uint32_t remote_mac_31_0 = CSR_REG32(cryptokey_table.entry[entry_idx].remote_mac_31_0);
   uart_send_hex(remote_mac_31_0, 8);
   uart_send("]: ");
   while (!uart_recv(uart_rx_data));
   if (bare_strlen(uart_rx_data) == 13) {
      str_parse_hex(uart_rx_data + 4, &remote_mac_31_0, 0, 0xFFFFFFFF);
      uart_rx_data[4] = '\n';
      str_parse_hex(uart_rx_data, &remote_mac_47_32, 0, 0xFFFF);
   }

   uart_send("  Remote IP address [");
   uint32_t uremote_ip = CSR_REG32(cryptokey_table.entry[entry_idx].remote_ip);
   ip_t remote_ip = {(uint8_t)((uremote_ip >> 24) & 0xFF), (uint8_t)((uremote_ip >> 16) & 0xFF), (uint8_t)((uremote_ip >> 8) & 0xFF), (uint8_t)(uremote_ip & 0xFF)};
   uart_send_ip(remote_ip);
   uart_send("]: ");
   while (!uart_recv(uart_rx_data));
   net_str_parse_ip(uart_rx_data, &remote_ip);
   uremote_ip = ((uint32_t)remote_ip[0] << 24) | ((uint32_t)remote_ip[1] << 16) | ((uint32_t)remote_ip[2] << 8) | (uint32_t)remote_ip[3];

   uart_send("  Remote port (0-65535) [");
   uint32_t remote_port = CSR_GET(cryptokey_table.entry[entry_idx].remote_port, CSR__CRYPTOKEY_TABLE__ENTRY__REMOTE_PORT__PORT);
   uart_send_dec(remote_port);
   uart_send("]: ");
   while (!uart_recv(uart_rx_data));
   str_parse_uint32(uart_rx_data, &remote_port, 0, 65535);

   uart_send("  Remote ID (8 hex digits) [");
   uint32_t remote_id = CSR_REG32(cryptokey_table.entry[entry_idx].remote_id);
   uart_send_hex(remote_id, 8);
   uart_send("]: ");
   while (!uart_recv(uart_rx_data));
   str_parse_hex(uart_rx_data, &remote_id, 0, 0xFFFFFFFF);

   uint32_t encrypt_key[8] = {
      CSR_REG32(cryptokey_table.entry[entry_idx].encrypt_key_255_224),
      CSR_REG32(cryptokey_table.entry[entry_idx].encrypt_key_223_192),
      CSR_REG32(cryptokey_table.entry[entry_idx].encrypt_key_191_160),
      CSR_REG32(cryptokey_table.entry[entry_idx].encrypt_key_159_128),
      CSR_REG32(cryptokey_table.entry[entry_idx].encrypt_key_127_96),
      CSR_REG32(cryptokey_table.entry[entry_idx].encrypt_key_95_64),
      CSR_REG32(cryptokey_table.entry[entry_idx].encrypt_key_63_32),
      CSR_REG32(cryptokey_table.entry[entry_idx].encrypt_key_31_0)};
   read_key("Encryption", encrypt_key, uart_rx_data);

   uint32_t decrypt_key[8] = {
      CSR_REG32(cryptokey_table.entry[entry_idx].decrypt_key_255_224),
      CSR_REG32(cryptokey_table.entry[entry_idx].decrypt_key_223_192),
      CSR_REG32(cryptokey_table.entry[entry_idx].decrypt_key_191_160),
      CSR_REG32(cryptokey_table.entry[entry_idx].decrypt_key_159_128),
      CSR_REG32(cryptokey_table.entry[entry_idx].decrypt_key_127_96),
      CSR_REG32(cryptokey_table.entry[entry_idx].decrypt_key_95_64),
      CSR_REG32(cryptokey_table.entry[entry_idx].decrypt_key_63_32),
      CSR_REG32(cryptokey_table.entry[entry_idx].decrypt_key_31_0)};
   read_key("Decryption", decrypt_key, uart_rx_data);

   uart_send("  Reset send/recv counters? (y/n) [n]: ");
   while (!uart_recv(uart_rx_data));
   bool reset_cnt = uart_rx_data[0] == 'y' || uart_rx_data[0] == 'Y';

   // Update cryptokeys table entry
   if (!dpe_pause()) return;
   CSR_SET(cryptokey_table.entry[entry_idx].local_mac_47_32, CSR__CRYPTOKEY_TABLE__ENTRY__LOCAL_MAC_47_32__MAC, local_mac_47_32);
   CSR_REG32(cryptokey_table.entry[entry_idx].local_mac_31_0) = local_mac_31_0;
   CSR_REG32(cryptokey_table.entry[entry_idx].local_ip) = ulocal_ip;
   CSR_SET(cryptokey_table.entry[entry_idx].local_port, CSR__CRYPTOKEY_TABLE__ENTRY__LOCAL_PORT__PORT, local_port);
   CSR_REG32(cryptokey_table.entry[entry_idx].local_id) = local_id;
   CSR_SET(cryptokey_table.entry[entry_idx].remote_mac_47_32, CSR__CRYPTOKEY_TABLE__ENTRY__REMOTE_MAC_47_32__MAC, remote_mac_47_32);
   CSR_REG32(cryptokey_table.entry[entry_idx].remote_mac_31_0) = remote_mac_31_0;
   CSR_REG32(cryptokey_table.entry[entry_idx].remote_ip) = uremote_ip;
   CSR_SET(cryptokey_table.entry[entry_idx].remote_port, CSR__CRYPTOKEY_TABLE__ENTRY__REMOTE_PORT__PORT, remote_port);
   CSR_REG32(cryptokey_table.entry[entry_idx].remote_id) = remote_id;
   CSR_REG32(cryptokey_table.entry[entry_idx].encrypt_key_255_224) = encrypt_key[0];
   CSR_REG32(cryptokey_table.entry[entry_idx].encrypt_key_223_192) = encrypt_key[1];
   CSR_REG32(cryptokey_table.entry[entry_idx].encrypt_key_191_160) = encrypt_key[2];
   CSR_REG32(cryptokey_table.entry[entry_idx].encrypt_key_159_128) = encrypt_key[3];
   CSR_REG32(cryptokey_table.entry[entry_idx].encrypt_key_127_96) = encrypt_key[4];
   CSR_REG32(cryptokey_table.entry[entry_idx].encrypt_key_95_64) = encrypt_key[5];
   CSR_REG32(cryptokey_table.entry[entry_idx].encrypt_key_63_32) = encrypt_key[6];
   CSR_REG32(cryptokey_table.entry[entry_idx].encrypt_key_31_0) = encrypt_key[7];
   CSR_REG32(cryptokey_table.entry[entry_idx].decrypt_key_255_224) = decrypt_key[0];
   CSR_REG32(cryptokey_table.entry[entry_idx].decrypt_key_223_192) = decrypt_key[1];
   CSR_REG32(cryptokey_table.entry[entry_idx].decrypt_key_191_160) = decrypt_key[2];
   CSR_REG32(cryptokey_table.entry[entry_idx].decrypt_key_159_128) = decrypt_key[3];
   CSR_REG32(cryptokey_table.entry[entry_idx].decrypt_key_127_96) = decrypt_key[4];
   CSR_REG32(cryptokey_table.entry[entry_idx].decrypt_key_95_64) = decrypt_key[5];
   CSR_REG32(cryptokey_table.entry[entry_idx].decrypt_key_63_32) = decrypt_key[6];
   CSR_REG32(cryptokey_table.entry[entry_idx].decrypt_key_31_0) = decrypt_key[7];
   if (reset_cnt) {
      CSR_REG32(cryptokey_table.entry[entry_idx].send_cnt_63_32) = 0;
      CSR_REG32(cryptokey_table.entry[entry_idx].send_cnt_31_0) = 0;
      CSR_REG32(cryptokey_table.entry[entry_idx].recv_cnt_63_32) = 0;
      CSR_REG32(cryptokey_table.entry[entry_idx].recv_cnt_31_0) = 0;
   }
   dpe_resume();

   uart_send("Cryptokey table entry updated.\r\n");

   show_cryptokeys_entry(entry_idx);
}

void reboot() {
#ifdef VPROC
   // Co-simulation: no restart, park the VProc node
   while (1) VTick(10000, SOC_CPU_VPNODE);
#else
   asm volatile ("jr zero" ::: "memory");
#endif
}

int main(void) {
   char uart_rx_data[UART_RXBUF_SIZE];
   uint8_t uart_rx_len;
   uint8_t debug_enabled = 0;

   // Check hardware ID
   if (CSR_GET(hw_id, CSR__HW_ID__VENDOR) != 0xCCBA ||
       CSR_GET(hw_id, CSR__HW_ID__PRODUCT) != 0xCACA) {
      uart_send("\r\nHardware ID mismatch! Halting...\r\n");
#ifdef VPROC
      while (1) VTick(10000, SOC_CPU_VPNODE);
#else
      asm volatile ("ebreak");
#endif
   }

   // Display banner
   uart_send("\r\n==========================================\r\n");
   uart_send("          WireGuard FPGA v");
   uart_send_dec(CSR_GET(hw_version, CSR__HW_VERSION__MAJOR));
   uart_send_char('.');
   uart_send_dec(CSR_GET(hw_version, CSR__HW_VERSION__MINOR));
   uart_send_char('.');
   uart_send_dec(CSR_GET(hw_version, CSR__HW_VERSION__PATCH));
   uart_send("\r\n   Copyright \u00A9 2024-2026 Chili.CHIPS*ba\r\n");
   uart_send("==========================================\r\n");

   // Boot sequence
   uart_send("Booting up...\r\n");
   init_network(&net_config);
   show_network(&net_config);

   // CLI prompt
   uart_send("\r\nType 'help' to display commands.\r\n");
   uart_send("(wireguard-fpga)# ");

   while (1) {
      // Receive Ethernet packet for CPU FIFO
      if (eth_receive_packet(&eth_packet_rx)) {
         CSR_RMW(gpio, CSR__GPIO__LED2, 1);
         // Parse packet header
         net_protocol_t protocol = net_parse_packet_header(&eth_packet_rx);
         switch (protocol) {
            case NET_PROTO_UNKNOWN:
               if (debug_enabled) {
                  uart_send("<< NET_PROTO_UNKNOWN: ");
                  uart_send_dec(eth_packet_rx.len);
                  uart_send("\r\n");
               }
               break;
            case NET_PROTO_ARP:
               if (debug_enabled) {
                  uart_send("<< NET_PROTO_ARP: ");
                  uart_send_dec(eth_packet_rx.len);
                  uart_send("\r\n");
               }
               if (net_process_arp(&net_config, &net_arp_cache, &eth_packet_rx, &eth_packet_tx)) {
                  eth_send_packet(&eth_packet_tx);
                  if (debug_enabled) {
                     uart_send(">> NET_PROTO_ARP: ");
                     uart_send_dec(eth_packet_tx.len);
                     uart_send("\r\n");
                  }
               }
               break;
            case NET_PROTO_ICMP:
               if (debug_enabled) {
                  uart_send("<< NET_PROTO_ICMP: ");
                  uart_send_dec(eth_packet_rx.len);
                  uart_send("\r\n");
               }
               if (net_process_icmp(&net_config, &eth_packet_rx, &eth_packet_tx)) {
                  eth_send_packet(&eth_packet_tx);
                  if (debug_enabled) {
                     uart_send(">> NET_PROTO_ICMP: ");
                     uart_send_dec(eth_packet_tx.len);
                     uart_send("\r\n");
                  }
               }
               break;
            case NET_PROTO_UDP:
               if (debug_enabled) {
                  uart_send("<< NET_PROTO_UDP: ");
                  uart_send_dec(eth_packet_rx.len);
                  uart_send("\r\n");
               }
               break;
         }

         if (eth_packet_rx.src == DPE_ADDR_ETH_1) {
            eth_packet_rx.dst = DPE_ADDR_ETH_2;
            eth_packet_rx.bypass_all = 1;
            eth_send_packet(&eth_packet_rx);
         } else if (eth_packet_rx.src == DPE_ADDR_ETH_2) {
            eth_packet_rx.dst = DPE_ADDR_ETH_1;
            eth_packet_rx.bypass_all = 1;
            eth_send_packet(&eth_packet_rx);
         }
      } else {
         CSR_RMW(gpio, CSR__GPIO__LED2, 0);
      }

      // Receive and process CLI command
      uart_rx_len = uart_recv(uart_rx_data);
      if (uart_rx_len) {
         if (bare_strcmp(uart_rx_data, "test chacha20poly1305\n") == 0) {
            test_chacha20poly1305();
         } else if (bare_strcmp(uart_rx_data, "test blake2s\n") == 0) {
            test_blake2s();
         } else if (bare_strcmp(uart_rx_data, "test curve25519\n") == 0) {
            test_curve25519();
         } else if (bare_strcmp(uart_rx_data, "test rng\n") == 0) {
            test_rng();
         } else if (bare_strcmp(uart_rx_data, "test timer\n") == 0) {
            test_timer();
         } else if (bare_strcmp(uart_rx_data, "show network\n") == 0) {
            show_network(&net_config);
         } else if (bare_strcmp(uart_rx_data, "config network\n") == 0) {
            config_network(&net_config);
         } else if (bare_strcmp(uart_rx_data, "show routes\n") == 0) {
            show_routes();
         } else if (bare_strcmp(uart_rx_data, "config routes\n") == 0) {
            config_routes();
         } else if (bare_strcmp(uart_rx_data, "show cryptokeys\n") == 0) {
            show_cryptokeys();
         } else if (bare_strcmp(uart_rx_data, "config cryptokeys\n") == 0) {
            config_cryptokeys();
         } else if (bare_strcmp(uart_rx_data, "debug\n") == 0) {
            debug_enabled = !debug_enabled;
            uart_send("Debug mode ");;
            if (debug_enabled) {
               uart_send("enabled.\r\n");
            } else {
               uart_send("disabled.\r\n");
            }
         } else if (bare_strcmp(uart_rx_data, "reboot\n") == 0) {
            reboot();
         } else if (bare_strcmp(uart_rx_data, "help\n") == 0) {
            uart_send("Available commands:\r\n");
            uart_send("  test chacha20poly1305  - Test ChaCha20-Poly1305 AEAD\r\n");
            uart_send("  test blake2s           - Test BLAKE2s hash function\r\n");
            uart_send("  test curve25519        - Test Curve25519 key exchange\r\n");
            uart_send("  test rng               - Test random number generator\r\n");
            uart_send("  test timer             - Test timer functionality\r\n");
            uart_send("  show network           - Show network configuration\r\n");
            uart_send("  config network         - Configure network settings\r\n");
            uart_send("  show routes            - Show routing table\r\n");
            uart_send("  config routes          - Configure routing table entry\r\n");
            uart_send("  show cryptokeys        - Show cryptokey table\r\n");
            uart_send("  config cryptokeys      - Configure cryptokey table entry\r\n");
            uart_send("  debug                  - Toggle debug mode\r\n");
            uart_send("  reboot                 - Reboot the system\r\n");
            uart_send("  help                   - Show this help message\r\n");
         } else if (uart_rx_len > 1) {
            uart_send("Unknown command\r\n");
         }
         uart_send("(wireguard-fpga)# ");
      }
   }

   return 0;
}

// -----------------------------------------------------------------------------
// Project:     WireGuard-FPGA
// Description: NLnet-funded open-source implementation
// Funding:     https://nlnet.nl/project/KlusterLab-Wireguard (2023-12 to 2025-12)
// -----------------------------------------------------------------------------
