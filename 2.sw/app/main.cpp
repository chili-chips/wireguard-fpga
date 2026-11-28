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
#include "noise.h"
#include "wg_session.h"
#include "flash.h"
#include "rtc.h"

//--------------------------------------------------------------------------
// Stack scrub: crypto code leaves keys and intermediate values in its stack
// frames after it returns (X25519 alone about 1.7 KB), and DMEM is readable
// over the UART debug mode. After each command and each packet, zero the
// stack below the current stack pointer: nothing there is live (eduBOS5
// takes no interrupts). The co-simulation runs on the host stack: no-op.
//--------------------------------------------------------------------------
#ifndef VPROC
extern "C" uint8_t _stack_end[];  // lowest stack address (link_map.lds)

static void __attribute__((noinline)) stack_scrub(void) {
   uintptr_t sp;
   __asm__ volatile ("mv %0, sp" : "=r"(sp));
   for (volatile uint32_t *p = (volatile uint32_t *)_stack_end; (uintptr_t)p < sp; p++) {
      *p = 0;
   }
}
#else
static void stack_scrub(void) {}
#endif

// The co-simulation's end-to-end test (4.sim, WG_E2E=1) only: its bench
// reads the tables back over the co-sim HAL, on this node, between two
// rounds of the main loop (4.sim/usercode/VUserMainWg.cpp)
#if defined(VPROC) && defined(WG_E2E_HOOK)
extern "C" void wg_e2e_hook(void);
#endif

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

static uint8_t    debug_enabled = 0;

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

// ---- words: IPv4 addresses, MACs and keys as the CSR words hold them ----

// an IPv4 address as one word, the first byte in bits 31:24
static uint32_t ip_word(const uint8_t ip[4]) {
   return ((uint32_t)ip[0] << 24) | ((uint32_t)ip[1] << 16) | ((uint32_t)ip[2] << 8) | ip[3];
}

static void word_ip(uint32_t w, uint8_t ip[4]) {
   for (int k = 0; k < 4; k++) ip[k] = (uint8_t)(w >> (24 - 8 * k));
}

// a MAC as bits 47:32 (hi) and 31:0 (lo), the first byte in bits 47:40
static void mac_words(const uint8_t m[6], uint32_t *hi, uint32_t *lo) {
   *hi = ((uint32_t)m[0] << 8) | m[1];
   *lo = ip_word(m + 2);
}

static void words_mac(uint32_t hi, uint32_t lo, uint8_t m[6]) {
   m[0] = (uint8_t)(hi >> 8);
   m[1] = (uint8_t)hi;
   word_ip(lo, m + 2);
}

// the CSR key words from 32 key bytes: one little-endian 256-bit number,
// word 0 = bits 255:224 (bytes 31 .. 28), as csr.rdl
static void key_words(const uint8_t key[32], uint32_t w[8]) {
   for (int k = 0; k < 8; k++) {
      w[k] = ((uint32_t)key[31 - 4 * k] << 24) | ((uint32_t)key[30 - 4 * k] << 16) |
             ((uint32_t)key[29 - 4 * k] << 8) | (uint32_t)key[28 - 4 * k];
   }
}

// ---- console input ----

// a prompt, then wait for the answer line
static void ask(const char *prompt, char *buf) {
   uart_send(prompt);
   while (!uart_recv(buf));
}

static bool is_empty(const char *buf) { return buf[0] == '\n' || buf[0] == '\0'; }
static bool is_yes(const char *buf)   { return buf[0] == 'y' || buf[0] == 'Y'; }

static void send_dec_s(uint32_t v, const char *s) {
   uart_send_dec(v);
   uart_send(s);
}

// a MAC as 12 hex digits: true and hi/lo (as mac_words), else false and
// both kept
static bool parse_mac(char *buf, uint32_t *hi, uint32_t *lo) {
   uint32_t h, l;
   if (bare_strlen(buf) != 13 || !str_parse_hex(buf + 4, &l, 0, 0xFFFFFFFF)) return false;
   buf[4] = '\n';
   if (!str_parse_hex(buf, &h, 0, 0xFFFF)) return false;
   *hi = h;
   *lo = l;
   return true;
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
   uint8_t key[32];

   uart_send("  ");
   uart_send(name);
   ask(", base64 (Enter: 8 hex words): ", buf);
   if (!is_empty(buf)) {
      if (base64_key(buf, key)) {
         key_words(key, w);
         return;
      }
      uart_send("  Not a base64 key (44 characters); as 8 hex words:\r\n");
   }
   for (int k = 0; k < 8; k++) {
      uart_send("  ");
      uart_send(name);
      uart_send(" (");
      uart_send_dec((uint32_t)k + 1);
      uart_send(k == 0 ? "st" : k == 1 ? "nd" : k == 2 ? "rd" : "th");
      uart_send(" 8 hex digits) [");
      uart_send_hex(w[k], 8);
      ask("]: ", buf);
      str_parse_hex(buf, &w[k], 0, 0xFFFFFFFF);
   }
}

// " [.1...]": the Ethernet ports of interface code v (0: the CPU; 5: 1 and
// 3, 6: 2 and 4, 7: all four)
static void send_ifc(uint32_t v) {
   static const uint8_t ports[8] = {0x01, 0x02, 0x04, 0x08, 0x10, 0x0A, 0x14, 0x1E};
   if (v > 7) return;
   uart_send(" [");
   for (int j = 0; j < 5; j++) uart_send_char((ports[v] >> j) & 1 ? (char)('0' + j) : '.');
   uart_send_char(']');
}

//--------------------------------------------------------------------------
// The tables the CLI shows and edits (network, routes, cryptokeys): one
// field list each. An entry is first copied into words (v[]: the CSR words
// of a table entry, or the network configuration as words); show_fields
// prints them, edit_fields asks for each editable field, its value now as
// the default (Enter, or a bad answer, keeps it); the caller writes back.
//--------------------------------------------------------------------------

enum {
   F_DEC,     // decimal, bits bp up of word w, hi is the mask: lo .. hi
   F_IFC,     // as F_DEC, shown with its ports: send_ifc
   F_PEER,    // as F_DEC, a routing table peer index: shows its WireGuard peer
   F_IP,      // IPv4 address, word w (ip_word)
   F_MAC,     // MAC, words w (47:32) and w + 1 (31:0): 12 hex digits
   F_MACGEN,  // as F_MAC, shown xx:xx:..; edited: make a new one or not
   F_HEX,     // bp words from w, in hex: 0x... (bp = 1: an 8 hex digit word)
   F_KEY      // as F_HEX, 8 words: a key (read_key)
};

enum {
   F_NL = 1,  // shown on a new line
   F_RO = 2   // shown only
};

struct cli_field_t {
   const char *name;   // as shown
   const char *ask;    // the prompt: NULL: name; " ...": name and this; else this
   uint8_t     w, fmt, bp, flags;
   uint16_t    lo, hi;
};

// the cryptokey table entry: its CSR words in order (csr.rdl)
static const cli_field_t ck_fields[] = {
   {"Local MAC",      " address",         0, F_MAC,  0, 0,           0, 0},
   {"Local IP",       " address",         2, F_IP,   0, 0,           0, 0},
   {"Local port",     " (0-65535)",       3, F_DEC,  0, 0,           0, 0xFFFF},
   {"Tag",            NULL,               3, F_DEC, 16, F_RO,        0, 63},
   {"Local ID",       " (8 hex digits)",  4, F_HEX,  1, 0,           0, 0},
   {"Remote MAC",     " address",         5, F_MAC,  0, F_NL,        0, 0},
   {"Remote IP",      " address",         7, F_IP,   0, 0,           0, 0},
   {"Remote port",    " (0-65535)",       8, F_DEC,  0, 0,           0, 0xFFFF},
   {"Remote ID",      " (8 hex digits)",  9, F_HEX,  1, 0,           0, 0},
   {"Encryption key", NULL,              10, F_KEY,  8, F_NL,        0, 0},
   {"Decryption key", NULL,              18, F_KEY,  8, F_NL,        0, 0},
   {"Send counter",   NULL,              26, F_HEX,  2, F_NL | F_RO, 0, 0},
   {"Recv counter",   NULL,              28, F_HEX,  2, F_NL | F_RO, 0, 0},
   {"Recv window",    NULL,              30, F_HEX,  2, F_NL | F_RO, 0, 0},
};

#define CK_WORDS  32  // words of a cryptokey table entry
#define CK_KEYED  26  // the words up to the keys: the counters follow

// the routing table entry: ip, mask, peer_idx, dst
static const cli_field_t rt_fields[] = {
   {"IP",                    "Destination IP address",                     0, F_IP,   0, 0, 0, 0},
   {"Mask",                  "Subnet mask",                                1, F_IP,   0, 0, 0, 0},
   {"Peer index",            " (0-63; a WireGuard peer if Encrypt is 1)",  2, F_PEER, 0, 0, 0, 63},
   {"Encrypt",               " (0/1: through the tunnel to the peer)",     2, F_DEC,  8, 0, 0, 1},
   {"Destination interface", " (0-7)",                                     3, F_IFC,  0, 0, 0, 7},
};

// the network configuration, as net_words
static const cli_field_t net_fields[] = {
   {"IP address",        NULL,         0, F_IP,     0, 0, 0, 0},
   {"Subnet mask",       NULL,         1, F_IP,     0, 0, 0, 0},
   {"MAC address",       NULL,         2, F_MACGEN, 0, 0, 0, 0},
   {"Default gateway",   NULL,         4, F_IP,     0, 0, 0, 0},
   {"Default interface", " (0-7)",     5, F_IFC,    0, 0, 0, 7},
   {"WireGuard port",    " (1-65535)", 6, F_DEC,    0, 0, 1, 0xFFFF},
};

#define N_FIELDS(t)  ((int)(sizeof(t) / sizeof((t)[0])))

// the words the field lists name, at the offsets they have in the CSR block
static_assert(offsetof(csr__cryptokey_table__entry_t, remote_mac_47_32) == 4 * 5, "csr.rdl");
static_assert(offsetof(csr__cryptokey_table__entry_t, remote_port) == 4 * 8, "csr.rdl");
static_assert(offsetof(csr__cryptokey_table__entry_t, encrypt_key_255_224) == 4 * 10, "csr.rdl");
static_assert(offsetof(csr__cryptokey_table__entry_t, decrypt_key_255_224) == 4 * 18, "csr.rdl");
static_assert(offsetof(csr__cryptokey_table__entry_t, send_cnt_63_32) == 4 * CK_KEYED, "csr.rdl");
static_assert(sizeof(csr__cryptokey_table__entry_t) == 4 * CK_WORDS, "csr.rdl");
static_assert(offsetof(csr__routing_table__entry_t, dst) == 4 * 3, "csr.rdl");

// a CSR word by its byte address
#ifdef VPROC
# define CSR_AT(a)  (csr_vp_reg32(a))  // parenthesized: not a declaration
#else
# define CSR_AT(a)  (*(volatile uint32_t *)(uintptr_t)(a))
#endif

static void csr_read_words(uint32_t a, uint32_t *v, int n) {
   for (int k = 0; k < n; k++) v[k] = CSR_AT(a + 4u * (uint32_t)k);
}

// a field's value; prompt: as the default in a prompt (no 0x, no ports, no
// WireGuard peer). entry: the routing table entry (F_PEER)
static void send_field(const cli_field_t *f, const uint32_t *v, int entry, bool prompt) {
   const uint32_t *p = v + f->w;
   uint32_t        x = (*p >> f->bp) & f->hi;
   uint8_t         b[6];
   switch (f->fmt) {
      case F_IP:
         word_ip(*p, b);
         uart_send_ip(b);
         break;
      case F_MAC:
         uart_send_hex(p[0], 4);
         uart_send_hex(p[1], 8);
         break;
      case F_MACGEN:
         words_mac(p[0], p[1], b);
         uart_send_mac(b);
         break;
      case F_HEX:
      case F_KEY:
         if (!prompt) uart_send("0x");
         for (int k = 0; k < f->bp; k++) uart_send_hex(p[k], 8);
         break;
      default:  // F_DEC, F_IFC, F_PEER
         uart_send_dec(x);
         if (prompt) break;
         if (f->fmt == F_IFC) send_ifc(x);
         if (f->fmt == F_PEER && wg_route_peer(entry)) {  // the entry follows that peer's sessions (#85)
            uart_send(" (WireGuard peer ");
            uart_send_dec((uint32_t)wg_route_peer(entry));
            uart_send_char(')');
         }
   }
}

// entry >= 0: "  (entry) A: a, B: b", an F_NL field on a new line;
// entry < 0: one "  A:   a" line each, the values aligned
static void show_fields(const cli_field_t *f, int n, const uint32_t *v, int entry) {
   if (entry >= 0) {
      uart_send("  (");
      uart_send_dec((uint32_t)entry);
      uart_send_char(')');
   }
   for (int k = 0; k < n; k++, f++) {
      if (entry < 0) {
         uart_send("  ");
      } else {
         uart_send(k == 0 ? " " : (f->flags & F_NL) ? "\r\n    " : ", ");
      }
      uart_send(f->name);
      uart_send_char(':');
      for (int s = entry < 0 ? 18 - (int)bare_strlen(f->name) : 1; s > 0; s--) uart_send_char(' ');
      send_field(f, v, entry, false);
      if (entry < 0) uart_send("\r\n");
   }
   if (entry >= 0) uart_send("\r\n");
}

static void edit_fields(const cli_field_t *f, int n, uint32_t *v, char *buf) {
   for (; n > 0; n--, f++) {
      uint32_t *p = v + f->w;
      if (f->flags & F_RO) continue;
      if (f->fmt == F_KEY) {
         read_key(f->name, p, buf);
         continue;
      }
      uart_send("  ");
      if (f->fmt == F_MACGEN) {
         uart_send("Generate new ");
         uart_send(f->name);
         ask("? (y/n) [n]: ", buf);
         if (is_yes(buf)) {
            uint8_t rnd[32];  // random_32bytes() writes 32 bytes
            random_32bytes(rnd);
            // the last two bytes made up; a made-up MAC is locally
            // administered (bit 1 of byte 0) and unicast (bit 0)
            p[1] = (p[1] & 0xFFFF0000u) | ((uint32_t)rnd[0] << 8) | rnd[1];
            p[0] = (p[0] | 0x0200u) & ~0x0100u;
         }
         continue;
      }
      if (!f->ask || f->ask[0] == ' ') uart_send(f->name);
      if (f->ask) uart_send(f->ask);
      uart_send(" [");
      send_field(f, v, 0, true);
      ask("]: ", buf);
      switch (f->fmt) {
         case F_IP: {
            ip_t ip;
            word_ip(*p, ip);
            net_str_parse_ip(buf, &ip);
            *p = ip_word(ip);
            break;
         }
         case F_MAC:
            parse_mac(buf, p, p + 1);
            break;
         case F_HEX:
            str_parse_hex(buf, p, 0, 0xFFFFFFFF);
            break;
         default: {  // F_DEC, F_IFC, F_PEER
            uint32_t x = (*p >> f->bp) & f->hi;
            str_parse_uint32(buf, &x, f->lo, f->hi);
            *p = (*p & ~((uint32_t)f->hi << f->bp)) | (x << f->bp);
         }
      }
   }
}

// ---- network ----

// The data plane takes IPv4 UDP to wg_ip:wg_port as WireGuard for this device:
// the device's own address and its WireGuard listen port
// The DPE pauses while they change: no packet sees half of them. False: the
// DPE did not drain, nothing written
bool set_wg_addr(const net_config_t* config) {
   if (!dpe_pause()) return false;
   CSR_REG32(dpe.wg_ip) = ip_word(config->ip);
   CSR_SET(dpe.wg_port, CSR__DPE__WG_PORT__PORT, config->wg_port);
   dpe_resume();
   return true;
}

void init_network(net_config_t* config) {
   static const net_config_t def = {
      {192, 168, 1, 98}, {255, 255, 255, 0}, {0xCC, 0xBA, 0xCA, 0xCA, 0x00, 0x01},
      {192, 168, 1, 254}, 1, 0};
   if (ip_word(config->ip) == 0) {
      uint16_t port = config->wg_port;
      *config = def;
      config->wg_port = port;
   }
   if (config->wg_port == 0) {
      config->wg_port = 51820;
   }
   set_wg_addr(config);
}

// the network configuration as words, for net_fields
static void net_words(const net_config_t *c, uint32_t v[7]) {
   v[0] = ip_word(c->ip);
   v[1] = ip_word(c->sub_mask);
   mac_words(c->mac, &v[2], &v[3]);
   v[4] = ip_word(c->def_gw);
   v[5] = c->def_if;
   v[6] = c->wg_port;
}

void show_network(net_config_t* config) {
   uint32_t v[7];
   net_words(config, v);
   uart_send("Network configuration:\r\n");
   show_fields(net_fields, N_FIELDS(net_fields), v, -1);
}

void config_network(net_config_t* config) {
   char           buf[UART_RXBUF_SIZE];
   uint32_t       v[7];
   const uint32_t old_ip = ip_word(config->ip);  // the IP and port the DPE has
   const uint16_t old_port = config->wg_port;

   uart_send("Enter new network configuration:\r\n");
   net_words(config, v);
   edit_fields(net_fields, N_FIELDS(net_fields), v, buf);
   word_ip(v[0], config->ip);
   word_ip(v[1], config->sub_mask);
   words_mac(v[2], v[3], config->mac);
   word_ip(v[4], config->def_gw);
   config->def_if  = (uint8_t)v[5];
   config->wg_port = (uint16_t)v[6];
   if (set_wg_addr(config)) {
      uart_send("Network configuration updated.\r\n");
   } else {
      // the firmware keeps what the data plane uses
      word_ip(old_ip, config->ip);
      config->wg_port = old_port;
      uart_send("Network configuration updated, but not the IP address and WireGuard port.\r\n");
   }

   show_network(config);
}

// ---- routing table ----

static void rt_read(int i, uint32_t v[4]) {
   csr_read_words(CSR_ADDR(routing_table.entry[i]), v, 4);
}

void show_routes_entry(int i) {
   uint32_t v[4];
   rt_read(i, v);
   show_fields(rt_fields, N_FIELDS(rt_fields), v, i);
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
   char     buf[UART_RXBUF_SIZE];
   uint32_t e = 0, v[4];

   uart_send("Enter new routing table entry:\r\n");
   ask("  Entry index (0-63) [0]: ", buf);
   str_parse_uint32(buf, &e, 0, 63);
   rt_read((int)e, v);

   // a WireGuard peer (wg show) with Encrypt 1: the route follows its
   // sessions (#85), peer_idx = its current entry; else peer_idx as entered
   int rp = wg_route_peer((int)e);
   if (rp) v[2] = (v[2] & ~(uint32_t)CSR__ROUTING_TABLE__ENTRY__PEER_IDX__PEER_IDX_bm) | (uint32_t)rp;
   edit_fields(rt_fields, N_FIELDS(rt_fields), v, buf);
   uint32_t peer_idx = RDL_FIELD(v[2], CSR__ROUTING_TABLE__ENTRY__PEER_IDX__PEER_IDX);
   uint32_t encrypt  = RDL_FIELD(v[2], CSR__ROUTING_TABLE__ENTRY__PEER_IDX__ENCRYPT);

   // Update routing table entry
   const wg_peer_t* wp = encrypt ? wg_peer((int)peer_idx) : NULL;
   uint32_t hw_idx = wp ? wp->cur.entry : peer_idx;
   if (!dpe_pause()) return;
   CSR_REG32(routing_table.entry[e].ip) = v[0];
   CSR_REG32(routing_table.entry[e].mask) = v[1];
   // peer_idx and encrypt in one word write: a byte store reaches every lane on
   // this bus, and the DUMMY switch's table ignores byte enables
   CSR_REG32(routing_table.entry[e].peer_idx) =
      CSR_FLD_VAL(CSR__ROUTING_TABLE__ENTRY__PEER_IDX__PEER_IDX, hw_idx) |
      CSR_FLD_VAL(CSR__ROUTING_TABLE__ENTRY__PEER_IDX__ENCRYPT, encrypt);
   CSR_SET(routing_table.entry[e].dst, CSR__ROUTING_TABLE__ENTRY__DST__DST, v[3]);
   dpe_resume();
   wg_route_set((int)e, wp ? (int)peer_idx : 0);

   uart_send("Routing table entry updated.\r\n");

   show_routes_entry((int)e);
}

// ---- cryptokey table ----

static uint32_t ck_addr(int n) {
   return CSR_ADDR(cryptokey_table.entry[n]);
}

// words 0 .. n - 1 of cryptokey table entry e, in order, the DPE paused: the
// MAC high halves and the remote port (bits 15:0, alone in their word) in
// a half-word store, the rest in word stores
static void ck_write(int e, const uint32_t *v, int n) {
   uint32_t a = ck_addr(e);
   for (int w = 0; w < n; w++, a += 4) {
      if (w == 0 || w == 5 || w == 8) {
         csr_wr_lanes(a, 0, 2, v[w]);
      } else {
         CSR_AT(a) = v[w];
      }
   }
}

// R&D: shows the keys too (removed for the final product)
void show_cryptokeys_entry(int i) {
   uint32_t v[CK_WORDS];
   csr_read_words(ck_addr(i), v, CK_WORDS);
   show_fields(ck_fields, N_FIELDS(ck_fields), v, i);
}

void show_cryptokeys(void) {
   uart_send("Cryptokey table:\r\n");
   for (int i = 1; i < 64; i++) {
      show_cryptokeys_entry(i);
   }
}

// As config_routes: the DPE pauses only for the writes
void config_cryptokeys(void) {
   char     buf[UART_RXBUF_SIZE];
   uint32_t e = 1, v[CK_WORDS];

   uart_send("Enter new cryptokey table entry:\r\n");
   ask("  Entry index (1-63) [1]: ", buf);
   str_parse_uint32(buf, &e, 1, 63);
   csr_read_words(ck_addr((int)e), v, CK_WORDS);
   edit_fields(ck_fields, N_FIELDS(ck_fields), v, buf);
   ask("  Reset send/recv counters? (y/n) [n]: ", buf);
   bool reset_cnt = is_yes(buf);

   // the peer tag: the entry itself
   v[3] = CSR_FLD_VAL(CSR__CRYPTOKEY_TABLE__ENTRY__LOCAL_PORT__PORT, v[3]) |
          CSR_FLD_VAL(CSR__CRYPTOKEY_TABLE__ENTRY__LOCAL_PORT__TAG, e);
   for (int w = CK_KEYED; w < CK_WORDS; w++) v[w] = 0;

   // Update cryptokeys table entry
   if (!dpe_pause()) return;
   ck_write((int)e, v, reset_cnt ? CK_WORDS : CK_KEYED);
   dpe_resume();

   uart_send("Cryptokey table entry updated.\r\n");

   show_cryptokeys_entry((int)e);
}

//--------------------------------------------------------------------------
// WireGuard handshake (wg_session.c, noise.c): the platform side
//--------------------------------------------------------------------------

extern "C" void wg_hw_random(uint8_t out[32]) { random_32bytes(out); }  // #2

// Cryptokey table entry n for a new session (in = NULL: cleared), with the
// DPE paused: MAC, IP and port in natural order, the keys as key_words
extern "C" int wg_hw_install(int n, const wg_install_t *in) {
   uint32_t v[CK_WORDS] = {0};  // the counters 0
   int      rc = -1;
   if (in) {
      mac_words(net_config.mac, &v[0], &v[1]);
      v[2] = ip_word(net_config.ip);
      v[3] = CSR_FLD_VAL(CSR__CRYPTOKEY_TABLE__ENTRY__LOCAL_PORT__PORT, net_config.wg_port) |
             CSR_FLD_VAL(CSR__CRYPTOKEY_TABLE__ENTRY__LOCAL_PORT__TAG, in->tag);
      v[4] = in->local_id;
      mac_words(in->remote.mac, &v[5], &v[6]);
      v[7] = ip_word(in->remote.ip);
      v[8] = in->remote.port;
      v[9] = in->remote_id;
      key_words(in->send_key, v + 10);
      key_words(in->recv_key, v + 18);
   }
   if (dpe_pause()) {
      ck_write(n, v, CK_WORDS);
      dpe_resume();
      rc = 0;
   }
   bare_wipe(v, sizeof(v));
   return rc;
}

// A UDP datagram to dst from our WireGuard port, in eth_packet_tx, out
// through dst->ifc past the data plane (bypass_all)
static void udp_send(const wg_endpoint_t *dst, const uint8_t *data, uint32_t len) {
   uint8_t *f = eth_packet_tx.payload;
   uint32_t ip_len = 20 + 8 + len;
   memcpy(f, dst->mac, 6);
   memcpy(f + 6, net_config.mac, 6);
   f[12] = 0x08; f[13] = 0x00;
   uint8_t *ip = f + 14;
   memset(ip, 0, 20);
   ip[0] = 0x45;
   ip[2] = (uint8_t)(ip_len >> 8); ip[3] = (uint8_t)ip_len;
   ip[6] = 0x40;                       // DF
   ip[8] = 64;                         // TTL
   ip[9] = 17;                         // UDP
   memcpy(ip + 12, net_config.ip, 4);
   memcpy(ip + 16, dst->ip, 4);
   uint16_t c = net_calculate_checksum(ip, 20);
   ip[10] = (uint8_t)(c >> 8); ip[11] = (uint8_t)c;
   uint8_t *udp = ip + 20;
   udp[0] = (uint8_t)(net_config.wg_port >> 8); udp[1] = (uint8_t)net_config.wg_port;
   udp[2] = (uint8_t)(dst->port >> 8);          udp[3] = (uint8_t)dst->port;
   udp[4] = (uint8_t)((8 + len) >> 8);          udp[5] = (uint8_t)(8 + len);
   udp[6] = 0; udp[7] = 0;             // no UDP checksum (IPv4 allows it)
   memcpy(udp + 8, data, len);
   eth_packet_tx.dst          = dst->ifc;
   eth_packet_tx.bypass_all   = 1;
   eth_packet_tx.bypass_stage = 0;
   eth_packet_tx.len          = 14 + ip_len < 60 ? 60 : 14 + ip_len;
   if (eth_packet_tx.len > 14 + ip_len) memset(f + 14 + ip_len, 0, eth_packet_tx.len - 14 - ip_len);
   eth_send_packet(&eth_packet_tx);
}

// ---- the timers (#80, wg_session_timers) ----

// the counters the data plane writes back; read on the CPU's own port, no
// pause (a torn 64-bit read only looks like one more event)
extern "C" void wg_hw_counters(int n, uint64_t *send_cnt, uint64_t *recv_cnt, uint64_t *recv_win) {
   *send_cnt = ((uint64_t)CSR_REG32(cryptokey_table.entry[n].send_cnt_63_32) << 32) |
               CSR_REG32(cryptokey_table.entry[n].send_cnt_31_0);
   *recv_cnt = ((uint64_t)CSR_REG32(cryptokey_table.entry[n].recv_cnt_63_32) << 32) |
               CSR_REG32(cryptokey_table.entry[n].recv_cnt_31_0);
   *recv_win = ((uint64_t)CSR_REG32(cryptokey_table.entry[n].recv_win_63_32) << 32) |
               CSR_REG32(cryptokey_table.entry[n].recv_win_31_0);
}

// a send counter for a keepalive: with the DPE drained no packet of the
// encryptor's is in flight, so send_cnt is the next free one; + 1 back
extern "C" int wg_hw_take_send_cnt(int n, uint64_t *cnt) {
   if (!dpe_pause()) return -1;
   uint64_t c = ((uint64_t)CSR_REG32(cryptokey_table.entry[n].send_cnt_63_32) << 32) |
                CSR_REG32(cryptokey_table.entry[n].send_cnt_31_0);
   CSR_REG32(cryptokey_table.entry[n].send_cnt_63_32) = (uint32_t)((c + 1) >> 32);
   CSR_REG32(cryptokey_table.entry[n].send_cnt_31_0)  = (uint32_t)(c + 1);
   dpe_resume();
   *cnt = c;
   return 0;
}

extern "C" void wg_hw_send(const wg_endpoint_t *dst, const uint8_t *msg, size_t len) {
   udp_send(dst, msg, (uint32_t)len);
}

// the session pool (#85): a peer's routes to its new entry, and the peer tag
// of its entries, under one pause; peer_idx and encrypt in one word write,
// as config_routes; the tag in a byte store of its own, the port kept
extern "C" int wg_hw_routes(uint64_t routes, uint64_t entries, int e) {
   if (!dpe_pause()) return -1;
   for (int x = 1; x < 64; x++) {
      if ((entries >> x) & 1) CSR_SET(cryptokey_table.entry[x].local_port, CSR__CRYPTOKEY_TABLE__ENTRY__LOCAL_PORT__TAG, e);
   }
   for (int r = 0; r < 64; r++) {
      if (!((routes >> r) & 1)) continue;
      uint32_t enc = CSR_GET(routing_table.entry[r].peer_idx, CSR__ROUTING_TABLE__ENTRY__PEER_IDX__ENCRYPT);
      CSR_REG32(routing_table.entry[r].peer_idx) =
         (((uint32_t)e << CSR__ROUTING_TABLE__ENTRY__PEER_IDX__PEER_IDX_bp) & CSR__ROUTING_TABLE__ENTRY__PEER_IDX__PEER_IDX_bm) |
         ((enc << CSR__ROUTING_TABLE__ENTRY__PEER_IDX__ENCRYPT_bp) & CSR__ROUTING_TABLE__ENTRY__PEER_IDX__ENCRYPT_bm);
   }
   dpe_resume();
   return 0;
}

// A received UDP frame: a WireGuard handshake message to our IP and port goes
// to wg_session_rx, and its answer out. True when it was one (consumed)
static bool wg_udp_rx(const eth_raw_packet_t *pkt, uint8_t debug) {
   const uint8_t *f = pkt->payload, *ip = f + 14, *udp = f + 34;
   if (pkt->len < 42 || ip[0] != 0x45) return false;           // no IPv4 options
   uint32_t ip_len = ((uint32_t)ip[2] << 8) | ip[3];
   if (ip_len < 28 || ip_len > pkt->len - 14) return false;
   if (net_calculate_checksum(ip, 20) != 0 || (ip[6] & 0x3F) != 0 || ip[7] != 0) return false;
   if (memcmp(ip + 16, net_config.ip, 4) != 0) return false;
   uint16_t dport = (uint16_t)((udp[2] << 8) | udp[3]);
   uint32_t ulen  = ((uint32_t)udp[4] << 8) | udp[5];
   if (dport != net_config.wg_port || ulen < 8 || ulen > ip_len - 20) return false;

   wg_endpoint_t src, dst;
   memcpy(src.mac, f + 6, 6);
   memcpy(src.ip, ip + 12, 4);
   src.port = (uint16_t)((udp[0] << 8) | udp[1]);
   src.ifc  = pkt->src;
   static uint8_t reply[WG_MSG_INIT_LEN];
   size_t         reply_len;
   int rc = wg_session_rx(udp + 8, ulen - 8, &src, reply, &reply_len, &dst);
   if (debug) {
      uart_send(rc == 0 ? "<< WireGuard handshake from " : "<< WireGuard message dropped, from ");
      uart_send_ip(src.ip);
      uart_send("\r\n");
   }
   if (rc == 0 && reply_len) udp_send(&dst, reply, (uint32_t)reply_len);
   return true;
}

// ---- CLI -----------------------------------------------------------------

static void send_base64(const uint8_t key[32]) {
   static const char t[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
   for (int i = 0; i < 30; i += 3) {
      uint32_t v = ((uint32_t)key[i] << 16) | ((uint32_t)key[i + 1] << 8) | key[i + 2];
      for (int j = 3; j >= 0; j--) uart_send_char(t[(v >> (6 * j)) & 63]);
   }
   uint32_t v = ((uint32_t)key[30] << 16) | ((uint32_t)key[31] << 8);
   uart_send_char(t[(v >> 18) & 63]);
   uart_send_char(t[(v >> 12) & 63]);
   uart_send_char(t[(v >> 6) & 63]);
   uart_send_char('=');
}

// wg key: set our private key (base64), or Enter to make one
static void wg_cli_key(void) {
   char    buf[UART_RXBUF_SIZE];
   uint8_t priv[32];
   ask("  Private key, base64 (Enter: make a new one): ", buf);
   bool ok = true;
   if (is_empty(buf)) {
      random_32bytes(priv);
   } else {
      ok = base64_key(buf, priv);
   }
   bare_wipe(buf, sizeof(buf));
   if (ok) wg_set_private(priv);
   bare_wipe(priv, sizeof(priv));
   if (!ok) {
      uart_send("  Not a base64 key (44 characters).\r\n");
      return;
   }
   uart_send("  Public key: ");
   send_base64(wg_identity()->pub);
   uart_send("\r\n");
}

// wg peer add: public key, preshared key, endpoint (optional)
static void wg_cli_peer_add(void) {
   char          buf[UART_RXBUF_SIZE];
   uint8_t       pub[32], psk[32];
   bool          has_psk = false;
   wg_endpoint_t ep;
   bool          has_ep = false;
   const char   *err = "  Not a base64 key.\r\n";

   ask("  Public key, base64: ", buf);
   if (base64_key(buf, pub)) {
      ask("  Preshared key, base64 (Enter: none): ", buf);
      has_psk = !is_empty(buf);
      if (!has_psk || base64_key(buf, psk)) err = NULL;
      bare_wipe(buf, sizeof(buf));
   }
   if (!err) {
      ask("  Endpoint IP (Enter: learn it from the peer's handshake): ", buf);
      if (!is_empty(buf)) {
         uint32_t port = 51820, ifc = 1, hi, lo;
         if (!net_str_parse_ip(buf, &ep.ip)) {
            err = "  Not an IP address.\r\n";
         } else {
            ask("  Endpoint port [51820]: ", buf);
            str_parse_uint32(buf, &port, 1, 65535);
            ask("  Endpoint (or gateway) MAC, 12 hex digits: ", buf);  // no ARP lookup yet
            if (!parse_mac(buf, &hi, &lo)) {
               err = "  Not 12 hex digits.\r\n";
            } else {
               ask("  Ethernet port (1-4) [1]: ", buf);
               str_parse_uint32(buf, &ifc, 1, 4);
               words_mac(hi, lo, ep.mac);
               ep.port = (uint16_t)port;
               ep.ifc  = (uint8_t)ifc;
               has_ep  = true;
            }
         }
      }
   }
   if (!err) {
      int n = wg_peer_add(pub, has_psk ? psk : NULL, has_ep ? &ep : NULL);
      if (n < 0) {
         err = "  Not added: the table is full, or the key is ours or there already.\r\n";
      } else {
         uart_send("  Peer ");
         send_dec_s((uint32_t)n, " added.\r\n");
      }
   }
   bare_wipe(psk, sizeof(psk));
   if (err) uart_send(err);
}

static int wg_cli_entry(void) {
   char     buf[UART_RXBUF_SIZE];
   uint32_t n = 0;
   ask("  Peer (1-63): ", buf);
   if (!str_parse_uint32(buf, &n, 1, 63) || !wg_peer((int)n)) {
      uart_send("  No such peer.\r\n");
      return -1;
   }
   return (int)n;
}

// the load mode and whether we are under load now (#81)
static void wg_send_load(void) {
   int m = wg_load_mode();
   uart_send(m == WG_LOAD_ON ? "forced on" : m == WG_LOAD_OFF ? "forced off" : "auto");
   uart_send(wg_under_load() ? ", under load (mac2 required)" : ", not under load");
}

// wg load [on|off|auto]: arg is the rest of the line after "wg load"
static void wg_cli_load(const char *arg) {
   if (bare_strcmp(arg, " on\n") == 0) {
      wg_set_load_mode(WG_LOAD_ON);
   } else if (bare_strcmp(arg, " off\n") == 0) {
      wg_set_load_mode(WG_LOAD_OFF);
   } else if (bare_strcmp(arg, " auto\n") == 0) {
      wg_set_load_mode(WG_LOAD_AUTO);
   } else if (bare_strcmp(arg, "\n") != 0) {
      uart_send("  Usage: wg load [on|off|auto]\r\n");
      return;
   }
   uart_send("  Load: ");
   wg_send_load();
   uart_send(".\r\n");
}

// " <what> N s ago", or never (valid 0)
static void wg_send_ago(const char *what, uint32_t now, uint32_t t, int valid) {
   uart_send(what);
   if (valid) {
      send_dec_s((now - t) / 1000u, " s ago");
   } else {
      uart_send("never");
   }
}

// a peer's timers (#80): its session, the traffic the counters showed, the state
static void wg_send_timers(const wg_peer_t *p) {
   uint32_t now = wg_timer_ms();
   uart_send("      ");
   if (p->live) {
      uart_send("session ");
      send_dec_s((now - p->cur.t_start) / 1000u, " s old (");
      uart_send(p->tm & WG_TM_INITIATOR ? "we initiated)," : "it initiated),");
   } else {
      uart_send("no session,");
   }
   wg_send_ago(" last handshake ", now, p->t_hs, p->tm & WG_TM_HS);
   wg_send_ago(", send ", now, p->t_sent, p->tm & WG_TM_SENT);
   wg_send_ago(", receive ", now, p->t_recv, p->tm & WG_TM_RECV);
   uart_send("\r\n      timers: ");
   if (p->tm & WG_TM_ATTEMPT) {
      uart_send(p->live ? "rekey pending, " : "handshake pending, ");
      uart_send("retransmit ");
      uart_send_dec(p->retries);
   } else if (p->tm & WG_TM_GAVE_UP) {
      uart_send("gave up (no answer in 90 s)");
   } else if (!p->live && (p->tm & WG_TM_REJECTED)) {
      uart_send("keys rejected (expired)");
   } else {
      uart_send("idle");
   }
   if (p->tm & WG_TM_KA) uart_send(", keepalive due");
   uart_send(", persistent keepalive ");
   if (p->keepalive) {
      send_dec_s(p->keepalive, " s\r\n");
   } else {
      uart_send("off\r\n");
   }
}

// wg keepalive: a peer's persistent keepalive interval (0 = off)
static void wg_cli_keepalive(void) {
   char     buf[UART_RXBUF_SIZE];
   uint32_t s = 0;
   int      n = wg_cli_entry();
   if (n < 0) return;
   ask("  Persistent keepalive, s (0 = off, up to 65535): ", buf);
   bool ok = str_parse_uint32(buf, &s, 0, 0xFFFF) && wg_peer_set_keepalive(n, (uint16_t)s) == 0;
   uart_send(ok ? "  Set.\r\n" : "  Not set.\r\n");
}

// wg show's counters: a wg_stats_t word (its offset / 4), or one of these
enum { ST_POOL = 0xF0, ST_HS, ST_SLOTS, ST_LOAD };
#define ST(f)  ((uint8_t)(offsetof(wg_stats_t, f) / 4))
static_assert(sizeof(wg_stats_t) % 4 == 0, "wg_stats_t: uint32_t counters only");

static void wg_send_stats(void) {
   static const struct { uint8_t i; const char *s; } st[] = {
      {ST(rx_init), " answered, "}, {ST(tx_init), " sent, "}, {ST(rx_resp), " answered to us, "},
      {ST(sessions), " sessions\r\n  Timers: "},
      {ST(rekeys), " rekeys, "}, {ST(retransmits), " retransmits, "}, {ST(gave_up), " gave up, "},
      {ST(rejected), " keys rejected, "}, {ST(keepalive_tx), " keepalives sent\r\n  Session pool: "},
      {ST_POOL, " / 63 entries free, "}, {ST(switches), " switches, "}, {ST(retired), " retired, "},
      {ST(in_place), " in place (pool full)\r\n  Handshake slots: "},
      {ST_HS, " / "}, {ST_SLOTS, " free, "},
      {ST(hs_busy), " initiations deferred (all busy)\r\n  Cookie replies: "},
      {ST(cookie_tx), " sent, "}, {ST(cookie_rx), " taken\r\n  Load: "},
      {ST_LOAD, ", rate exceeded "}, {ST(load_hits), " times\r\n  Dropped: "},
      {ST(drop_bad), " invalid, "}, {ST(drop_unknown), " unknown peer or index, "},
      {ST(drop_replay), " replayed, "}, {ST(drop_hw), " data plane busy\r\n"}};
   const uint32_t *w = (const uint32_t *)wg_stats();
   uart_send("  Handshakes: ");
   for (unsigned k = 0; k < sizeof(st) / sizeof(st[0]); k++) {
      uint8_t i = st[k].i;
      if (i == ST_LOAD) {
         wg_send_load();
      } else {
         uart_send_dec(i == ST_POOL ? (uint32_t)wg_pool_free() : i == ST_HS ? (uint32_t)wg_hs_free() :
                       i == ST_SLOTS ? (uint32_t)WG_HS_SLOTS : w[i]);
      }
      uart_send(st[k].s);
   }
}

static void wg_cli_show(void) {
   uart_send("WireGuard:\r\n  Public key: ");
   if (wg_has_private()) {
      send_base64(wg_identity()->pub);
   } else {
      uart_send("none (wg key)");
   }
   uart_send("\r\n");
   for (int n = 1; n < WG_PEERS; n++) {
      const wg_peer_t *p = wg_peer(n);
      if (!p) continue;
      uart_send("  (");
      send_dec_s((uint32_t)n, ") ");
      send_base64(p->pub);
      // its entries (the session pool, #85): current, next, old
      uart_send(p->live ? ", live, entry " : ", no session, entry ");
      send_dec_s(p->cur.entry, " (local ID 0x");
      uart_send_hex(p->cur.local_id, 8);
      uart_send("), next ");
      if (p->next.entry) {
         uart_send_dec(p->next.entry);
         uart_send(p->next.state == WG_KP_RESERVED ? " (our initiation)" : " (to confirm)");
      } else {
         uart_send("none");
      }
      if (p->prev.entry) {
         uart_send(", old ");
         send_dec_s(p->prev.entry, " (retiring)");
      }
      uart_send(", endpoint ");
      if (p->has_ep) {
         uart_send_ip(p->ep.ip);
         uart_send_char(':');
         uart_send_dec(p->ep.port);
      } else {
         uart_send("unknown");
      }
      uart_send("\r\n");
      wg_send_timers(p);
   }
   wg_send_stats();
}

static void wg_cli_initiate(void) {
   int n = wg_cli_entry();
   if (n < 0) return;
   uint8_t       msg[WG_MSG_INIT_LEN];
   wg_endpoint_t dst;
   if (wg_session_initiate(n, msg, &dst) != 0) {
      uart_send("  Needs our key (wg key) and the peer's endpoint; or its new session awaits confirmation.\r\n");
      return;
   }
   udp_send(&dst, msg, sizeof(msg));
   uart_send("  Handshake initiation sent.\r\n");
}

// clock: the real-time clock (rtc.c, #30) and its high-water mark in the flash
static void clock_show(void) {
   const rtc_state_t *s = rtc_state();
   uint64_t sec;
   uint32_t nsec;
   rtc_get(&sec, &nsec);
   uart_send("  Time: ");
   uart_send_dec((uint32_t)sec);  // Unix seconds: 32 bits until 2106
   uart_send_char('.');
   uart_send_dec(nsec);
   uart_send(" (Unix)\r\n  Mark: ");
   uart_send_dec((uint32_t)s->mark);
   uart_send(", boots ");
   uart_send_dec(s->boots);
   uart_send(", flash ID 0x");
   uart_send_hex(s->flash_id, 6);
   uart_send(s->flash_id == 0 ? " (none: the clock restarts at 2026-01-01)\r\n"
             : s->flash_ok    ? ", last record written\r\n"
                              : ", last record FAILED\r\n");
}

// clock set <unix>: only forward (a peer keeps our newest timestamp). arg:
// the rest of the line after "clock set"
static void clock_set(const char *arg) {
   uint32_t t = 0;
   if (*arg != ' ' || !str_parse_uint32(arg + 1, &t, 1, 0xFFFFFFFF)) {
      uart_send("  Usage: clock set <Unix seconds>\r\n");
   } else if (wg_set_time(t) != 0) {
      uart_send("  Refused: not ahead of the clock (it only goes forward).\r\n");
   } else {
      clock_show();
   }
}

static void flash_cli_id(void) {
   if (flash_init() != 0) {
      uart_send("  No flash answers.\r\n");
      return;
   }
   uart_send("  JEDEC ID 0x");
   uart_send_hex(flash_id(), 6);
   uart_send("\r\n");
}

void reboot() {
#ifdef VPROC
   // Co-simulation: no restart, park the VProc node
   while (1) VTick(10000, SOC_CPU_VPNODE);
#else
   asm volatile ("jr zero" ::: "memory");
#endif
}

// ---- the commands: each takes the rest of its line ----

static void cmd_test_aead(const char *)       { test_chacha20poly1305(); }
static void cmd_test_blake2s(const char *)    { test_blake2s(); }
static void cmd_test_curve25519(const char *) { test_curve25519(); }
static void cmd_test_rng(const char *)        { test_rng(); }
static void cmd_test_timer(const char *)      { test_timer(); }
static void cmd_show_network(const char *)    { show_network(&net_config); }
static void cmd_config_network(const char *)  { config_network(&net_config); }
static void cmd_show_routes(const char *)     { show_routes(); }
static void cmd_config_routes(const char *)   { config_routes(); }
static void cmd_show_ck(const char *)         { show_cryptokeys(); }
static void cmd_config_ck(const char *)       { config_cryptokeys(); }
static void cmd_wg_key(const char *)          { wg_cli_key(); }
static void cmd_wg_peer_add(const char *)     { wg_cli_peer_add(); }
static void cmd_wg_initiate(const char *)     { wg_cli_initiate(); }
static void cmd_wg_keepalive(const char *)    { wg_cli_keepalive(); }
static void cmd_wg_show(const char *)         { wg_cli_show(); }
static void cmd_clock(const char *)           { clock_show(); }
static void cmd_flash_id(const char *)        { flash_cli_id(); }
static void cmd_reboot(const char *)          { reboot(); }

static void cmd_wg_peer_remove(const char *) {
   int n = wg_cli_entry();
   if (n > 0) uart_send(wg_peer_remove(n) == 0 ? "  Removed.\r\n" : "  Not removed.\r\n");
}

static void cmd_debug(const char *) {
   debug_enabled = !debug_enabled;
   uart_send("Debug mode ");
   uart_send(debug_enabled ? "enabled.\r\n" : "disabled.\r\n");
}

static void cmd_help(const char *);

// name: the command, then " <...>" or " [...]" for its arguments (in help)
static const struct {
   const char *name, *help;
   void      (*fn)(const char *arg);
} cli_cmds[] = {
   {"test chacha20poly1305", "Test ChaCha20-Poly1305 AEAD",                     cmd_test_aead},
   {"test blake2s",          "Test BLAKE2s hash function",                      cmd_test_blake2s},
   {"test curve25519",       "Test Curve25519 key exchange",                    cmd_test_curve25519},
   {"test rng",              "Test random number generator",                    cmd_test_rng},
   {"test timer",            "Test timer functionality",                        cmd_test_timer},
   {"show network",          "Show network configuration",                      cmd_show_network},
   {"config network",        "Configure network settings",                      cmd_config_network},
   {"show routes",           "Show routing table",                              cmd_show_routes},
   {"config routes",         "Configure routing table entry",                   cmd_config_routes},
   {"show cryptokeys",       "Show cryptokey table",                            cmd_show_ck},
   {"config cryptokeys",     "Configure cryptokey table entry",                 cmd_config_ck},
   {"wg key",                "Set or make our WireGuard private key",           cmd_wg_key},
   {"wg peer add",           "Add a peer (public key, psk, endpoint)",          cmd_wg_peer_add},
   {"wg peer remove",        "Remove a peer and its table entry",               cmd_wg_peer_remove},
   {"wg initiate",           "Start a handshake with a peer",                   cmd_wg_initiate},
   {"wg keepalive",          "A peer's persistent keepalive (s, 0 = off)",      cmd_wg_keepalive},
   {"wg show",               "Show our key, the peers and counters",            cmd_wg_show},
   {"wg load [on|off|auto]", "Under load (cookie replies): forced, or auto",    wg_cli_load},
   {"clock",                 "Show the clock, its flash mark, boots",           cmd_clock},
   {"clock set <unix>",      "Set the clock (Unix seconds; only forward)",      clock_set},
   {"flash id",              "Read the configuration flash's JEDEC ID",         cmd_flash_id},
   {"debug",                 "Toggle debug mode",                               cmd_debug},
   {"reboot",                "Reboot the system",                               cmd_reboot},
   {"help",                  "Show this help message",                          cmd_help},
};

static void cmd_help(const char *) {
   uart_send("Available commands:\r\n");
   for (const auto &c : cli_cmds) {
      uart_send("  ");
      uart_send(c.name);
      for (int s = 23 - (int)bare_strlen(c.name); s > 0; s--) uart_send_char(' ');
      uart_send("- ");
      uart_send(c.help);
      uart_send("\r\n");
   }
}

// line is command name: the rest of the line (its "\n", or for a command
// with arguments " ..." too), else NULL
static const char *cli_match(const char *line, const char *name) {
   for (; *name; name++, line++) {
      if (name[0] == ' ' && (name[1] == '<' || name[1] == '[')) {
         return (*line == ' ' || *line == '\n') ? line : NULL;
      }
      if (*name != *line) return NULL;
   }
   return *line == '\n' ? line : NULL;
}

// a line of the debug mode: "<< NET_PROTO_ARP: 60"
static void debug_packet(const char *dir, net_protocol_t protocol, uint32_t len) {
   static const char *const name[] = {"UNKNOWN", "ARP", "ICMP", "UDP"};
   if (!debug_enabled) return;
   uart_send(dir);
   uart_send(" NET_PROTO_");
   uart_send(name[protocol]);
   uart_send(": ");
   send_dec_s(len, "\r\n");
}

int main(void) {
   char uart_rx_data[UART_RXBUF_SIZE];
   uint8_t uart_rx_len;

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
   if (rtc_boot() != 0) {  // before the first timestamp
      uart_send("Clock: no flash, starts at 2026-01-01 (clock set)\r\n");
   }
   init_network(&net_config);
   wg_session_init();  // no key yet: wg key
   show_network(&net_config);

   // CLI prompt
   uart_send("\r\nType 'help' to display commands.\r\n");
   uart_send("(wireguard-fpga)# ");

   stack_scrub();  // the start-up key generation
   while (1) {
#if defined(VPROC) && defined(WG_E2E_HOOK)
      wg_e2e_hook();
#endif
      rtc_poll();  // a new high-water mark in the flash before the clock reaches it
      // WireGuard timers (#80): every 200 ms, the peers' counters polled;
      // rekeys, retransmits, keepalives, keys rejected. Never blocks (a
      // handshake initiation: 2 X25519)
      if (wg_session_timers()) stack_scrub();
      // Receive Ethernet packet for CPU FIFO
      if (eth_receive_packet(&eth_packet_rx)) {
         bool consumed = false;  // a WireGuard handshake: not forwarded below
         bool reply    = false;  // an ARP or ICMP answer in eth_packet_tx
         CSR_RMW(gpio, CSR__GPIO__LED2, 1);
         // Parse packet header
         net_protocol_t protocol = net_parse_packet_header(&eth_packet_rx);
         debug_packet("<<", protocol, eth_packet_rx.len);
         switch (protocol) {
            case NET_PROTO_UNKNOWN:
               break;
            case NET_PROTO_ARP:
               reply = net_process_arp(&net_config, &net_arp_cache, &eth_packet_rx, &eth_packet_tx);
               break;
            case NET_PROTO_ICMP:
               reply = net_process_icmp(&net_config, &eth_packet_rx, &eth_packet_tx);
               break;
            case NET_PROTO_UDP:
               consumed = wg_udp_rx(&eth_packet_rx, debug_enabled);
               break;
         }
         if (reply) {
            eth_send_packet(&eth_packet_tx);
            debug_packet(">>", protocol, eth_packet_tx.len);
         }

         if (consumed) {
            // answered (or dropped) by the WireGuard handshake
         } else if (eth_packet_rx.src == DPE_ADDR_ETH_1 || eth_packet_rx.src == DPE_ADDR_ETH_2) {
            eth_packet_rx.dst = eth_packet_rx.src == DPE_ADDR_ETH_1 ? DPE_ADDR_ETH_2 : DPE_ADDR_ETH_1;
            eth_packet_rx.bypass_all = 1;
            eth_send_packet(&eth_packet_rx);
         }
         stack_scrub();
      } else {
         CSR_RMW(gpio, CSR__GPIO__LED2, 0);
      }

      // Receive and process CLI command
      uart_rx_len = uart_recv(uart_rx_data);
      if (uart_rx_len) {
         const char *arg = NULL;
         unsigned    k;
         for (k = 0; k < sizeof(cli_cmds) / sizeof(cli_cmds[0]); k++) {
            arg = cli_match(uart_rx_data, cli_cmds[k].name);
            if (arg) break;
         }
         if (arg) {
            cli_cmds[k].fn(arg);
         } else if (uart_rx_len > 1) {
            uart_send("Unknown command\r\n");
         }
         stack_scrub();
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
