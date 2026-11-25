// SPDX-FileCopyrightText: 2026 Chili.CHIPS
//
// SPDX-License-Identifier: BSD-3-Clause

// Interop of 2.sw/app/noise.c with the Linux kernel's WireGuard (wg0 in a
// user+net namespace, run_interop.sh). Our side is 10.0.0.2 on UDP 40000.
//   wg_interop pub       print our public key and the psk (base64)
//   wg_interop respond   the kernel initiates (ping 10.0.0.2): we respond,
//                        then decrypt its first data packet (the ICMP echo)
//   wg_interop initiate  we initiate, then send an ICMP echo through the
//                        tunnel and decrypt the kernel's reply
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <time.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/time.h>
#include "noise.h"
#include "chacha20poly1305.h"

static void key(uint8_t k[32], int b) { for (int i = 0; i < 32; i++) k[i] = (uint8_t)(b + i); }

static void b64(const uint8_t *in, char out[45]) {
    static const char t[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    int o = 0;
    for (int i = 0; i < 30; i += 3) {
        uint32_t v = (in[i] << 16) | (in[i + 1] << 8) | in[i + 2];
        for (int j = 3; j >= 0; j--) out[o++] = t[(v >> (6 * j)) & 63];
    }
    uint32_t v = (in[30] << 16) | (in[31] << 8);
    out[o++] = t[(v >> 18) & 63]; out[o++] = t[(v >> 12) & 63]; out[o++] = t[(v >> 6) & 63];
    out[o++] = '='; out[o] = 0;
}

static uint16_t csum(const uint8_t *p, size_t n) {
    uint32_t s = 0;
    for (size_t i = 0; i + 1 < n; i += 2) s += (p[i] << 8) | p[i + 1];
    if (n & 1) s += p[n - 1] << 8;
    while (s >> 16) s = (s & 0xffff) + (s >> 16);
    return (uint16_t)~s;
}

static void nonce(uint8_t n[12], uint64_t c) {
    memset(n, 0, 12);
    for (int i = 0; i < 8; i++) n[4 + i] = (uint8_t)(c >> (8 * i));
}

// decrypt a type-4 message with key; returns the plaintext length or -1
static int open_data(const uint8_t *m, int len, uint32_t receiver, const uint8_t k[32], uint8_t *pt) {
    if (len < 32 || m[0] != 4) return -1;
    uint32_t r = m[4] | (m[5] << 8) | (m[6] << 16) | ((uint32_t)m[7] << 24);
    if (r != receiver) return -1;
    uint64_t c = 0;
    for (int i = 0; i < 8; i++) c |= (uint64_t)m[8 + i] << (8 * i);
    uint8_t n[12]; nonce(n, c);
    int ct = len - 16 - 16;
    if (chacha20poly1305_decrypt(pt, k, n, m + 16, ct, m + 16 + ct, NULL, 0) != 0) return -1;
    return ct;
}

static int sock, fails;
static struct sockaddr_in kernel;

static int recv_msg(uint8_t *buf, int cap, struct sockaddr_in *from) {
    socklen_t fl = sizeof(*from);
    return (int)recvfrom(sock, buf, cap, 0, (struct sockaddr *)from, &fl);
}

static void ok(const char *what, int c) { printf("%s %s\n", c ? "PASS" : "FAIL", what); if (!c) fails++; }

// is pt an ICMP echo of the given type, from src to dst
static int is_echo(const uint8_t *pt, int n, int type, const char *src, const char *dst) {
    char s[16], d[16];
    if (n < 28 || pt[0] != 0x45 || pt[9] != 1 || pt[20] != type) return 0;
    inet_ntop(AF_INET, pt + 12, s, sizeof(s)); inet_ntop(AF_INET, pt + 16, d, sizeof(d));
    printf("  ICMP type %d %s -> %s, %d bytes\n", type, s, d, n);
    return strcmp(s, src) == 0 && strcmp(d, dst) == 0;
}

int main(int argc, char **argv) {
    uint8_t priv[32], psk[32], kpub[32], e[32];
    key(priv, 0x10); key(psk, 0x90); key(e, 0x55);
    wg_identity_t id; wg_identity_init(&id, priv);
    const char *mode = argc > 1 ? argv[1] : "pub";
    char s[45];
    if (!strcmp(mode, "pub")) { b64(id.pub, s); printf("%s ", s); b64(psk, s); printf("%s\n", s); return 0; }

    // the kernel's public key, base64, from argv[2]
    {
        static const char t[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        uint32_t acc = 0; int bits = 0, n = 0;
        for (const char *c = argv[2]; *c && *c != '='; c++) {
            acc = (acc << 6) | (uint32_t)(strchr(t, *c) - t); bits += 6;
            if (bits >= 8) { bits -= 8; if (n < 32) kpub[n++] = (uint8_t)(acc >> bits); }
        }
    }

    sock = socket(AF_INET, SOCK_DGRAM, 0);
    struct sockaddr_in me = {0};
    me.sin_family = AF_INET; me.sin_port = htons(40000); me.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    bind(sock, (struct sockaddr *)&me, sizeof(me));
    struct timeval tv = {3, 0};
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    kernel.sin_family = AF_INET; kernel.sin_port = htons(51820); kernel.sin_addr.s_addr = htonl(INADDR_LOOPBACK);

    uint8_t buf[2048], pt[2048];
    struct sockaddr_in from;
    wg_handshake_t hs; memset(&hs, 0, sizeof(hs));

    if (!strcmp(mode, "respond")) {
        int n = recv_msg(buf, sizeof(buf), &from);
        ok("kernel sent a 148-byte initiation", n == WG_MSG_INIT_LEN);
        uint8_t is[32], ts[12];
        int rc = wg_consume_initiation(&id, &hs, buf, is, ts);
        ok("our responder accepts the kernel's initiation", rc == 0);
        ok("initiator static = the kernel's public key", memcmp(is, kpub, 32) == 0);
        memcpy(hs.psk, psk, 32);
        uint8_t m2[WG_MSG_RESP_LEN];
        wg_create_response(&hs, 0x0badcafe, e, m2);
        sendto(sock, m2, sizeof(m2), 0, (struct sockaddr *)&from, sizeof(from));
        for (int tries = 0; tries < 5; tries++) {  // skip a retransmitted initiation
            n = recv_msg(buf, sizeof(buf), &from);
            if (n > 0 && buf[0] == 4) break;
        }
        int p = open_data(buf, n, 0x0badcafe, hs.recv_key, pt);
        ok("kernel's data packet decrypts with our recv key", p > 0);
        ok("it is the ping 10.0.0.1 -> 10.0.0.2", p > 0 && is_echo(pt, p, 8, "10.0.0.1", "10.0.0.2"));
    } else {
        memcpy(hs.remote_static, kpub, 32); memcpy(hs.psk, psk, 32);
        struct timespec now; clock_gettime(CLOCK_REALTIME, &now);
        uint8_t ts[12], m1[WG_MSG_INIT_LEN];
        wg_tai64n(ts, (uint64_t)now.tv_sec, (uint32_t)now.tv_nsec);
        wg_create_initiation(&id, &hs, 0x12345678, e, ts, m1);
        sendto(sock, m1, sizeof(m1), 0, (struct sockaddr *)&kernel, sizeof(kernel));
        int n = recv_msg(buf, sizeof(buf), &from);
        ok("kernel sent a 92-byte response", n == WG_MSG_RESP_LEN);
        ok("our initiator accepts the kernel's response", n == WG_MSG_RESP_LEN && wg_consume_response(&id, &hs, buf) == 0);

        // ICMP echo request 10.0.0.2 -> 10.0.0.1, 32 data bytes, padded to 16
        uint8_t ip[64] = {0};
        int len = 20 + 8 + 32;
        ip[0] = 0x45; ip[3] = (uint8_t)len; ip[8] = 64; ip[9] = 1;
        inet_pton(AF_INET, "10.0.0.2", ip + 12); inet_pton(AF_INET, "10.0.0.1", ip + 16);
        uint16_t c = csum(ip, 20); ip[10] = c >> 8; ip[11] = (uint8_t)c;
        ip[20] = 8; ip[24] = 0x12; ip[25] = 0x34; ip[27] = 1;
        for (int i = 0; i < 32; i++) ip[28 + i] = (uint8_t)i;
        c = csum(ip + 20, 40); ip[22] = c >> 8; ip[23] = (uint8_t)c;
        int padded = (len + 15) & ~15;
        uint8_t m4[16 + 64 + 16] = {4};
        for (int i = 0; i < 4; i++) m4[4 + i] = (uint8_t)(hs.remote_index >> (8 * i));
        uint8_t nn[12]; nonce(nn, 0);
        chacha20poly1305_encrypt(m4 + 16, m4 + 16 + padded, hs.send_key, nn, ip, padded, NULL, 0);
        sendto(sock, m4, 16 + padded + 16, 0, (struct sockaddr *)&kernel, sizeof(kernel));
        int p = -1;
        for (int tries = 0; tries < 5 && p <= 0; tries++) {
            n = recv_msg(buf, sizeof(buf), &from);
            if (n > 0) p = open_data(buf, n, 0x12345678, hs.recv_key, pt);
        }
        ok("kernel's reply decrypts with our recv key", p > 0);
        ok("it is the echo reply 10.0.0.1 -> 10.0.0.2", p > 0 && is_echo(pt, p, 0, "10.0.0.1", "10.0.0.2"));
    }
    return fails;
}

// -----------------------------------------------------------------------------
// Project:     WireGuard-FPGA
// Description: NLnet-funded open-source implementation
// Funding:     https://nlnet.nl/project/KlusterLab-Wireguard (2023-12 to 2025-12)
// -----------------------------------------------------------------------------
