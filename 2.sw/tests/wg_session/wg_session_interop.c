// SPDX-FileCopyrightText: 2026 Chili.CHIPS
//
// SPDX-License-Identifier: BSD-3-Clause

// wg_session.c (the firmware's session layer) against the Linux kernel's
// WireGuard (run_interop.sh): the keys it hands the data plane
// (wg_hw_install) must decrypt the kernel's data packets and encrypt ours.
//   wg_session_interop pub       our public key and the psk (base64)
//   wg_session_interop respond   the kernel initiates (ping 10.0.0.2)
//   wg_session_interop initiate  we initiate (wg_session_initiate)
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <time.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/time.h>
#include "wg_session.h"
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

// ---- the platform: the table entry is kept here ----
static wg_install_t entry[WG_ENTRIES];
void wg_hw_random(uint8_t out[32]) {
    FILE *f = fopen("/dev/urandom", "rb");
    if (!f || fread(out, 1, 32, f) != 32) abort();
    fclose(f);
}
void random_32bytes(uint8_t *out) { wg_hw_random(out); }
static uint64_t send_cnt[WG_ENTRIES], recv_cnt[WG_ENTRIES];
static int      sock, fails;
int wg_hw_install(int n, const wg_install_t *in) {
    if (in) entry[n] = *in; else memset(&entry[n], 0, sizeof(entry[n]));
    send_cnt[n] = recv_cnt[n] = 0;
    return 0;
}
// the timers (#80): the counters, and the messages they send go out the socket
void wg_hw_counters(int n, uint64_t *s, uint64_t *r, uint64_t *w) { *s = send_cnt[n]; *r = recv_cnt[n]; *w = 0; }
int wg_hw_routes(uint64_t routes, uint64_t entries, int e) { (void)routes; (void)entries; (void)e; return 0; }  // no routes here
int wg_hw_take_send_cnt(int n, uint64_t *c) { *c = send_cnt[n]++; return 0; }
static struct sockaddr_in sa_of(const wg_endpoint_t *e);
void wg_hw_send(const wg_endpoint_t *dst, const uint8_t *msg, size_t len) {
    struct sockaddr_in d = sa_of(dst);
    sendto(sock, msg, len, 0, (struct sockaddr *)&d, sizeof(d));
}
// the kernel's rx bytes from peer 1 (wg show wg0 transfer)
static long kernel_rx(void) {
    char line[256]; long rx = -1, tx;
    FILE *f = popen("wg show wg0 transfer", "r");
    if (f && fgets(line, sizeof(line), f)) sscanf(strchr(line, '\t') ? strchr(line, '\t') : line, "%ld %ld", &rx, &tx);
    if (f) pclose(f);
    return rx;
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
static int open_data(const uint8_t *m, int len, uint32_t receiver, const uint8_t k[32], uint8_t *pt) {
    if (len < 32 || m[0] != 4) return -1;
    uint32_t r = m[4] | (m[5] << 8) | (m[6] << 16) | ((uint32_t)m[7] << 24);
    if (r != receiver) return -1;
    uint64_t c = 0;
    for (int i = 0; i < 8; i++) c |= (uint64_t)m[8 + i] << (8 * i);
    uint8_t n[12]; nonce(n, c);
    int ct = len - 32;
    if (chacha20poly1305_decrypt(pt, k, n, m + 16, ct, m + 16 + ct, NULL, 0) != 0) return -1;
    return ct;
}

static void ok(const char *what, int c) { printf("%s %s\n", c ? "PASS" : "FAIL", what); if (!c) fails++; }
static int is_echo(const uint8_t *pt, int n, int type) {
    char s[16], d[16];
    if (n < 28 || pt[0] != 0x45 || pt[9] != 1 || pt[20] != type) return 0;
    inet_ntop(AF_INET, pt + 12, s, sizeof(s)); inet_ntop(AF_INET, pt + 16, d, sizeof(d));
    printf("  ICMP type %d %s -> %s, %d bytes\n", type, s, d, n);
    return !strcmp(s, "10.0.0.1") && !strcmp(d, "10.0.0.2");  // both: from the kernel
}

static wg_endpoint_t ep_of(const struct sockaddr_in *a) {
    wg_endpoint_t e; memset(&e, 0, sizeof(e));
    memcpy(e.ip, &a->sin_addr.s_addr, 4);
    e.port = ntohs(a->sin_port);
    e.ifc  = 1;
    return e;
}
static struct sockaddr_in sa_of(const wg_endpoint_t *e) {
    struct sockaddr_in a; memset(&a, 0, sizeof(a));
    a.sin_family = AF_INET; a.sin_port = htons(e->port);
    memcpy(&a.sin_addr.s_addr, e->ip, 4);
    return a;
}

// ICMP echo 10.0.0.2 -> 10.0.0.1 through entry e (encrypt key, its next
// send counter), and the kernel's reply opened with e's decrypt key: its
// length, or <= 0
static int echo(int e, const struct sockaddr_in *d, uint8_t *pt) {
    uint8_t ip[64] = {0}, buf[2048];
    int len = 20 + 8 + 32, p = -1;
    ip[0] = 0x45; ip[3] = (uint8_t)len; ip[8] = 64; ip[9] = 1;
    inet_pton(AF_INET, "10.0.0.2", ip + 12); inet_pton(AF_INET, "10.0.0.1", ip + 16);
    uint16_t c = csum(ip, 20); ip[10] = c >> 8; ip[11] = (uint8_t)c;
    ip[20] = 8; ip[24] = 0x12; ip[25] = 0x34; ip[27] = 1;
    for (int i = 0; i < 32; i++) ip[28 + i] = (uint8_t)i;
    c = csum(ip + 20, 40); ip[22] = c >> 8; ip[23] = (uint8_t)c;
    int padded = (len + 15) & ~15;
    uint8_t m4[16 + 64 + 16] = {4};
    uint64_t cnt = send_cnt[e]++;
    for (int i = 0; i < 4; i++) m4[4 + i] = (uint8_t)(entry[e].remote_id >> (8 * i));
    for (int i = 0; i < 8; i++) m4[8 + i] = (uint8_t)(cnt >> (8 * i));
    uint8_t nn[12]; nonce(nn, cnt);
    chacha20poly1305_encrypt(m4 + 16, m4 + 16 + padded, entry[e].send_key, nn, ip, padded, NULL, 0);
    sendto(sock, m4, 16 + padded + 16, 0, (const struct sockaddr *)d, sizeof(*d));
    for (int tries = 0; tries < 5 && p <= 0; tries++) {
        struct sockaddr_in from; socklen_t fl = sizeof(from);
        int n = (int)recvfrom(sock, buf, sizeof(buf), 0, (struct sockaddr *)&from, &fl);
        if (n > 0) p = open_data(buf, n, entry[e].local_id, entry[e].recv_key, pt);
    }
    return p;
}

int main(int argc, char **argv) {
    uint8_t priv[32], psk[32], kpub[32];
    key(priv, 0x10); key(psk, 0x90);
    const char *mode = argc > 1 ? argv[1] : "pub";
    wg_session_init();
    wg_set_private(priv);
    char s[45];
    if (!strcmp(mode, "pub")) { b64(wg_identity()->pub, s); printf("%s ", s); b64(psk, s); printf("%s\n", s); return 0; }
    {
        static const char t[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        uint32_t acc = 0; int bits = 0, n = 0;
        for (const char *c = argv[2]; *c && *c != '='; c++) {
            acc = (acc << 6) | (uint32_t)(strchr(t, *c) - t); bits += 6;
            if (bits >= 8) { bits -= 8; if (n < 32) kpub[n++] = (uint8_t)(acc >> bits); }
        }
    }
    struct timespec now; clock_gettime(CLOCK_REALTIME, &now);
    wg_set_time((uint64_t)now.tv_sec);

    sock = socket(AF_INET, SOCK_DGRAM, 0);
    struct sockaddr_in me = {0}, from;
    me.sin_family = AF_INET; me.sin_port = htons(40000); me.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    bind(sock, (struct sockaddr *)&me, sizeof(me));
    struct timeval tv = {3, 0};
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    socklen_t fl;
    uint8_t buf[2048], pt[2048], out[WG_MSG_INIT_LEN];
    size_t out_len; wg_endpoint_t dst;
    int n, p = -1;

    if (!strcmp(mode, "respond")) {
        int peer = wg_peer_add(kpub, psk, NULL);
        fl = sizeof(from);
        n = (int)recvfrom(sock, buf, sizeof(buf), 0, (struct sockaddr *)&from, &fl);
        wg_endpoint_t src = ep_of(&from);
        ok("wg_session answers the kernel's message 1",
           wg_session_rx(buf, n, &src, out, &out_len, &dst) == 0 && out_len == WG_MSG_RESP_LEN);
        int ne = wg_peer(peer)->next.entry;
        ok("... in a next entry, waiting for confirmation (#85)",
           ne > 0 && wg_peer(peer)->next.state == WG_KP_PENDING && !wg_peer(peer)->live);
        struct sockaddr_in d = sa_of(&dst);
        sendto(sock, out, out_len, 0, (struct sockaddr *)&d, sizeof(d));
        for (int tries = 0; tries < 5 && p <= 0; tries++) {
            fl = sizeof(from);
            n = (int)recvfrom(sock, buf, sizeof(buf), 0, (struct sockaddr *)&from, &fl);
            if (n > 0 && buf[0] == 4) p = open_data(buf, n, entry[ne].local_id, entry[ne].recv_key, pt);
        }
        ok("the kernel's data decrypts with the installed decrypt key", p > 0);
        ok("it is the ping 10.0.0.1 -> 10.0.0.2", p > 0 && is_echo(pt, p, 8));
        recv_cnt[ne] = 1;  // the data plane's replay window moved: key confirmation
        wg_session_timers();
        ok("... it confirms the session: live, the current entry",
           wg_peer(peer)->live && wg_peer(peer)->cur.entry == ne && wg_stats()->switches == 1);
    } else {
        wg_endpoint_t kep; memset(&kep, 0, sizeof(kep));
        kep.ip[0] = 127; kep.ip[3] = 1; kep.port = 51820; kep.ifc = 1;
        int peer = wg_peer_add(kpub, psk, &kep);
        uint8_t m1[WG_MSG_INIT_LEN];
        ok("wg_session builds message 1", wg_session_initiate(peer, m1, &dst) == 0);
        struct sockaddr_in d = sa_of(&dst);
        sendto(sock, m1, sizeof(m1), 0, (struct sockaddr *)&d, sizeof(d));
        fl = sizeof(from);
        n = (int)recvfrom(sock, buf, sizeof(buf), 0, (struct sockaddr *)&from, &fl);
        wg_endpoint_t src = ep_of(&from);
        ok("wg_session accepts the kernel's message 2, sends a keepalive", n == WG_MSG_RESP_LEN &&
           wg_session_rx(buf, n, &src, out, &out_len, &dst) == 0 && wg_stats()->keepalive_tx == 1);
        int e = wg_peer(peer)->cur.entry;
        p = echo(e, &d, pt);
        ok("the kernel's reply decrypts with the installed decrypt key", p > 0);
        ok("it is the echo reply 10.0.0.1 -> 10.0.0.2", p > 0 && is_echo(pt, p, 0));
        // a rekey (#85): our next initiation for a next entry; message 2
        // switches to it, our keepalive confirms it to the kernel. Linux
        // takes one initiation per peer per 20 ms (INITIATIONS_PER_SECOND)
        struct timespec gap = {0, 100000000};
        nanosleep(&gap, NULL);
        ok("rekey: message 1 for a next entry", wg_session_initiate(peer, m1, &dst) == 0
           && wg_peer(peer)->next.entry > 0 && wg_peer(peer)->next.entry != e);
        sendto(sock, m1, sizeof(m1), 0, (struct sockaddr *)&d, sizeof(d));
        n = -1;
        for (int tries = 0; tries < 5 && n != WG_MSG_RESP_LEN; tries++) {
            fl = sizeof(from);
            n = (int)recvfrom(sock, buf, sizeof(buf), 0, (struct sockaddr *)&from, &fl);
        }
        int ne = wg_peer(peer)->next.entry;
        printf("  rekey: %d bytes back, entry %d -> %d\n", n, e, ne);
        ok("... the kernel's message 2: switched, the old entry kept", n == WG_MSG_RESP_LEN
           && wg_session_rx(buf, n, &src, out, &out_len, &dst) == 0 && wg_peer(peer)->cur.entry == ne
           && wg_peer(peer)->prev.entry == e && wg_stats()->keepalive_tx == 2);
        p = echo(ne, &d, pt);
        ok("... the kernel's reply decrypts with the new entry", p > 0 && is_echo(pt, p, 0));
        // a keepalive the timers build (#80): the persistent keepalive at 1
        // s, its counter after the echo's; the kernel must take it
        long rx0 = kernel_rx();
        uint64_t c0 = send_cnt[ne];
        wg_peer_set_keepalive(peer, 1);
        struct timespec t0, t1, w = {0, 50000000};
        clock_gettime(CLOCK_MONOTONIC, &t0);
        int sent = 0;
        do {
            sent += wg_session_timers();
            nanosleep(&w, NULL);
            clock_gettime(CLOCK_MONOTONIC, &t1);
        } while (!sent && t1.tv_sec - t0.tv_sec < 3);
        nanosleep(&w, NULL);
        long rx1 = kernel_rx();
        printf("  kernel rx bytes %ld -> %ld\n", rx0, rx1);
        ok("the timers' keepalive is taken by the kernel",
           sent == 1 && send_cnt[ne] == c0 + 1 && wg_stats()->keepalive_tx == 3 && rx1 > rx0 && rx0 >= 0);
    }
    return fails;
}

// -----------------------------------------------------------------------------
// Project:     WireGuard-FPGA
// Description: NLnet-funded open-source implementation
// Funding:     https://nlnet.nl/project/KlusterLab-Wireguard (2023-12 to 2025-12)
// -----------------------------------------------------------------------------
