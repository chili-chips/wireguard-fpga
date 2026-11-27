// SPDX-FileCopyrightText: 2026 Chili.CHIPS
//
// SPDX-License-Identifier: BSD-3-Clause

// Cookie interop of 2.sw/app/cookie.c with the Linux kernel's WireGuard (wg0
// in a user+net namespace, run_interop.sh). Our side: 10.0.0.2, UDP 40000,
// the keys of tests/noise/wg_interop.c.
//   cookie_interop pub         print our public key and the psk (base64)
//   cookie_interop kernel-reply  we flood the kernel with initiations until
//                              it is under load and sends cookie replies; we
//                              take the cookie, then under load our next
//                              initiation (with mac2) gets a response
//   cookie_interop our-reply   the kernel initiates (ping 10.0.0.2); we act
//                              under load and send a cookie reply; its
//                              retransmit (5 s later) must carry a valid
//                              mac2; then we respond and decrypt the ping
#define _GNU_SOURCE  // sendmmsg
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <time.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/wait.h>
#include <unistd.h>
#include "noise.h"
#include "cookie.h"
#include "chacha20poly1305.h"

// the host's RNG and clock, for the firmware's random.c (csr.cycle) and #30
void random_32bytes(uint8_t *out) {
    FILE *f = fopen("/dev/urandom", "rb");
    if (!f || fread(out, 1, 32, f) != 32) abort();
    fclose(f);
}

uint32_t wg_now_seconds(void) {
    struct timespec t;
    clock_gettime(CLOCK_MONOTONIC, &t);
    return (uint32_t)t.tv_sec;
}

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

static void unb64(const char *s, uint8_t k[32]) {
    static const char t[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    uint32_t acc = 0; int bits = 0, n = 0;
    for (const char *c = s; *c && *c != '='; c++) {
        acc = (acc << 6) | (uint32_t)(strchr(t, *c) - t); bits += 6;
        if (bits >= 8) { bits -= 8; if (n < 32) k[n++] = (uint8_t)(acc >> bits); }
    }
}

static uint32_t le32(const uint8_t *p) {
    return p[0] | (p[1] << 8) | (p[2] << 16) | ((uint32_t)p[3] << 24);
}

static int sock, fails;
static struct sockaddr_in kernel;

static void timeout_ms(int ms) {
    struct timeval tv = {ms / 1000, (ms % 1000) * 1000};
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
}

static int recv_msg(uint8_t *buf, int cap, struct sockaddr_in *from) {
    socklen_t fl = sizeof(*from);
    return (int)recvfrom(sock, buf, cap, 0, (struct sockaddr *)from, &fl);
}

static void ok(const char *what, int c) { printf("%s %s\n", c ? "PASS" : "FAIL", what); if (!c) fails++; }

static void initiation(const wg_identity_t *id, wg_handshake_t *hs, const uint8_t kpub[32],
                       const uint8_t psk[32], uint32_t index, uint8_t m1[WG_MSG_INIT_LEN]) {
    uint8_t e[32], ts[12];
    struct timespec now;
    key(e, 0x55 + (int)(index & 0x0f));
    clock_gettime(CLOCK_REALTIME, &now);
    wg_tai64n(ts, (uint64_t)now.tv_sec, (uint32_t)now.tv_nsec);
    memset(hs, 0, sizeof(*hs));
    memcpy(hs->remote_static, kpub, 32); memcpy(hs->psk, psk, 32);
    wg_create_initiation(id, hs, index, e, ts, m1);
}

// the kernel is the responder and sends the cookie replies
static void kernel_reply(const wg_identity_t *id, const uint8_t kpub[32], const uint8_t psk[32]) {
    uint8_t m1[WG_MSG_INIT_LEN], probe[WG_MSG_INIT_LEN], buf[2048];
    struct sockaddr_in from;
    wg_handshake_t hs, hp;
    wg_cookie_t ck;
    wg_cookie_init(&ck, kpub);

    initiation(id, &hs, kpub, psk, 0x1000, m1);
    ok("no cookie yet: mac2 zeros", wg_cookie_add_mac2(&ck, m1, sizeof(m1)) == 0);
    // one sender per CPU, in batches: one sender alone, the kernel keeps up
    const int procs = (int)sysconf(_SC_NPROCESSORS_ONLN), batch = 64, flood = 400000;
    for (int p = 0; p < procs; p++) {
        if (fork() != 0) continue;
        struct mmsghdr mm[64];
        struct iovec iov = {m1, sizeof(m1)};
        memset(mm, 0, sizeof(mm));
        for (int i = 0; i < batch; i++) {
            mm[i].msg_hdr.msg_name = &kernel; mm[i].msg_hdr.msg_namelen = sizeof(kernel);
            mm[i].msg_hdr.msg_iov = &iov; mm[i].msg_hdr.msg_iovlen = 1;
        }
        for (int i = 0; i < flood / procs / batch; i++) sendmmsg(sock, mm, batch, 0);
        _exit(0);
    }
    while (wait(NULL) > 0) {}

    // take one cookie reply, then read until the kernel is quiet
    int replies = 0, got = 0, n;
    timeout_ms(200);
    while ((n = recv_msg(buf, sizeof(buf), &from)) > 0) {
        if (n == WG_MSG_COOKIE_LEN && buf[0] == WG_MSG_COOKIE && wg_cookie_reply_receiver(buf) == 0x1000) {
            replies++;
            if (!got) got = wg_cookie_consume_reply(&ck, buf, n) == 0;
        }
    }
    printf("  %d initiations sent, %d cookie replies back\n", flood, replies);
    ok("the kernel sent cookie replies under load", replies > 0);
    ok("our initiator takes the kernel's cookie (XChaCha20-Poly1305 opens)", got);

    // still under load (1 s after the queue): a probe without mac2 gets a
    // cookie reply, our initiation with mac2 a response
    initiation(id, &hp, kpub, psk, 0x3000, probe);  // mac2 zeros: no add_mac2
    sendto(sock, probe, sizeof(probe), 0, (struct sockaddr *)&kernel, sizeof(kernel));
    initiation(id, &hs, kpub, psk, 0x2000, m1);
    ok("cookie held: mac2 set", wg_cookie_add_mac2(&ck, m1, sizeof(m1)) == 1);
    sendto(sock, m1, sizeof(m1), 0, (struct sockaddr *)&kernel, sizeof(kernel));
    int probe_cookie = 0, resp = 0;
    timeout_ms(1000);
    while ((n = recv_msg(buf, sizeof(buf), &from)) > 0 && !(probe_cookie && resp)) {
        if (n == WG_MSG_COOKIE_LEN && buf[0] == WG_MSG_COOKIE && wg_cookie_reply_receiver(buf) == 0x3000)
            probe_cookie = 1;
        if (n == WG_MSG_RESP_LEN && buf[0] == WG_MSG_RESP && le32(buf + 8) == 0x2000)
            resp = wg_consume_response(id, &hs, buf) == 0;
    }
    ok("probe without mac2 got a cookie reply (the kernel was under load)", probe_cookie);
    ok("our initiation with mac2 got a valid response under load", resp);
}

// we are the responder under load and send the cookie reply
static void our_reply(const wg_identity_t *id, const uint8_t kpub[32], const uint8_t psk[32]) {
    uint8_t buf[2048], pt[2048], r[WG_MSG_COOKIE_LEN], is[32], ts[12];
    struct sockaddr_in from;
    wg_cookie_checker_t chk;
    wg_cookie_checker_init(&chk, id->pub);
    timeout_ms(9000);

    int n = recv_msg(buf, sizeof(buf), &from);
    uint8_t ip[4]; memcpy(ip, &from.sin_addr, 4);
    uint16_t port = ntohs(from.sin_port);
    ok("kernel sent an initiation", n == WG_MSG_INIT_LEN);
    ok("under load, no mac2: we send a cookie reply",
       wg_cookie_validate(&chk, buf, n, ip, port, 1) == WG_COOKIE_SEND_REPLY);
    wg_cookie_create_reply(&chk, r, buf, n, ip, port);
    sendto(sock, r, sizeof(r), 0, (struct sockaddr *)&from, sizeof(from));

    time_t t0 = time(NULL);
    n = recv_msg(buf, sizeof(buf), &from);
    printf("  the kernel's next initiation after %ld s\n", (long)(time(NULL) - t0));
    memcpy(ip, &from.sin_addr, 4); port = ntohs(from.sin_port);
    ok("kernel retransmits its initiation", n == WG_MSG_INIT_LEN);
    ok("its mac2 is valid: the kernel took our cookie", wg_cookie_check_mac2(&chk, buf, n, ip, port));
    ok("under load it passes", wg_cookie_validate(&chk, buf, n, ip, port, 1) == WG_COOKIE_OK);

    wg_handshake_t hs; memset(&hs, 0, sizeof(hs));
    ok("our responder accepts it", wg_consume_initiation(id, &hs, buf, is, ts) == 0 &&
                                   memcmp(is, kpub, 32) == 0);
    memcpy(hs.psk, psk, 32);
    uint8_t e[32], m2[WG_MSG_RESP_LEN]; key(e, 0x66);
    wg_create_response(&hs, 0x0badcafe, e, m2);
    sendto(sock, m2, sizeof(m2), 0, (struct sockaddr *)&from, sizeof(from));
    timeout_ms(3000);
    int p = -1;
    for (int tries = 0; tries < 5 && p < 0; tries++) {
        n = recv_msg(buf, sizeof(buf), &from);
        if (n >= 32 && buf[0] == 4 && le32(buf + 4) == 0x0badcafe) {
            uint8_t nn[12] = {0};
            for (int i = 0; i < 8; i++) nn[4 + i] = buf[8 + i];
            int ct = n - 32;
            if (chacha20poly1305_decrypt(pt, hs.recv_key, nn, buf + 16, ct, buf + 16 + ct, NULL, 0) == 0)
                p = ct;
        }
    }
    ok("then the kernel's ping decrypts with our recv key", p >= 28 && pt[9] == 1 && pt[20] == 8);
}

int main(int argc, char **argv) {
    uint8_t priv[32], psk[32], kpub[32];
    key(priv, 0x10); key(psk, 0x90);
    wg_identity_t id; wg_identity_init(&id, priv);
    const char *mode = argc > 1 ? argv[1] : "pub";
    char s[45];
    if (!strcmp(mode, "pub")) { b64(id.pub, s); printf("%s ", s); b64(psk, s); printf("%s\n", s); return 0; }
    if (argc < 3) return 2;
    unb64(argv[2], kpub);

    sock = socket(AF_INET, SOCK_DGRAM, 0);
    struct sockaddr_in me = {0};
    me.sin_family = AF_INET; me.sin_port = htons(40000); me.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    bind(sock, (struct sockaddr *)&me, sizeof(me));
    kernel.sin_family = AF_INET; kernel.sin_port = htons(51820); kernel.sin_addr.s_addr = htonl(INADDR_LOOPBACK);

    if (!strcmp(mode, "kernel-reply")) kernel_reply(&id, kpub, psk);
    else our_reply(&id, kpub, psk);
    return fails;
}

// -----------------------------------------------------------------------------
// Project:     WireGuard-FPGA
// Description: NLnet-funded open-source implementation
// Funding:     https://nlnet.nl/project/KlusterLab-Wireguard (2023-12 to 2025-12)
// -----------------------------------------------------------------------------
