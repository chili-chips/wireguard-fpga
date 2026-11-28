// SPDX-FileCopyrightText: 2026 Chili.CHIPS
//
// SPDX-License-Identifier: BSD-3-Clause

//==========================================================================
// Wireguard-1GE FPGA * NLnet-sponsored open-source implementation
//--------------------------------------------------------------------------
// Description:
//   The end-to-end WireGuard co-simulation (MakefileVProc.mk WG_E2E=1,
//   4.sim/README.md "End-to-end WireGuard test"). The real firmware runs on
//   VProc node 0 (VUserMain0.cpp) against the RTL SoC and its data plane.
//   Here:
//   - node 1 (eth1) is a remote WireGuard peer, built from the firmware's
//     own noise.c and chacha20poly1305.c, compiled for the host: it runs
//     handshakes with the firmware and sends and checks transport data;
//   - node 2 (eth2) is a LAN host behind the device: it checks what the
//     data plane decrypts and sends plaintext for the peer's network;
//   - nodes 3 and 4 idle.
//   The peer configures the firmware over the UART console (models/
//   bfm_uart.sv, CLI_MAILBOX: a line mailbox and a log of what the firmware
//   prints, in the shared mem_model memory). The bench reads the cryptokey
//   and routing tables back over the co-sim HAL: wg_e2e_hook(), which the
//   firmware's main loop calls on node 0 in this build (WG_E2E_HOOK), reads
//   them with the firmware's own register accesses.
//   The firmware's timers run WG_TIME_SCALE times faster (wg_session.c),
//   so the protocol's 120 s and 180 s fit in simulated time. Every check
//   prints "E2E: PASS" or "E2E: FAIL"; the run ends with "E2E: ALL PASS".
//==========================================================================

#include <cstdio>
#include <cstdint>
#include <cstring>
#include <cstdarg>
#include <string>
#include <vector>
#include <deque>
#include <map>
#include "udpVProc.h"

extern "C" {
#include "mem.h"
}

#include "csr_regs.h"
#include "noise.h"
#include "wg_session.h"
#include "chacha20poly1305.h"
#include "xchacha20poly1305.h"
#include "blake2s.h"

#ifndef WG_TIME_SCALE
#define WG_TIME_SCALE 1
#endif

// ---- addresses ----------------------------------------------------------------
// the device (main.cpp init_network: the defaults)
static const uint8_t  FW_MAC[6]  = {0xCC, 0xBA, 0xCA, 0xCA, 0x00, 0x01};
static const uint8_t  FW_IP[4]   = {192, 168, 1, 98};
static const uint16_t FW_PORT    = 51820;
// the remote peer, on eth1, and its network behind the tunnel
static const uint8_t  PEER_MAC[6] = {0x02, 0x00, 0x00, 0x00, 0x01, 0x08};
static const uint8_t  PEER_IP[4]  = {192, 168, 1, 8};
static const uint16_t PEER_PORT   = 51000;
static const uint8_t  PEER_NET[4] = {10, 0, 0, 2};   // its inner address, in 10.0.0.0/24
// the LAN host, on eth2, in 192.168.152.0/24
static const uint8_t  LAN_MAC[6] = {0x02, 0x00, 0x00, 0x00, 0x02, 0x01};
static const uint8_t  LAN_IP[4]  = {192, 168, 152, 1};
static const uint16_t IN_PORT_PEER = 5000, IN_PORT_LAN = 6000;  // the inner UDP ports

// the shared mem_model memory (models/bfm_uart.sv, CLI_MAILBOX)
#define CLI_TX_ADDR 0x50010000u  // a line for the console: length, then the bytes
#define CLI_RX_ADDR 0x50020000u  // what the firmware printed: count, then the bytes
#define CLI_RX_SIZE 65536u
#define MEM_NODE    0

// ---- time: node 1's GMII clock, 125 MHz ----------------------------------------
// one scaled millisecond of the firmware's timers, in GMII clocks
static uint64_t ms(double scaled_ms) {
    return (uint64_t)(scaled_ms * 125000.0 / WG_TIME_SCALE + 0.5);
}

// ---- the checks ---------------------------------------------------------------
static int n_pass, n_fail;
static void check(const char *id, bool ok, const char *fmt, ...) __attribute__((format(printf, 3, 4)));
static void check(const char *id, bool ok, const char *fmt, ...) {
    char    buf[512];
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(buf, sizeof(buf), fmt, ap);
    va_end(ap);
    VPrint("E2E: %s %s %s\n", ok ? "PASS" : "FAIL", id, buf);
    if (ok) n_pass++; else n_fail++;
}

// ---- a raw GMII node -----------------------------------------------------------
// udpIpPg checks the MAC, IP and port of what it receives; the decrypted
// frames on the LAN keep the outer header (our MAC), and the peer needs the
// whole frame: so this node takes raw frames (CRC checked) and sends them
class wgNode : public udpVProc {
public:
    explicit wgNode(int n) : udpVProc(n) {}
    std::deque<std::vector<uint8_t>> rx;  // frames received: dst MAC .. payload
    uint64_t now = 0;                     // GMII clocks so far

    void idle(uint64_t n) {
        while (n) {
            uint32_t k = n > 1000 ? 1000 : (uint32_t)n;
            UdpVpSendIdle(k);
            now += k;
            n -= k;
        }
    }
    // f: dst MAC .. payload, no CRC; padded to 60 bytes
    void send(const uint8_t *f, size_t len) {
        std::vector<uint32_t> w;
        for (int i = 0; i < 7; i++) w.push_back(0x55);
        w.push_back(0xD5);
        size_t start = w.size();
        for (size_t i = 0; i < len; i++) w.push_back(f[i]);
        while (w.size() - start < 60) w.push_back(0);
        uint32_t c = crc(&w[start], w.size() - start);
        for (int i = 0; i < 4; i++) w.push_back((c >> (8 * i)) & 0xFF);
        UdpVpSendRawEthFrame(w.data(), (uint32_t)w.size());
        now += w.size() + 1;
        idle(12);  // the inter-frame gap
    }

protected:
    uint32_t processFrame(uint32_t *d, uint32_t len) override {
        if (len < 64 || crc(d, len - 4) != (d[len - 4] | (d[len - 3] << 8) | (d[len - 2] << 16) |
                                            ((uint32_t)d[len - 1] << 24))) {
            VPrint("Node%d: frame with a bad CRC or too short (%u bytes)\n", node, len);
            return 1;
        }
        std::vector<uint8_t> f(len - 4);
        for (uint32_t i = 0; i < len - 4; i++) f[i] = (uint8_t)d[i];
        rx.push_back(f);
        return 0;
    }

private:
    static uint32_t crc(const uint32_t *b, size_t n) {
        uint32_t c = 0xFFFFFFFF;
        while (n--) {
            uint32_t v = (c ^ *b++) & 0xFF;
            for (int i = 0; i < 8; i++) v = (v & 1) ? (v >> 1) ^ 0xEDB88320 : v >> 1;
            c = v ^ (c >> 8);
        }
        return c ^ 0xFFFFFFFF;
    }
};

// ---- frames ---------------------------------------------------------------------
static uint16_t csum(const uint8_t *p, size_t n) {
    uint32_t s = 0;
    for (size_t i = 0; i + 1 < n; i += 2) s += (p[i] << 8) | p[i + 1];
    if (n & 1) s += p[n - 1] << 8;
    while (s >> 16) s = (s & 0xFFFF) + (s >> 16);
    return (uint16_t)~s;
}

// Ethernet + IPv4 + UDP around data, into f: the frame's length
static size_t udp_frame(uint8_t *f, const uint8_t dmac[6], const uint8_t smac[6], const uint8_t sip[4],
                        const uint8_t dip[4], uint16_t sport, uint16_t dport, const uint8_t *data,
                        size_t len, bool udp_csum) {
    memcpy(f, dmac, 6);
    memcpy(f + 6, smac, 6);
    f[12] = 0x08; f[13] = 0x00;
    uint8_t *ip = f + 14, *u = ip + 20;
    size_t   ip_len = 20 + 8 + len;
    memset(ip, 0, 20);
    ip[0] = 0x45; ip[2] = (uint8_t)(ip_len >> 8); ip[3] = (uint8_t)ip_len;
    ip[6] = 0x40; ip[8] = 64; ip[9] = 17;
    memcpy(ip + 12, sip, 4);
    memcpy(ip + 16, dip, 4);
    uint16_t c = csum(ip, 20);
    ip[10] = (uint8_t)(c >> 8); ip[11] = (uint8_t)c;
    u[0] = (uint8_t)(sport >> 8); u[1] = (uint8_t)sport;
    u[2] = (uint8_t)(dport >> 8); u[3] = (uint8_t)dport;
    u[4] = (uint8_t)((8 + len) >> 8); u[5] = (uint8_t)(8 + len);
    u[6] = 0; u[7] = 0;
    memcpy(u + 8, data, len);
    if (udp_csum) {  // over the pseudo header and the segment
        std::vector<uint8_t> ph(12 + 8 + len);
        memcpy(&ph[0], sip, 4); memcpy(&ph[4], dip, 4);
        ph[8] = 0; ph[9] = 17; ph[10] = (uint8_t)((8 + len) >> 8); ph[11] = (uint8_t)(8 + len);
        memcpy(&ph[12], u, 8 + len);
        c = csum(ph.data(), ph.size());
        if (c == 0) c = 0xFFFF;
        u[6] = (uint8_t)(c >> 8); u[7] = (uint8_t)c;
    }
    return 14 + ip_len;
}

// the inner packet: IPv4 + UDP, 64 bytes (a multiple of 16: no padding),
// its payload a magic, a sequence number and a pattern
#define INNER_LEN 64
static void inner_packet(uint8_t pkt[INNER_LEN], bool from_peer, uint32_t seq) {
    uint8_t f[14 + INNER_LEN], data[INNER_LEN - 28];
    memcpy(data, from_peer ? "WGP2" : "WGL2", 4);
    for (int i = 0; i < 4; i++) data[4 + i] = (uint8_t)(seq >> (8 * i));
    for (size_t i = 8; i < sizeof(data); i++) data[i] = (uint8_t)(seq * 7 + i);
    udp_frame(f, FW_MAC, FW_MAC, from_peer ? PEER_NET : LAN_IP, from_peer ? LAN_IP : PEER_NET,
              from_peer ? IN_PORT_PEER : IN_PORT_LAN, from_peer ? IN_PORT_LAN : IN_PORT_PEER, data,
              sizeof(data), true);
    memcpy(pkt, f + 14, INNER_LEN);
}

// the sequence number of an inner packet from the peer (to the LAN) or from
// the LAN (to the peer), checked byte for byte; -1 when it is not one
static long inner_seq(const uint8_t *ip, size_t len, bool from_peer) {
    if (len < INNER_LEN) return -1;
    uint32_t seq = ip[28 + 4] | (ip[28 + 5] << 8) | (ip[28 + 6] << 16) | ((uint32_t)ip[28 + 7] << 24);
    uint8_t  want[INNER_LEN];
    inner_packet(want, from_peer, seq);
    return memcmp(ip, want, INNER_LEN) == 0 ? (long)seq : -1;
}

static uint32_t get32(const uint8_t *p) {
    return p[0] | (p[1] << 8) | (p[2] << 16) | ((uint32_t)p[3] << 24);
}
static void put32(uint8_t *p, uint32_t v) { for (int i = 0; i < 4; i++) p[i] = (uint8_t)(v >> (8 * i)); }
static void put64(uint8_t *p, uint64_t v) { for (int i = 0; i < 8; i++) p[i] = (uint8_t)(v >> (8 * i)); }

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

// ---- the bench's view of the tables, over the co-sim HAL (node 0) ------------------
// The peer asks (pending = 1) and waits; the firmware's main loop calls
// wg_e2e_hook() each time round, which reads the entries and routes with the
// firmware's own register accesses (csr_regs.h: VProc bus cycles on node 0,
// through soc_fabric and the CSR block) and copies the firmware's state
struct ck_entry_t {
    uint32_t local_port, local_id, remote_ip, remote_port, remote_id;
    uint32_t enc[8], dec[8];
    uint64_t send_cnt, recv_cnt, recv_win;
};
static struct {
    volatile int pending;
    ck_entry_t   ck[WG_ENTRIES];
    uint32_t     route_peer_idx[4];
    wg_peer_t    peer;
    wg_stats_t   stats;
    int          pool_free;
} hal;

#define CK(e, w) ((uint32_t)CSR_REG32(cryptokey_table.entry[e].w))
extern "C" void wg_e2e_hook(void) {
    if (!hal.pending) return;
    for (int e = 1; e < WG_ENTRIES; e++) {
        ck_entry_t *k = &hal.ck[e];
        k->local_port  = CK(e, local_port);
        k->local_id    = CK(e, local_id);
        k->remote_ip   = CK(e, remote_ip);
        k->remote_port = CK(e, remote_port);
        k->remote_id   = CK(e, remote_id);
        k->enc[0] = CK(e, encrypt_key_255_224); k->enc[1] = CK(e, encrypt_key_223_192);
        k->enc[2] = CK(e, encrypt_key_191_160); k->enc[3] = CK(e, encrypt_key_159_128);
        k->enc[4] = CK(e, encrypt_key_127_96);  k->enc[5] = CK(e, encrypt_key_95_64);
        k->enc[6] = CK(e, encrypt_key_63_32);   k->enc[7] = CK(e, encrypt_key_31_0);
        k->dec[0] = CK(e, decrypt_key_255_224); k->dec[1] = CK(e, decrypt_key_223_192);
        k->dec[2] = CK(e, decrypt_key_191_160); k->dec[3] = CK(e, decrypt_key_159_128);
        k->dec[4] = CK(e, decrypt_key_127_96);  k->dec[5] = CK(e, decrypt_key_95_64);
        k->dec[6] = CK(e, decrypt_key_63_32);   k->dec[7] = CK(e, decrypt_key_31_0);
        k->send_cnt = ((uint64_t)CK(e, send_cnt_63_32) << 32) | CK(e, send_cnt_31_0);
        k->recv_cnt = ((uint64_t)CK(e, recv_cnt_63_32) << 32) | CK(e, recv_cnt_31_0);
        k->recv_win = ((uint64_t)CK(e, recv_win_63_32) << 32) | CK(e, recv_win_31_0);
        if (e > 8) break;  // the test uses the first entries of the pool
    }
    for (int r = 0; r < 4; r++) {
        hal.route_peer_idx[r] = RDL_FIELD((uint32_t)CSR_REG32(routing_table.entry[r].peer_idx),
                                          CSR__ROUTING_TABLE__ENTRY__PEER_IDX__PEER_IDX);
    }
    hal.peer      = *wg_peer(1);
    hal.stats     = *wg_stats();
    hal.pool_free = wg_pool_free();
    hal.pending   = 0;
}

static int tag_of(int e) { return (hal.ck[e].local_port >> 16) & 0x3F; }

// a key as its eight CSR words (main.cpp key_words): word 0 = bytes 31 .. 28
static bool key_is(const uint32_t w[8], const uint8_t *key) {
    for (int k = 0; k < 8; k++) {
        uint32_t v = 0;
        if (key) v = ((uint32_t)key[31 - 4 * k] << 24) | (key[30 - 4 * k] << 16) |
                     (key[29 - 4 * k] << 8) | key[28 - 4 * k];
        if (w[k] != v) return false;
    }
    return true;
}

// ---- the LAN host (node 2) ----------------------------------------------------------
static std::deque<uint32_t>     lan_tx;    // sequence numbers to send to the peer's network
static std::map<uint32_t, int>  lan_rx;    // what came from the peer: seq -> times
static int                      lan_other; // frames that are not one of the peer's

// ---- the peer (node 1) --------------------------------------------------------------
struct sess_t {
    bool     ok;
    uint32_t me, them;          // our receiver index, the firmware's
    uint8_t  tx[32], rx[32];    // our send and receive keys
    uint64_t ctr;               // our next counter
};
static sess_t               s_cur, s_prev, s_next;  // s_next: ours as responder, unconfirmed
static wg_identity_t        peer_id;
static uint8_t              fw_pub[32], psk[32];
static wg_handshake_t       hs_init;                // our initiation in flight
static uint8_t              last_init[WG_MSG_INIT_LEN];
static uint32_t             k_index = 0x1000;       // our indices and ephemerals
static uint64_t             k_time  = 1798761600;   // our TAI64N seconds (2027-01-01), each one newer
static wgNode              *peer;

// what the peer saw
static std::map<uint32_t, int> peer_rx;            // data from the LAN: seq -> times
static std::map<uint32_t, uint32_t> peer_rx_sess;  // seq -> our index it came on
static std::map<uint32_t, uint64_t> peer_rx_ctr;   // seq -> its counter
static int      n_resp, n_init_rx, n_cookie, n_keepalive, n_bad, n_other;
static uint64_t t_resp, t_init_rx, t_keepalive, ka_ctr;
static uint32_t ka_sess;
static uint8_t  cookie_msg[64];

static void peer_send_udp(const uint8_t *msg, size_t len) {
    uint8_t f[1600];
    size_t  n = udp_frame(f, FW_MAC, PEER_MAC, PEER_IP, FW_IP, PEER_PORT, FW_PORT, msg, len, false);
    peer->send(f, n);
}

static void nonce_of(uint8_t n[12], uint64_t c) { memset(n, 0, 4); put64(n + 4, c); }

// a transport message on s: the inner packet seq (or a keepalive, seq < 0);
// the frame in *out when asked (for a replay)
static void peer_send_data(sess_t &s, long seq, std::vector<uint8_t> *out = nullptr) {
    uint8_t m[16 + INNER_LEN + 16] = {4};
    uint8_t n[12], pt[INNER_LEN];
    size_t  len = 0;
    if (seq >= 0) { inner_packet(pt, true, (uint32_t)seq); len = INNER_LEN; }
    put32(m + 4, s.them);
    put64(m + 8, s.ctr);
    nonce_of(n, s.ctr);
    chacha20poly1305_encrypt(m + 16, m + 16 + len, s.tx, n, pt, len, NULL, 0);
    s.ctr++;
    uint8_t f[1600];
    size_t  fl = udp_frame(f, FW_MAC, PEER_MAC, PEER_IP, FW_IP, PEER_PORT, FW_PORT, m, 32 + len, false);
    if (out) out->assign(f, f + fl);
    peer->send(f, fl);
}

static void ephemeral(uint8_t e[32]) {
    k_index++;
    for (int i = 0; i < 32; i++) e[i] = (uint8_t)(0x70 + 13 * k_index + i);
}

// message 1 to the firmware: our new initiation (mac2 with a cookie, when given)
static void peer_initiate(const uint8_t *cookie = nullptr) {
    uint8_t e[32], ts[WG_TAI64N_LEN];
    ephemeral(e);
    wg_tai64n(ts, k_time++, 0);
    memset(&hs_init, 0, sizeof(hs_init));
    memcpy(hs_init.remote_static, fw_pub, 32);
    memcpy(hs_init.psk, psk, 32);
    uint32_t idx = 0xA0000000u | k_index;
    if (wg_create_initiation(&peer_id, &hs_init, idx, e, ts, last_init) != 0) {
        check("peer", false, "wg_create_initiation failed");
        return;
    }
    if (cookie) hash(last_init + WG_MSG_INIT_LEN - 16, 16, cookie, 16, last_init, WG_MSG_INIT_LEN - 16);
    peer_send_udp(last_init, sizeof(last_init));
}

// one frame the firmware sent to the peer
static void peer_rx_frame(const std::vector<uint8_t> &f) {
    const uint8_t *ip = &f[14], *u = ip + 20, *m = u + 8;
    if (f.size() < 42 || f[12] != 0x08 || f[13] != 0x00 || ip[9] != 17 ||
        memcmp(ip + 12, FW_IP, 4) != 0 || memcmp(ip + 16, PEER_IP, 4) != 0 ||
        ((u[2] << 8) | u[3]) != PEER_PORT || memcmp(&f[0], PEER_MAC, 6) != 0) {
        n_other++;
        VPrint("E2E: peer: a frame not for it (%zu bytes)\n", f.size());
        return;
    }
    size_t len = ((u[4] << 8) | u[5]) - 8;
    if (len < 4 || 42 + len > f.size()) { n_other++; return; }
    switch (m[0]) {
    case WG_MSG_RESP: {  // the answer to our initiation
        if (len != WG_MSG_RESP_LEN || hs_init.state != WG_HS_INITIATED ||
            wg_consume_response(&peer_id, &hs_init, m) != 0) {
            n_bad++;
            VPrint("E2E: peer: a message 2 it does not take\n");
            return;
        }
        s_prev = s_cur;  // the initiator sends on the new session at once
        memset(&s_cur, 0, sizeof(s_cur));
        s_cur.ok = true;
        s_cur.me = hs_init.local_index;
        s_cur.them = hs_init.remote_index;
        memcpy(s_cur.tx, hs_init.send_key, 32);
        memcpy(s_cur.rx, hs_init.recv_key, 32);
        wg_handshake_wipe(&hs_init);
        n_resp++;
        t_resp = peer->now;
        VPrint("E2E: peer: message 2 taken, session %08x <-> %08x\n", s_cur.me, s_cur.them);
        break;
    }
    case WG_MSG_INIT: {  // the firmware initiates: answer, as a WireGuard responder
        wg_handshake_t hs;
        uint8_t        is[32], ts[WG_TAI64N_LEN], e[32], out[WG_MSG_RESP_LEN];
        memset(&hs, 0, sizeof(hs));
        if (len != WG_MSG_INIT_LEN || wg_consume_initiation(&peer_id, &hs, m, is, ts) != 0 ||
            memcmp(is, fw_pub, 32) != 0) {
            n_bad++;
            VPrint("E2E: peer: a message 1 it does not take\n");
            return;
        }
        memcpy(hs.psk, psk, 32);
        ephemeral(e);
        if (wg_create_response(&hs, 0xB0000000u | k_index, e, out) != 0) { n_bad++; return; }
        memset(&s_next, 0, sizeof(s_next));  // used once the firmware confirms it
        s_next.ok = true;
        s_next.me = hs.local_index;
        s_next.them = hs.remote_index;
        memcpy(s_next.tx, hs.send_key, 32);
        memcpy(s_next.rx, hs.recv_key, 32);
        wg_handshake_wipe(&hs);
        peer_send_udp(out, sizeof(out));
        n_init_rx++;
        t_init_rx = peer->now;
        VPrint("E2E: peer: message 1 from the firmware answered, session %08x <-> %08x\n",
               s_next.me, s_next.them);
        break;
    }
    case WG_MSG_COOKIE:
        if (len == WG_MSG_COOKIE_LEN) memcpy(cookie_msg, m, 64);
        n_cookie++;
        VPrint("E2E: peer: a cookie reply\n");
        break;
    case WG_MSG_DATA: {
        uint32_t r = get32(m + 4);
        sess_t  *s = s_cur.ok && r == s_cur.me ? &s_cur : s_prev.ok && r == s_prev.me ? &s_prev
                   : s_next.ok && r == s_next.me ? &s_next : nullptr;
        uint64_t c = 0;
        for (int i = 0; i < 8; i++) c |= (uint64_t)m[8 + i] << (8 * i);
        uint8_t n[12], pt[1600];
        nonce_of(n, c);
        if (!s || len < 32 || chacha20poly1305_decrypt(pt, s->rx, n, m + 16, len - 32, m + len - 16, NULL, 0) != 0) {
            n_bad++;
            VPrint("E2E: peer: transport data that does not open (receiver %08x)\n", r);
            return;
        }
        if (s == &s_next) {  // the firmware's first packet on it: confirmed
            s_prev = s_cur;
            s_cur = s_next;
            memset(&s_next, 0, sizeof(s_next));
            s = &s_cur;
            VPrint("E2E: peer: session %08x confirmed by the firmware\n", s_cur.me);
        }
        if (len == 32) {
            n_keepalive++;
            t_keepalive = peer->now;
            ka_ctr = c;
            ka_sess = r;
            VPrint("E2E: peer: keepalive, counter %llu, on %08x\n", (unsigned long long)c, r);
            return;
        }
        long seq = inner_seq(pt, len - 32, false);
        if (seq < 0) { n_bad++; VPrint("E2E: peer: plaintext that is not the LAN's\n"); return; }
        peer_rx[(uint32_t)seq]++;
        peer_rx_sess[(uint32_t)seq] = r;
        peer_rx_ctr[(uint32_t)seq] = c;
        break;
    }
    default:
        n_other++;
    }
}

// idle n clocks, taking what arrives
static void run(uint64_t n) {
    while (n) {
        uint64_t k = n > 50 ? 50 : n;
        peer->idle(k);
        n -= k;
        while (!peer->rx.empty()) {
            std::vector<uint8_t> f = peer->rx.front();
            peer->rx.pop_front();
            peer_rx_frame(f);
        }
    }
}

// idle until cond() or for at most max clocks; true when cond() held
template <class F> static bool run_until(uint64_t max, F cond) {
    uint64_t t0 = peer->now;
    while (!cond()) {
        if (peer->now - t0 >= max) return false;
        run(50);
    }
    return true;
}

// a snapshot of the tables and the firmware's state, over the co-sim HAL
static bool snap() {
    hal.pending = 1;
    if (!run_until(ms(200000), [] { return hal.pending == 0; })) {
        check("hal", false, "no snapshot: the firmware's main loop did not run");
        return false;
    }
    return true;
}

// ---- the console, over the UART BFM ------------------------------------------------
static uint32_t cli_seen;  // bytes of the firmware's output read so far
static uint32_t cli_count() { return ReadRamWord(CLI_RX_ADDR, 1, MEM_NODE); }
static std::string cli_text(uint32_t from) {
    std::string s;
    uint32_t    n = cli_count();
    for (uint32_t i = from; i < n; i++) s += (char)ReadRamByte(CLI_RX_ADDR + 4 + (i % CLI_RX_SIZE), MEM_NODE);
    return s;
}

// the firmware waits for input: its output ends with a prompt (": " or "# ")
// and nothing more came for a while
static bool cli_wait_prompt(uint64_t max = 12500000) {  // 100 ms
    uint64_t t0 = peer->now;
    uint32_t last = 0xFFFFFFFF;
    uint64_t t_last = 0;
    while (peer->now - t0 < max) {
        run(2000);
        uint32_t n = cli_count();
        if (n != last) { last = n; t_last = peer->now; continue; }
        if (n >= 2 && ReadRamWord(CLI_TX_ADDR, 1, MEM_NODE) == 0 && peer->now - t_last >= 20000) {
            char a = (char)ReadRamByte(CLI_RX_ADDR + 4 + ((n - 2) % CLI_RX_SIZE), MEM_NODE);
            char b = (char)ReadRamByte(CLI_RX_ADDR + 4 + ((n - 1) % CLI_RX_SIZE), MEM_NODE);
            if ((a == ':' || a == '#') && b == ' ') return true;
        }
    }
    return false;
}

// one console line (CR added); the firmware's answer up to its next prompt
static std::string cli(const char *line) {
    uint32_t from = cli_count();
    size_t   n = strlen(line);
    for (size_t i = 0; i < n; i++) WriteRamByte(CLI_TX_ADDR + 4 + i, (uint8_t)line[i], MEM_NODE);
    WriteRamByte(CLI_TX_ADDR + 4 + n, '\r', MEM_NODE);
    WriteRamWord(CLI_TX_ADDR, (uint32_t)(n + 1), 1, MEM_NODE);
    if (!cli_wait_prompt()) check("cli", false, "no prompt after '%s'", line);
    return cli_text(from);
}

static bool has(const std::string &s, const char *what) { return s.find(what) != std::string::npos; }

// ---- the test ------------------------------------------------------------------------
static uint32_t pseq = 1;   // the peer's next inner sequence number
static uint32_t lseq = 1;   // the LAN's

static bool all_once(const std::map<uint32_t, int> &m, uint32_t from, uint32_t to, uint32_t *lost) {
    *lost = 0;
    bool ok = true;
    for (uint32_t s = from; s < to; s++) {
        auto it = m.find(s);
        if (it == m.end()) { (*lost)++; ok = false; }
        else if (it->second != 1) ok = false;
    }
    return ok;
}

static void test(void) {
    uint8_t fw_priv[32], peer_priv[32];
    char    k64[45];
    for (int i = 0; i < 32; i++) { fw_priv[i] = (uint8_t)(0x10 + i); peer_priv[i] = (uint8_t)(0x40 + i); psk[i] = (uint8_t)(0x90 + i); }
    wg_identity_t fw_id;
    wg_identity_init(&fw_id, fw_priv);
    memcpy(fw_pub, fw_id.pub, 32);
    wg_identity_init(&peer_id, peer_priv);
    VPrint("E2E: scaled time: the firmware's timers run %d times faster (WG_TIME_SCALE)\n", WG_TIME_SCALE);

    // ---- 0: the firmware's set-up, over the console ----
    if (!cli_wait_prompt()) { check("0", false, "the firmware never prompted"); return; }
    std::string a = cli("wg key");
    b64(fw_priv, k64);
    a = cli(k64);
    char pub64[45];
    b64(fw_pub, pub64);
    bool ok = has(a, pub64);
    cli("wg peer add");
    b64(peer_id.pub, k64);
    cli(k64);
    b64(psk, k64);
    cli(k64);
    a = cli("");  // the endpoint: learnt from its handshake
    ok = ok && has(a, "Peer 1 added.");
    const char *routes[3][6] = {
        {"0", "10.0.0.0", "255.255.255.0", "1", "1", "1"},        // the peer's network: tunnel, eth1
        {"1", "192.168.152.0", "255.255.255.0", "0", "0", "2"},   // the LAN: plain, eth2
        {"2", "0.0.0.0", "0.0.0.0", "0", "0", "0"}};              // the rest: the CPU
    for (int r = 0; r < 3; r++) {
        cli("config routes");
        for (int i = 0; i < 6; i++) a = cli(routes[r][i]);
        ok = ok && has(a, "Routing table entry updated.") && (r != 0 || has(a, "(WireGuard peer 1)"));
    }
    check("0-config", ok, "wg key (public key %s), wg peer add, 3 routes, over the UART console", pub64);

    // ---- 1: handshake, the peer initiates ----
    peer_initiate();
    ok = run_until(ms(20000), [] { return n_resp == 1; });  // its first random number prints a line first
    snap();
    int e1 = (int)(s_cur.them & 63), c0 = hal.peer.cur.entry;
    ck_entry_t *k = &hal.ck[e1];
    check("1-handshake", ok && k->local_id == s_cur.them && k->remote_id == s_cur.me &&
          key_is(k->enc, s_cur.rx) && key_is(k->dec, s_cur.tx) &&
          k->remote_ip == 0xC0A80108u && k->remote_port == PEER_PORT && tag_of(e1) == c0 &&
          hal.peer.next.entry == e1 && hal.peer.next.state == WG_KP_PENDING && !hal.peer.live &&
          (int)hal.route_peer_idx[0] == c0 && c0 != e1,
          "message 2 taken; entry %d (read back over the HAL): local_id %08x, remote_id %08x, both "
          "keys, endpoint, tag %d; next entry, pending; the routes stay on keyless entry %d",
          e1, k->local_id, k->remote_id, tag_of(e1), c0);

    // ---- 4a: key confirmation: nothing to the peer before its first packet ----
    lan_tx.push_back(lseq++);
    run(ms(1000));
    snap();
    check("4a-confirm-wait", peer_rx.empty() && n_keepalive == 0 && hal.ck[c0].send_cnt == 1 &&
          !hal.peer.live,
          "a LAN packet before confirmation: nothing reaches the peer (dropped on keyless entry %d, "
          "its send_cnt %llu)", c0, (unsigned long long)hal.ck[c0].send_cnt);

    // ---- 2a: data peer -> LAN ----
    uint32_t p0 = pseq;
    std::vector<uint8_t> cap[8];
    for (int i = 0; i < 3; i++) { peer_send_data(s_cur, pseq++, &cap[i]); run(ms(100)); }
    run(ms(500));
    uint32_t lost;
    check("2a-peer-to-lan", all_once(lan_rx, p0, pseq, &lost) && lan_other == 0,
          "%u transport packets (counters 0-2) decrypted by the DPE, forwarded to eth2, plaintext "
          "checked (%u lost)", pseq - p0, lost);
    snap();
    check("4b-confirmed", hal.peer.live && hal.peer.cur.entry == e1 &&
          (int)hal.route_peer_idx[0] == e1 && tag_of(e1) == e1 && hal.stats.switches == 1 &&
          hal.peer.next.entry == 0,
          "the first data confirms the session: routes and tag on entry %d (switches %u)",
          e1, hal.stats.switches);

    // ---- 2b: data LAN -> peer ----
    uint32_t l0 = lseq;
    for (int i = 0; i < 3; i++) { lan_tx.push_back(lseq++); run(ms(100)); }
    run(ms(500));
    ok = all_once(peer_rx, l0, lseq, &lost);
    for (uint32_t s = l0; s < lseq && ok; s++) ok = peer_rx_sess[s] == s_cur.me && peer_rx_ctr[s] == s - l0;
    check("2b-lan-to-peer", ok && peer_rx.count(1) == 0,
          "%u LAN packets encrypted by the DPE on entry %d (counters 0-2), the peer decrypts and "
          "checks them (%u lost)", lseq - l0, e1, lost);

    // ---- 3: replay ----
    uint64_t t3 = peer->now;
    peer_send_data(s_cur, pseq++);            // counter 3
    run(ms(100));
    peer->send(cap[1].data(), cap[1].size());  // counter 1 again
    run(ms(100));
    s_cur.ctr = 6;
    std::vector<uint8_t> c6, c4;
    peer_send_data(s_cur, pseq + 1, &c6);     // counter 6, seq+1
    run(ms(100));
    s_cur.ctr = 4;
    peer_send_data(s_cur, pseq, &c4);         // counter 4, out of order: in the window
    run(ms(100));
    peer->send(c4.data(), c4.size());         // counter 4 again
    run(ms(100));
    peer->send(c6.data(), c6.size());         // counter 6 again
    pseq += 2;
    s_cur.ctr = 7;
    run(ms(500));
    snap();
    ok = all_once(lan_rx, p0, pseq, &lost);
    check("3-replay", ok && hal.ck[e1].recv_cnt == 6 && hal.ck[e1].recv_win == 0x7D,
          "counters 3, 1 (replay), 6, 4 (late), 4 and 6 (replays): the replays are dropped, each "
          "packet forwarded once (%u lost); recv_cnt %llu, recv_win 0x%llx (want 6, 0x7d)",
          lost, (unsigned long long)hal.ck[e1].recv_cnt, (unsigned long long)hal.ck[e1].recv_win);

    // ---- 5a: a keepalive after KEEPALIVE_TIMEOUT of receive only ----
    ok = run_until(ms(15000), [] { return n_keepalive == 1; });
    double dt = (double)(t_keepalive - t3) * WG_TIME_SCALE / 125000.0;
    uint64_t want_ctr = 3;  // the LAN's 3 packets on this entry
    snap();
    check("5a-keepalive", ok && dt >= KEEPALIVE_TIMEOUT_MS && dt < KEEPALIVE_TIMEOUT_MS + 1000 &&
          ka_ctr == want_ctr && ka_sess == s_cur.me && hal.ck[e1].send_cnt == want_ctr + 1 &&
          hal.stats.keepalive_tx == 1,
          "data in, nothing out: a keepalive %.0f ms after (KEEPALIVE_TIMEOUT %u), its counter %llu "
          "taken from send_cnt (now %llu)", dt, KEEPALIVE_TIMEOUT_MS, (unsigned long long)ka_ctr,
          (unsigned long long)hal.ck[e1].send_cnt);

    // ---- 4c: a rekey by the peer, with data both ways through the overlap ----
    uint32_t p1 = pseq, l1 = lseq;
    bool initiated = false, old_late = false;
    uint64_t t_hs2 = 0;
    sess_t old = s_cur;
    for (int i = 0; i < 24; i++) {  // a packet each way every 250 ms, 6 s
        if (i == 4) { peer_initiate(); initiated = true; }
        if (initiated && n_resp == 2 && !t_hs2) t_hs2 = peer->now;
        peer_send_data(s_cur, pseq++);  // on the new session once message 2 came
        lan_tx.push_back(lseq++);
        if (n_resp == 2 && i == 20 && !old_late) {  // late on the old keys, after the switch
            peer_send_data(s_prev, pseq++);
            old_late = true;
        }
        run(ms(250));
    }
    run(ms(500));
    snap();
    int e2 = (int)(s_cur.them & 63);
    uint32_t lost_l = 0, lost_p = 0;
    bool ok_l = all_once(lan_rx, p1, pseq, &lost_l), ok_p = all_once(peer_rx, l1, lseq, &lost_p);
    int on_old = 0, on_new = 0;
    for (uint32_t s = l1; s < lseq; s++) {
        if (peer_rx_sess[s] == old.me) on_old++;
        else if (peer_rx_sess[s] == s_cur.me) on_new++;
    }
    check("4c-rekey-peer", n_resp == 2 && old_late && ok_l && ok_p && e2 != e1 && on_old > 0 &&
          on_new > 0 && hal.peer.cur.entry == e2 && hal.peer.prev.entry == e1 &&
          (int)hal.route_peer_idx[0] == e2 && tag_of(e1) == e2 && tag_of(e2) == e2 &&
          hal.stats.switches == 2,
          "rekey from the peer under traffic: %u packets to the LAN (one late on the old keys after "
          "the switch), %u to the peer (%d on the old session, %d on the new), none lost or dropped "
          "at the AllowedIPs check (lost %u, %u); routes and both tags on entry %d, old entry %d kept",
          pseq - p1, lseq - l1, on_old, on_new, lost_l, lost_p, e2, e1);

    // ---- 4d: the old entry is kept (Linux's previous keypair) ----
    run(ms(2 * REKEY_TIMEOUT_MS));
    uint32_t pd = pseq;
    peer_send_data(s_prev, pseq++);  // late on the old keys, 10 s without data on them
    run(ms(500));
    snap();
    check("4d-keep", hal.peer.prev.entry == e1 && hal.stats.retired == 0 &&
          hal.ck[e1].local_id == old.them && lan_rx.count(pd) == 1,
          "old entry %d kept %u ms without data (until the next switch or its REJECT_AFTER_TIME): "
          "a packet on its keys still decrypts", e1, 2 * REKEY_TIMEOUT_MS);

    // ---- 5c: REJECT_AFTER_TIME ----
    int      init_pre = n_init_rx;
    uint64_t t_rej = t_hs2 + ms(REJECT_AFTER_TIME_MS + 1000);
    if (peer->now < t_rej) run(t_rej - peer->now);
    snap();
    ok = hal.stats.rejected == 1 && !hal.peer.live && hal.ck[e2].local_id == 0 &&
         key_is(hal.ck[e2].enc, nullptr) && key_is(hal.ck[e2].dec, nullptr);
    // the old entry went at its own REJECT_AFTER_TIME, before
    bool old_gone = hal.peer.prev.entry == 0 && hal.stats.retired == 1 && hal.ck[e1].local_id == 0 &&
                    key_is(hal.ck[e1].enc, nullptr) && key_is(hal.ck[e1].dec, nullptr);
    uint32_t pr = pseq;
    peer_send_data(s_cur, pseq++);
    run(ms(300));
    ok = ok && lan_rx.count(pr) == 0;
    uint32_t lr = lseq;
    int init0 = n_init_rx, ka0 = n_keepalive;
    lan_tx.push_back(lseq++);
    bool quiet = init0 == init_pre;  // no initiation of its own before the LAN packet
    bool init_ok = run_until(ms(20000), [&] { return n_init_rx == init0 + 1; });
    uint64_t t_hs3 = peer->now;
    snap();
    check("5c-reject", ok && old_gone && quiet && init_ok && peer_rx.count(lr) == 0 && hal.stats.tx_init >= 1,
          "%u ms after the handshake the keys left entry %d (rejected %u; old entry %d retired at "
          "its own): the peer's data is dropped; a LAN packet is dropped by the zero-key rule but "
          "counted in send_cnt, and the firmware initiates a handshake", REJECT_AFTER_TIME_MS, e2,
          hal.stats.rejected, e1);

    // ---- 4e: the firmware as initiator: switch on message 2, its keepalive confirms ----
    ok = run_until(ms(20000), [&] { return n_keepalive == ka0 + 1; });
    snap();
    int e3 = hal.peer.cur.entry;
    check("4e-initiator", ok && ka_sess == s_cur.me && hal.peer.live && (int)hal.route_peer_idx[0] == e3 &&
          (hal.peer.tm & WG_TM_INITIATOR) && hal.ck[e3].local_id == s_cur.them,
          "the firmware's initiation answered: it installs entry %d on message 2 and its keepalive "
          "confirms the session to the peer", e3);

    // ---- 5b: REKEY_AFTER_TIME, the firmware initiator, traffic both ways ----
    uint32_t p2 = pseq, l2 = lseq;
    int      i0 = n_init_rx;
    uint64_t t_rk = 0;
    uint32_t me3 = s_cur.me;
    while (peer->now - t_hs3 < ms(REKEY_AFTER_TIME_MS + 6000)) {
        lan_tx.push_back(lseq++);
        run(ms(100));
        peer_send_data(s_cur, pseq++);
        run(ms(1900));
        if (!t_rk && n_init_rx > i0) t_rk = t_init_rx;
    }
    run(ms(500));
    double rk = (double)(t_rk - t_hs3) * WG_TIME_SCALE / 125000.0;
    ok_l = all_once(lan_rx, p2, pseq, &lost_l);
    ok_p = all_once(peer_rx, l2, lseq, &lost_p);
    check("5b-rekey-time", t_rk && rk >= REKEY_AFTER_TIME_MS && rk < REKEY_AFTER_TIME_MS + 3000 &&
          n_init_rx == i0 + 1 && s_cur.me != me3 && peer_rx_sess[lseq - 1] == s_cur.me && ok_l && ok_p,
          "the firmware rekeys %.0f ms after its handshake (REKEY_AFTER_TIME %u) while it sends; "
          "data goes on on the new session, none lost (%u, %u)", rk, REKEY_AFTER_TIME_MS, lost_l, lost_p);

    // ---- 6: a cookie reply under load (wg load on, over the console) ----
    a = cli("wg load on");
    int ck0 = n_cookie, r0 = n_resp;
    peer_initiate();
    ok = run_until(ms(20000), [&] { return n_cookie == ck0 + 1; });
    // the cookie: XChaCha20-Poly1305 under HASH("cookie--" || its public key),
    // the AAD our mac1; then mac2 = MAC(cookie, message up to mac2)
    uint8_t ckey[32], cookie[16];
    blake2s_ctx bc;
    blake2s_init(&bc, 32, NULL, 0);
    blake2s_update(&bc, "cookie--", 8);
    blake2s_update(&bc, fw_pub, 32);
    blake2s_final(&bc, ckey);
    bool opened = ok && get32(cookie_msg + 4) == (0xA0000000u | k_index) &&
                  xchacha20poly1305_decrypt(cookie, ckey, cookie_msg + 8, cookie_msg + 32, 16, cookie_msg + 48,
                                            last_init + WG_MSG_INIT_LEN - 32, 16) == 0;
    bool resp = false;
    if (opened) {
        peer_initiate(cookie);
        resp = run_until(ms(20000), [&] { return n_resp == r0 + 1; });
    }
    snap();
    check("6-cookie", ok && opened && resp && hal.stats.cookie_tx >= 1 && n_resp == r0 + 1,
          "under load (wg load on) an initiation without mac2 gets a cookie reply, the peer opens it, "
          "and its next initiation with mac2 is answered (cookie_tx %u)", hal.stats.cookie_tx);
    cli("wg load auto");
}

// ----------------------------------------------------------------------------------------
extern "C" void VUserMain1(void) {
    wgNode n(1);
    peer = &n;
    VPrint("Node1: the WireGuard peer (eth1)\n");
    test();
    VPrint("E2E: %s (%d checks passed, %d failed)\n", n_fail ? "FAILED" : "ALL PASS", n_pass, n_fail);
    VPrint("E2E: peer saw %d bad, %d other frames; the LAN %d other frames\n", n_bad, n_other, lan_other);
    n.UdpVpSetHalt(1);
    while (true) n.idle(1000);
}

extern "C" void VUserMain2(void) {
    wgNode n(2);
    VPrint("Node2: the LAN host (eth2)\n");
    while (true) {
        n.idle(20);
        while (!n.rx.empty()) {
            std::vector<uint8_t> f = n.rx.front();
            n.rx.pop_front();
            long seq = f.size() >= 14 + INNER_LEN && f[12] == 0x08 && f[13] == 0x00
                     ? inner_seq(&f[14], f.size() - 14, true) : -1;
            if (seq < 0) {
                lan_other++;
                VPrint("E2E: LAN: a frame that is not the peer's plaintext (%zu bytes)\n", f.size());
            } else {
                lan_rx[(uint32_t)seq]++;
            }
        }
        if (!lan_tx.empty()) {
            uint8_t pkt[INNER_LEN], f[14 + INNER_LEN];
            inner_packet(pkt, false, lan_tx.front());
            lan_tx.pop_front();
            memcpy(f, FW_MAC, 6);
            memcpy(f + 6, LAN_MAC, 6);
            f[12] = 0x08; f[13] = 0x00;
            memcpy(f + 14, pkt, INNER_LEN);
            n.send(f, sizeof(f));
        }
    }
}

extern "C" void VUserMain3(void) {
    wgNode n(3);
    while (true) n.idle(1000);
}

extern "C" void VUserMain4(void) {
    wgNode n(4);
    while (true) n.idle(1000);
}

// -----------------------------------------------------------------------------
// Project:     WireGuard-FPGA
// Description: NLnet-funded open-source implementation
// Funding:     https://nlnet.nl/project/KlusterLab-Wireguard (2023-12 to 2025-12)
// -----------------------------------------------------------------------------
