// SPDX-FileCopyrightText: 2026 Chili.CHIPS
//
// SPDX-License-Identifier: BSD-3-Clause

//==========================================================================
// Wireguard-1GE FPGA * NLnet-sponsored open-source implementation
//--------------------------------------------------------------------------
//                   Copyright (C) 2026 Chili.CHIPS
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
//   dpe_switch system bench: the whole WireGuard data path, the ChaCha20-
//   Poly1305 cores in it.
//   1. Both tables over their CSR ports (routing_table, cryptokey_table),
//      as the firmware writes them; wg_ip:wg_port as csr.dpe gives them.
//   2. Frames from output/sys_in.pcap (sys_check.py gen): plaintext to the
//      peers, WireGuard from them, and frames it must drop or pass on. The
//      links stall on both sides (dpe_tb_throttle).
//   The output goes to output/sys_out.pcap, the tuser of each frame to
//   output/sys_meta.txt; sys_check.py checks both (see the Makefile).
//==========================================================================

module tb
  import dpe_pkg::*;
  import net_pkg::*;
  import lkup_pkg::*;
;
  logic clk, rst, rst_src;  // rst_src: the source waits for the tables
  logic pcapfinished, idle;

  dpe_if from_pcap (.clk(clk), .rst(rst_src));
  dpe_if to_dut    (.clk(clk), .rst(rst));
  dpe_if from_dut  (.clk(clk), .rst(rst));
  dpe_if to_pcap   (.clk(clk), .rst(rst));

  rt_cfg_t rt_cfg;
  rt_sta_t rt_sta;
  ck_cfg_t ck_cfg;
  ck_sta_t ck_sta;

  // this device: csr.dpe.wg_ip, wg_port (sys_check.py: US)
  localparam ipv4_addr_t WG_IP = 32'hC0A8_0162;  // 192.168.1.98
  localparam udp_port_t WG_PORT = 16'd51820;
  localparam logic [47:0] MAC = 48'hCCBA_CACA_0001;

  dpe_pcapreader #(
      .PCAP_FILENAME   ("sys_in.pcap"),  // in output/
      .TUSER_SRC       (DPE_ADDR_ETH_2),
      .TUSER_DST       (DPE_ADDR_CPU)
  ) pcaprd (
      .outp        (from_pcap),
      .pcapfinished(pcapfinished)
  );

  dpe_tb_throttle #(.PASS_PCT(60), .SEED(16'hACE1)) stall_in (.inp(from_pcap), .outp(to_dut));

  dpe_switch dut (
      .inp    (to_dut),
      .outp   (from_dut),
      .idle   (idle),
      .wg_ip  (WG_IP),
      .wg_port(WG_PORT),
      .rt_cfg (rt_cfg),
      .rt_sta (rt_sta),
      .ck_cfg (ck_cfg),
      .ck_sta (ck_sta)
  );

  dpe_tb_throttle #(.PASS_PCT(60), .SEED(16'h1D2C)) stall_out (.inp(from_dut), .outp(to_pcap));

  dpe_pcapwriter #(
      .PCAP_FILENAME("sys_out.pcap")  // in output/
  ) pcapwr (
      .inp(to_pcap)
  );

  // the tuser of each frame out
  int meta_fd;
  initial meta_fd = $fopen("sys_meta.txt", "w");
  always @(posedge clk) begin
    if (!rst && to_pcap.tvalid && to_pcap.tready && to_pcap.tlast) begin
      $fwrite(meta_fd, "%0d %0d\n", to_pcap.tuser.dst, to_pcap.tuser.bypass_all);
    end
  end

  // 80 MHz at 1 ns precision: halves of 6, 6, 7, 6 ns, 12.5 ns on average
  initial begin
    clk = 1'b0;
    forever begin
      #6ns clk = 1'b1;
      #6ns clk = 1'b0;
      #7ns clk = 1'b1;
      #6ns clk = 1'b0;
    end
  end

  // a hang (a stuck link, idle never set) fails instead of running on
  initial begin
    #20ms;
    $display("RESULT: FAIL (timeout: the frames did not get through)");
    $finish;
  end

  //------------------------------------------------------------------
  // CSR writes: one clock of req, acknowledged in that clock
  //------------------------------------------------------------------
  int errors = 0;

  // routing_table: entry[addr[9:4]], field addr[3:2]: 0 ip, 1 mask,
  // 2 peer_idx (encrypt in bit 8), 3 dst
  task automatic rt_write(int e, int field, logic [31:0] data);
    @(negedge clk);
    rt_cfg = '{req: 1'b1, req_is_wr: 1'b1, addr: 10'({6'(e), 2'(field), 2'b00}),
               wr_data: data, wr_biten: '1};
    #3ns;
    if (!rt_sta.wr_ack) begin
      $display("ERROR: routing_table entry %0d field %0d: no wr_ack", e, field);
      errors++;
    end
    @(negedge clk);
    rt_cfg.req = 1'b0;
  endtask

  task automatic route(int e, logic [31:0] prefix, logic [31:0] mask, int peer, logic encrypt,
                       dpe_addr_t dst);
    rt_write(e, 0, prefix);
    rt_write(e, 1, mask);
    rt_write(e, 2, {23'd0, encrypt, 8'(peer)});
    rt_write(e, 3, 32'(dst));
  endtask

  // cryptokey_table: entry[addr[12:7]], word addr[6:2] (lkup_pkg ck_word_t)
  task automatic ck_write(int e, ck_word_t w, logic [31:0] data);
    @(negedge clk);
    ck_cfg = '{req: 1'b1, req_is_wr: 1'b1, addr: 13'({6'(e), w, 2'b00}),
               wr_data: data, wr_biten: '1};
    #3ns;
    if (!ck_sta.wr_ack) begin
      $display("ERROR: cryptokey_table entry %0d word %0d: no wr_ack", e, w);
      errors++;
    end
    @(negedge clk);
    ck_cfg.req = 1'b0;
  endtask

  // a peer, numbers as the CPU writes them (sys_check.py: PEERS)
  task automatic peer(int e, logic [47:0] mac, logic [31:0] ip, logic [15:0] port,
                      logic [31:0] local_id, logic [31:0] remote_id, logic [255:0] enc_key,
                      logic [255:0] dec_key, logic [63:0] send_cnt);
    ck_write(e, CK_LOCAL_MAC_HI, 32'(MAC[47:32]));
    ck_write(e, CK_LOCAL_MAC_LO, MAC[31:0]);
    ck_write(e, CK_LOCAL_IP, WG_IP);
    ck_write(e, CK_LOCAL_PORT, 32'(WG_PORT));
    ck_write(e, CK_LOCAL_ID, local_id);
    ck_write(e, CK_REMOTE_MAC_HI, 32'(mac[47:32]));
    ck_write(e, CK_REMOTE_MAC_LO, mac[31:0]);
    ck_write(e, CK_REMOTE_IP, ip);
    ck_write(e, CK_REMOTE_PORT, 32'(port));
    ck_write(e, CK_REMOTE_ID, remote_id);
    for (int k = 0; k < 8; k++) begin
      ck_write(e, ck_word_t'(CK_ENC_KEY_0 + k), enc_key[255-32*k-:32]);
      ck_write(e, ck_word_t'(CK_DEC_KEY_0 + k), dec_key[255-32*k-:32]);
    end
    ck_write(e, CK_SEND_CNT_HI, send_cnt[63:32]);
    ck_write(e, CK_SEND_CNT_LO, send_cnt[31:0]);
  endtask

  initial begin
    rt_cfg  = '{req: 1'b0, addr: '0, req_is_wr: 1'b0, wr_data: '0, wr_biten: '0};
    ck_cfg  = '{req: 1'b0, addr: '0, req_is_wr: 1'b0, wr_data: '0, wr_biten: '0};
    rst     = 1'b1;
    rst_src = 1'b1;
    @(negedge clk);
    rst = 1'b0;

    // 1. the tables. Routes: first match wins; the unused entries are host
    // routes nothing here uses (the table has no reset)
    route(0, 32'h0A01_0000, 32'hFFFF_0000, 1, 1'b1, DPE_ADDR_ETH_1);  // 10.1/16: peer 1
    route(1, 32'h0A02_0000, 32'hFFFF_0000, 2, 1'b1, DPE_ADDR_ETH_4);  // 10.2/16: peer 2
    route(2, 32'hAC10_0000, 32'hFFF0_0000, 0, 1'b0, DPE_ADDR_ETH_3);  // 172.16/12: LAN
    route(3, 32'hC0A8_0100, 32'hFFFF_FF00, 0, 1'b0, DPE_ADDR_ETH_2);  // 192.168.1/24
    for (int e = 4; e < 64; e++) route(e, {24'hAC1F_FF, 8'(e)}, '1, 0, 1'b0, DPE_ADDR_CPU);

    // peers: our receiver index has the entry in its low 6 bits; the other
    // entries' indexes match no packet here
    for (int e = 0; e < 64; e++) ck_write(e, CK_LOCAL_ID, 32'hDEAD_0000 | 32'(e));
    peer(1, 48'h0200_0000_0099, 32'hC0A8_0163, 16'd51821, 32'h5EED_0041, 32'hAABB_CCDD,
         {4{64'h0123_4567_89AB_CDEF}}, {4{64'hFEDC_BA98_7654_3210}},
         64'h0000_0000_FFFF_FFFE);  // the count crosses into the upper word
    peer(2, 48'h0200_0000_0077, 32'hC0A8_014D, 16'd51822, 32'h7A11_0042, 32'h1122_3344,
         {2{128'h0011_2233_4455_6677_8899_AABB_CCDD_EEFF}},
         {2{128'hA5A5_A5A5_5A5A_5A5A_0F0F_0F0F_F0F0_F0F0}}, 64'd5);

    // 2. the frames
    @(negedge clk);
    rst_src = 1'b0;
    while (!pcapfinished) @(negedge clk);
    do begin
      repeat (64) @(negedge clk);
    end while (!idle || to_dut.tvalid || from_dut.tvalid || to_pcap.tvalid);
    repeat (2) @(negedge clk);
    $fclose(meta_fd);
    if (errors != 0) $display("RESULT: FAIL (%0d CSR errors)", errors);
    $finish;
  end
endmodule

// -----------------------------------------------------------------------------
// Project:     WireGuard-FPGA
// Description: NLnet-funded open-source implementation
// Funding:     https://nlnet.nl/project/KlusterLab-Wireguard (2023-12 to 2025-12)
// -----------------------------------------------------------------------------
