// SPDX-FileCopyrightText: 2026 Chili.CHIPS
//
// SPDX-License-Identifier: BSD-3-Clause

//==========================================================================
// Wireguard-1GE FPGA * NLnet-sponsored open-source implementation
//--------------------------------------------------------------------------
// Description:
//   dpe_wg_decryptor bench. LOOPBACK=1 (default): plaintext frames into
//   dpe_wg_encryptor, its WireGuard frames into dpe_wg_decryptor, its
//   output to a pcap. Every link stalls (dpe_tb_throttle). One bit of frame
//   CORRUPT_FRAME's ciphertext is flipped on the way: the decryptor must
//   drop that frame (its tag fails) and give back all others.
//   ../wg_check.py checks the output (see the Makefile).
//==========================================================================

module tb
  import dpe_pkg::*;
  import net_pkg::*;
#(
    parameter bit LOOPBACK = 1
);

  localparam int CORRUPT_FRAME = 3;  // the Makefile's check knows it too
  localparam int CORRUPT_BEAT = 6;  // in the ciphertext of that frame

  logic clk, rst;
  logic pcapfinished, enc_idle, dec_idle;

  dpe_if from_pcap (.clk(clk), .rst(rst));
  dpe_if to_enc    (.clk(clk), .rst(rst));
  dpe_if from_enc  (.clk(clk), .rst(rst));
  dpe_if wire_in   (.clk(clk), .rst(rst));  // the WireGuard frames, stalled
  dpe_if to_dec    (.clk(clk), .rst(rst));  // the same, one frame corrupted
  dpe_if from_dec  (.clk(clk), .rst(rst));
  dpe_if to_pcap   (.clk(clk), .rst(rst));

  // The peer's routing-table entry; MAC, IP and port in bus byte order
  localparam wg_peer_cfg_t PEER = '{
      local_mac: 48'hAABBCCDDEEFF,
      local_ip: 32'h0100A8C0,  // 192.168.0.1
      local_port: 16'h6DCA,
      remote_mac: 48'hFFEEDDCCBBAA,
      remote_ip: 32'h0200A8C0,  // 192.168.0.2
      remote_port: 16'h6CCA,
      remote_id: 32'hAABBCCDD,
      key: 256'h0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF,
      send_cnt: 64'd1
  };

  // LOOPBACK 1: the plaintext through dpe_wg_encryptor; 0: the WireGuard
  // frames ../wg_check.py builds (RFC 8439), so the decryptor is checked
  // without the encryptor
  dpe_pcapreader #(
      .PCAP_FILENAME     (LOOPBACK ? "../../dpe_wg_encryptor/plaintext_mix.pcap" :
                                     "../wg_mix.pcap"),
      .TUSER_BYPASS_STAGE(1'b0)
  ) pcaprd (
      .outp        (from_pcap),
      .pcapfinished(pcapfinished)
  );

  if (LOOPBACK) begin : g_loopback
    dpe_tb_throttle #(.PASS_PCT(60), .SEED(16'hACE1)) stall_in (.inp(from_pcap), .outp(to_enc));

    // its core: standalone encrypt (in the SoC, dpe_switch's shared one)
    dpe_if to_enc_core   (.clk(clk), .rst(rst));
    dpe_if from_enc_core (.clk(clk), .rst(rst));
    logic [255:0] enc_key;
    logic [ 95:0] enc_nonce;

    dpe_wg_encryptor encryptor (
        .inp          (to_enc),
        .outp         (from_enc),
        .idle         (enc_idle),
        .peer_req     (),
        .peer_rsp     (PEER),
        .core_key     (enc_key),
        .core_nonce   (enc_nonce),
        .to_encrypt   (to_enc_core),
        .from_encrypt (from_enc_core)
    );

    chacha20poly1305_encrypt u_enc_core (
        .clk_80p0              (clk),
        .encrypt_key           (enc_key),
        .encrypt_nonce         (enc_nonce),
        .encrypt_aad           (256'd0),
        .encrypt_aad_len       (8'd0),
        .encrypt_s_axis_tdata  (to_enc_core.tdata),
        .encrypt_s_axis_tkeep  (to_enc_core.tkeep),
        .encrypt_s_axis_tlast  (to_enc_core.tlast),
        .encrypt_s_axis_tvalid (to_enc_core.tvalid),
        .encrypt_s_axis_tready (to_enc_core.tready),
        .encrypt_m_axis_tdata  (from_enc_core.tdata),
        .encrypt_m_axis_tkeep  (from_enc_core.tkeep),
        .encrypt_m_axis_tlast  (from_enc_core.tlast),
        .encrypt_m_axis_tvalid (from_enc_core.tvalid),
        .encrypt_m_axis_tready (from_enc_core.tready)
    );

    dpe_tb_throttle #(.PASS_PCT(60), .SEED(16'h5A5A)) stall_mid (.inp(from_enc), .outp(wire_in));
  end
  else begin : g_reference
    assign enc_idle = 1'b1;
    assign from_enc.tvalid = 1'b0;
    dpe_tb_throttle #(.PASS_PCT(60), .SEED(16'h5A5A)) stall_mid (.inp(from_pcap), .outp(wire_in));
  end

  // the link: passes everything, but flips bit 0 of beat CORRUPT_BEAT of
  // frame CORRUPT_FRAME
  int link_frame = 0, link_beat = 0;
  always_ff @(posedge clk) begin
    if (rst) begin
      link_frame <= 0;
      link_beat  <= 0;
    end
    else if (wire_in.tvalid && wire_in.tready) begin
      if (wire_in.tlast) begin
        link_frame <= link_frame + 1;
        link_beat  <= 0;
      end
      else begin
        link_beat <= link_beat + 1;
      end
    end
  end
  assign to_dec.tvalid  = wire_in.tvalid;
  assign wire_in.tready = to_dec.tready;
  assign to_dec.tdata   = wire_in.tdata ^ dpe_data_t'(link_frame == CORRUPT_FRAME &&
                                                      link_beat == CORRUPT_BEAT);
  assign to_dec.tkeep   = wire_in.tkeep;
  assign to_dec.tlast   = wire_in.tlast;
  assign to_dec.tuser   = wire_in.tuser;
  assign to_dec.tid     = wire_in.tid;

  // the core: standalone decrypt (in the SoC, dpe_switch's shared one)
  dpe_if to_core   (.clk(clk), .rst(rst));
  dpe_if from_core (.clk(clk), .rst(rst));
  logic [255:0] core_key;
  logic [ 95:0] core_nonce;
  logic         core_verified;

  dpe_wg_decryptor decryptor (
      .inp           (to_dec),
      .outp          (from_dec),
      .idle          (dec_idle),
      .peer_req      (),
      .peer_rsp      (PEER),
      .core_key      (core_key),
      .core_nonce    (core_nonce),
      .to_decrypt    (to_core),
      .from_decrypt  (from_core),
      .core_verified (core_verified)
  );

  chacha20poly1305_decrypt u_core (
      .clk_80p0              (clk),
      .decrypt_key           (core_key),
      .decrypt_nonce         (core_nonce),
      .decrypt_aad           (256'd0),
      .decrypt_aad_len       (8'd0),
      .decrypt_s_axis_tdata  (to_core.tdata),
      .decrypt_s_axis_tkeep  (to_core.tkeep),
      .decrypt_s_axis_tlast  (to_core.tlast),
      .decrypt_s_axis_tvalid (to_core.tvalid),
      .decrypt_s_axis_tready (to_core.tready),
      .decrypt_m_axis_tdata  (from_core.tdata),
      .decrypt_m_axis_tkeep  (from_core.tkeep),
      .decrypt_m_axis_tlast  (from_core.tlast),
      .decrypt_m_axis_tvalid (from_core.tvalid),
      .decrypt_m_axis_tready (from_core.tready),
      .decrypt_m_verified    (core_verified)
  );

  dpe_tb_throttle #(.PASS_PCT(60), .SEED(16'h1D2C)) stall_out (.inp(from_dec), .outp(to_pcap));

  dpe_pcapwriter #(
      .PCAP_FILENAME("decrypted_mix.pcap")  // in output/
  ) pcapwr (
      .inp(to_pcap)
  );

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

  // done: all frames read, both blocks idle, and nothing on the links
  initial begin
    rst = 1'b1;
    @(negedge clk);
    rst = 1'b0;
    while (!pcapfinished) @(negedge clk);
    do begin
      repeat (64) @(negedge clk);
    end while (!enc_idle || !dec_idle || to_dec.tvalid || from_enc.tvalid || to_pcap.tvalid);
    repeat (2) @(negedge clk);
    $finish;
  end
endmodule

// -----------------------------------------------------------------------------
// Project:     WireGuard-FPGA
// Description: NLnet-funded open-source implementation
// Funding:     https://nlnet.nl/project/KlusterLab-Wireguard (2023-12 to 2025-12)
// -----------------------------------------------------------------------------
