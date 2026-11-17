// SPDX-FileCopyrightText: 2026 Chili.CHIPS
//
// Enhanced by Chili.CHIPS with NLnet-sponsored project
// wireguard-fpga (https://github.com/chili-chips/wireguard-fpga).
// The original header follows.

// verilator lint_off SYNCASYNCNET

// Copyright (c) 2015-2018 Alex Forencich
//
// SPDX-License-Identifier: MIT

// Language: Verilog 2001

`resetall
`default_nettype none

/*
 * AXI4-Stream GMII frame receiver (GMII in, AXI out)
 */
module axis_gmii_rx #(
    parameter DATA_WIDTH    = 8,
    parameter PTP_TS_ENABLE = 0,
    parameter PTP_TS_WIDTH  = 96,
    parameter USER_WIDTH    = (PTP_TS_ENABLE ? PTP_TS_WIDTH : 0) + 1
) (
    input  logic                    clk,
    input  logic                    rst,

    /*
     * GMII input
     */
    input  logic [DATA_WIDTH-1:0]   gmii_rxd,
    input  logic                    gmii_rx_dv,
    input  logic                    gmii_rx_er,

    /*
     * AXI output
     */
    output logic [DATA_WIDTH-1:0]   m_axis_tdata,
    output logic                    m_axis_tvalid,
    output logic                    m_axis_tlast,
    output logic [USER_WIDTH-1:0]   m_axis_tuser,

    /*
     * PTP
     */
    input  logic [PTP_TS_WIDTH-1:0] ptp_ts,

    /*
     * Control
     */
    input  logic                    clk_enable,
    input  logic                    mii_select,

    /*
     * Configuration
     */
    input  logic                    cfg_rx_enable,

    /*
     * Status
     */
    output logic                    start_packet,
    output logic                    error_bad_frame,
    output logic                    error_bad_fcs
);

  // bus width assertions
  initial begin
    if (DATA_WIDTH != 8) begin
      $error("Error: Interface width must be 8");
      $finish;
    end
  end

  // verilator lint_off UNUSEDPARAM
  localparam [7:0] ETH_PRE    = 8'h55, ETH_SFD = 8'hD5;
  // verilator lint_on UNUSEDPARAM

  localparam [2:0] STATE_IDLE = 3'd0, STATE_PAYLOAD = 3'd1, STATE_WAIT_LAST = 3'd2;

  logic [2:0] state_reg = STATE_IDLE, state_next;

  // datapath control signals
  logic                  reset_crc;
  logic                  update_crc;

  logic                  mii_odd = 1'b0;
  logic                  in_frame = 1'b0;

  logic [DATA_WIDTH-1:0] gmii_rxd_d0 = {DATA_WIDTH{1'b0}};
  logic [DATA_WIDTH-1:0] gmii_rxd_d1 = {DATA_WIDTH{1'b0}};
  logic [DATA_WIDTH-1:0] gmii_rxd_d2 = {DATA_WIDTH{1'b0}};
  logic [DATA_WIDTH-1:0] gmii_rxd_d3 = {DATA_WIDTH{1'b0}};
  logic [DATA_WIDTH-1:0] gmii_rxd_d4 = {DATA_WIDTH{1'b0}};

  logic                  gmii_rx_dv_d0 = 1'b0;
  logic                  gmii_rx_dv_d1 = 1'b0;
  logic                  gmii_rx_dv_d2 = 1'b0;
  logic                  gmii_rx_dv_d3 = 1'b0;
  logic                  gmii_rx_dv_d4 = 1'b0;

  logic                  gmii_rx_er_d0 = 1'b0;
  logic                  gmii_rx_er_d1 = 1'b0;
  logic                  gmii_rx_er_d2 = 1'b0;
  logic                  gmii_rx_er_d3 = 1'b0;
  logic                  gmii_rx_er_d4 = 1'b0;

  logic [DATA_WIDTH-1:0] m_axis_tdata_reg = {DATA_WIDTH{1'b0}}, m_axis_tdata_next;
  logic m_axis_tvalid_reg = 1'b0, m_axis_tvalid_next;
  logic m_axis_tlast_reg = 1'b0, m_axis_tlast_next;
  logic m_axis_tuser_reg = 1'b0, m_axis_tuser_next;

  logic start_packet_int_reg = 1'b0;
  logic start_packet_reg = 1'b0;
  logic error_bad_frame_reg = 1'b0, error_bad_frame_next;
  logic error_bad_fcs_reg = 1'b0, error_bad_fcs_next;

  logic [PTP_TS_WIDTH-1:0] ptp_ts_reg = 0;

  logic [            31:0] crc_state = 32'hFFFFFFFF;
  logic [            31:0] crc_next;

  assign m_axis_tdata    = m_axis_tdata_reg;
  assign m_axis_tvalid   = m_axis_tvalid_reg;
  assign m_axis_tlast    = m_axis_tlast_reg;
  // verilator lint_off WIDTHEXPAND
  // verilator lint_off WIDTHTRUNC
  assign m_axis_tuser    = PTP_TS_ENABLE ? {ptp_ts_reg, m_axis_tuser_reg} : m_axis_tuser_reg;
  // verilator lint_on WIDTHEXPAND
  // verilator lint_on WIDTHTRUNC

  assign start_packet    = start_packet_reg;
  assign error_bad_frame = error_bad_frame_reg;
  assign error_bad_fcs   = error_bad_fcs_reg;

  lfsr #(
      .LFSR_WIDTH        (32),
      .LFSR_POLY         (32'h4c11db7),
      .LFSR_CONFIG       ("GALOIS"),
      .LFSR_FEED_FORWARD (0),
      .REVERSE           (1),
      .DATA_WIDTH        (8),
      .STYLE             ("AUTO")
  ) eth_crc_8 (
      .data_in   (gmii_rxd_d4),
      .state_in  (crc_state),
      .data_out  (),
      .state_out (crc_next)
  );

  always_comb begin
    state_next           = STATE_IDLE;

    reset_crc            = 1'b0;
    update_crc           = 1'b0;

    m_axis_tdata_next    = {DATA_WIDTH{1'b0}};
    m_axis_tvalid_next   = 1'b0;
    m_axis_tlast_next    = 1'b0;
    m_axis_tuser_next    = 1'b0;

    error_bad_frame_next = 1'b0;
    error_bad_fcs_next   = 1'b0;

    if (!clk_enable) begin
      // clock disabled - hold state
      state_next = state_reg;
    end
    else if (mii_select && !mii_odd) begin
      // MII even cycle - hold state
      state_next = state_reg;
    end
    else begin
      unique case (state_reg)
        STATE_IDLE: begin
          // idle state - wait for packet
          reset_crc = 1'b1;

          if (gmii_rx_dv_d4 && !gmii_rx_er_d4 && gmii_rxd_d4 == ETH_SFD && cfg_rx_enable) begin
            state_next = STATE_PAYLOAD;
          end
          else begin
            state_next = STATE_IDLE;
          end
        end
        STATE_PAYLOAD: begin
          // read payload
          update_crc         = 1'b1;

          m_axis_tdata_next  = gmii_rxd_d4;
          m_axis_tvalid_next = 1'b1;

          if (gmii_rx_dv_d4 && gmii_rx_er_d4) begin
            // error
            m_axis_tlast_next    = 1'b1;
            m_axis_tuser_next    = 1'b1;
            error_bad_frame_next = 1'b1;
            state_next           = STATE_WAIT_LAST;
          end
          else if (!gmii_rx_dv) begin
            // end of packet
            m_axis_tlast_next = 1'b1;
            if (gmii_rx_er_d0 || gmii_rx_er_d1 || gmii_rx_er_d2 || gmii_rx_er_d3) begin
              // error received in FCS bytes
              m_axis_tuser_next    = 1'b1;
              error_bad_frame_next = 1'b1;
            end
            else if ({gmii_rxd_d0, gmii_rxd_d1, gmii_rxd_d2, gmii_rxd_d3} == ~crc_next) begin
              // FCS good
              m_axis_tuser_next = 1'b0;
            end
            else begin
              // FCS bad
              m_axis_tuser_next    = 1'b1;
              error_bad_frame_next = 1'b1;
              error_bad_fcs_next   = 1'b1;
            end
            state_next = STATE_IDLE;
          end
          else begin
            state_next = STATE_PAYLOAD;
          end
        end
        STATE_WAIT_LAST: begin
          // wait for end of packet

          if (~gmii_rx_dv) begin
            state_next = STATE_IDLE;
          end
          else begin
            state_next = STATE_WAIT_LAST;
          end
        end
        default: state_next = STATE_IDLE;  // not a state: back to idle
      endcase
    end
  end

  always_ff @(posedge clk) begin
    state_reg            <= state_next;

    m_axis_tdata_reg     <= m_axis_tdata_next;
    m_axis_tvalid_reg    <= m_axis_tvalid_next;
    m_axis_tlast_reg     <= m_axis_tlast_next;
    m_axis_tuser_reg     <= m_axis_tuser_next;

    start_packet_int_reg <= 1'b0;
    start_packet_reg     <= 1'b0;

    if (start_packet_int_reg) begin
      ptp_ts_reg       <= ptp_ts;
      start_packet_reg <= 1'b1;
    end

    if (clk_enable) begin
      if (mii_select) begin
        mii_odd <= !mii_odd;

        if (in_frame) begin
          in_frame <= gmii_rx_dv;
        end
        else if (gmii_rx_dv && {gmii_rxd[3:0], gmii_rxd_d0[7:4]} == ETH_SFD) begin
          in_frame             <= 1'b1;
          start_packet_int_reg <= 1'b1;
          mii_odd              <= 1'b1;
        end

        gmii_rxd_d0 <= {gmii_rxd[3:0], gmii_rxd_d0[7:4]};

        if (mii_odd) begin
          gmii_rxd_d1   <= gmii_rxd_d0;
          gmii_rxd_d2   <= gmii_rxd_d1;
          gmii_rxd_d3   <= gmii_rxd_d2;
          gmii_rxd_d4   <= gmii_rxd_d3;

          gmii_rx_dv_d0 <= gmii_rx_dv & gmii_rx_dv_d0;
          gmii_rx_dv_d1 <= gmii_rx_dv_d0 & gmii_rx_dv;
          gmii_rx_dv_d2 <= gmii_rx_dv_d1 & gmii_rx_dv;
          gmii_rx_dv_d3 <= gmii_rx_dv_d2 & gmii_rx_dv;
          gmii_rx_dv_d4 <= gmii_rx_dv_d3 & gmii_rx_dv;

          gmii_rx_er_d0 <= gmii_rx_er | gmii_rx_er_d0;
          gmii_rx_er_d1 <= gmii_rx_er_d0;
          gmii_rx_er_d2 <= gmii_rx_er_d1;
          gmii_rx_er_d3 <= gmii_rx_er_d2;
          gmii_rx_er_d4 <= gmii_rx_er_d3;
        end
        else begin
          gmii_rx_dv_d0 <= gmii_rx_dv;
          gmii_rx_er_d0 <= gmii_rx_er;
        end
      end
      else begin
        if (in_frame) begin
          in_frame <= gmii_rx_dv;
        end
        else if (gmii_rx_dv && gmii_rxd == ETH_SFD) begin
          in_frame             <= 1'b1;
          start_packet_int_reg <= 1'b1;
        end

        gmii_rxd_d0   <= gmii_rxd;
        gmii_rxd_d1   <= gmii_rxd_d0;
        gmii_rxd_d2   <= gmii_rxd_d1;
        gmii_rxd_d3   <= gmii_rxd_d2;
        gmii_rxd_d4   <= gmii_rxd_d3;

        gmii_rx_dv_d0 <= gmii_rx_dv;
        gmii_rx_dv_d1 <= gmii_rx_dv_d0 & gmii_rx_dv;
        gmii_rx_dv_d2 <= gmii_rx_dv_d1 & gmii_rx_dv;
        gmii_rx_dv_d3 <= gmii_rx_dv_d2 & gmii_rx_dv;
        gmii_rx_dv_d4 <= gmii_rx_dv_d3 & gmii_rx_dv;

        gmii_rx_er_d0 <= gmii_rx_er;
        gmii_rx_er_d1 <= gmii_rx_er_d0;
        gmii_rx_er_d2 <= gmii_rx_er_d1;
        gmii_rx_er_d3 <= gmii_rx_er_d2;
        gmii_rx_er_d4 <= gmii_rx_er_d3;
      end
    end

    if (reset_crc) begin
      crc_state <= 32'hFFFFFFFF;
    end
    else if (update_crc) begin
      crc_state <= crc_next;
    end

    error_bad_frame_reg <= error_bad_frame_next;
    error_bad_fcs_reg   <= error_bad_fcs_next;

    if (rst) begin
      state_reg            <= STATE_IDLE;

      m_axis_tvalid_reg    <= 1'b0;

      start_packet_int_reg <= 1'b0;
      start_packet_reg     <= 1'b0;
      error_bad_frame_reg  <= 1'b0;
      error_bad_fcs_reg    <= 1'b0;

      in_frame             <= 1'b0;
      mii_odd              <= 1'b0;

      gmii_rx_dv_d0        <= 1'b0;
      gmii_rx_dv_d1        <= 1'b0;
      gmii_rx_dv_d2        <= 1'b0;
      gmii_rx_dv_d3        <= 1'b0;
      gmii_rx_dv_d4        <= 1'b0;
    end
  end

endmodule

`resetall
// verilator lint_on SYNCASYNCNET
