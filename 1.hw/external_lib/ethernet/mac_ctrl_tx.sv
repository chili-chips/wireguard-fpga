// SPDX-FileCopyrightText: 2026 Chili.CHIPS
//
// Enhanced by Chili.CHIPS with NLnet-sponsored project
// wireguard-fpga (https://github.com/chili-chips/wireguard-fpga).
// The original header follows.

// Copyright (c) 2023 Alex Forencich
//
// SPDX-License-Identifier: MIT

// Language: Verilog 2001

`resetall
`default_nettype none

/*
 * MAC control transmit
 */
module mac_ctrl_tx #(
    parameter DATA_WIDTH      = 8,
    parameter KEEP_ENABLE     = DATA_WIDTH > 8,
    parameter KEEP_WIDTH      = DATA_WIDTH / 8,
    parameter ID_ENABLE       = 0,
    parameter ID_WIDTH        = 8,
    parameter DEST_ENABLE     = 0,
    parameter DEST_WIDTH      = 8,
    parameter USER_ENABLE     = 1,
    parameter USER_WIDTH      = 1,
    parameter MCF_PARAMS_SIZE = 18
) (
    input  logic                         clk,
    input  logic                         rst,

    /*
     * AXI stream input
     */
    input  logic [DATA_WIDTH-1:0]        s_axis_tdata,
    input  logic [KEEP_WIDTH-1:0]        s_axis_tkeep,
    input  logic                         s_axis_tvalid,
    output logic                         s_axis_tready,
    input  logic                         s_axis_tlast,
    input  logic [  ID_WIDTH-1:0]        s_axis_tid,
    input  logic [DEST_WIDTH-1:0]        s_axis_tdest,
    input  logic [USER_WIDTH-1:0]        s_axis_tuser,

    /*
     * AXI stream output
     */
    output logic [DATA_WIDTH-1:0]        m_axis_tdata,
    output logic [KEEP_WIDTH-1:0]        m_axis_tkeep,
    output logic                         m_axis_tvalid,
    input  logic                         m_axis_tready,
    output logic                         m_axis_tlast,
    output logic [  ID_WIDTH-1:0]        m_axis_tid,
    output logic [DEST_WIDTH-1:0]        m_axis_tdest,
    output logic [USER_WIDTH-1:0]        m_axis_tuser,

    /*
     * MAC control frame interface
     */
    input  logic                         mcf_valid,
    output logic                         mcf_ready,
    input  logic [                 47:0] mcf_eth_dst,
    input  logic [                 47:0] mcf_eth_src,
    input  logic [                 15:0] mcf_eth_type,
    input  logic [                 15:0] mcf_opcode,
    input  logic [MCF_PARAMS_SIZE*8-1:0] mcf_params,
    input  logic [         ID_WIDTH-1:0] mcf_id,
    input  logic [       DEST_WIDTH-1:0] mcf_dest,
    input  logic [       USER_WIDTH-1:0] mcf_user,

    /*
     * Pause interface
     */
    input  logic                         tx_pause_req,
    output logic                         tx_pause_ack,

    /*
     * Status
     */
    output logic                         stat_tx_mcf
);

  parameter BYTE_LANES  = KEEP_ENABLE ? KEEP_WIDTH : 1;

  parameter HDR_SIZE    = 60;

  parameter CYCLE_COUNT = (HDR_SIZE + BYTE_LANES - 1) / BYTE_LANES;

  parameter PTR_WIDTH   = $clog2(CYCLE_COUNT);

  parameter OFFSET      = HDR_SIZE % BYTE_LANES;

  // check configuration
  initial begin
    if (BYTE_LANES * 8 != DATA_WIDTH) begin
      $error("Error: AXI stream interface requires byte (8-bit) granularity (instance %m)");
      $finish;
    end

    if (MCF_PARAMS_SIZE > 44) begin
      $error("Error: Maximum MCF_PARAMS_SIZE is 44 bytes (instance %m)");
      $finish;
    end
  end

  /*

MAC control frame

 Field                       Length
 Destination MAC address     6 octets [01:80:C2:00:00:01]
 Source MAC address          6 octets
 Ethertype                   2 octets [0x8808]
 Opcode                      2 octets
 Parameters                  0-44 octets

This module manages the transmission of MAC control frames.  Control frames
are accepted in parallel, serialized, and merged at a higher priority with
data traffic.

*/

  logic send_data_reg = 1'b0, send_data_next;
  logic send_mcf_reg = 1'b0, send_mcf_next;
  logic [PTR_WIDTH-1:0] ptr_reg = 0, ptr_next;

  logic s_axis_tready_reg = 1'b0, s_axis_tready_next;
  logic mcf_ready_reg = 1'b0, mcf_ready_next;
  logic tx_pause_ack_reg = 1'b0, tx_pause_ack_next;
  logic stat_tx_mcf_reg = 1'b0, stat_tx_mcf_next;

  // internal datapath
  logic [DATA_WIDTH-1:0] m_axis_tdata_int;
  logic [KEEP_WIDTH-1:0] m_axis_tkeep_int;
  logic                  m_axis_tvalid_int;
  logic                  m_axis_tready_int_reg = 1'b0;
  logic                  m_axis_tlast_int;
  logic [  ID_WIDTH-1:0] m_axis_tid_int;
  logic [DEST_WIDTH-1:0] m_axis_tdest_int;
  logic [USER_WIDTH-1:0] m_axis_tuser_int;
  logic                  m_axis_tready_int_early;

  assign s_axis_tready = s_axis_tready_reg;
  assign mcf_ready     = mcf_ready_reg;
  assign tx_pause_ack  = tx_pause_ack_reg;
  assign stat_tx_mcf   = stat_tx_mcf_reg;

  always_comb begin
    send_data_next     = send_data_reg;
    send_mcf_next      = send_mcf_reg;
    ptr_next           = ptr_reg;

    s_axis_tready_next = 1'b0;
    mcf_ready_next     = 1'b0;
    tx_pause_ack_next  = tx_pause_ack_reg;
    stat_tx_mcf_next   = 1'b0;

    m_axis_tdata_int   = 0;
    m_axis_tkeep_int   = 0;
    m_axis_tvalid_int  = 1'b0;
    m_axis_tlast_int   = 1'b0;
    m_axis_tid_int     = 0;
    m_axis_tdest_int   = 0;
    m_axis_tuser_int   = 0;

    if (!send_data_reg && !send_mcf_reg) begin
      m_axis_tdata_int   = s_axis_tdata;
      m_axis_tkeep_int   = s_axis_tkeep;
      m_axis_tvalid_int  = 1'b0;
      m_axis_tlast_int   = s_axis_tlast;
      m_axis_tid_int     = s_axis_tid;
      m_axis_tdest_int   = s_axis_tdest;
      m_axis_tuser_int   = s_axis_tuser;
      s_axis_tready_next = m_axis_tready_int_early && !tx_pause_req;
      tx_pause_ack_next  = tx_pause_req;
      if (s_axis_tvalid && s_axis_tready) begin
        s_axis_tready_next = m_axis_tready_int_early;
        tx_pause_ack_next  = 1'b0;
        m_axis_tvalid_int  = 1'b1;
        if (s_axis_tlast) begin
          s_axis_tready_next = m_axis_tready_int_early && !mcf_valid && !mcf_ready;
          send_data_next     = 1'b0;
        end
        else begin
          send_data_next = 1'b1;
        end
      end
      else if (mcf_valid) begin
        s_axis_tready_next = 1'b0;
        ptr_next           = 0;
        send_mcf_next      = 1'b1;
        mcf_ready_next     = (CYCLE_COUNT == 1) && m_axis_tready_int_early;
      end
    end

    if (send_data_reg) begin
      m_axis_tdata_int   = s_axis_tdata;
      m_axis_tkeep_int   = s_axis_tkeep;
      m_axis_tvalid_int  = 1'b0;
      m_axis_tlast_int   = s_axis_tlast;
      m_axis_tid_int     = s_axis_tid;
      m_axis_tdest_int   = s_axis_tdest;
      m_axis_tuser_int   = s_axis_tuser;
      s_axis_tready_next = m_axis_tready_int_early;
      if (s_axis_tvalid && s_axis_tready) begin
        m_axis_tvalid_int = 1'b1;
        if (s_axis_tlast) begin
          s_axis_tready_next = m_axis_tready_int_early && !tx_pause_req;
          send_data_next     = 1'b0;
          if (mcf_valid) begin
            s_axis_tready_next = 1'b0;
            ptr_next           = 0;
            send_mcf_next      = 1'b1;
            mcf_ready_next     = (CYCLE_COUNT == 1) && m_axis_tready_int_early;
          end
        end
        else begin
          send_data_next = 1'b1;
        end
      end
    end

    if (send_mcf_reg) begin
      mcf_ready_next = (CYCLE_COUNT == 1 || ptr_reg == CYCLE_COUNT - 1) && m_axis_tready_int_early;
      if (m_axis_tready_int_reg) begin
        ptr_next          = ptr_reg + 1;

        m_axis_tvalid_int = 1'b1;
        m_axis_tid_int    = mcf_id;
        m_axis_tdest_int  = mcf_dest;
        m_axis_tuser_int  = mcf_user;

        for (int k = 0; k < 6; k++) begin  // eth_dst: header bytes 0 to 5
          if (ptr_reg == (0 + k) / BYTE_LANES) begin
            m_axis_tdata_int[((0+k)%BYTE_LANES)*8+:8] = mcf_eth_dst[(5-k)*8+:8];
            m_axis_tkeep_int[(0+k)%BYTE_LANES]        = 1'b1;
          end
        end
        for (int k = 0; k < 6; k++) begin  // eth_src: header bytes 6 to 11
          if (ptr_reg == (6 + k) / BYTE_LANES) begin
            m_axis_tdata_int[((6+k)%BYTE_LANES)*8+:8] = mcf_eth_src[(5-k)*8+:8];
            m_axis_tkeep_int[(6+k)%BYTE_LANES]        = 1'b1;
          end
        end
        for (int k = 0; k < 2; k++) begin  // eth_type: header bytes 12 to 13
          if (ptr_reg == (12 + k) / BYTE_LANES) begin
            m_axis_tdata_int[((12+k)%BYTE_LANES)*8+:8] = mcf_eth_type[(1-k)*8+:8];
            m_axis_tkeep_int[(12+k)%BYTE_LANES]        = 1'b1;
          end
        end
        for (int k = 0; k < 2; k++) begin  // opcode: header bytes 14 to 15
          if (ptr_reg == (14 + k) / BYTE_LANES) begin
            m_axis_tdata_int[((14+k)%BYTE_LANES)*8+:8] = mcf_opcode[(1-k)*8+:8];
            m_axis_tkeep_int[(14+k)%BYTE_LANES]        = 1'b1;
          end
        end

        for (int k = 0; k < HDR_SIZE - 16; k = k + 1) begin
          if (ptr_reg == (16 + k) / BYTE_LANES) begin
            if (k < MCF_PARAMS_SIZE) begin
              m_axis_tdata_int[((16+k)%BYTE_LANES)*8+:8] = mcf_params[k*8+:8];
            end
            else begin
              m_axis_tdata_int[((16+k)%BYTE_LANES)*8+:8] = 0;
            end
            m_axis_tkeep_int[(16+k)%BYTE_LANES] = 1'b1;
          end
        end

        if (ptr_reg == (HDR_SIZE - 1) / BYTE_LANES) begin
          s_axis_tready_next = m_axis_tready_int_early && !tx_pause_req;
          mcf_ready_next     = 1'b0;
          m_axis_tlast_int   = 1'b1;
          send_mcf_next      = 1'b0;
          stat_tx_mcf_next   = 1'b1;
        end
        else begin
          mcf_ready_next = (ptr_next == CYCLE_COUNT - 1) && m_axis_tready_int_early;
        end

      end
    end
  end

  always_ff @(posedge clk) begin
    send_data_reg     <= send_data_next;
    send_mcf_reg      <= send_mcf_next;
    ptr_reg           <= ptr_next;

    s_axis_tready_reg <= s_axis_tready_next;
    mcf_ready_reg     <= mcf_ready_next;
    tx_pause_ack_reg  <= tx_pause_ack_next;
    stat_tx_mcf_reg   <= stat_tx_mcf_next;

    if (rst) begin
      send_data_reg     <= 1'b0;
      send_mcf_reg      <= 1'b0;
      ptr_reg           <= 0;
      s_axis_tready_reg <= 1'b0;
      mcf_ready_reg     <= 1'b0;
      tx_pause_ack_reg  <= 1'b0;
      stat_tx_mcf_reg   <= 1'b0;
    end
  end

  // output datapath logic
  logic [DATA_WIDTH-1:0] m_axis_tdata_reg = {DATA_WIDTH{1'b0}};
  logic [KEEP_WIDTH-1:0] m_axis_tkeep_reg = {KEEP_WIDTH{1'b0}};
  logic m_axis_tvalid_reg = 1'b0, m_axis_tvalid_next;
  logic                  m_axis_tlast_reg = 1'b0;
  logic [  ID_WIDTH-1:0] m_axis_tid_reg = {ID_WIDTH{1'b0}};
  logic [DEST_WIDTH-1:0] m_axis_tdest_reg = {DEST_WIDTH{1'b0}};
  logic [USER_WIDTH-1:0] m_axis_tuser_reg = {USER_WIDTH{1'b0}};

  logic [DATA_WIDTH-1:0] temp_m_axis_tdata_reg = {DATA_WIDTH{1'b0}};
  logic [KEEP_WIDTH-1:0] temp_m_axis_tkeep_reg = {KEEP_WIDTH{1'b0}};
  logic temp_m_axis_tvalid_reg = 1'b0, temp_m_axis_tvalid_next;
  logic                  temp_m_axis_tlast_reg = 1'b0;
  logic [  ID_WIDTH-1:0] temp_m_axis_tid_reg = {ID_WIDTH{1'b0}};
  logic [DEST_WIDTH-1:0] temp_m_axis_tdest_reg = {DEST_WIDTH{1'b0}};
  logic [USER_WIDTH-1:0] temp_m_axis_tuser_reg = {USER_WIDTH{1'b0}};

  // datapath control
  logic                  store_axis_int_to_output;
  logic                  store_axis_int_to_temp;
  logic                  store_axis_temp_to_output;

  assign m_axis_tdata = m_axis_tdata_reg;
  assign m_axis_tkeep = KEEP_ENABLE ? m_axis_tkeep_reg : {KEEP_WIDTH{1'b1}};
  assign m_axis_tvalid = m_axis_tvalid_reg;
  assign m_axis_tlast = m_axis_tlast_reg;
  assign m_axis_tid = ID_ENABLE ? m_axis_tid_reg : {ID_WIDTH{1'b0}};
  assign m_axis_tdest = DEST_ENABLE ? m_axis_tdest_reg : {DEST_WIDTH{1'b0}};
  assign m_axis_tuser = USER_ENABLE ? m_axis_tuser_reg : {USER_WIDTH{1'b0}};

  // enable ready input next cycle if output is ready or the temp reg will
  // not be filled on the next cycle (output reg empty or no input)
  assign m_axis_tready_int_early =
      m_axis_tready | (~temp_m_axis_tvalid_reg & (~m_axis_tvalid_reg | ~m_axis_tvalid_int));

  always_comb begin
    // transfer sink ready state to source
    m_axis_tvalid_next        = m_axis_tvalid_reg;
    temp_m_axis_tvalid_next   = temp_m_axis_tvalid_reg;

    store_axis_int_to_output  = 1'b0;
    store_axis_int_to_temp    = 1'b0;
    store_axis_temp_to_output = 1'b0;

    if (m_axis_tready_int_reg) begin
      // input is ready
      if (m_axis_tready || !m_axis_tvalid_reg) begin
        // output is ready or currently not valid, transfer data to output
        m_axis_tvalid_next       = m_axis_tvalid_int;
        store_axis_int_to_output = 1'b1;
      end
      else begin
        // output is not ready, store input in temp
        temp_m_axis_tvalid_next = m_axis_tvalid_int;
        store_axis_int_to_temp  = 1'b1;
      end
    end
    else if (m_axis_tready) begin
      // input is not ready, but output is ready
      m_axis_tvalid_next        = temp_m_axis_tvalid_reg;
      temp_m_axis_tvalid_next   = 1'b0;
      store_axis_temp_to_output = 1'b1;
    end
  end

  always_ff @(posedge clk) begin
    m_axis_tvalid_reg      <= m_axis_tvalid_next;
    m_axis_tready_int_reg  <= m_axis_tready_int_early;
    temp_m_axis_tvalid_reg <= temp_m_axis_tvalid_next;

    // datapath
    if (store_axis_int_to_output) begin
      m_axis_tdata_reg <= m_axis_tdata_int;
      m_axis_tkeep_reg <= m_axis_tkeep_int;
      m_axis_tlast_reg <= m_axis_tlast_int;
      m_axis_tid_reg   <= m_axis_tid_int;
      m_axis_tdest_reg <= m_axis_tdest_int;
      m_axis_tuser_reg <= m_axis_tuser_int;
    end
    else if (store_axis_temp_to_output) begin
      m_axis_tdata_reg <= temp_m_axis_tdata_reg;
      m_axis_tkeep_reg <= temp_m_axis_tkeep_reg;
      m_axis_tlast_reg <= temp_m_axis_tlast_reg;
      m_axis_tid_reg   <= temp_m_axis_tid_reg;
      m_axis_tdest_reg <= temp_m_axis_tdest_reg;
      m_axis_tuser_reg <= temp_m_axis_tuser_reg;
    end

    if (store_axis_int_to_temp) begin
      temp_m_axis_tdata_reg <= m_axis_tdata_int;
      temp_m_axis_tkeep_reg <= m_axis_tkeep_int;
      temp_m_axis_tlast_reg <= m_axis_tlast_int;
      temp_m_axis_tid_reg   <= m_axis_tid_int;
      temp_m_axis_tdest_reg <= m_axis_tdest_int;
      temp_m_axis_tuser_reg <= m_axis_tuser_int;
    end

    if (rst) begin
      m_axis_tvalid_reg      <= 1'b0;
      m_axis_tready_int_reg  <= 1'b0;
      temp_m_axis_tvalid_reg <= 1'b0;
    end
  end

endmodule

`resetall
