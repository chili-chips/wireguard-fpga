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
//   DPE multiplexer: round robin over the input ports (from_port, indexed
//   by source address: CPU, then Ethernet 1 to 4), a whole packet at a time.
//   A port is visited (R) and, when it has a beat, its packet is sent (S)
//   to its tlast. tuser.src is the port's address. pause: stop between
//   packets; idle: stopped, and the output holds nothing
//==========================================================================

module dpe_mux
  import dpe_pkg::*;
(
    input  logic  pause,
    output logic  idle,

    dpe_if.s_axis from_port[DPE_PORTS],
    dpe_if.m_axis to_dpe
);

  typedef logic [$clog2(DPE_PORTS)-1:0] port_t;

  function automatic port_t next_port(port_t p);
    return (p == port_t'(DPE_PORTS - 1)) ? '0 : p + port_t'(1);
  endfunction

  // each input, indexable by the port the FSM serves
  logic [DPE_PORTS-1:0] in_valid, in_last, in_ready;
  dpe_data_t  in_data[DPE_PORTS];
  dpe_keep_t  in_keep[DPE_PORTS];
  dpe_tuser_t in_user[DPE_PORTS];

  for (genvar p = 0; p < DPE_PORTS; p++) begin : g_in
    assign in_valid[p]         = from_port[p].tvalid;
    assign in_last[p]          = from_port[p].tlast;
    assign in_data[p]          = from_port[p].tdata;
    assign in_keep[p]          = from_port[p].tkeep;
    assign in_user[p]          = from_port[p].tuser;
    assign from_port[p].tready = in_ready[p];
  end

  typedef enum logic [1:0] {
    IDLE,
    VISIT,  // R: is there a packet on port?
    SEND    // S: its beats, to its tlast
  } phase_t;

  phase_t phase, phase_next;
  port_t port, port_next;

  dpe_if to_dpe_sbuff (
      .clk (to_dpe.clk),
      .rst (to_dpe.rst)
  );

  // FSM registers
  always_ff @(posedge to_dpe.clk) begin
    if (to_dpe.rst) begin
      phase <= IDLE;
      port  <= '0;
    end
    else begin
      phase <= phase_next;
      port  <= port_next;
    end
  end

  // a beat of port's goes out this clock
  logic  beat;
  assign beat = in_valid[port] & to_dpe_sbuff.tready;

  // FSM transition logic. After a packet, or a visit with nothing to send,
  // the next port; pause stops it there (and a restart begins at port 0)
  always_comb begin
    phase_next = phase;
    port_next  = port;

    unique case (phase)
      IDLE: begin
        if (!pause) begin
          phase_next = VISIT;
          port_next  = '0;
        end
      end

      VISIT: begin
        if (beat) begin
          // a one-beat packet ends here: on to the next port
          if (!in_last[port]) begin
            phase_next = SEND;
          end
          else if (pause) begin
            phase_next = IDLE;
          end
          else begin
            port_next = next_port(port);
          end
        end
        else if (pause) begin
          phase_next = IDLE;
        end
        else if (!in_valid[port] && to_dpe_sbuff.tready) begin
          port_next = next_port(port);  // nothing to send
        end
      end

      SEND: begin
        if (beat && in_last[port]) begin
          if (pause) begin
            phase_next = IDLE;
          end
          else begin
            phase_next = VISIT;
            port_next  = next_port(port);
          end
        end
      end

      default: phase_next = phase;
    endcase
  end

  // Outputs logic: the served port's beats, stamped with its address
  always_comb begin
    idle                = (phase == IDLE) & ~to_dpe.tvalid;
    in_ready            = '0;
    to_dpe_sbuff.tvalid = 1'b0;
    to_dpe_sbuff.tdata  = '0;
    to_dpe_sbuff.tlast  = 1'b0;
    to_dpe_sbuff.tkeep  = '0;
    to_dpe_sbuff.tuser  = '0;
    to_dpe_sbuff.tid    = '0;  // no peer yet: the lookup sets it

    if (phase != IDLE) begin
      to_dpe_sbuff.tvalid    = in_valid[port];
      to_dpe_sbuff.tdata     = in_data[port];
      to_dpe_sbuff.tlast     = in_last[port];
      to_dpe_sbuff.tkeep     = in_keep[port];
      to_dpe_sbuff.tuser     = in_user[port];
      to_dpe_sbuff.tuser.src = dpe_addr_t'(port);
      in_ready[port]         = to_dpe_sbuff.tready;
    end
  end

  // Skid buffer
  dpe_if_skid_buffer u_dpe_if_skid_buffer_to_dpe (
      .inp  (to_dpe_sbuff),
      .outp (to_dpe)
  );
endmodule

// -----------------------------------------------------------------------------
// Project:     WireGuard-FPGA
// Description: NLnet-funded open-source implementation
// Funding:     https://nlnet.nl/project/KlusterLab-Wireguard (2023-12 to 2025-12)
// -----------------------------------------------------------------------------
