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
//   CPU FIFOs
//==========================================================================

module cpu_fifo
  import csr_pkg::*;
  import dpe_pkg::*;
(
    input  csr__out_t          from_csr,
    output csr__cpu_fifo__in_t to_csr,
    dpe_if.s_axis              to_cpu,
    dpe_if.m_axis              from_cpu
);
  // The CSR side of the two FIFOs, as dpe_if: to_cpu -> tx_fifo -> csr_tx -> CSR,
  // CSR -> csr_rx -> rx_fifo -> from_cpu
  dpe_if csr_tx (
      .clk (to_cpu.clk),
      .rst (to_cpu.rst)
  );
  dpe_if csr_rx (
      .clk (to_cpu.clk),
      .rst (to_cpu.rst)
  );

  assign {
    to_csr.tx.data_127_96.tdata.next,
    to_csr.tx.data_95_64.tdata.next,
    to_csr.tx.data_63_32.tdata.next,
    to_csr.tx.data_31_0.tdata.next
  } = csr_tx.tdata;
  assign to_csr.tx.control.tkeep.next = csr_tx.tkeep;
  assign to_csr.tx.status.tvalid.next = csr_tx.tvalid;
  assign csr_tx.tready = from_csr.cpu_fifo.tx.trigger.tready.value;
  assign to_csr.tx.control.tlast.next = csr_tx.tlast;
  assign to_csr.tx.control.tuser_bypass_all.next = csr_tx.tuser.bypass_all;
  assign to_csr.tx.control.tuser_bypass_stage.next = csr_tx.tuser.bypass_stage;
  assign to_csr.tx.control.tuser_src.next = csr_tx.tuser.src;
  assign to_csr.tx.control.tuser_dst.next = csr_tx.tuser.dst;

  assign csr_rx.tdata = {
    from_csr.cpu_fifo.rx.data_127_96.tdata.value,
    from_csr.cpu_fifo.rx.data_95_64.tdata.value,
    from_csr.cpu_fifo.rx.data_63_32.tdata.value,
    from_csr.cpu_fifo.rx.data_31_0.tdata.value
  };
  assign csr_rx.tkeep = from_csr.cpu_fifo.rx.control.tkeep.value;
  assign csr_rx.tvalid = from_csr.cpu_fifo.rx.trigger.tvalid.value;
  assign to_csr.rx.status.tready.next = csr_rx.tready;
  assign csr_rx.tlast = from_csr.cpu_fifo.rx.control.tlast.value;
  assign csr_rx.tuser = '{
          bypass_all: from_csr.cpu_fifo.rx.control.tuser_bypass_all.value,
          bypass_stage: from_csr.cpu_fifo.rx.control.tuser_bypass_stage.value,
          src: dpe_addr_t'(from_csr.cpu_fifo.rx.control.tuser_src.value),
          dst: dpe_addr_t'(from_csr.cpu_fifo.rx.control.tuser_dst.value)
      };
  assign csr_rx.tid = '0;  // ID_ENABLE is 0

  axis_fifo #(
      .DEPTH          (4096),
      .FRAME_FIFO     (1),
      .DROP_WHEN_FULL (1),
      .ID_ENABLE      (0)      // the CSR has no tid
  ) tx_fifo (
      .s_axis              (to_cpu),
      .m_axis              (csr_tx),
      .pause_req           (1'b0),
      .pause_ack           (  /*LINT:OK*/),  // PAUSE_ENABLE is 0
      .status_depth        (  /*LINT:OK*/),  // FIFO status not monitored
      .status_depth_commit (  /*LINT:OK*/),  // FIFO status not monitored
      .status_overflow     (  /*LINT:OK*/),  // FIFO status not monitored
      .status_bad_frame    (  /*LINT:OK*/),  // FIFO status not monitored
      .status_good_frame   (  /*LINT:OK*/)   // FIFO status not monitored
  );

  axis_fifo #(
      .DEPTH          (4096),
      .FRAME_FIFO     (1),
      .DROP_WHEN_FULL (1),
      .ID_ENABLE      (0)      // the CSR has no tid
  ) rx_fifo (
      .s_axis              (csr_rx),
      .m_axis              (from_cpu),
      .pause_req           (1'b0),
      .pause_ack           (  /*LINT:OK*/),  // PAUSE_ENABLE is 0
      .status_depth        (  /*LINT:OK*/),  // FIFO status not monitored
      .status_depth_commit (  /*LINT:OK*/),  // FIFO status not monitored
      .status_overflow     (  /*LINT:OK*/),  // FIFO status not monitored
      .status_bad_frame    (  /*LINT:OK*/),  // FIFO status not monitored
      .status_good_frame   (  /*LINT:OK*/)   // FIFO status not monitored
  );
endmodule
