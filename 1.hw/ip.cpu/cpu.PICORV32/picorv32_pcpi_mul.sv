// SPDX-FileCopyrightText: 2015 Clifford Wolf
// SPDX-FileCopyrightText: 2026 Chili.CHIPS*ba
//
// SPDX-License-Identifier: MIT

//--------------------------------------------------------------------------
// Improved by Chili.CHIPS (2023/24)
//--------------------------------------------------------------------------

/***************************************************************
 * picorv32_pcpi_mul
 ***************************************************************/

module picorv32_pcpi_mul #(
    parameter int STEPS_AT_ONCE = 1,
    parameter int CARRY_CHAIN   = 4
) (
    input  logic        clk,
    resetn,

    input  logic        pcpi_valid,
    input  logic [31:0] pcpi_insn,
    input  logic [31:0] pcpi_rs1,
    input  logic [31:0] pcpi_rs2,

    output logic        pcpi_wr,
    output logic [31:0] pcpi_rd,
    output logic        pcpi_wait,
    output logic        pcpi_ready
);
  logic  instr_mul, instr_mulh, instr_mulhsu, instr_mulhu;
  logic  instr_any_mul;
  assign instr_any_mul    = |{instr_mul, instr_mulh, instr_mulhsu, instr_mulhu};
  logic  instr_any_mulh;
  assign instr_any_mulh   = |{instr_mulh, instr_mulhsu, instr_mulhu};
  logic  instr_rs1_signed;
  assign instr_rs1_signed = |{instr_mulh, instr_mulhsu};
  logic  instr_rs2_signed;
  assign instr_rs2_signed = |{instr_mulh};

  logic  pcpi_wait_q;
  logic  mul_start;
  assign mul_start = pcpi_wait & ~pcpi_wait_q;

  // an RV32M instruction (MUL, MULH*, DIV*, REM*): OP opcode, funct7 0000001
  logic  insn_is_rv32m;
  assign insn_is_rv32m = (pcpi_insn[6:0] == 7'b0110011) & (pcpi_insn[31:25] == 7'b0000001);

  always_ff @(posedge clk) begin
    instr_mul    <= 0;
    instr_mulh   <= 0;
    instr_mulhsu <= 0;
    instr_mulhu  <= 0;

    if (resetn && pcpi_valid && insn_is_rv32m) begin
      unique case (pcpi_insn[14:12])
        3'b000: instr_mul <= 1;
        3'b001: instr_mulh <= 1;
        3'b010: instr_mulhsu <= 1;
        3'b011: instr_mulhu <= 1;
        default: begin
        end
      endcase
    end

    pcpi_wait   <= instr_any_mul;
    pcpi_wait_q <= pcpi_wait;
  end

  logic [63:0] rs1, rs2, rd, rdx;
  logic [63:0] next_rs1, next_rs2, this_rs2;
  logic [63:0] next_rd, next_rdx, next_rdt;
  logic [6:0] mul_counter;
  logic       mul_waiting;
  logic       mul_finish;

  // carry save accumulator
  always_comb begin
    next_rd  = rd;
    next_rdx = rdx;
    next_rs1 = rs1;
    next_rs2 = rs2;

    for (int i = 0; i < STEPS_AT_ONCE; i = i + 1) begin
      this_rs2 = next_rs1[0] ? next_rs2 : 0;
      if (CARRY_CHAIN == 0) begin
        next_rdt = next_rd ^ next_rdx ^ this_rs2;
        next_rdx = ((next_rd & next_rdx) | (next_rd & this_rs2) | (next_rdx & this_rs2)) << 1;
        next_rd  = next_rdt;
      end
      else begin
        next_rdt = 0;
        for (int j = 0; j < 64; j = j + CARRY_CHAIN) begin
          {next_rdt[j+CARRY_CHAIN-1], next_rd[j +: CARRY_CHAIN]} =
              next_rd[j+:CARRY_CHAIN] + next_rdx[j+:CARRY_CHAIN] + this_rs2[j+:CARRY_CHAIN];
        end
        next_rdx = next_rdt << 1;
      end
      next_rs1 = next_rs1 >> 1;
      next_rs2 = next_rs2 << 1;
    end
  end

  always_ff @(posedge clk) begin
    mul_finish <= 0;
    if (!resetn) begin
      mul_waiting <= 1;
    end
    else if (mul_waiting) begin
      if (instr_rs1_signed) begin
        rs1 <= $signed(pcpi_rs1);
      end
      else begin
        rs1 <= $unsigned(pcpi_rs1);
      end

      if (instr_rs2_signed) begin
        rs2 <= $signed(pcpi_rs2);
      end
      else begin
        rs2 <= $unsigned(pcpi_rs2);
      end

      rd          <= 0;
      rdx         <= 0;
      mul_counter <= (instr_any_mulh ? 63 - STEPS_AT_ONCE : 31 - STEPS_AT_ONCE);
      mul_waiting <= !mul_start;
    end
    else begin
      rd          <= next_rd;
      rdx         <= next_rdx;
      rs1         <= next_rs1;
      rs2         <= next_rs2;

      mul_counter <= mul_counter - STEPS_AT_ONCE;
      if (mul_counter[6]) begin
        mul_finish  <= 1;
        mul_waiting <= 1;
      end
    end
  end

  always_ff @(posedge clk) begin
    pcpi_wr    <= 0;
    pcpi_ready <= 0;

    if (mul_finish && resetn) begin
      pcpi_wr    <= 1;
      pcpi_ready <= 1;
      pcpi_rd    <= instr_any_mulh ? rd >> 32 : rd;
    end
  end

endmodule : picorv32_pcpi_mul
