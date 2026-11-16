// SPDX-FileCopyrightText: 2026 Chili.CHIPS
//
// SPDX-License-Identifier: BSD-3-Clause

/**
 * @file main.cpp
 * @brief Cycles per instruction class on the RTL CPU in this SOC, for the
 *        rv32 ISS timing tables (4.sim/models/rv32/usercode/
 *        rv32_timing_config.h): linear, jump, taken branch, load, store.
 *        Each class runs as N back-to-back instructions between two
 *        csr.cycle reads; an empty block gives the read overhead. Prints
 *        total cycles x 100 / N per class on the UART, and keeps the raw
 *        counts in DMEM at RESULT for the test bench.
 *
 *  cd 3.build && make -f MakefileSW SW_MAIN='$(SW_TESTS)/iss_timing' sw_all
 *  cd 4.sim   && make -f MakefileVProc.mk CPU=rtl run
 */

#include <stdint.h>
#include "csr_regs.h"
#include "uart.h"

#define N       64                                  // instructions per block
#define RESULT  ((volatile uint32_t*)0x1000F000u)   // [0] magic, then raw counts
#define MAGIC   0x7111E500u
#define SCRATCH ((volatile uint32_t*)0x10009000u)   // load/store target

#define STR2(x) #x
#define STR(x)  STR2(x)

// One measurement: csr.cycle before and after the block, inline (no call)
#define MEASURE(out, block)                                         \
   do {                                                             \
      uint32_t t0 = CSR_REG32(cycle);                               \
      __asm__ volatile(block ::: "t0", "t1", "memory");             \
      uint32_t t1 = CSR_REG32(cycle);                               \
      (out) = t1 - t0;                                              \
   } while (0)

static void report(const char* name, uint32_t raw, uint32_t empty)
{
   uint32_t x100 = (raw - empty) * 100 / N;
   uart_send(name);
   uart_send(": ");
   uart_send_dec(x100 / 100);
   uart_send(".");
   if (x100 % 100 < 10) uart_send("0");
   uart_send_dec(x100 % 100);
   uart_send(" cycles\r\n");
}

int main(void)
{
   uint32_t empty, linear, jump, branch, load, store;
   uint32_t base = (uint32_t)(uintptr_t)SCRATCH;

   RESULT[0] = MAGIC;
   SCRATCH[0] = 0;

   // each block twice: the first run warms nothing (no caches), but keeps
   // the second run's measurement free of first-pass effects
   for (int pass = 0; pass < 2; pass++) {
      MEASURE(empty,  "");
      MEASURE(linear, ".rept " STR(N) "\n addi t0, t0, 1\n .endr");
      MEASURE(jump,   ".rept " STR(N) "\n jal zero, 1f\n 1:\n .endr");
      MEASURE(branch, ".rept " STR(N) "\n beq zero, zero, 1f\n 1:\n .endr");
      {
         uint32_t t0 = CSR_REG32(cycle);
         __asm__ volatile(".rept " STR(N) "\n lw t0, 0(%0)\n .endr" :: "r"(base) : "t0", "memory");
         uint32_t t1 = CSR_REG32(cycle);
         load = t1 - t0;
      }
      {
         uint32_t t0 = CSR_REG32(cycle);
         __asm__ volatile(".rept " STR(N) "\n sw zero, 0(%0)\n .endr" :: "r"(base) : "memory");
         uint32_t t1 = CSR_REG32(cycle);
         store = t1 - t0;
      }
   }

   RESULT[1] = empty;
   RESULT[2] = linear;
   RESULT[3] = jump;
   RESULT[4] = branch;
   RESULT[5] = load;
   RESULT[6] = store;

   uart_send("\r\nISS timing, cycles per instruction (x" STR(N) " blocks):\r\n");
   report("linear", linear, empty);
   report("jump  ", jump,   empty);
   report("branch", branch, empty);
   report("load  ", load,   empty);
   report("store ", store,  empty);
   uart_send("ISS timing done\r\n");

   for (;;) {}
   return 0;
}
