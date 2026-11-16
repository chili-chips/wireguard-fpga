#!/usr/bin/bash

# SPDX-FileCopyrightText: 2024 Simon Southwell
#
# SPDX-License-Identifier: GPL-3.0-or-later

# usage: rv_asm.sh [file.s]   (default main.s) -> main.bin, main.list
FNAME=${1:-main.s}

ONAME=main
STARTADDR=0
DATAADDR=1000
TESTDIR=.

# RISCV_PREFIX: the toolchain prefix, else riscv64-unknown-elf- (as MakefileSW;
# the xPack toolchain is riscv-none-elf-)
PREFIX=${RISCV_PREFIX:-riscv64-unknown-elf-}

${PREFIX}as -fpic -march=rv32imafdc -aghlms=$TESTDIR/$ONAME.list -o $TESTDIR/$ONAME.o $TESTDIR/$FNAME
${PREFIX}ld $TESTDIR/$ONAME.o -Ttext $STARTADDR -Tdata $DATAADDR -melf32lriscv -o $ONAME.bin
