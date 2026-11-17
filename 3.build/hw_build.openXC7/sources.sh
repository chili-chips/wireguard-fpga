# SPDX-FileCopyrightText: 2026 Chili.CHIPS*ba
#
# SPDX-License-Identifier: BSD-3-Clause
#
# The RTL file lists, one place for run-lint.sh, run-format.sh and run-leq.sh.
# The design is 1.hw/top.filelist, the list Vivado and 4.sim use. Source this
# file, then call a function:
#
#   design_rtl <1.hw> <3.build>   every .sv/.v file of top, in filelist order
#   own_rtl <1.hw> <3.build>      our own RTL: the design's, plus both soc_cpu
#                                 wrappers and eduBOS5, whichever CPU is in;
#                                 what run-format.sh formats and the verible
#                                 phase lints, also our forks of third-party
#                                 RTL: external_lib (Alex Forencich's
#                                 verilog-ethernet and verilog-axis) and
#                                 PicoRV32. Not the PeakRDL-generated CSR.
#   cpu_select <top.filelist> <picorv32|edubos5>
#                                 switch the CPU in a copy of top.filelist: the
#                                 PicoRV32 lines or the eduBOS5 lines (commented
#                                 out there) go in
#   block_rtl <top> <1.hw>        what a block top adds to the design's files
#
# BLOCK_TOPS: the DPE blocks top does not instantiate yet, each a top of its
# own through a wrapper in leq_tops.sv (LEQ_TOP_<top> defined), so that
# run-leq.sh proves them and run-lint.sh lints them

design_rtl() {
  local hw=$1 bld=$2
  sed -e 's/\r$//' -e 's/^[[:space:]]*//' -e 's/[[:space:]]*$//' "$hw/top.filelist" |
    grep -E '^[^#+].*\.s?v$' | sed -e "s|\${HW_SRC}|$hw|" -e "s|\${BLD_DIR}|$bld|"
}

own_rtl() {
  { design_rtl "$1" "$2" | grep -v -e '/csr_build/'
    ls "$1"/ip.cpu/soc_cpu.*.sv "$1"/ip.cpu/cpu.EDUBOS5/*.sv "$1"/ip.cpu/cpu.PICORV32/*.sv
    ls "$1"/external_lib/*/*.sv
    # the DPE blocks top does not instantiate yet (run-leq.sh proves them too)
    ls "$1"/ip.dpe/dpe_wg_encryptor.sv "$1"/ip.dpe/dpe_wg_decryptor.sv "$1"/ip.dpe/dpe_wg_disassembler.sv
    ls "$1"/ip.dpe/dpe_egress_ip_lookup.sv "$1"/ip.dpe/dpe_route_mem.sv
    ls "$1"/ip.dpe/dpe_if_pipeline.sv "$1"/ip.dpe/net_pkg.sv
  } | awk '!seen[$0]++'
}

BLOCK_TOPS="leq_dpe_wg_encryptor leq_dpe_wg_decryptor leq_dpe_egress_ip_lookup leq_dpe_wg_disassembler"

block_rtl() {
  local d=$2
  case $1 in
    leq_dpe_wg_encryptor) echo "$d/ip.dpe/net_pkg.sv $d/ip.dpe/dpe_wg_encryptor.sv $d/ip.dpe/dpe_if_pipeline.sv" ;;
    leq_dpe_wg_decryptor) echo "$d/ip.dpe/net_pkg.sv $d/ip.dpe/dpe_wg_decryptor.sv $d/ip.dpe/dpe_if_pipeline.sv" ;;
    leq_dpe_egress_ip_lookup) echo "$d/ip.dpe/net_pkg.sv $d/ip.dpe/dpe_egress_ip_lookup.sv $d/ip.dpe/dpe_route_mem.sv" ;;
    leq_dpe_wg_disassembler) echo "$d/ip.dpe/net_pkg.sv $d/ip.dpe/dpe_wg_disassembler.sv" ;;
    *) echo "block_rtl: no files for top $1" >&2; return 1 ;;
  esac
}

cpu_select() {
  local p='(ip.cpu/cpu.PICORV32/picorv32.CHILI|ip.cpu/soc_cpu.PICORV32).sv'
  local e='(ip.cpu/cpu.EDUBOS5/edubos5[a-z_]*|ip.cpu/soc_cpu.EDUBOS5).sv'
  case $2 in
    picorv32) sed -i -E -e "s@^#(.*$p)@\1@" -e "s@^([^#].*$e)@#\1@" "$1" ;;
    edubos5)  sed -i -E -e "s@^#(.*$e)@\1@" -e "s@^([^#].*$p)@#\1@" "$1" ;;
    *) echo "CPU must be picorv32 or edubos5, got \"$2\"" >&2; return 1 ;;
  esac
}

# -----------------------------------------------------------------------------
# Project:     WireGuard-FPGA
# Description: NLnet-funded open-source implementation
# Funding:     https://nlnet.nl/project/KlusterLab-Wireguard (2023-12 to 2025-12)
# -----------------------------------------------------------------------------
