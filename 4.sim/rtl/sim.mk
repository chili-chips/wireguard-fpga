# SPDX-FileCopyrightText: 2026 Chili.CHIPS
#
# SPDX-License-Identifier: BSD-3-Clause

#==========================================================================
# Shared rules of the block-level benches. A bench Makefile sets
#   VFLAGS  its Verilator warning options
#   SRC_F   its file lists (paths, read with -f)
#   SRC     its other sources, tb.sv last
# then includes this file. SIM picks the simulator:
#   make                  Verilator (default)
#   make SIM=icarus       Icarus Verilog (iverilog -g2012, vvp)
#   make SIM=janushdl     JanusHDL (jhdl 0.17 or later)
# Each one writes output/sim.log and output/wave.fst. Timescale 1ns/1ns:
# no `timescale in our HDL, the command line gives it.
#==========================================================================

SHELL   := /bin/bash
.SHELLFLAGS := -o pipefail -c
SIM     ?= verilator
TB_NAME ?= tb
BLD_DIR ?= $(CURDIR)/../../../3.build
HW_SRC  ?= $(CURDIR)/../../../1.hw
SIM_SRC ?= $(CURDIR)/../../../4.sim
export BLD_DIR HW_SRC SIM_SRC TB_NAME

# The file lists with their variables expanded, for Icarus and JanusHDL
EXPAND   = sed -e 's|$${HW_SRC}|$(HW_SRC)|g' -e 's|$${BLD_DIR}|$(BLD_DIR)|g' \
               -e 's|$${SIM_SRC}|$(SIM_SRC)|g'
SRC_ABS  = $(abspath $(SRC))

# A bench with a scoreboard prints RESULT: PASS or RESULT: FAIL; FAIL fails
# the make. A bench without one passes when its simulator ends without error.
CHECK    = @! grep -q "RESULT: FAIL" output/sim.log

.PHONY: all clean unpack compile sim wave wave-alt
all: clean sim

clean:
	rm -rf output

output/files.f: $(SRC_F)
	@mkdir -p output
	@for f in $(SRC_F); do $(EXPAND) $$f; done > $@

# A generated core is kept gzip'd (3.build/pypeline_build/soc/*.v.gz): unpack each
# .v the file lists name that has a newer .v.gz next to it
unpack:
	@for f in $$(for l in $(SRC_F); do $(EXPAND) $$l; done | grep -E '\.v$$'); do \
	  if [ -f "$$f.gz" ] && [ ! "$$f" -nt "$$f.gz" ]; then gunzip -c "$$f.gz" > "$$f"; fi; \
	done

#------------------------
ifeq ($(SIM),verilator)

compile: unpack
	verilator $(VFLAGS) --cc --timing --trace-fst --trace-structs \
		--timescale 1ns/1ns --exe versimSV.cpp --Mdir ./output \
		../waivers.vlt +define+SIM_ONLY \
		$(addprefix -f ,$(SRC_F)) $(SRC) --top-module $(TB_NAME)

sim: compile
	cd output && make -f V$(TB_NAME).mk V$(TB_NAME) && ./V$(TB_NAME) | tee sim.log
	$(CHECK)

#------------------------
else ifeq ($(SIM),icarus)

compile: unpack output/files.f
	echo '+timescale+1ns/1ns' > output/icarus.cmd
	iverilog -g2012 -DSIM_ONLY -o output/$(TB_NAME).vvp \
		-s $(TB_NAME) -s sim_dump -c output/icarus.cmd -c output/files.f \
		$(SRC) ../sim_dump.sv

sim: compile
	cd output; vvp -n $(TB_NAME).vvp -fst | tee sim.log
	$(CHECK)

#------------------------
# SYNTHESIS leaves out the immediate assertions of the PeakRDL csr.sv,
# which JanusHDL 0.17 does not parse
else ifeq ($(SIM),janushdl)

compile: unpack output/files.f
	jhdl --elaborate-only --top $(TB_NAME) +define+SIM_ONLY +define+SYNTHESIS \
		-f output/files.f $(SRC)

sim: unpack output/files.f
	cd output; jhdl --top $(TB_NAME) +define+SIM_ONLY +define+SYNTHESIS \
		-f files.f $(SRC_ABS) --fst wave.fst | tee sim.log
	$(CHECK)

#------------------------
else
  $(error SIM must be verilator, icarus or janushdl (got "$(SIM)"))
endif

#------------------------
wave:
	cd output; \
	gtkwave --saveonexit --slider-zoom --logfile sim.log --dump wave.fst &

wave-alt:
	cd output; \
	surfer.exe -s ../wave.surfer.ron wave.fst &

# -----------------------------------------------------------------------------
# Project:     WireGuard-FPGA
# Description: NLnet-funded open-source implementation
# Funding:     https://nlnet.nl/project/KlusterLab-Wireguard (2023-12 to 2025-12)
# -----------------------------------------------------------------------------
