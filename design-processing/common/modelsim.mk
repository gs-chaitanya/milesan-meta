# Copyright 2024 Tobias Kovats, Flavien Solt, ETH Zurich.
# Licensed under the General Public License, Version 3.0, see LICENSE for details.
# SPDX-License-Identifier: GPL-3.0-only

# Make fragment that designs can include for common functionality regarding Modelsim

ifeq "" "$(MILESAN_ENV_SOURCED)"
$(error Please re-source env.sh first, in the meta repo, and run from there, not this repo. See README.md in the meta repo)
endif

ifeq "" "$(MILESAN_META_ROOT)"
$(error Please re-source env.sh first, in the meta repo, and run from there, not this repo. See README.md in the meta repo)
endif

# Requires the env variables
# - MODELSIM_PATH_TO_BUILD_TCL: path to the ModelSim build TCL script
# - TOP_SOC: the top SoC name, for ibex_tiny_soc
# - MILESAN_DIR: the path of the design's milesan/ directory

FUZZCOREID ?= 0
VARIANT_ID ?=
VSIM ?= /usr/local/questa-2023-04/questasim/linux_x86_64/vsim
MODELSIM_TIMEOUT ?= 600
MODELSIM_TIMEOUT_TRACE_EN ?= 6000
MODELSIM_SV_VANILLA = generated/out/vanilla.sv dv/sv/tb_top.sv src/$(TOP_SOC).sv $(MILESAN_DESIGN_PROCESSING_ROOT)/common/src/sram_mem.sv
MODELSIM_SV_DRFUZZ_MEM = generated/out/drfuzz_mem.sv dv/sv/tb_top_taints.sv src/$(TOP_SOC)_drfuzz_mem.sv $(MILESAN_DESIGN_PROCESSING_ROOT)/common/src/ift_sram_mem.sv
MODELSIM_SV_DRFUZZ_MEM_MUXCOV = generated/out/drfuzz_mem_muxcov.sv dv/sv/tb_top_taints_muxcov.sv src/$(TOP_SOC)_drfuzz_mem_muxcov.sv $(MILESAN_DESIGN_PROCESSING_ROOT)/common/src/ift_sram_mem.sv

MODELSIM_SV_PASSTHROUGH = generated/out/passthrough.sv dv/sv/tb_top.sv src/$(TOP_SOC).sv $(MILESAN_DESIGN_PROCESSING_ROOT)/common/src/sram_mem.sv

MODELSIM_WORKDIR = $(MODELSIM_WORKROOT)/$(TOP_SOC)$(VARIANT_ID)_$(FUZZCOREID)

build_vanilla_notrace_modelsim:       $(MODELSIM_PATH_TO_BUILD_TCL) $(MODELSIM_SV_VANILLA)     | $(MODELSIM_WORKDIR) modelsim traces logs
	cd $(MODELSIM_WORKDIR); MILESAN_DIR=$(MILESAN_DIR) TRACE=notrace   INSTRUMENTATION=vanilla MILESAN_META_COMMON=$(MILESAN_DESIGN_PROCESSING_ROOT)/common     MODELSIM_INCDIRSTR=$(MODELSIM_INCDIRSTR) MODELSIM_VLOG_COVERFLAG=$(MODELSIM_VLOG_COVERFLAG) TOP_SOC=$(TOP_SOC) VARIANT_ID=$(VARIANT_ID) SV_TOP=src/$(TOP_SOC).sv        SV_MEM=$(MILESAN_DESIGN_PROCESSING_ROOT)/common/src/sram_mem.sv SV_TB=dv/sv/tb_top.sv CURR_OPENTITAN_ROOT=$(CURR_OPENTITAN_ROOT) $(MODELSIM_VERSION) $(VSIM) -64 -c -do $<

build_vanilla_trace_modelsim:         $(MODELSIM_PATH_TO_BUILD_TCL) $(MODELSIM_SV_VANILLA)     | $(MODELSIM_WORKDIR) modelsim traces logs
	cd $(MODELSIM_WORKDIR); MILESAN_DIR=$(MILESAN_DIR) TRACE=trace     INSTRUMENTATION=vanilla MILESAN_META_COMMON=$(MILESAN_DESIGN_PROCESSING_ROOT)/common     MODELSIM_INCDIRSTR=$(MODELSIM_INCDIRSTR) MODELSIM_VLOG_COVERFLAG=$(MODELSIM_VLOG_COVERFLAG) TOP_SOC=$(TOP_SOC) VARIANT_ID=$(VARIANT_ID) SV_TOP=src/$(TOP_SOC).sv        SV_MEM=$(MILESAN_DESIGN_PROCESSING_ROOT)/common/src/sram_mem.sv SV_TB=dv/sv/tb_top.sv CURR_OPENTITAN_ROOT=$(CURR_OPENTITAN_ROOT) $(MODELSIM_VERSION) $(VSIM) -64 -c -do $<

build_vanilla_trace_fst_modelsim:     $(MODELSIM_PATH_TO_BUILD_TCL) $(MODELSIM_SV_VANILLA)     | $(MODELSIM_WORKDIR) modelsim traces logs
	cd $(MODELSIM_WORKDIR); MILESAN_DIR=$(MILESAN_DIR) TRACE=trace_fst INSTRUMENTATION=vanilla MILESAN_META_COMMON=$(MILESAN_DESIGN_PROCESSING_ROOT)/common     MODELSIM_INCDIRSTR=$(MODELSIM_INCDIRSTR) MODELSIM_VLOG_COVERFLAG=$(MODELSIM_VLOG_COVERFLAG) TOP_SOC=$(TOP_SOC) VARIANT_ID=$(VARIANT_ID) SV_TOP=src/$(TOP_SOC).sv        SV_MEM=$(MILESAN_DESIGN_PROCESSING_ROOT)/common/src/sram_mem.sv SV_TB=dv/sv/tb_top.sv CURR_OPENTITAN_ROOT=$(CURR_OPENTITAN_ROOT) $(MODELSIM_VERSION) $(VSIM) -64 -c -do $<


build_drfuzz_mem_trace_modelsim:         $(MODELSIM_PATH_TO_BUILD_TCL) $(MODELSIM_SV_DRFUZZ_MEM)     | $(MODELSIM_WORKDIR) modelsim traces logs
	cd $(MODELSIM_WORKDIR); MILESAN_DIR=$(MILESAN_DIR) TRACE=trace     INSTRUMENTATION=drfuzz_mem MILESAN_META_COMMON=$(MILESAN_DESIGN_PROCESSING_ROOT)/common     MODELSIM_INCDIRSTR=$(MODELSIM_INCDIRSTR) MODELSIM_VLOG_COVERFLAG=$(MODELSIM_VLOG_COVERFLAG) TOP_SOC=$(TOP_SOC) VARIANT_ID=$(VARIANT_ID) SV_TOP=src/$(TOP_SOC)_drfuzz_mem.sv        SV_MEM=$(MILESAN_DESIGN_PROCESSING_ROOT)/common/src/ift_sram_mem.sv SV_TB=dv/sv/tb_top_taints.sv CURR_OPENTITAN_ROOT=$(CURR_OPENTITAN_ROOT) $(MODELSIM_VERSION) $(VSIM) -64 -c -do $<

build_drfuzz_mem_notrace_modelsim:         $(MODELSIM_PATH_TO_BUILD_TCL) $(MODELSIM_SV_DRFUZZ_MEM)     | $(MODELSIM_WORKDIR) modelsim traces logs
	cd $(MODELSIM_WORKDIR); MILESAN_DIR=$(MILESAN_DIR) TRACE=notrace     INSTRUMENTATION=drfuzz_mem MILESAN_META_COMMON=$(MILESAN_DESIGN_PROCESSING_ROOT)/common     MODELSIM_INCDIRSTR=$(MODELSIM_INCDIRSTR) MODELSIM_VLOG_COVERFLAG=$(MODELSIM_VLOG_COVERFLAG) TOP_SOC=$(TOP_SOC) VARIANT_ID=$(VARIANT_ID) SV_TOP=src/$(TOP_SOC)_drfuzz_mem.sv        SV_MEM=$(MILESAN_DESIGN_PROCESSING_ROOT)/common/src/ift_sram_mem.sv SV_TB=dv/sv/tb_top_taints.sv CURR_OPENTITAN_ROOT=$(CURR_OPENTITAN_ROOT) $(MODELSIM_VERSION) $(VSIM) -64 -c -do $<

build_drfuzz_mem_muxcov_notrace_modelsim:         $(MODELSIM_PATH_TO_BUILD_TCL) $(MODELSIM_SV_DRFUZZ_MEM_MUXCOV)     | $(MODELSIM_WORKDIR) modelsim traces logs
	cd $(MODELSIM_WORKDIR); MILESAN_DIR=$(MILESAN_DIR) TRACE=notrace     INSTRUMENTATION=drfuzz_mem_muxcov MILESAN_META_COMMON=$(MILESAN_DESIGN_PROCESSING_ROOT)/common     MODELSIM_INCDIRSTR=$(MODELSIM_INCDIRSTR) MODELSIM_VLOG_COVERFLAG=$(MODELSIM_VLOG_COVERFLAG) TOP_SOC=$(TOP_SOC) VARIANT_ID=$(VARIANT_ID) SV_TOP=src/$(TOP_SOC)_drfuzz_mem_muxcov.sv        SV_MEM=$(MILESAN_DESIGN_PROCESSING_ROOT)/common/src/ift_sram_mem.sv SV_TB=dv/sv/tb_top_taints_muxcov.sv CURR_OPENTITAN_ROOT=$(CURR_OPENTITAN_ROOT) $(MODELSIM_VERSION) $(VSIM) -64 -c -do $<


build_passthrough_notrace_modelsim:         $(MODELSIM_PATH_TO_BUILD_TCL) $(MODELSIM_SV_PASSTHROUGH)     | $(MODELSIM_WORKDIR) modelsim traces logs
	cd $(MODELSIM_WORKDIR); MILESAN_DIR=$(MILESAN_DIR) TRACE=notrace     INSTRUMENTATION=passthrough MILESAN_META_COMMON=$(MILESAN_DESIGN_PROCESSING_ROOT)/common     MODELSIM_INCDIRSTR=$(MODELSIM_INCDIRSTR) MODELSIM_VLOG_COVERFLAG=$(MODELSIM_VLOG_COVERFLAG) TOP_SOC=$(TOP_SOC) VARIANT_ID=$(VARIANT_ID) SV_TOP=src/$(TOP_SOC).sv        SV_MEM=$(MILESAN_DESIGN_PROCESSING_ROOT)/common/src/sram_mem.sv SV_TB=dv/sv/tb_top.sv CURR_OPENTITAN_ROOT=$(CURR_OPENTITAN_ROOT) $(MODELSIM_VERSION) $(VSIM) -64 -c -do $<

build_passthrough_trace_modelsim:         $(MODELSIM_PATH_TO_BUILD_TCL) $(MODELSIM_SV_PASSTHROUGH)     | $(MODELSIM_WORKDIR) modelsim traces logs
	cd $(MODELSIM_WORKDIR); MILESAN_DIR=$(MILESAN_DIR) TRACE=trace     INSTRUMENTATION=passthrough MILESAN_META_COMMON=$(MILESAN_DESIGN_PROCESSING_ROOT)/common     MODELSIM_INCDIRSTR=$(MODELSIM_INCDIRSTR) MODELSIM_VLOG_COVERFLAG=$(MODELSIM_VLOG_COVERFLAG) TOP_SOC=$(TOP_SOC) VARIANT_ID=$(VARIANT_ID) SV_TOP=src/$(TOP_SOC).sv        SV_MEM=$(MILESAN_DESIGN_PROCESSING_ROOT)/common/src/sram_mem.sv SV_TB=dv/sv/tb_top.sv CURR_OPENTITAN_ROOT=$(CURR_OPENTITAN_ROOT) $(MODELSIM_VERSION) $(VSIM) -64 -c -do $<


RERUN_MODELSIM_TARGETS_NOTRACE   = rerun_vanilla_notrace_modelsim rerun_drfuzz_mem_notrace_modelsim rerun_drfuzz_mem_muxcov_notrace_modelsim rerun_passthrough_notrace_modelsim
RERUN_MODELSIM_TARGETS_TRACE     = rerun_vanilla_trace_modelsim rerun_drfuzz_mem_trace_modelsim rerun_passthrough_trace_modelsim
RERUN_MODELSIM_TARGETS_TRACE_FST = rerun_vanilla_trace_fst_modelsim
$(RERUN_MODELSIM_TARGETS_NOTRACE):   rerun_%_notrace_modelsim:   $(MILESAN_DESIGN_PROCESSING_ROOT)/common/modelsim/modelsim_run.tcl | $(MODELSIM_WORKDIR) modelsim traces logs
	cd $(MODELSIM_WORKDIR); TOP_SOC=$(TOP_SOC) MILESAN_DIR=$(MILESAN_DIR) VARIANT_ID=$(VARIANT_ID) TRACE=notrace   INSTRUMENTATION=$* TRACEFILE=$(TRACEFILE) MODELSIM_VSIM_COVERFLAG=$(MODELSIM_VSIM_COVERFLAG) MODELSIM_VSIM_COVERPATH=$(MODELSIM_VSIM_COVERPATH) $(MODELSIM_VERSION) timeout $(MODELSIM_TIMEOUT) $(VSIM) -64 -c -do $<
$(RERUN_MODELSIM_TARGETS_TRACE):     rerun_%_trace_modelsim:     $(MILESAN_DESIGN_PROCESSING_ROOT)/common/modelsim/modelsim_run.tcl | $(MODELSIM_WORKDIR) modelsim traces logs
	cd $(MODELSIM_WORKDIR); TOP_SOC=$(TOP_SOC) MILESAN_DIR=$(MILESAN_DIR) VARIANT_ID=$(VARIANT_ID) TRACE=trace     INSTRUMENTATION=$* TRACEFILE=$(TRACEFILE) VCD_REGEX=$(VCD_REGEX) MODELSIM_VSIM_COVERFLAG=$(MODELSIM_VSIM_COVERFLAG) MODELSIM_VSIM_COVERPATH=$(MODELSIM_VSIM_COVERPATH) $(MODELSIM_VERSION) timeout $(MODELSIM_TIMEOUT_TRACE_EN) $(VSIM)  -64 -vopt -c -do $<
$(RERUN_MODELSIM_TARGETS_TRACE_FST): rerun_%_trace_fst_modelsim: $(MILESAN_DESIGN_PROCESSING_ROOT)/common/modelsim/modelsim_run.tcl | $(MODELSIM_WORKDIR) modelsim traces logs
	cd $(MODELSIM_WORKDIR); TOP_SOC=$(TOP_SOC) MILESAN_DIR=$(MILESAN_DIR) VARIANT_ID=$(VARIANT_ID) TRACE=trace_fst INSTRUMENTATION=$* TRACEFILE=$(TRACEFILE) MODELSIM_NOQUIT=1 MODELSIM_VSIM_COVERFLAG=$(MODELSIM_VSIM_COVERFLAG) MODELSIM_VSIM_COVERPATH=$(MODELSIM_VSIM_COVERPATH) timeout $(MODELSIM_TIMEOUT_TRACE_EN) $(VSIM) -64 -do $<

$(MODELSIM_WORKDIR):
	mkdir -p $@
