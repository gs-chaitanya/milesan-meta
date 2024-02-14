if { [info exists ::env(VERILOG_INPUT)] }    { set VERILOG_INPUT $::env(VERILOG_INPUT) }       else { puts "Please set VERILOG_INPUT environment variable"; exit 1 }
if { [info exists ::env(VERILOG_OUTPUT)] }   { set VERILOG_OUTPUT $::env(VERILOG_OUTPUT) }     else { puts "Please set VERILOG_OUTPUT environment variable"; exit 1 }
if { [info exists ::env(TOML_OUTPUT)] }   { set TOML_OUTPUT $::env(TOML_OUTPUT) }     else { puts "TOML_OUTPUT not set, skipping gen_toml pass";}
if { [info exists ::env(VERBOSE)]}   {set VERBOSE -verbose}     else { set VERBOSE ""}
if { [info exists ::env(SHALLOW)]}   {set SHALLOW -shallow}     else { set SHALLOW ""}
if { [info exists ::env(EXCLUDE_SIGNALS)]}   {set EXCLUDE_SIGNALS $::env(EXCLUDE_SIGNALS)}     else { set EXCLUDE_SIGNALS ""}
if { [info exists ::env(TOP_MODULE)] }       { set TOP_MODULE $::env(TOP_MODULE) }             else { puts "Please set TOP_MODULE environment variable"; exit 1 }
if { [info exists ::env(TOP_RESET)] }       { set TOP_RESET $::env(TOP_RESET) }             else { puts "Please set TOP_RESET environment variable"; exit 1 }
if { [info exists ::env(INSTRUMENTATION)] }  { set INSTRUMENTATION $::env(INSTRUMENTATION) }   else { set INSTRUMENTATION "rfuzz" }
if { [info exists ::env(FUZZTYPE)] }  { set FUZZTYPE $::env(FUZZTYPE) }   else { set FUZZTYPE "bin" }
if { [info exists ::env(DECOMPOSE_MEMORY)] } { set DECOMPOSE_MEMORY $::env(DECOMPOSE_MEMORY) } else { set DECOMPOSE_MEMORY 0 }
if { [info exists ::env(MUL_TO_ADDS)] }      { set MUL_TO_ADDS $::env(MUL_TO_ADDS) }           else { set MUL_TO_ADDS 0 }
if { [info exists ::env(DECOMPOSE_MEMORY)] }    { set DECOMPOSE_MEMORY $::env(DECOMPOSE_MEMORY) }    else { set DECOMPOSE_MEMORY 0 }
if { [info exists ::env(INST_TOP)] }    { set INST_TOP $::env(INST_TOP) }    else { puts "Please set INST_TOP environment variable"; exit 1 }
if { [info exists ::env(WIRE_PC_TO_TOP)]} {
    set WIRE_PC_TO_TOP $::env(WIRE_PC_TO_TOP);
    if { [info exists ::env(PC_TARGET_MODULE)] } { set PC_TARGET_MODULE $::env(PC_TARGET_MODULE) }  else { puts "Please set PC_TARGET_MODULE environment variable"; exit 1 }
    if { [info exists ::env(PC_TARGET)] } { set PC_TARGET $::env(PC_TARGET) }  else { puts "Please set PC_TARGET environment variable"; exit 1 }
    } else {set WIRE_PC_TO_TOP 0}

if { [info exists ::env(ADD_SHADOW_PC_RESET)]} {
    set ADD_SHADOW_PC_RESET $::env(ADD_SHADOW_PC_RESET);
    if { [info exists ::env(PC_TARGET_MODULE)] } { set PC_TARGET_MODULE $::env(PC_TARGET_MODULE) }  else { puts "Please set PC_TARGET_MODULE environment variable"; exit 1 }
    if { [info exists ::env(PC_TARGET_T0)] } { set PC_TARGET_T0 $::env(PC_TARGET_T0) }  else { puts "Please set PC_TARGET_T0 environment variable"; exit 1 }
    } else {set ADD_SHADOW_PC_RESET 0}


yosys read_verilog -DSTOP_COND=0 -sv $VERILOG_INPUT 
yosys hierarchy -top $TOP_MODULE -check
yosys proc
yosys opt -purge
yosys pmuxtree

yosys count_mux
yosys mark_resets $VERBOSE $SHALLOW $TOP_RESET
yosys mux_probes $VERBOSE $SHALLOW $INST_TOP
yosys port_mux_probes $VERBOSE
yosys assert_probes $VERBOSE
yosys port_assert_probes $VERBOSE

if {$DECOMPOSE_MEMORY == 1} {
    yosys memory
    yosys proc
    yosys opt -purge
}

if {$WIRE_PC_TO_TOP == 1} { 
    yosys pc_probe $VERBOSE $PC_TARGET_MODULE $PC_TARGET
}

if {[string equal $INSTRUMENTATION "drfuzz"]} {
    if {$MUL_TO_ADDS == 1} {
        yosys mul_to_adds
        yosys timestamp mul_to_adds
    }

    yosys opt -purge
    yosys cellift -exclude-signals $EXCLUDE_SIGNALS -imprecise-shl-sshl -verbose
    yosys opt -purge
    if {[string equal $FUZZTYPE "bin"]} {
        yosys port_cellift_input_probes $VERBOSE
    }
    # yosys port_cellift_output_probes $VERBOSE
    if {$ADD_SHADOW_PC_RESET == 1} { 
        yosys meta_reset_pc_t0 $VERBOSE $PC_TARGET_MODULE $PC_TARGET_T0
    }
    yosys meta_reset_t0 $VERBOSE

}


if {[string equal $FUZZTYPE "bin"]} {
    yosys port_fuzz_inputs $VERBOSE $EXCLUDE_SIGNALS
}
yosys dffunmap
yosys meta_reset $VERBOSE


yosys opt_clean

if {[info exists ::env(TOML_OUTPUT)]} {
    yosys gen_toml $TOML_OUTPUT
}

yosys write_verilog -sv $VERILOG_OUTPUT 


