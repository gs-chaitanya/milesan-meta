if { [info exists ::env(VERILOG_INPUT)] }    { set VERILOG_INPUT $::env(VERILOG_INPUT) }       else { puts "Please set VERILOG_INPUT environment variable"; exit 1 }
if { [info exists ::env(VERILOG_OUTPUT)] }   { set VERILOG_OUTPUT $::env(VERILOG_OUTPUT) }     else { puts "Please set VERILOG_OUTPUT environment variable"; exit 1 }
if { [info exists ::env(TOP_MODULE)] }       { set TOP_MODULE $::env(TOP_MODULE) }             else { puts "Please set TOP_MODULE environment variable"; exit 1 }

if { [info exists ::env(VERBOSE)]}   {set VERBOSE -verbose}     else { set VERBOSE ""}
if { [info exists ::env(DECOMPOSE_MEMORY)] } { set DECOMPOSE_MEMORY $::env(DECOMPOSE_MEMORY) } else { set DECOMPOSE_MEMORY 0 }
if { [info exists ::env(ASSERT_PROBES_EN)] }      { set ASSERT_PROBES_EN $::env(ASSERT_PROBES_EN) }           else { set ASSERT_PROBES_EN 0 }
if { [info exists ::env(CELLIFT_EN)] }      { set CELLIFT_EN $::env(CELLIFT_EN) }           else { set CELLIFT_EN 0 }

if { [info exists ::env(MUXCOV_EN)]} {
    set MUXCOV_EN $::env(MUXCOV_EN);
    if { [info exists ::env(INST_TOP)]} {set INST_TOP $::env(INST_TOP)} else {puts "Please set INST_TOP variable when MUXCOV_EN is set to specify highest level for mux to be considered."; exit 1}
    if { [info exists ::env(SHALLOW)] }      { set SHALLOW $::env(SHALLOW) }           else { set SHALLOW 0 }
} else {set MUXCOV_EN 0}

if { [info exists ::env(META_RESET)]} {
    set META_RESET $::env(META_RESET);
    if { [info exists ::env(SHALLOW)] }      { set SHALLOW $::env(SHALLOW) }           else { set SHALLOW 0 }
    if { [info exists ::env(TOP_RESET)] }       { set TOP_RESET $::env(TOP_RESET) }             else { puts "Please set TOP_RESET environment variable"; exit 1 }
} else {set META_RESET 0}

if { [info exists ::env(WIRE_PC_TO_TOP)]} {
    set WIRE_PC_TO_TOP $::env(WIRE_PC_TO_TOP);
    if { [info exists ::env(PC_TARGET_MODULE)] } { set PC_TARGET_MODULE $::env(PC_TARGET_MODULE) }  else { puts "Please set PC_TARGET_MODULE environment variable"; exit 1 }
    if { [info exists ::env(PC_TARGET)] } { set PC_TARGET $::env(PC_TARGET) }  else { puts "Please set PC_TARGET environment variable"; exit 1 }
} else {set WIRE_PC_TO_TOP 0}

if {[info exists ::env(CELLIFT_EN)]} {
    if { [info exists ::env(MUL_TO_ADDS)] }      { set MUL_TO_ADDS $::env(MUL_TO_ADDS) }           else { set MUL_TO_ADDS 0 }
    if { [info exists ::env(EXCLUDE_SIGNALS)]}   {set EXCLUDE_SIGNALS $::env(EXCLUDE_SIGNALS)}     else { set EXCLUDE_SIGNALS ""}
} else {set CELLIFT_EN 0}

yosys read_verilog -DSTOP_COND=0 -defer -sv $VERILOG_INPUT 
yosys hierarchy -top $TOP_MODULE -check
yosys proc
yosys opt -purge
yosys pmuxtree


if {$META_RESET == 1} {
    yosys mark_resets $VERBOSE $SHALLOW $TOP_RESET
}

if {$MUXCOV_EN == 1} {
    yosys mux_probes $VERBOSE $SHALLOW $INST_TOP
    yosys port_mux_probes $VERBOSE
}

if {$ASSERT_PROBES_EN == 1} {
    yosys assert_probes $VERBOSE
    yosys port_assert_probes $VERBOSE
}

if {$DECOMPOSE_MEMORY == 1} {
    yosys memory
    yosys proc
    yosys opt -purge
}

if {$WIRE_PC_TO_TOP == 1} { 
    yosys pc_probe $VERBOSE $PC_TARGET_MODULE $PC_TARGET
}

if {$CELLIFT_EN == 1} {
    if {$MUL_TO_ADDS == 1} {
        yosys mul_to_adds
        yosys timestamp mul_to_adds
    }

    yosys opt -purge
    yosys cellift -exclude-signals $EXCLUDE_SIGNALS -imprecise-shl-sshl -imprecise-shr-sshr -verbose
    
    if {$META_RESET == 1} {
        yosys meta_reset_t0 $VERBOSE
    }
}

if {$META_RESET == 1} {
    yosys meta_reset $VERBOSE
}

yosys opt_clean

yosys write_verilog -sv $VERILOG_OUTPUT 


