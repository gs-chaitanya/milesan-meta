# Modelsim script

if { [info exists ::env(MODELSIM_WORKROOT)] } { set MODELSIM_WORKROOT $::env(MODELSIM_WORKROOT)} else { puts "Please set MODELSIM_WORKROOT environment variable"; exit 1 }
if { [info exists ::env(INSTRUMENTATION)] }   { set INSTRUMENTATION $::env(INSTRUMENTATION)}     else { puts "Please set INSTRUMENTATION environment variable"; exit 1 }
if { [info exists ::env(TRACE)] }             { set TRACE $::env(TRACE)}                         else { puts "Please set TRACE environment variable"; exit 1 }
if { [info exists ::env(TOP_SOC)] }           { set TOP_SOC   $::env(TOP_SOC) }                  else { puts "Please set TOP_SOC environment variable"; exit 1 }
if { [info exists ::env(FUZZCOREID)] }        { set FUZZCOREID  $::env(FUZZCOREID) }             else { puts "No FUZZCOREID specified. Defaulting to 0."; set FUZZCOREID 0 }
if { [info exists ::env(VARIANT_ID)] }        { set VARIANT_ID  $::env(VARIANT_ID) }             else { set VARIANT_ID "" }
# Cover flag should be -coverage or empty
if { [info exists ::env(MODELSIM_VSIM_COVERFLAG)] }  { set MODELSIM_VSIM_COVERFLAG  $::env(MODELSIM_VSIM_COVERFLAG) }     else { set MODELSIM_VSIM_COVERFLAG "" }
if { [info exists ::env(MODELSIM_VSIM_COVERPATH)] }  { set MODELSIM_VSIM_COVERPATH  $::env(MODELSIM_VSIM_COVERPATH) }     else { set MODELSIM_VSIM_COVERPATH "" }

set LIB ${MODELSIM_WORKROOT}/${TOP_SOC}${VARIANT_ID}_${FUZZCOREID}/work_${INSTRUMENTATION}_${TRACE}

if { [info exists ::env(VCD_WILDCARD)] } { set VCD_WILDCARD $::env(VCD_WILDCARD) } else { set VCD_WILDCARD /* }
if { [info exists ::env(MODELSIM_NOQUIT)] } { set MODELSIM_NOQUIT $::env(MODELSIM_NOQUIT) } else { set MODELSIM_NOQUIT "0" }
if { [info exists ::env(VCD_REGEX)] } { set VCD_REGEX $::env(VCD_REGEX) } else { set VCD_REGEX "*" }


if { [string equal $TRACE trace_fst] } { 
    set VOPTARGS "-voptargs=+acc"
    set DEBUGDBARG "-debugdb"
    if { [info exists ::env(TRACEFILE)] }    { set TRACEFILE $::env(TRACEFILE) }       else { puts "Please set TRACEFILE environment variable"; exit 1 }
} elseif {[string equal $TRACE trace]} {
    set VOPTARGS "-voptargs=+acc" 
    set DEBUGDBARG "-debugdb"
    if { [info exists ::env(TRACEFILE)] }    { set TRACEFILE $::env(TRACEFILE) }       else { puts "Please set TRACEFILE environment variable"; exit 1 }
} else {
    set VOPTARGS ""
    set DEBUGDBARG ""
}


# vsim -64 -lib $LIB $MODELSIM_VSIM_COVERFLAG  $DEBUGDBARG $VOPTARGS tb_top

if { $TRACE != "trace_fst" && $TRACE != "trace" } {
    vsim -64 -suppress 3009 -suppress 3085 -suppress 3015 -suppress 2718 -suppress 2685 -suppress 2244 -lib $LIB $MODELSIM_VSIM_COVERFLAG tb_top_opt
} else {
    vsim -64 -suppress 3009 -suppress 3085 -suppress 3015 -suppress 2718 -suppress 2685 -suppress 2244 -lib $LIB $MODELSIM_VSIM_COVERFLAG -debugdb -voptargs=+acc tb_top_trace
}
if { [string equal $TRACE trace_fst] } { 
    log -r /*
} elseif { [string equal $TRACE trace] } {
    vcd file $TRACEFILE
    vcd add -r $VCD_REGEX
}

run -a

if { [string equal $MODELSIM_VSIM_COVERFLAG -coverage] } {
    coverage save $MODELSIM_VSIM_COVERPATH
}

if { !([string equal $MODELSIM_NOQUIT 1]) } {
    quit -f
}
