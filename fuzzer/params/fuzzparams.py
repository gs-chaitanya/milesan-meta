# Copyright 2023 Flavien Solt, ETH Zurich.
# Licensed under the General Public License, Version 3.0, see LICENSE for details.
# SPDX-License-Identifier: GPL-3.0-only

from enum import IntEnum, auto
import numpy as np
import os 

##
# MMU
##
USE_MMU = False

##
# RVC
##
USE_COMPRESSED = False
COMPRESS_INSTRUCTION = 1

FENCE_CF_INSTR = False

# assert not (USE_MMU and USE_COMPRESSED)

if "USE_MMU" in os.environ:
    USE_MMU = int(os.environ["USE_MMU"]) == 1
    print(f"Setting USE_MMU = {USE_MMU} from env vars.")

if "USE_COMPRESSED" in os.environ:
    USE_COMPRESSED = int(os.environ["USE_COMPRESSED"]) == 1
    print(f"Setting USE_COMPRESSED = {USE_COMPRESSED} from env vars.")

assert not (USE_COMPRESSED and USE_MMU), "This does not work yet."

MAX_NUM_LAYOUTS = 5
PROBA_ENTANGLE_LAYOUT = 0
MAX_NUM_INSTR_IN_PRV = 100
MIN_NUM_INSTR_IN_PRV = 20
MAX_NUM_INSTR_IN_LAYOUT = 100
MIN_NUM_INSTR_IN_LAYOUT = 20
PROBA_NEW_SATP_NOT_USED = 0.01
PROBA_NEW_SATP_XEPC_POP = 0.0001
PROBA_NEW_SATP_STVEC_POP = 0.1
PROBA_SAME_BASE_PT = 0.5
REGFSM_BIAS = 0.1
ALLOC_PAGE_PER_PT = True

###
# Basic blocks
###

BLOCK_HEADER_RANDOM_DATA_BYTES = 12
RANDOM_DATA_BLOCK_MIN_SIZE_BYTES = 12
RANDOM_DATA_BLOCK_MAX_SIZE_BYTES = 64

MIN_N_RANDOM_DATA_BLOCKS = 3
MAX_N_RANDOM_DATA_BLOCKS = 10
assert MIN_N_RANDOM_DATA_BLOCKS >=2, "We need at least two random data blocks when taint is enabled." # TODO only assert when taint is enabled.

###
# Branches
###

BRANCH_TAKEN_PROBA = 0.2 # Proba of a branch to be taken
NONTAKEN_BRANCH_INTO_RANDOM_DATA_PROBA = 0.9 # Proba of a branch to target the random data block if it is in range

###
# Memory operations
###

# Picking memory addresses

class MemaddrPickPolicy(IntEnum):
    MEM_ANY_STORELOC = auto() # proba weight to take any store location.
    MEM_ANY          = auto() # proba weight to take any register and any authorized address.

# Weights to choose the address of the next
MEMADDR_PICK_POLICY_WEIGTHS = {
    True: { # If it is a load
        MemaddrPickPolicy.MEM_ANY_STORELOC: 1,
        MemaddrPickPolicy.MEM_ANY:          1,
    },
    False: { # If it is a store
        MemaddrPickPolicy.MEM_ANY_STORELOC: 1,
        MemaddrPickPolicy.MEM_ANY:          0, # This must always be 0 for stores, because they can only be performed to specific locations.
    }
}

# Store locations
MAX_NUM_STORE_LOCATIONS = 30 # Max number of locations where doublewords can be stored.
MAX_NUM_FENCES_PER_EXECUTION = 10

###
# End condition
###

# Stop generating instructions when the memory saturation reaches this level.
# In other words, if the memory is occupied by more than this amount, then do not start generating new basic blocks.
LIMIT_MEM_SATURATION_RATIO = 0.8

###
# Register picking
###

# When a register is produced, it gets this probability to be picked next. What is nice is that it immediately saturates: producing it twice does not increase picking proba.
REGPICK_PROTUBERANCE_RATIO = 0.2 

if USE_MMU:
    NUM_MIN_FREE_INTREGS = 3 # 3, we need at least 2 free regs which are not 0
else:
    NUM_MIN_FREE_INTREGS = 2

if USE_MMU:
    MAX_NUM_PICKABLE_REGS = 22
else:
    MAX_NUM_PICKABLE_REGS = 24

def reset_reg_settings():
    global MAX_NUM_PICKABLE_REGS
    global MIN_NUM_PICKABLE_REGS
    global NUM_MIN_FREE_INTREGS
    global USE_MMU
    if USE_MMU:
        MAX_NUM_PICKABLE_REGS = 22
        NUM_MIN_FREE_INTREGS = 3
    # elif USE_COMPRESSED:
    #     MAX_NUM_PICKABLE_REGS = 10 # Use less regs so we get more compressed instructions.
    #     NUM_MIN_FREE_INTREGS = 2
    else:
        MAX_NUM_PICKABLE_REGS = 24
        NUM_MIN_FREE_INTREGS = 2
    MIN_NUM_PICKABLE_REGS = 8

# # Reduce the registers that we allow ourselves to pick randomly
MIN_NUM_PICKABLE_REGS = 10
NUM_MAX_CONSUMED_INTREGS = 2
# When we have more than NUM_MAX_CONSUMED_INTREGS consumed registers,
# we nudge the program generation to use them, preferably with privilege switches
PROTURBANCE_CONSUMED_REGS_TVECFSM = 1
PROTURBANCE_CONSUMED_REGS_JALR = 2
PROTURBANCE_CONSUMED_REGS_EPCFSM = 3
PROTURBANCE_CONSUMED_REGS_PPFSM = 2
PROTURBANCE_CONSUMED_REGS_MEDELEG = 1.8
PROTURBANCE_CONSUMED_REGS_EXCEPTION = 1.2

NUM_MAX_RELOCUSED_INTREGS = 3
PROTURBANCE_RELOCUSED_REGS_ALU = 3



NUM_MAX_PRODUCED0_REGS = 2
NUM_MAX_PRODUCED1_REGS = 2

MIN_NUM_PICKABLE_FLOATING_REGS = 1
MAX_NUM_PICKABLE_FLOATING_REGS = 14

RELOCATOR_REGISTER_ID = 31
RDEP_MASK_REGISTER_ID = 30 # The mask to limit the value of the dependent register at the consumer level
FPU_ENDIS_REGISTER_ID = 29 # The mask to enable or disable the FPU
MPP_BOTH_ENDIS_REGISTER_ID = 28 # The mask to switch both MPP bits
MPP_TOP_ENDIS_REGISTER_ID = 27 # The mask to switch only the top MPP bit. We cannot do it for the bottom, because we could not go to supervisor mode reliably on a design that does not have user mode.
SPP_ENDIS_REGISTER_ID = 26 # The mask to switch the (unique) SPP Bit
REGDUMP_REGISTER_ID = 25 # Holds the address we write to when dumping registers.
# ONLY USED FOR MMU
RPROD_MASK_REGISTER_ID = 24 # Used to generate 64 bit long virtual addresses
RDEP_MASK_REGISTER_ID_VIRT = 23 # A 31 bit mask for rprod, used in a virtualized memory setting

assert RELOCATOR_REGISTER_ID < 32
assert RDEP_MASK_REGISTER_ID < 32
assert FPU_ENDIS_REGISTER_ID < 32
assert MPP_BOTH_ENDIS_REGISTER_ID < 32
assert MPP_TOP_ENDIS_REGISTER_ID < 32
assert SPP_ENDIS_REGISTER_ID < 32
assert REGDUMP_REGISTER_ID < 32

assert RELOCATOR_REGISTER_ID >= MAX_NUM_PICKABLE_REGS
assert RDEP_MASK_REGISTER_ID >= MAX_NUM_PICKABLE_REGS
assert FPU_ENDIS_REGISTER_ID >= MAX_NUM_PICKABLE_REGS
assert MPP_BOTH_ENDIS_REGISTER_ID >= MAX_NUM_PICKABLE_REGS
assert MPP_TOP_ENDIS_REGISTER_ID >= MAX_NUM_PICKABLE_REGS
assert SPP_ENDIS_REGISTER_ID >= MAX_NUM_PICKABLE_REGS
assert REGDUMP_REGISTER_ID >= MAX_NUM_PICKABLE_REGS


assert RDEP_MASK_REGISTER_ID != RELOCATOR_REGISTER_ID
# Check that they are all distinct
if USE_MMU:
    NONPICKABLE_REGISTERS = [RELOCATOR_REGISTER_ID, RDEP_MASK_REGISTER_ID, FPU_ENDIS_REGISTER_ID, MPP_BOTH_ENDIS_REGISTER_ID, MPP_TOP_ENDIS_REGISTER_ID, SPP_ENDIS_REGISTER_ID, REGDUMP_REGISTER_ID, RPROD_MASK_REGISTER_ID, RDEP_MASK_REGISTER_ID_VIRT, MAX_NUM_PICKABLE_REGS]
else:
    NONPICKABLE_REGISTERS = [RELOCATOR_REGISTER_ID, RDEP_MASK_REGISTER_ID, FPU_ENDIS_REGISTER_ID, MPP_BOTH_ENDIS_REGISTER_ID, MPP_TOP_ENDIS_REGISTER_ID, SPP_ENDIS_REGISTER_ID, REGDUMP_REGISTER_ID, MAX_NUM_PICKABLE_REGS]
assert len(set(NONPICKABLE_REGISTERS)) == len(NONPICKABLE_REGISTERS), NONPICKABLE_REGISTERS

###
# Register FSM
###

REG_FSM_WEIGHTS = np.array([
    1,  # FREE           -> PRODUCED0
    50, # PRODUCED0      -> PRODUCED1
    50, # PRODUCED1      -> FREE/CONSUMED
])

PROBA_CONSUME_PRODUCED1_SAME = 0.05 # The proba to output the same register as PRODUCED1 at the output of a CONSUME op

###
# Exceptions
###

SIMPLE_ILLEGAL_INSTRUCTION_PROBA = 0.01
PROBA_PICK_WRONG_FPU = 0.0 # Having this being zero eases the analysis of the program since we can try to simply remove all the FPU activations/deactivations to ensure that dumping is possible. More sophisticated methods could be implemented.
if USE_MMU:
    PROBA_AUTHORIZE_PRIVILEGES = 1
else:
    PROBA_AUTHORIZE_PRIVILEGES = 0.5
# Environment setup
MAX_CYCLES_PER_INSTR = 30
SETUP_CYCLES = 10000 # Without this, we had issues with BOOM with very short programs (typically <20 instructions) not being able to finish in time.

USE_SPIKE_INTERM_ELF = False # When both this and INSERT_REGDUMPS are enabled, the nops from the regdumps are part of the elf, which might be unintended.

## TAINT PARAMETERS ##

TAINT_EN = True

P_TAINT_REG = 0 # Probability that an initial register value is tainted. If non-zero, might be loaded into icache as the register values are stored right after the instruction code. TODO: use loads from (non-)tainted page instead
if USE_MMU: # not used if TAINT_IN_PRIVS fixed.
        P_TAINT_IN_MACHINE = 0.5
else:
    P_TAINT_IN_MACHINE = 1

MAX_NUM_INIT_TAINTED_REGS = 5

# There should be at least this number of untainted regs
NUM_MIN_UNTAINTED_INTREGS = 2

NUM_MIN_TAINTED_REGS = 1

P_RANDOM_DATA_TAINTED = 1
P_PAGE_HAS_TAINT = 0.8
P_LOAD_TAINT = 0.8

MIN_WEIGHT_T0 = 0.01
MAX_WEIGHT_T0 = 1

# The maximal probability proturbance introduced when a register is fully tainted i.e. relative taint hamming weight is one.
REGPICK_PROTUBERANCE_RATIO_T0_POS = 0.6 # Prefer tainted registers for rs.
REGPICK_PROTUBERANCE_RATIO_T0_NEG = 0.8 # Prefer untainted registers for rd.

LEAVE_M_MODE_PROTURBANCE_RATIO = 4 # Factor by which increase M-mode leaving ISA classes when in M-mode.

ALLOW_CSR_TAINT = False

P_UNTAINT_BIT = 0.3 # probability to untaint a single bit during input taint reduction

# factor by which we multiply the probability for an ALU ISA class s.t. 
# it is more likely to be chosen when there is too little taint in the registers
TAINT_IMM_PROTURBANCE_FACTOR = 10

LOG2_MEMSIZE_UPPERBOUND = 20
LOG2_MEMSIZE_LOWERBOUND = 17
NUM_MIN_BBS_LOWERBOUND = 20
if "NUM_MIN_BBS_LOWERBOUND" in os.environ:
    NUM_MIN_BBS_LOWERBOUND = int(os.environ["NUM_MIN_BBS_LOWERBOUND"])
    print(f"Setting NUM_MIN_BBS_LOWERBOUND = {NUM_MIN_BBS_LOWERBOUND} from env vars.")

NUM_MAX_BBS_UPPERBOUND = 300
if "NUM_MAX_BBS_UPPERBOUND" in os.environ:
    NUM_MAX_BBS_UPPERBOUND = int(os.environ("NUM_MAX_BBS_UPPERBOUND"))
    print(f"Setting NUM_MAX_BBS_UPPERBOUND = {NUM_MAX_BBS_UPPERBOUND} from env vars.")


NUM_BBS = 0 # When set to a positive value, fixes the number of BBs.

# The tanh saturates, so that we don't neglect registers that have only few bits tainted when there are regs that have much more bits tainted
USE_TAINT_TANH = True
USE_TAINT_HW = False
USE_TAINT_BIN = False
assert USE_TAINT_TANH or USE_TAINT_BIN or USE_TAINT_HW

INSERT_SPECTRE_GADGETS = False

# Tainting the immediates might taint the PC if instruction code is loaded and speculated on.
TAINT_IMMRD_IMM = False
if "TAINT_IMMRD_IMM" in os.environ:
    TAINT_IMMRD_IMM = int(os.environ["TAINT_IMMRD_IMM"]) == 1
    print(f"Setting TAINT_IMMRD_IMM = {TAINT_IMMRD_IMM} from env vars.")

TAINT_REGIMM_IMM = False
if "TAINT_REGIMM_IMM" in os.environ:
    TAINT_REGIMM_IMM = int(os.environ["TAINT_REGIMM_IMM"]) == 1
    print(f"Setting TAINT_REGIMM_IMM = {TAINT_REGIMM_IMM} from env vars.")

# Tainting immediates of branches could taint the pc without taking the branch as the BPU is updated speculatively.
TAINT_NONTAKEN_BRANCH_IMM = False
if "TAINT_NONTAKEN_BRANCHES" in os.environ:
    TAINT_NONTAKEN_BRANCH_IMM = int(os.environ["TAINT_NONTAKEN_BRANCHES"]) == 1
    print(f"Setting TAINT_NONTAKEN_BRANCHES = {TAINT_NONTAKEN_BRANCH_IMM} from env vars.")

# We can disable non-taken branches in the privileges that have access to taint to avoid tainting the pc in those privileges. Useful if we look for leakage through e.g. shared BPU and we probe it in one of the NO_TAINT privs 
ALLOW_NONTAKEN_BRANCHES_IN_TAINT_PRIVS = False
if "ALLOW_NONTAKEN_BRANCHES_IN_TAINT_PRIVS" in os.environ:
    ALLOW_NONTAKEN_BRANCHES_IN_TAINT_PRIVS = int(os.environ["ALLOW_NONTAKEN_BRANCHES_IN_TAINT_PRIVS"]) == 1
    print(f"Setting ALLOW_NONTAKEN_BRANCHES_IN_TAINT_PRIVS = {ALLOW_NONTAKEN_BRANCHES_IN_TAINT_PRIVS} from env vars.")

# We can disable non-taken branches in the privileges that have no access to taint to avoid tainting the pc in those privileges. Useful if we search for e.g. BNE in taint privs that leaks
ALLOW_NONTAKEN_BRANCHES_IN_NOTAINT_PRIVS = True
if "ALLOW_NONTAKEN_BRANCHES_IN_NOTAINT_PRIVS" in os.environ:
    ALLOW_NONTAKEN_BRANCHES_IN_NOTAINT_PRIVS = int(os.environ["ALLOW_NONTAKEN_BRANCHES_IN_NOTAINT_PRIVS"]) == 1
    print(f"Setting ALLOW_NONTAKEN_BRANCHES_IN_NOTAINT_PRIVS = {ALLOW_NONTAKEN_BRANCHES_IN_NOTAINT_PRIVS} from env vars.")

# We can disable non-taken branches in M mode s.t. we don't get any prediction based on unmapped data where M is a confused deputy.
ALLOW_NONTAKEN_BRANCHES_IN_MACHINE_MODE = False
if "ALLOW_NONTAKEN_BRANCHES_IN_MACHINE_MODE" in os.environ:
    ALLOW_NONTAKEN_BRANCHES_IN_MACHINE_MODE = int(os.environ["ALLOW_NONTAKEN_BRANCHES_IN_MACHINE_MODE"]) == 1
    print(f"Setting ALLOW_NONTAKEN_BRANCHES_IN_MACHINE_MODE = {ALLOW_NONTAKEN_BRANCHES_IN_MACHINE_MODE} from env vars.")

ALLOW_JALR_IN_MACHINE_MODE = False
if "ALLOW_JALR_IN_MACHINE_MODE" in os.environ:
    ALLOW_JALR_IN_MACHINE_MODE = int(os.environ["ALLOW_JALR_IN_MACHINE_MODE"]) == 1
    print(f"Setting ALLOW_JALR_IN_MACHINE_MODE = {ALLOW_JALR_IN_MACHINE_MODE} from env vars.")

ALLOW_BRANCH_IN_MACHINE_MODE = False
if "ALLOW_BRANCH_IN_MACHINE_MODE" in os.environ:
    ALLOW_BRANCH_IN_MACHINE_MODE = int(os.environ["ALLOW_BRANCH_IN_MACHINE_MODE"]) == 1
    print(f"Setting ALLOW_BRANCH_IN_MACHINE_MODE = {ALLOW_BRANCH_IN_MACHINE_MODE} from env vars.")

# When this is enabled, tainted data will be loaded but not computed on. This allows testing if leakage is coming from the dataflow.
DISABLE_COMPUTATION_ON_TAINT = False
if "DISABLE_COMPUTATION_ON_TAINT" in os.environ:
    DISABLE_COMPUTATION_ON_TAINT = int(os.environ["DISABLE_COMPUTATION_ON_TAINT"]) == 1
    print(f"Setting DISABLE_COMPUTATION_ON_TAINT = {DISABLE_COMPUTATION_ON_TAINT} from env vars.")

# We can statically set which privileges should have access to taints, e.g. "MSU" for all of them. If this is None, they are chosen randomly. This is ignored when MMU is disabled.
TAINT_IN_PRIVS = None
if "TAINT_IN_PRIVS" in os.environ:
    TAINT_IN_PRIVS = os.environ["TAINT_IN_PRIVS"]
    assert TAINT_IN_PRIVS != "M", f"Taint only in M-mode not supported right now."
    print(f"Setting TAINT_IN_PRIVS = {TAINT_IN_PRIVS} from env vars.")


# Abort fuzzing run if the computed program does not execute in taint sink privilege.
ASSERT_EXEC_IN_TAINT_SINK_PRIV = True
ASSERT_EXEC_IN_TAINT_SRC_PRIV = False

# Ignore exception types to e.g. only fuzz for leakage and ignore architectural bugs that trigger timeouts or value mismatches.
IGNORE_RTL_TIMEOUT = False
IGNORE_SPIKE_TIMEOUT = False
IGNORE_VALUE_MISMATCH = False
IGNORE_TAINT_MISMATCH = False
IGNORE_SPIKE_MISMATCH = False

# Use the uninstrumented design for fuzzing/reducing. This helps checking if theres a translation bug in yosys.
USE_VANILLA = False

DUMP_MCYCLES = False
assert not (DUMP_MCYCLES and USE_MMU), f"We can only dump MCYCLES when executing in M-mode in final BB."
INIT_MIE = False

FILL_MEM_WITH_DEAD_CODE = False