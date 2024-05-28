# Copyright 2023 Flavien Solt, ETH Zurich.
# Licensed under the General Public License, Version 3.0, see LICENSE for details.
# SPDX-License-Identifier: GPL-3.0-only

from enum import IntEnum, auto
import numpy as np

###
# Basic blocks
###

BLOCK_HEADER_RANDOM_DATA_BYTES = 12
RANDOM_DATA_BLOCK_MIN_SIZE_BYTES = 12
RANDOM_DATA_BLOCK_MAX_SIZE_BYTES = 64

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

# There should always be at least this number of free or relocused registers
NUM_MIN_FREE_INTREGS = 2

# Reduce the registers that we allow ourselves to pick randomly
MIN_NUM_PICKABLE_REGS = 4
MAX_NUM_PICKABLE_REGS = 25

MIN_NUM_PICKABLE_FLOATING_REGS = 1
MAX_NUM_PICKABLE_FLOATING_REGS = 14

RELOCATOR_REGISTER_ID = 31
RDEP_MASK_REGISTER_ID = 30 # The mask to limit the value of the dependent register at the consumer level
FPU_ENDIS_REGISTER_ID = 29 # The mask to enable or disable the FPU
MPP_BOTH_ENDIS_REGISTER_ID = 28 # The mask to switch both MPP bits
MPP_TOP_ENDIS_REGISTER_ID = 27 # The mask to switch only the top MPP bit. We cannot do it for the bottom, because we could not go to supervisor mode reliably on a design that does not have user mode.
SPP_ENDIS_REGISTER_ID = 26 # The mask to switch the (unique) SPP Bit
REGDUMP_REGISTER_ID = 25 # Holds the address we write to when dumping registers.

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
assert len({RELOCATOR_REGISTER_ID, RDEP_MASK_REGISTER_ID, FPU_ENDIS_REGISTER_ID, MPP_BOTH_ENDIS_REGISTER_ID, MPP_TOP_ENDIS_REGISTER_ID, SPP_ENDIS_REGISTER_ID, REGDUMP_REGISTER_ID}) == len([RELOCATOR_REGISTER_ID, RDEP_MASK_REGISTER_ID, FPU_ENDIS_REGISTER_ID, MPP_BOTH_ENDIS_REGISTER_ID, MPP_TOP_ENDIS_REGISTER_ID, SPP_ENDIS_REGISTER_ID, REGDUMP_REGISTER_ID])

###
# Register FSM
###

REG_FSM_WEIGHTS = np.array([
    1,  # FREE           -> PRODUCED0
    10, # PRODUCED0      -> PRODUCED1
    10, # PRODUCED1      -> FREE/CONSUMED
])

PROBA_CONSUME_PRODUCED1_SAME = 0.05 # The proba to output the same register as PRODUCED1 at the output of a CONSUME op

###
# Exceptions
###

SIMPLE_ILLEGAL_INSTRUCTION_PROBA = 0.01
PROBA_PICK_WRONG_FPU = 0.0 # Having this being zero eases the analysis of the program since we can try to simply remove all the FPU activations/deactivations to ensure that dumping is possible. More sophisticated methods could be implemented.
PROBA_AUTHORIZE_PRIVILEGES = 0.05

# Environment setup
MAX_CYCLES_PER_INSTR = 30
SETUP_CYCLES = 1000 # Without this, we had issues with BOOM with very short programs (typically <20 instructions) not being able to finish in time.

USE_SPIKE_INTERM_ELF = False # When both this and INSERT_REGDUMPS are enabled, the nops from the regdumps are part of the elf, which might be unintended.


## TAINT PARAMETERS ##

TAINT_EN = True
P_TAINT_REG = 0.5
MAX_NUM_INIT_TAINTED_REGS = 5

# There should be at least this number of untainted regs
NUM_MIN_UNTAINTED_INTREGS = 2

NUM_MIN_TAINTED_REGS = 1

P_RANDOM_DATA_TAINTED = 0.1

MIN_WEIGHT_T0 = 0.01
MAX_WEIGHT_T0 = 1

# The maximal probability proturbance introduced when a register is fully tainted i.e. relative taint hamming weight is one.
REGPICK_PROTUBERANCE_RATIO_T0_POS = 0.3
REGPICK_PROTUBERANCE_RATIO_T0_NEG = 0.2


ALLOW_CSR_TAINT = False

P_UNTAINT_BIT = 0.3 # probability to untaint a single bit during input taint reduction

# factor by which we multiply the probability for an ALU ISA class s.t. 
# it is more likely to be chosen when there is too little taint in the registers
TAINT_IMM_PROTURBANCE_FACTOR = 10

LOG2_MEMSIZE_UPPERBOUND = 20
LOG2_MEMSIZE_LOWERBOUND = 17
NUM_MAX_BBS_UPPERBOUND = 100
NUM_MIN_BBS_LOWERBOUND = 20
NUM_BBS = 0

# The tanh saturates, so that we don't neglect registers that have only few bits tainted when there are regs that have much more bits tainted
USE_TAINT_TANH = True
USE_TAINT_HW = False
USE_TAINT_BIN = False
assert USE_TAINT_TANH or USE_TAINT_BIN or USE_TAINT_HW