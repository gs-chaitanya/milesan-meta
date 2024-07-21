import os
from params.fuzzparams import USE_MMU, INSERT_SPECTRE_GADGETS, TAINT_NONTAKEN_BRANCH_IMM
# tmpdir
if "CASCADE_ENV_SOURCED" not in os.environ:
    raise Exception("The Cascade environment must be sourced prior to running the Python recipes.")

PATH_TO_TMP = os.path.join(os.environ['CASCADE_DATADIR'])
os.makedirs(PATH_TO_TMP, exist_ok=True)

PATH_TO_MNT = os.path.join(os.environ['LOCAL_MNT'])

PATH_TO_COV = os.path.join(os.environ['COVDUMP_DIR'])

PATH_TO_FIGURES = os.environ['CASCADE_PATH_TO_FIGURES']

DO_ASSERT = True
DO_EXPENSIVE_ASSERT = False # More expensive assertions

NO_REMOVE_TMPFILES = False # Used for debugging purposes
# TODO: below currently need to be enabled for reduction with pillar.
NO_REMOVE_TMPDIRS = False # When disabled, removes the /cascade-data/[design-name]/[ID] directories even when leakage (or bug) detected. Enable to save storage when fuzzing multi-threaded.

RUN_TIMEOUT_SECONDS = 60*3 # A program is not supposed to run longer than this in RTL simulation.

PRINT_FSM_TRANSITIONS = False # Print transitions between states for register FSM instructions.

CHECK_REGS_T0_PRECISE = False
CHECK_MEM_T0_PRECISE = False
CHECK_MEM = False
PRINT_CHECK_REGS_T0 = False # Print taint propagation checks.
PRINT_CHECK_REGS_T0_MISMATCH_OK = False
PRINT_CHECK_REGS = False
PRINT_WRITEBACK_T0 = False # Print taint writeback of instructions.
PRINT_WRITEBACK = False

PRINT_INSTRUCTION_EXECUTION_IN_SITU = False # Prints execution during program generation.
PRINT_INSTRUCTION_EXECUTION_FINAL = False # Prints execution during register value checks.
PRINT_INSTRUCTION_EXECUTION_REDUCE = False # Prints execution during program reduction.
PRINT_INSTRUCTION_EXECUTION_REGDUMP_REQS = False
PRINT_COLOR_TAINT = True

PRINT_REG_TRACEBACK = False
PRINT_FILTERED_REG_TRACEBACK = False

PRINT_ENVIRONMENT = False

INSERT_REGDUMPS = False # Speculative bugs will likely diappear when enabled. Used to test correctness of dataflow computation.
INSERT_FENCE = False # The stores should become architectually visible in order, so this should not be necessary in most cases with WT caches. CVA6 needs it.
assert not (USE_MMU and INSERT_REGDUMPS), "Regdumps are not supported when MMU is enabled." # We would have to translate the regdump address for each context switch, otherwise not difficult to implement.
assert not (INSERT_SPECTRE_GADGETS and INSERT_REGDUMPS), "Regdumps are not supported when spectre gadgets enabled."
assert not (TAINT_NONTAKEN_BRANCH_IMM and INSERT_REGDUMPS), "Enabling TAINT_NONTAKEN_BRANCH_IMM might render INSERT_REGDUMPS useless as pc might get tainted if non-taken branch is predicted taken."
CHECK_PC_SPIKE_AGAIN = True
assert not (INSERT_REGDUMPS and CHECK_PC_SPIKE_AGAIN)
assert not (INSERT_FENCE and not INSERT_REGDUMPS), f"INSERT_REGDUMPS must be enabled."

PRINT_REGISTER_VALIDATION = False
PRINT_MEMORY_VALIDATION = False
PRINT_AND_COMPARE = False
PRINT_SKIPPED_CHECKS = False

PRINT_MEM_LOADS = False
PRINT_MEM_LOADS_T0 = False
PRINT_MEM_STORES = False
PRINT_MEM_STORES_T0 = False

GET_DATA = False
DEBUG_PRINT = False

ASSERT_ADDR = True

PRINT_PRIV_STATS = False

DO_DOUBLECHECK_SIM = True

# Trace settings
TRACE_EN = False
TRACE_FST = False

# Use this as global parameter to set start time of fuzzing.
TIMESTAMP_START = None

