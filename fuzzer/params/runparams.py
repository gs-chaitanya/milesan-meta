import os

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

NO_REMOVE_TMPFILES = True # Used for debugging purposes.

RUN_TIMEOUT_SECONDS = 60*60*2 # A program is not supposed to run longer than this in RTL simulation.

PRINT_FSM_TRANSITIONS = False # Print transitions between states for register FSM instructions.

CHECK_REGS_T0_PRECISE = False
CHECK_MEM_T0_PRECISE = False
PRINT_CHECK_REGS_T0 = False # Print taint propagation checks.
PRINT_CHECK_REGS_T0_MISMATCH_OK = False
PRINT_CHECK_REGS = False
PRINT_WRITEBACK_T0 = False # Print taint writeback of instructions.

PRINT_INSTRUCTION_EXECUTION_IN_SITU = False # Prints execution during program generation.
PRINT_INSTRUCTION_EXECUTION_FINAL = False # Prints execution during register value checks.
PRINT_INSTRUCTION_EXECUTION_REDUCE = False # Prints execution during program reduction.
PRINT_INSTRUCTION_EXECUTION_REGDUMP_REQS = False

PRINT_REG_TRACEBACK = False
PRINT_FILTERED_REG_TRACEBACK = False

PRINT_ENVIRONMENT = False

INSERT_REGDUMPS = False
INSERT_FENCE = False # The stores should become architectually visible in order, so this should not be necessary

PRINT_REGISTER_VALIDATION = False
PRINT_MEMORY_VALIDATION = False
PRINT_AND_COMPARE = False
PRINT_SKIPPED_CHECKS = False

PRINT_MEM_LOADS = False
PRINT_MEM_LOADS_T0 = False
PRINT_MEM_STORES = False
PRINT_MEM_STORES_T0 = False