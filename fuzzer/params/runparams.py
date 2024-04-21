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
PRINT_CHECK_REGS_T0 = False # Print taint propagation checks.
PRINT_CHECK_REGS_T0_MISMATCH_OK = False
PRINT_WRITEBACK_T0 = False # Print taint writeback of instructions.

PRINT_CHECK_REGS = False

PRINT_INSTRUCTION_EXECUTION_IN_SITU = False # Prints execution during program generation.
PRINT_INSTRUCTION_EXECUTION_FINAL = False # Prints execution during register value checks.

PRINT_DBUS_TAINT = False

PRINT_REG_TRACEBACK = False
PRINT_FILTERED_REG_TRACEBACK = True

PRINT_ENVIRONMENT = True

INSERT_REGDUMPS = False

PRINT_REGISTER_VALIDATION = False

PRINT_SKIPPED_CHECKS = False