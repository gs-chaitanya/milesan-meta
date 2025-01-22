from params.env_helperfuncs import get_env_int, get_env_bool
from params.reduceparams_default import *
from params.fuzzparams import USE_MMU, USE_COMPRESSED
NOPIZE_SANDWICH_INSTRUCTIONS = get_env_bool("NOPIZE_SANDWICH_INSTRUCTIONS",NOPIZE_SANDWICH_INSTRUCTIONS_DEFAULT)
FLATTEN_SANDWICH_INSTRUCTIONS = get_env_bool("FLATTEN_SANDWICH_INSTRUCTIONS",FLATTEN_SANDWICH_INSTRUCTIONS_DEFAULT)
assert not FLATTEN_SANDWICH_INSTRUCTIONS, "Not implemented yet, likely not useful."
REDUCE_TAINT = get_env_bool("REDUCE_TAINT",REDUCE_TAINT_DEFAULT)
REDUCE_DEAD_CODE = get_env_bool("REDUCE_DEAD_CODE",REDUCE_DEAD_CODE_DEFAULT)
FIND_PILLARS = get_env_bool("FIND_PILLARS",FIND_PILLARS_DEFAULT)
FIND_PILLAR_INSTRUCTION =  get_env_bool("FIND_PILLAR_INSTRUCTION",FIND_PILLAR_INSTRUCTION_DEFAULT)
# assert not USE_MMU and FIND_PILLAR_INSTRUCTION, f"Not implemented yet when MMU is enabled, likely not useful. Use NOPIZE_SANDWICH_INSTRUCTIONS instead."
DOUBLECHECK_MODELSIM = get_env_bool("DOUBLECHECK_MODELSIM",DOUBLECHECK_MODELSIM_DEFAULT)
# During reduction from the front, the leakage mechanism might change, especialy on OpenC910.
# We can therfore check if removing the leaker instruction removes the leakage during reduction from the front
# to ensure the mechanism is an invariant. 
# This however requires one extra RTL simulation per reduction iteration and seems only necessary for OpenC910.
CHECK_LEAKER_INVARIANCE = get_env_bool("CHECK_LEAKER_INVARIANCE",CHECK_LEAKER_INVARIANCE_DEFAULT)
FAILING_BB_ID = get_env_int("FAILING_BB_ID",FAILING_BB_ID_DEFAULT)
FAILING_INSTR_ID = get_env_int("FAILING_INSTR_ID",FAILING_INSTR_ID_DETAULT)
PILLAR_BB_ID = get_env_int("PILLAR_BB_ID",PILLAR_BB_ID_DEFAULT)
assert PILLAR_BB_ID > 0 or PILLAR_BB_ID==-1, f"PILLAR_BB_ID must be > 0!"
PILLAR_INSTR_ID = get_env_int("PILLAR_INSTR_ID",PILLAR_INSTR_ID_DEFAULT)
assert not (USE_COMPRESSED and FIND_PILLARS), f"Cannot find pillars with USE_COMPRESSED enabled, context setter not compatible yet."
assert not (USE_COMPRESSED and FIND_PILLAR_INSTRUCTION), f"Cannot find pillar instructions with USE_COMPRESSED enabled, context setter not compatible yet."