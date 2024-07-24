ADD_CONJ = False
SUB_CONJ = False
assert not ADD_CONJ and not SUB_CONJ, f"Conjuctive form does not give upper bound for add and sub, thus cannot be used if cellift does not instrument accordingly."
SLL_IMPRECISE = True
SLL_CONJ = False
assert not (SLL_CONJ and SLL_IMPRECISE) 
SLT_CONJ = False
assert not SLT_CONJ, f"Conjuctive form does not give upper bound for slt, thus cannot be used if cellift does not instrument accordingly."
SLTU_CONJ = False
assert not SLTU_CONJ, f"Conjuctive form does not give upper bound for sltu, thus cannot be used if cellift does not instrument accordingly."
XOR_CONJ = False
SRL_IMPRECISE = True
SRL_CONJ = False
assert not (SRL_CONJ and SRL_IMPRECISE) 
SRA_CONJ = False
OR_CONJ = True
AND_CONJ = False
ADDI_CONJ = False
SLLI_CONJ = False
SLTI_CONJ = False
assert not SLTI_CONJ, f"Conjuctive form does not give upper bound for slti, thus cannot be used if cellift does not instrument accordingly."
SLTIU_CONJ = False
assert not SLTIU_CONJ, f"Conjuctive form does not give upper bound for sltiu, thus cannot be used if cellift does not instrument accordingly."
XORI_CONJ = False
SRLI_CONJ = False
SRAI_CONJ = False
ORI_CONJ = True
ANDI_CONJ = False

USE_TAG = True # Instead of propagating by some rule, mark as either fully tainted or not tainted at all

