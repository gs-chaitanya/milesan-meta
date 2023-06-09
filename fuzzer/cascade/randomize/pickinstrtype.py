# Copyright 2023 Flavien Solt, ETH Zurich.
# Licensed under the General Public License, Version 3.0, see LICENSE for details.
# SPDX-License-Identifier: GPL-3.0-only

from cascade.cfinstructionclasses import *
from cascade.toleratebugs import TOLERATE_CVA6_FDIVS_FLAGS, TOLERATE_VEXRISCV_IMPRECISE_FCVT, TOLERATE_VEXRISCV_FMIN, TOLERATE_VEXRISCV_DOUBLE_TO_FLOAT, TOLERATE_VEXRISCV_DEPENDENT_SINGLE_PRECISION, TOLERATE_VEXRISCV_DEPENDENT_FLE_FEQ_RET1, TOLERATE_VEXRISCV_DEPENDENT_FLT_RET0, TOLERATE_VEXRISCV_SQRT, TOLERATE_VEXRISCV_MULDIV_CONVERSION
from cascade.util import ISAInstrClass, IntRegIndivState, INSTRUCTIONS_BY_ISA_CLASS
from params.fuzzparams import NUM_MIN_FREE_INTREGS

from copy import copy
from collections import defaultdict
import random

# For a given ISAInstrClass, this module helps picking an instruction type.

###
# Helper functions
###

# INSTRTYPE_INITIAL_RELATIVE_WEIGHTS[ISAInstrClass]["add"] = float. Weights will be normalized by instr class.
INSTRTYPE_INITIAL_RELATIVE_WEIGHTS = {
    # For the moment, give all instructions inside the same ISA class the same appearance chance.
    curr_key: dict.fromkeys(curr_instrs, 1) for curr_key, curr_instrs in INSTRUCTIONS_BY_ISA_CLASS.items()
}

# Useful for time to bug evaluation
def forbid_vexriscv_ops(keys_and_weights_dict):
    keys_and_weights_dict_ret = copy(keys_and_weights_dict)
    # Double precision
    keys_and_weights_dict_ret["fsgnj.d"] = 0
    keys_and_weights_dict_ret["fsgnjn.d"] = 0
    keys_and_weights_dict_ret["fsgnjx.d"] = 0
    keys_and_weights_dict_ret["fnmadd.s"] = 0
    keys_and_weights_dict_ret["fmadd.s"] = 0
    keys_and_weights_dict_ret["fnmsub.s"] = 0
    keys_and_weights_dict_ret["fmsub.s"] = 0

    # Single precision
    keys_and_weights_dict_ret["fsgnj.s"] = 0
    keys_and_weights_dict_ret["fsgnjn.s"] = 0
    keys_and_weights_dict_ret["fsgnjx.s"] = 0
    keys_and_weights_dict_ret["fnmadd.d"] = 0
    keys_and_weights_dict_ret["fmadd.d"] = 0
    keys_and_weights_dict_ret["fnmsub.d"] = 0
    keys_and_weights_dict_ret["fmsub.d"] = 0

    assert TOLERATE_VEXRISCV_IMPRECISE_FCVT + TOLERATE_VEXRISCV_FMIN + TOLERATE_VEXRISCV_DOUBLE_TO_FLOAT + TOLERATE_VEXRISCV_DEPENDENT_SINGLE_PRECISION + TOLERATE_VEXRISCV_DEPENDENT_FLE_FEQ_RET1 + TOLERATE_VEXRISCV_DEPENDENT_FLT_RET0 + TOLERATE_VEXRISCV_SQRT + TOLERATE_VEXRISCV_MULDIV_CONVERSION  <= 1

    if TOLERATE_VEXRISCV_IMPRECISE_FCVT or TOLERATE_VEXRISCV_FMIN or TOLERATE_VEXRISCV_DOUBLE_TO_FLOAT or TOLERATE_VEXRISCV_DEPENDENT_SINGLE_PRECISION or TOLERATE_VEXRISCV_DEPENDENT_FLE_FEQ_RET1 or TOLERATE_VEXRISCV_DEPENDENT_FLT_RET0 or TOLERATE_VEXRISCV_SQRT or TOLERATE_VEXRISCV_MULDIV_CONVERSION:
        keys_and_weights_dict_ret["fcvt.w.s"] = 0
        keys_and_weights_dict_ret["fcvt.wu.s"] = 0
        keys_and_weights_dict_ret["fmin.s"] = 0
        keys_and_weights_dict_ret["fmax.s"] = 0
        keys_and_weights_dict_ret["fsqrt.s"] = 0
        keys_and_weights_dict_ret["fmul.s"] = 0
        keys_and_weights_dict_ret["fmul.d"] = 0
        keys_and_weights_dict_ret["fadd.s"] = 0
        keys_and_weights_dict_ret["fsub.s"] = 0
        keys_and_weights_dict_ret["fdiv.s"] = 0
        keys_and_weights_dict_ret["fdiv.d"] = 0
        keys_and_weights_dict_ret["flt.s"] = 0
        keys_and_weights_dict_ret["fle.s"] = 0
        keys_and_weights_dict_ret["feq.s"] = 0
        keys_and_weights_dict_ret["fcvt.l.s"] = 0
        keys_and_weights_dict_ret["fcvt.lu.s"] = 0
        keys_and_weights_dict_ret["fcvt.s.w"] = 0
        keys_and_weights_dict_ret["fcvt.s.wu"] = 0
        keys_and_weights_dict_ret["fcvt.s.l"] = 0
        keys_and_weights_dict_ret["fcvt.s.lu"] = 0
        keys_and_weights_dict_ret["fcvt.d.s"] = 0
        keys_and_weights_dict_ret["fmin.d"] = 0
        keys_and_weights_dict_ret["fmax.d"] = 0

        if TOLERATE_VEXRISCV_IMPRECISE_FCVT or TOLERATE_VEXRISCV_FMIN or TOLERATE_VEXRISCV_DOUBLE_TO_FLOAT or TOLERATE_VEXRISCV_DEPENDENT_SINGLE_PRECISION or TOLERATE_VEXRISCV_DEPENDENT_FLE_FEQ_RET1 or TOLERATE_VEXRISCV_DEPENDENT_FLT_RET0 or TOLERATE_VEXRISCV_SQRT:
            keys_and_weights_dict_ret["fcvt.w.s"] = keys_and_weights_dict["fcvt.w.s"]
            keys_and_weights_dict_ret["fcvt.wu.s"] = keys_and_weights_dict["fcvt.wu.s"]
            keys_and_weights_dict_ret["fcvt.l.s"] = keys_and_weights_dict["fcvt.l.s"]
            keys_and_weights_dict_ret["fcvt.lu.s"] = keys_and_weights_dict["fcvt.lu.s"]
            keys_and_weights_dict_ret["fcvt.d.s"] = keys_and_weights_dict["fcvt.d.s"]

        if TOLERATE_VEXRISCV_IMPRECISE_FCVT:
            keys_and_weights_dict_ret["fcvt.s.w"] = keys_and_weights_dict["fcvt.s.w"]
            keys_and_weights_dict_ret["fcvt.s.wu"] = keys_and_weights_dict["fcvt.s.wu"]
            keys_and_weights_dict_ret["fcvt.s.l"] = keys_and_weights_dict["fcvt.s.l"]
            keys_and_weights_dict_ret["fcvt.s.lu"] = keys_and_weights_dict["fcvt.s.lu"]
        if TOLERATE_VEXRISCV_FMIN:
            keys_and_weights_dict_ret["fmin.s"] = keys_and_weights_dict["fmin.s"]
            keys_and_weights_dict_ret["fmin.d"] = keys_and_weights_dict["fmin.d"]
        if TOLERATE_VEXRISCV_DOUBLE_TO_FLOAT:
            keys_and_weights_dict_ret["fcvt.d.s"] = keys_and_weights_dict["fcvt.d.s"]
        if TOLERATE_VEXRISCV_DEPENDENT_SINGLE_PRECISION:
            keys_and_weights_dict_ret["fmul.s"] = keys_and_weights_dict["fmul.s"]
            keys_and_weights_dict_ret["fadd.s"] = keys_and_weights_dict["fadd.s"]
            keys_and_weights_dict_ret["fsub.s"] = keys_and_weights_dict["fsub.s"]
            keys_and_weights_dict_ret["fdiv.s"] = keys_and_weights_dict["fdiv.s"]
        if TOLERATE_VEXRISCV_DEPENDENT_FLE_FEQ_RET1:
            keys_and_weights_dict_ret["fle.s"] = keys_and_weights_dict["fle.s"]
            keys_and_weights_dict_ret["fle.d"] = keys_and_weights_dict["fle.d"]
            keys_and_weights_dict_ret["feq.s"] = keys_and_weights_dict["feq.s"]
            keys_and_weights_dict_ret["feq.d"] = keys_and_weights_dict["feq.d"]
        if TOLERATE_VEXRISCV_DEPENDENT_FLT_RET0:
            keys_and_weights_dict_ret["flt.s"] = keys_and_weights_dict["flt.s"]
            keys_and_weights_dict_ret["flt.d"] = keys_and_weights_dict["flt.d"]
        if TOLERATE_VEXRISCV_SQRT:
            keys_and_weights_dict_ret["fsqrt.s"] = keys_and_weights_dict["fsqrt.s"]
            keys_and_weights_dict_ret["fsqrt.d"] = keys_and_weights_dict["fsqrt.d"]
    
        if TOLERATE_VEXRISCV_MULDIV_CONVERSION:
            keys_and_weights_dict_ret["fmul.s"] = keys_and_weights_dict["fmul.s"]
            keys_and_weights_dict_ret["fmul.d"] = keys_and_weights_dict["fmul.d"]
            keys_and_weights_dict_ret["fdiv.s"] = keys_and_weights_dict["fdiv.s"]
            keys_and_weights_dict_ret["fdiv.d"] = keys_and_weights_dict["fdiv.d"]

    return keys_and_weights_dict_ret

###
# Exposed functions
###

# @param isaclass
# @return a CFInstruction object or a placeholder object
def gen_next_instrstr_from_isaclass(isaclass: ISAInstrClass, fuzzerstate) -> str:
    # This global may prevent from copying the dict
    global INSTRTYPE_INITIAL_RELATIVE_WEIGHTS

    keys_and_weights_dict = defaultdict(int, INSTRTYPE_INITIAL_RELATIVE_WEIGHTS[isaclass])

    # No floating point sign injection
    if fuzzerstate.design_name == "vexriscv":
        keys_and_weights_dict = forbid_vexriscv_ops(keys_and_weights_dict)

    if fuzzerstate.design_name == "cva6":
        # Double precision
        keys_and_weights_dict["fsqrt.d"] = 0
        keys_and_weights_dict["fdiv.d"] = 0

        # Single precision
        keys_and_weights_dict["fsqrt.s"] = 0
        if not TOLERATE_CVA6_FDIVS_FLAGS:
            keys_and_weights_dict["fdiv.s"] = 0
        keys_and_weights_dict["fcvt.d.s"] = 0
        keys_and_weights_dict["fcvt.s.d"] = 0
        keys_and_weights_dict["fcvt.wu.d"] = 0

    if DO_ASSERT:
        assert isaclass != ISAInstrClass.REGFSM   , "ISAInstrClass.REGFSM must be treated separately"
        assert isaclass != ISAInstrClass.FPUFSM   , "ISAInstrClass.FPUFSM must be treated separately"
        assert isaclass != ISAInstrClass.EXCEPTION, "ISAInstrClass.EXCEPTION must be treated separately"
        assert isaclass != ISAInstrClass.TVECFSM  , "ISAInstrClass.TVECFSM must be treated separately"
        assert isaclass != ISAInstrClass.PPFSM    , "ISAInstrClass.PPFSM must be treated separately"
        assert isaclass != ISAInstrClass.EPCFSM   , "ISAInstrClass.EPCFSM must be treated separately"

    ret = None
    while ret is None or keys_and_weights_dict[ret] == 0:
        ret = random.choices(list(keys_and_weights_dict.keys()), weights=keys_and_weights_dict.values())[0]
    return ret
