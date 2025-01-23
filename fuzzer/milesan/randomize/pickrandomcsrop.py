# Copyright 2024 Tobias Kovats, Flavien Solt, ETH Zurich.
# Licensed under the General Public License, Version 3.0, see LICENSE for details.
# SPDX-License-Identifier: GPL-3.0-only

# This module picks some random valid CSR operation.

from params.runparams import DO_ASSERT
from params.fuzzparams import ALLOW_CSR_TAINT
from rv.csrids import CSR_IDS
from milesan.util import IntRegIndivState
from milesan.toleratebugs import is_no_interaction_minstret, is_tolerate_kronos_minstret, is_tolerate_vexriscv_minstret, is_tolerate_picorv32_missingmandatorycsrs, is_tolerate_picorv32_readnonimplcsr, is_tolerate_picorv32_writehpm, is_tolerate_cva6_mhpmcounter, is_tolerate_boom_minstret, is_tolerate_picorv32_readhpm_nocsrrs, is_tolerate_vexriscv_mhpmcountern, is_tolerate_cva6_mhpmevent31
from milesan.privilegestate import PrivilegeStateEnum
from milesan.cfinstructionclasses import CSRRegInstruction, CSRImmInstruction
from milesan.cfinstructionclasses_t0 import CSRRegInstruction_t0, CSRImmInstruction_t0
import random

from enum import Enum, auto

class MachineCSROpCandidates64(Enum):
    SCAUSE = auto()
    MCAUSE = auto()
    SSCRATCH = auto()
    MSCRATCH = auto()
    MINSTRET = auto()
    MHPMCOUNTER3 = auto()
    MHPMEVENT31 = auto()

class MachineCSROpCandidates32(Enum):
    SCAUSE = auto()
    MCAUSE = auto()
    SSCRATCH = auto()
    MSCRATCH = auto()
    MINSTRET = auto()

class SupervisorCSROpCandidates(Enum):
    SCAUSE = auto()
    SSCRATCH = auto()

# @brief Generate a privileged descent instruction or an mpp/spp write instruction.
# @return a list of instructions
def gen_random_csr_op(fuzzerstate):
    if DO_ASSERT:
        assert fuzzerstate.privilegestate.privstate in (PrivilegeStateEnum.MACHINE, PrivilegeStateEnum.SUPERVISOR)

    if fuzzerstate.privilegestate.privstate == PrivilegeStateEnum.MACHINE:
        if fuzzerstate.is_design_64bit:
            target_csr = None
            while target_csr is None or (target_csr == MachineCSROpCandidates64.MINSTRET and is_no_interaction_minstret()):
                target_csr = random.choice(list(MachineCSROpCandidates64))
            if not fuzzerstate.design_has_supervisor_mode:
                while target_csr in (MachineCSROpCandidates64.SCAUSE, MachineCSROpCandidates64.SSCRATCH):
                    target_csr = random.choice(list(MachineCSROpCandidates64))
            while 'cva6' in fuzzerstate.design_name and (not is_tolerate_cva6_mhpmcounter() and target_csr == MachineCSROpCandidates64.MHPMCOUNTER3 or not is_tolerate_cva6_mhpmevent31() and target_csr == MachineCSROpCandidates64.MHPMEVENT31):
                target_csr = random.choice(list(MachineCSROpCandidates64))

            if target_csr == MachineCSROpCandidates64.SCAUSE:
                # According to the spec, the SCAUSE CSR must be able to hold bits 0 to 4. mret is not required to.
                rd = fuzzerstate.intregpickstate.pick_untainted_int_outputreg(force=False)
                # The scause is unreliable if there was a MisalignedMemInstruction before and therefore the scause can be either the value from a page fault or from misaligned access.
                if fuzzerstate.csrfile.regs[CSR_IDS.SCAUSE].unreliable and rd>0:
                    fuzzerstate.intregpickstate.set_regstate(rd, IntRegIndivState.RELOCUSED, force=True)
                ret = CSRImmInstruction_t0(fuzzerstate,"csrrwi", rd, random.randrange(32), CSR_IDS.SCAUSE)
            elif target_csr == MachineCSROpCandidates64.MCAUSE:
                rd = fuzzerstate.intregpickstate.pick_untainted_int_outputreg(force=False)
                ret = CSRImmInstruction_t0(fuzzerstate,"csrrwi", rd, random.randrange(16), CSR_IDS.MCAUSE)
            elif target_csr == MachineCSROpCandidates64.SSCRATCH:
                    # It is important that rs is chosen first, otherwise it could be that as we choose rd, we set it from RELOCUSED->free, and then choose it mistakenly as rs.
                    rs = fuzzerstate.intregpickstate.pick_untainted_int_inputreg(force=True)
                    rd = fuzzerstate.intregpickstate.pick_untainted_int_outputreg_nonzero(force=False)
                    ret = CSRRegInstruction_t0(fuzzerstate,"csrrw", rd, rs, CSR_IDS.SSCRATCH)
            elif target_csr == MachineCSROpCandidates64.MSCRATCH:
                # It is important that rs is chosen first, otherwise it could be that as we choose rd, we set it from RELOCUSED->free, and then choose it mistakenly as rs.
                rs = fuzzerstate.intregpickstate.pick_untainted_int_inputreg(force=True)
                rd = fuzzerstate.intregpickstate.pick_untainted_int_outputreg_nonzero(force=False)
                ret = CSRRegInstruction_t0(fuzzerstate,"csrrw", rd, rs, CSR_IDS.MSCRATCH)
            elif target_csr == MachineCSROpCandidates64.MINSTRET:
                if fuzzerstate.is_minstret_inaccurate_because_ecall_ebreak or ("boom" in fuzzerstate.design_name and not is_tolerate_boom_minstret()):
                    ret = CSRImmInstruction_t0(fuzzerstate,"csrrwi", 0, random.randrange(16), CSR_IDS.MINSTRET)
                else:
                    ret = CSRRegInstruction_t0(fuzzerstate,"csrrw", 0, fuzzerstate.intregpickstate.pick_untainted_int_inputreg(force=True), CSR_IDS.MINSTRET)
                fuzzerstate.is_minstret_inaccurate_because_ecall_ebreak = False
            elif target_csr == MachineCSROpCandidates64.MHPMCOUNTER3: 
                ret = CSRImmInstruction_t0(fuzzerstate,"csrrwi", 0, random.randrange(16), CSR_IDS.MHPMCOUNTER3) # TODO: write to pickable register
            elif target_csr == MachineCSROpCandidates64.MHPMEVENT31:
                ret = CSRImmInstruction_t0(fuzzerstate,"csrrwi", 0, random.randrange(16), CSR_IDS.MHPMEVENT31) # MHPMEVENT is platform specific, needs to write to zero (?)
            else:
                raise Exception("Unexpected target_csr: {}".format(target_csr))
        else:
            if "vexriscv" in fuzzerstate.design_name and is_tolerate_vexriscv_mhpmcountern():
                return CSRImmInstruction_t0(fuzzerstate,"csrrwi", fuzzerstate.intregpickstate.pick_untainted_int_outputreg(force=False), random.randrange(16), CSR_IDS.MHPMCOUNTER3)
            elif "picorv32" in fuzzerstate.design_name and not is_tolerate_picorv32_missingmandatorycsrs() and not is_tolerate_picorv32_readnonimplcsr():
                assert not is_no_interaction_minstret(), "picorv32 only has minstret in this config."
                target_csr = MachineCSROpCandidates32.MINSTRET
            else:
                target_csr = None
                while target_csr is None or (target_csr == MachineCSROpCandidates32.MINSTRET and is_no_interaction_minstret()) \
                    or (not fuzzerstate.design_has_supervisor_mode and (target_csr in (MachineCSROpCandidates32.SCAUSE, MachineCSROpCandidates32.SSCRATCH))):
                    target_csr = random.choice(list(MachineCSROpCandidates32))
            if target_csr == MachineCSROpCandidates32.SCAUSE:
                rd = fuzzerstate.intregpickstate.pick_untainted_int_outputreg(force=False)
                # The scause is unreliable if there was a MisalignedMemInstruction before and therefore the scause can be either the value from a page fault or from misaligned access.
                if fuzzerstate.csrfile.regs[CSR_IDS.SCAUSE].unreliable and rd>0:
                        fuzzerstate.intregpickstate.set_regstate(rd, IntRegIndivState.RELOCUSED, force=True)
                # According to the spec, the SCAUSE CSR must be able to hold bits 0 to 4. mret is not required to.
                if "vexriscv" in fuzzerstate.design_name: # vexriscv complies with the privileged spec v1.10, which does not require scause to hold the 5th bit. Similarly, kronos implements privileged spec v1.11
                    randval = random.randrange(16)
                # The scause is unreliable if there was a MisalignedMemInstruction before and therefore the scause can be either the value from a page fault or from misaligned access.
                    ret = CSRImmInstruction_t0(fuzzerstate,"csrrwi", rd, randval, CSR_IDS.SCAUSE)
                else:
                    ret = CSRImmInstruction_t0(fuzzerstate,"csrrwi", rd, random.randrange(32), CSR_IDS.SCAUSE)
            elif target_csr == MachineCSROpCandidates32.MCAUSE:
                rd = fuzzerstate.intregpickstate.pick_untainted_int_outputreg(force=False)
                ret = CSRImmInstruction_t0(fuzzerstate,"csrrwi", rd, random.randrange(16), CSR_IDS.MCAUSE)
            elif target_csr == MachineCSROpCandidates32.SSCRATCH:
                # It is important that rs is chosen first, otherwise it could be that as we choose rd, we set it from RELOCUSED->free, and then choose it mistakenly as rs.
                rs = fuzzerstate.intregpickstate.pick_untainted_int_inputreg(force=True)
                rd = fuzzerstate.intregpickstate.pick_untainted_int_outputreg_nonzero(force=False)
                ret = CSRRegInstruction_t0(fuzzerstate,"csrrw", rd, rs, CSR_IDS.SSCRATCH)
            elif target_csr == MachineCSROpCandidates32.MSCRATCH:
                # It is important that rs is chosen first, otherwise it could be that as we choose rd, we set it from RELOCUSED->free, and then choose it mistakenly as rs.
                rs = fuzzerstate.intregpickstate.pick_untainted_int_inputreg(force=True)
                rd = fuzzerstate.intregpickstate.pick_untainted_int_outputreg_nonzero(force=False)
                ret = CSRRegInstruction_t0(fuzzerstate,"csrrw", rd, rs, CSR_IDS.MSCRATCH)
                # fuzzerstate.intregpickstate.set_regstate(rd,IntRegIndivState.RELOCUSED,True)
            elif target_csr == MachineCSROpCandidates32.MINSTRET:
                if "kronos" in fuzzerstate.design_name and not is_tolerate_kronos_minstret() or "vexriscv" in fuzzerstate.design_name and not is_tolerate_vexriscv_minstret():
                    ret = CSRRegInstruction_t0(fuzzerstate,"csrrw", 0, fuzzerstate.intregpickstate.pick_untainted_int_inputreg(force=True), CSR_IDS.MINSTRET)
                elif "picorv32" in fuzzerstate.design_name:
                    if is_tolerate_picorv32_readhpm_nocsrrs():
                        opcode_str = random.choice(("csrrw", "csrrs"))
                    else:
                        opcode_str = "csrrs"
                    if is_tolerate_picorv32_writehpm():
                        rs = fuzzerstate.intregpickstate.pick_untainted_int_inputreg(force=True)
                    else:
                        rs = 0
                    rd =  fuzzerstate.intregpickstate.pick_untainted_int_outputreg(force=False, authorize_sideeffects = False)
                    ret = CSRRegInstruction_t0(fuzzerstate,opcode_str,rd, rs, CSR_IDS.MINSTRET)
                else:
                    ret = CSRRegInstruction_t0(fuzzerstate,"csrrw", fuzzerstate.intregpickstate.pick_untainted_int_outputreg(force=False), fuzzerstate.intregpickstate.pick_untainted_int_inputreg(force=True), CSR_IDS.MINSTRET)
            else:
                raise Exception("Unexpected target_csr: {}".format(target_csr))
    else:
        target_csr = random.choice(list(SupervisorCSROpCandidates))
        if target_csr == SupervisorCSROpCandidates.SCAUSE:
            rd = fuzzerstate.intregpickstate.pick_untainted_int_outputreg(force=False)
            # The scause is unreliable if there was a MisalignedMemInstruction before and therefore the scause can be either the value from a page fault or from misaligned access.
            if fuzzerstate.csrfile.regs[CSR_IDS.SCAUSE].unreliable and rd>0:
                fuzzerstate.intregpickstate.set_regstate(rd, IntRegIndivState.RELOCUSED, force=True)
            if "vexriscv" in fuzzerstate.design_name: # vexriscv complies with the privileged spec v1.10, which does not require scause to hold the 5th bit. Similarly, kronos implements privileged spec v1.11
                ret = CSRImmInstruction_t0(fuzzerstate,"csrrwi", rd, random.randrange(16), CSR_IDS.SCAUSE)
            else:
                ret = CSRImmInstruction_t0(fuzzerstate,"csrrwi", rd, random.randrange(32), CSR_IDS.SCAUSE)
        elif target_csr == SupervisorCSROpCandidates.SSCRATCH:
            # It is important that rs is chosen first, otherwise it could be that as we choose rd, we set it from RELOCUSED->free, and then choose it mistakenly as rs.
            rs = fuzzerstate.intregpickstate.pick_untainted_int_inputreg(force=True)
            rd = fuzzerstate.intregpickstate.pick_untainted_int_outputreg(force=False)
            ret = CSRRegInstruction_t0(fuzzerstate,"csrrw", rd, rs, CSR_IDS.SSCRATCH)
        else:
            raise Exception("Unexpected target_csr: {}".format(target_csr))
    return ret
