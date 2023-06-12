# Copyright 2023 Flavien Solt, ETH Zurich.
# Licensed under the General Public License, Version 3.0, see LICENSE for details.
# SPDX-License-Identifier: GPL-3.0-only

# This module picks some random valid CSR operation.

from params.runparams import DO_ASSERT
from rv.csrids import CSR_IDS
from cascade.toleratebugs import NO_INTERACTION_MINSTRET, TOLERATE_KRONOS_MINSTRET, TOLERATE_VEXRISCV_MINSTRET, TOLERATE_PICORV32_MISSINGMANDATORYCSRS, TOLERATE_PICORV32_WRITEHPM, TOLERATE_CVA6_MHPMCOUNTER, TOLERATE_CVA6_MHPMEVENT31
from cascade.privilegestate import PrivilegeStateEnum
from cascade.cfinstructionclasses import CSRRegInstruction, CSRImmInstruction, RegImmInstruction
from cascade.toleratebugs import TOLERATE_BOOM_MINSTRET
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
    MINSTRETH = auto()

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
            while target_csr is None or (target_csr == MachineCSROpCandidates64.MINSTRET and NO_INTERACTION_MINSTRET):
                target_csr = random.choice(list(MachineCSROpCandidates64))
            if not fuzzerstate.design_has_supervisor_mode:
                while target_csr in (MachineCSROpCandidates64.SCAUSE, MachineCSROpCandidates64.SSCRATCH):
                    target_csr = random.choice(list(MachineCSROpCandidates64))
            while fuzzerstate.design_name == 'cva6' and not TOLERATE_CVA6_MHPMCOUNTER and target_csr == MachineCSROpCandidates64.MHPMCOUNTER3:
                target_csr = random.choice(list(MachineCSROpCandidates64))
            while fuzzerstate.design_name == 'cva6' and not TOLERATE_CVA6_MHPMCOUNTER and target_csr == MachineCSROpCandidates64.MHPMEVENT31:
                target_csr = random.choice(list(MachineCSROpCandidates64))

            if target_csr == MachineCSROpCandidates64.SCAUSE:
                # According to the spec, the SCAUSE CSR must be able to hold bits 0 to 4. mret is not required to.
                ret = CSRImmInstruction("csrrwi", fuzzerstate.intregpickstate.pick_int_outputreg(), random.randrange(32), CSR_IDS.SCAUSE)
            elif target_csr == MachineCSROpCandidates64.MCAUSE:
                ret = CSRImmInstruction("csrrwi", fuzzerstate.intregpickstate.pick_int_outputreg(), random.randrange(16), CSR_IDS.MCAUSE)
            elif target_csr == MachineCSROpCandidates64.SSCRATCH:
                    ret = CSRRegInstruction("csrrw", fuzzerstate.intregpickstate.pick_int_outputreg(), fuzzerstate.intregpickstate.pick_int_inputreg(), CSR_IDS.SSCRATCH)
            elif target_csr == MachineCSROpCandidates64.MSCRATCH:
                    ret = CSRRegInstruction("csrrw", fuzzerstate.intregpickstate.pick_int_outputreg(), fuzzerstate.intregpickstate.pick_int_inputreg(), CSR_IDS.MSCRATCH)
            elif target_csr == MachineCSROpCandidates64.MINSTRET:
                if fuzzerstate.is_minstret_inaccurate_because_ecall_ebreak or (fuzzerstate.design_name == "boom" and not TOLERATE_BOOM_MINSTRET):
                    ret = CSRImmInstruction("csrrwi", 0, random.randrange(16), CSR_IDS.MINSTRET)
                else:
                    ret = CSRRegInstruction("csrrw", fuzzerstate.intregpickstate.pick_int_outputreg(), fuzzerstate.intregpickstate.pick_int_outputreg(), CSR_IDS.MINSTRET)
                fuzzerstate.is_minstret_inaccurate_because_ecall_ebreak = False
            elif target_csr == MachineCSROpCandidates64.MHPMCOUNTER3:
                ret = CSRImmInstruction("csrrwi", 0, random.randrange(16), CSR_IDS.MHPMCOUNTER3)
            elif target_csr == MachineCSROpCandidates64.MHPMEVENT31:
                ret = CSRImmInstruction("csrrwi", 0, random.randrange(16), CSR_IDS.MHPMEVENT31)
            else:
                raise Exception("Unexpected target_csr: {}".format(target_csr))
        else:
            if fuzzerstate.design_name == "picorv32" and not TOLERATE_PICORV32_MISSINGMANDATORYCSRS:
                assert not NO_INTERACTION_MINSTRET, "picorv32 only has minstret in this config."
                target_csr = random.choice([MachineCSROpCandidates32.MINSTRET, MachineCSROpCandidates32.MINSTRETH])
            else:
                target_csr = None
                while target_csr is None or (target_csr in (MachineCSROpCandidates32.MINSTRET, MachineCSROpCandidates32.MINSTRETH) and NO_INTERACTION_MINSTRET) \
                    or (not fuzzerstate.design_has_supervisor_mode and (target_csr in (MachineCSROpCandidates32.SCAUSE, MachineCSROpCandidates32.SSCRATCH))):
                    target_csr = random.choice(list(MachineCSROpCandidates32))
            if target_csr == MachineCSROpCandidates32.SCAUSE:
                # According to the spec, the SCAUSE CSR must be able to hold bits 0 to 4. mret is not required to.
                if "vexriscv" in fuzzerstate.design_name: # vexriscv complies with the privileged spec v1.10, which does not require scause to hold the 5th bit. Similarly, kronos implements privileged spec v1.11
                    randval = random.randrange(16)
                    ret = CSRImmInstruction("csrrwi", fuzzerstate.intregpickstate.pick_int_outputreg(), randval, CSR_IDS.SCAUSE)
                else:
                    ret = CSRImmInstruction("csrrwi", fuzzerstate.intregpickstate.pick_int_outputreg(), random.randrange(32), CSR_IDS.SCAUSE)
            elif target_csr == MachineCSROpCandidates32.MCAUSE:
                ret = CSRImmInstruction("csrrwi", fuzzerstate.intregpickstate.pick_int_outputreg(), random.randrange(16), CSR_IDS.MCAUSE)
            elif target_csr == MachineCSROpCandidates32.SSCRATCH:
                    ret = CSRRegInstruction("csrrw", fuzzerstate.intregpickstate.pick_int_outputreg(), fuzzerstate.intregpickstate.pick_int_inputreg(), CSR_IDS.SSCRATCH)
            elif target_csr == MachineCSROpCandidates32.MSCRATCH:
                    ret = CSRRegInstruction("csrrw", fuzzerstate.intregpickstate.pick_int_outputreg(), fuzzerstate.intregpickstate.pick_int_inputreg(), CSR_IDS.MSCRATCH)
            elif target_csr == MachineCSROpCandidates32.MINSTRET:
                if fuzzerstate.design_name == "kronos" and not TOLERATE_KRONOS_MINSTRET or "vexriscv" in fuzzerstate.design_name and not TOLERATE_VEXRISCV_MINSTRET:
                    ret = CSRRegInstruction("csrrw", 0, fuzzerstate.intregpickstate.pick_int_inputreg(), CSR_IDS.MINSTRET)
                elif fuzzerstate.design_name == "picorv32" and not TOLERATE_PICORV32_WRITEHPM:
                    ret = CSRRegInstruction("csrrw", 0, 0, CSR_IDS.MINSTRET)
                else:
                    ret = CSRRegInstruction("csrrw", fuzzerstate.intregpickstate.pick_int_outputreg(), fuzzerstate.intregpickstate.pick_int_inputreg(), CSR_IDS.MINSTRET)
            elif target_csr == MachineCSROpCandidates32.MINSTRETH:
                if fuzzerstate.design_name == "kronos" and not TOLERATE_KRONOS_MINSTRET or "vexriscv" in fuzzerstate.design_name and not TOLERATE_VEXRISCV_MINSTRET:
                    ret = CSRRegInstruction("csrrw", 0, fuzzerstate.intregpickstate.pick_int_inputreg(), CSR_IDS.MINSTRETH)
                elif fuzzerstate.design_name == "picorv32" and not TOLERATE_PICORV32_WRITEHPM:
                    ret = CSRRegInstruction("csrrw", 0, 0, CSR_IDS.MINSTRETH)
                else:
                    ret = CSRRegInstruction("csrrw", fuzzerstate.intregpickstate.pick_int_outputreg(), fuzzerstate.intregpickstate.pick_int_inputreg(), CSR_IDS.MINSTRETH)
            else:
                raise Exception("Unexpected target_csr: {}".format(target_csr))
    else:
        target_csr = random.choice(list(SupervisorCSROpCandidates))
        if target_csr == SupervisorCSROpCandidates.SCAUSE:
            if "vexriscv" in fuzzerstate.design_name: # vexriscv complies with the privileged spec v1.10, which does not require scause to hold the 5th bit. Similarly, kronos implements privileged spec v1.11
                ret = CSRImmInstruction("csrrwi", fuzzerstate.intregpickstate.pick_int_outputreg(), random.randrange(16), CSR_IDS.SCAUSE)
            else:
                ret = CSRImmInstruction("csrrwi", fuzzerstate.intregpickstate.pick_int_outputreg(), random.randrange(32), CSR_IDS.SCAUSE)
        elif target_csr == SupervisorCSROpCandidates.SSCRATCH:
            ret = CSRRegInstruction("csrrw", fuzzerstate.intregpickstate.pick_int_outputreg(), fuzzerstate.intregpickstate.pick_int_inputreg(), CSR_IDS.SSCRATCH)
        else:
            raise Exception("Unexpected target_csr: {}".format(target_csr))
    return ret
