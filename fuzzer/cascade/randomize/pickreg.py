# Copyright 2023 Flavien Solt, ETH Zurich.
# Licensed under the General Public License, Version 3.0, see LICENSE for details.
# SPDX-License-Identifier: GPL-3.0-only

from params.runparams import DO_ASSERT, DO_EXPENSIVE_ASSERT
from params.fuzzparams import REGPICK_PROTUBERANCE_RATIO,  REGPICK_PROTUBERANCE_RATIO_T0_POS, REGPICK_PROTUBERANCE_RATIO_T0_NEG, NUM_MIN_FREE_INTREGS, RDEP_MASK_REGISTER_ID, RELOCATOR_REGISTER_ID,  MAX_NUM_PICKABLE_REGS, NUM_MIN_UNTAINTED_INTREGS, MIN_WEIGHT_T0, MAX_WEIGHT_T0
from cascade.randomize.createcfinstr import create_targeted_producer0_instrobj, create_targeted_producer1_instrobj, create_targeted_consumer_instrobj
from cascade.util import IntRegIndivState
from cascade.registers import Int32RegState, ABI_INAMES
from common.spike import SPIKE_STARTADDR
from cascade.registers import ABI_INAMES,MAX_32b
from copy import copy, deepcopy
import math
import numpy as np
import random

class IntRegPickState:
    def __init__(self, num_pickable_regs: int):
        self.num_pickable_regs = num_pickable_regs
        self.__reg_weights  = np.ones(self.num_pickable_regs)
        self.__reg_weights /= np.sum(self.__reg_weights)

        self.__reg_weights_t0  = np.ones(self.num_pickable_regs)
        self.__reg_weights_t0 /= np.sum(self.__reg_weights_t0)

        # self.regs   = [IntRegIndivState.FREE for _ in range(self.num_pickable_regs)]
        self.regs = {id:Int32RegState(id) for id in range(self.num_pickable_regs)}
        self.regs[RELOCATOR_REGISTER_ID] = Int32RegState(RELOCATOR_REGISTER_ID)
        self.regs[RDEP_MASK_REGISTER_ID] = Int32RegState(RDEP_MASK_REGISTER_ID)
        # Permits matching sensitive instructions with the producers
        self.__last_producer_ids = np.zeros(self.num_pickable_regs)
        # For each register, a pair of (basic block id, instr in basic block) that produced the register
        self.__last_producer_coords = [[[None, None], [None, None]] for _ in range(self.num_pickable_regs)]
        if DO_ASSERT:
            self.__last_producer_ids.fill(None) # To avoid luckily having offset 0
        # Mnemonic list for speeding up searches
        self.__regs_in_state_onehot = {curr_indiv_state: np.ones(self.num_pickable_regs, np.int8) if (curr_indiv_state == IntRegIndivState.FREE) else np.zeros(self.num_pickable_regs, np.int8) for curr_indiv_state in IntRegIndivState}
        # Will ignore x0 if line below is uncommented. This is a design decision.
        # self.__reg_weights[0] = 0

    def set_initial_values(self, fuzzerstate):
        for i,reg_data_content in enumerate(fuzzerstate.initial_reg_data_content):
            self.regs[i+1].set_val(reg_data_content) # skip reg 0
            self.regs[i+1].set_val_t0(0x0)
        self.regs[RELOCATOR_REGISTER_ID].set_val(SPIKE_STARTADDR)
        self.regs[RELOCATOR_REGISTER_ID].set_val_t0(0x0)
        self.regs[RDEP_MASK_REGISTER_ID].set_val(MAX_32b)
        self.regs[RDEP_MASK_REGISTER_ID].set_val_t0(0x0)

    def get_free_regs_onehot(self):
        ret = [int(self.regs[reg_id].fsm_state == IntRegIndivState.FREE) for reg_id in range(self.num_pickable_regs)]
        if DO_ASSERT:
            assert sum(ret) >= NUM_MIN_FREE_INTREGS
        return ret

    def get_untainted_regs_onehot(self):
        ret = [int(self.regs[reg_id].get_val_t0() == 0) for reg_id in range(self.num_pickable_regs)]
        if DO_ASSERT:
            assert sum(ret) >= NUM_MIN_UNTAINTED_INTREGS, f"There are less than {NUM_MIN_UNTAINTED_INTREGS} untainted registers available."
        return np.asarray(ret)

    def get_tainted_regs_onehot(self):
        ret = [int(self.regs[reg_id].get_val_t0() != 0) for reg_id in range(self.num_pickable_regs)]
        # if DO_ASSERT:
        #     assert sum(ret) >= NUM_MIN_TAINTED_REGS
        return np.asarray(ret)

    # def get_free_untainted_regs_onehot(self):
    #     ret = [int(self.regs[reg_id].fsm_state == IntRegIndivState.FREE and self.regs[reg_id].get_val_t0() == 0) for reg_id in range(self.num_pickable_regs)]
    #     return ret

    # def get_free_tainted_regs_onehot(self):
    #     ret = [int(self.regs[reg_id].fsm_state == IntRegIndivState.FREE and self.regs[reg_id].get_val_t0() != 0) for reg_id in range(self.num_pickable_regs)]
    #     return ret

    def get_free_or_relocused_regs_onehot(self): # WARNING: Use those only for outputs, not for inputs.
        ret = [int(self.regs[reg_id].fsm_state == IntRegIndivState.FREE) for reg_id in range(self.num_pickable_regs)]
        if DO_ASSERT:
            assert sum(ret) >= NUM_MIN_FREE_INTREGS
        return ret

    # def get_free_or_relocused_untainted_regs_onehot(self): # WARNING: Use those only for outputs, not for inputs.
    #     ret = [int(self.regs[reg_id].fsm_state == IntRegIndivState.FREE and self.regs[reg_id].get_val_t0() == 0) for reg_id in range(self.num_pickable_regs)]
    #     return ret

    # Weights after deducting the forbidden registers
    def get_effective_weights(self, authorized_regs_onehot):
        if DO_ASSERT:
            assert np.any(authorized_regs_onehot)
        return self.__reg_weights * authorized_regs_onehot

    # Weights after deducting the forbidden registers
    def get_effective_weights_t0(self, authorized_regs_onehot, inverse = False, force = False):
        if not force:
            taint_hws = np.asarray([reg.get_val_t0().bit_count()/reg.n_bits for reg in self.regs.values() if reg.id != RELOCATOR_REGISTER_ID and reg.id != RDEP_MASK_REGISTER_ID])
            if not inverse:
                taint_ps = self.__reg_weights + taint_hws*REGPICK_PROTUBERANCE_RATIO_T0_POS # Add pertubation to drive probability up for registers with higher taint hamming weight.
                taint_ps = np.asarray([i if i<MAX_WEIGHT_T0 else MAX_WEIGHT_T0 for i in taint_ps]) # upper bound with MAX_WEIGHT_T0
            else:
                taint_ps = self.__reg_weights - taint_hws*REGPICK_PROTUBERANCE_RATIO_T0_NEG # Substract to do the opposite.            
                taint_ps = np.asarray([i if i>MIN_WEIGHT_T0 else MIN_WEIGHT_T0 for i in taint_ps]) # lower bound with MIN_WEIGHT_T0

        else:
            if inverse:
                taint_ps = self.get_untainted_regs_onehot()
            else:
                taint_ps = self.get_tainted_regs_onehot()
            
            # If we force the register to be tainted or untainted, prefer the most recently used one that fulfulls the criteria.
            taint_ps = taint_ps * self.__reg_weights

        taint_ps_sum = np.sum(taint_ps)
        taint_ps /= taint_ps_sum if taint_ps_sum else 1

        if DO_ASSERT:
            # self.print()
            assert math.isclose(sum(taint_ps), 1, abs_tol=0.001), f"{sum(taint_ps)} {str(taint_ps)}"

        if DO_ASSERT:
            assert np.sum(taint_ps * authorized_regs_onehot) > 0, f"No register fulfills requested requirements! {self.__reg_weights}, {taint_ps}, {authorized_regs_onehot}"


        return  taint_ps * authorized_regs_onehot

    # Returns a free inputreg.
    def pick_int_inputreg(self, authorize_sideeffects: bool = True):
        return random.choices(range(self.num_pickable_regs), self.get_effective_weights(self.get_free_regs_onehot()))[0]
    
    # Returns a free and likely tainted inputreg.
    def pick_tainted_int_inputreg(self, authorize_sideeffects: bool = True, force: bool = False):
        return random.choices(range(self.num_pickable_regs), self.get_effective_weights_t0(self.get_free_regs_onehot(), False, force))[0]

    # Excludes the zero register
    def pick_int_inputreg_nonzero(self, authorize_sideeffects: bool = True):
        authorized_regs_onehot = self.get_free_regs_onehot()
        was_zero_authorized = authorized_regs_onehot[0]
        authorized_regs_onehot[0] = 0
        id = random.choices(range(self.num_pickable_regs), self.get_effective_weights(authorized_regs_onehot))[0]
        authorized_regs_onehot[0] = was_zero_authorized
        return id

    # Excludes the zero register
    def pick_tainted_int_inputreg_nonzero(self, authorize_sideeffects: bool = True, force: bool = False):
        authorized_regs_onehot = self.get_free_regs_onehot()
        was_zero_authorized = authorized_regs_onehot[0]
        authorized_regs_onehot[0] = 0
        id = random.choices(range(self.num_pickable_regs), self.get_effective_weights_t0(authorized_regs_onehot, False, force))[0]
        authorized_regs_onehot[0] = was_zero_authorized
        return id

    # Excludes the zero register. When force is enabled, will either throw an exception or return an untainted register.
    def pick_untainted_int_inputreg_nonzero(self, authorize_sideeffects: bool = True, force: bool = False):
        authorized_regs_onehot = self.get_free_regs_onehot()
        was_zero_authorized = authorized_regs_onehot[0]
        authorized_regs_onehot[0] = 0
        id = random.choices(range(self.num_pickable_regs), self.get_effective_weights_t0(authorized_regs_onehot, True, force))[0]
        authorized_regs_onehot[0] = was_zero_authorized
        return id

    # Consuming multiple input registers in one go.
    def pick_int_inputregs(self, n: int):
        authorized_regs_onehot = self.get_free_regs_onehot()
        if DO_ASSERT:
            assert n > 1, "The function pick_int_inputregs should not be used for n < 2. For n = 1, please use pick_int_inputreg."
        return random.choices(range(self.num_pickable_regs), self.get_effective_weights(authorized_regs_onehot), k=n)

    # Consuming multiple (likely) tainted input registers in one go.
    def pick_tainted_int_inputregs(self, n: int, force: bool = False):
        authorized_regs_onehot = self.get_free_regs_onehot()
        if DO_ASSERT:
            assert n > 1, "The function pick_int_inputregs should not be used for n < 2. For n = 1, please use pick_int_inputreg."
        return random.choices(range(self.num_pickable_regs), self.get_effective_weights_t0(authorized_regs_onehot, False, force), k=n)

    # Consuming multiple (likely) untainted input registers in one go.
    def pick_untainted_int_inputregs(self, n: int, force: bool = False):
        authorized_regs_onehot = self.get_free_regs_onehot()
        if DO_ASSERT:
            assert n > 1, "The function pick_int_inputregs should not be used for n < 2. For n = 1, please use pick_int_inputreg."
        return random.choices(range(self.num_pickable_regs), self.get_effective_weights_t0(authorized_regs_onehot, True, force), k=n)

    # This updates the Int32RegState.
    def pick_int_outputreg(self, authorize_sideeffects: bool = True):
        authorized_regs_onehot = self.get_free_or_relocused_regs_onehot() # We could use any, but let's not waste the generated ones
        if DO_ASSERT:
            assert np.max(authorized_regs_onehot) == 1, "Unexpectedly, some register was registered in two states at a time."
        rd = random.choices(range(self.num_pickable_regs), self.get_effective_weights(authorized_regs_onehot))[0]
        if authorize_sideeffects:
            self._update_probaweights(rd)
            if rd:
                self.set_regstate(rd, IntRegIndivState.FREE)
        return rd

    def pick_untainted_int_outputreg(self, authorize_sideeffects: bool = True, force: bool = False):
        authorized_regs_onehot = self.get_free_or_relocused_regs_onehot() # We could use any, but let's not waste the generated ones
        if DO_ASSERT:
            assert np.max(authorized_regs_onehot) == 1, "Unexpectedly, some register was registered in two states at a time."
        rd = random.choices(range(self.num_pickable_regs), self.get_effective_weights_t0(authorized_regs_onehot, True, force))[0]
        if authorize_sideeffects:
            self._update_probaweights(rd)
            if rd:
                self.set_regstate(rd, IntRegIndivState.FREE)
        return rd
  
    def pick_int_outputreg_nonzero(self, authorize_sideeffects: bool = True):
        authorized_regs_onehot = self.get_free_or_relocused_regs_onehot() # We could use any, but let's not waste the generated ones
        was_zero_authorized = authorized_regs_onehot[0]
        authorized_regs_onehot[0] = 0
        if DO_ASSERT:
            assert np.max(authorized_regs_onehot) == 1, "Unexpectedly, some register was registered in two states at a time."
        rd = random.choices(range(self.num_pickable_regs), self.get_effective_weights(authorized_regs_onehot))[0]
        if authorize_sideeffects:
            self._update_probaweights(rd)
            if rd:
                self.set_regstate(rd, IntRegIndivState.FREE)
        authorized_regs_onehot[0] = was_zero_authorized
        return rd

    def pick_untainted_int_outputreg_nonzero(self, authorize_sideeffects: bool = True, force: bool = False):
        authorized_regs_onehot = self.get_free_or_relocused_regs_onehot() # We could use any, but let's not waste the generated ones
        was_zero_authorized = authorized_regs_onehot[0]
        authorized_regs_onehot[0] = 0
        if DO_ASSERT:
            assert np.max(authorized_regs_onehot) == 1, "Unexpectedly, some register was registered in two states at a time."
        rd = random.choices(range(self.num_pickable_regs), self.get_effective_weights_t0(authorized_regs_onehot, True, force))[0]
        if authorize_sideeffects:
            self._update_probaweights(rd)
            if rd:
                self.set_regstate(rd, IntRegIndivState.FREE)
        authorized_regs_onehot[0] = was_zero_authorized
        return rd

    # @param outreg the produced register.
    def _update_probaweights(self, outreg: int):
        if DO_ASSERT:
            assert 0 <= outreg
            assert outreg < self.num_pickable_regs
            assert math.isclose(sum(self.__reg_weights), 1, abs_tol=0.001), f"{sum(self.__reg_weights)} {str(self.__reg_weights)}"
        # # Ignore x0
        # if outreg == 0:
        #     return
        # The lines here below are a heuristic algorithm to favor more recently produced registers
        sum_of_others = np.sum(self.__reg_weights) - self.__reg_weights[outreg]
        for reg_id in range(self.num_pickable_regs):
            # We also do it (for performance) for outreg and we overwrite it later
            self.__reg_weights[reg_id] = self.__reg_weights[reg_id] * (1-REGPICK_PROTUBERANCE_RATIO) / sum_of_others
        self.__reg_weights[outreg] = REGPICK_PROTUBERANCE_RATIO



    # Getter and setter for register states
    def get_regstate(self, reg_id: int):
        if DO_ASSERT:
            assert 0 < reg_id
            assert reg_id < self.num_pickable_regs
        return self.regs[reg_id].fsm_state

    # @param force: do not check compatibility before->after. Used for restoring some saved state, for example.
    def set_regstate(self, reg_id: int, new_state: int, force: bool = False):
        if DO_ASSERT:
            assert 0 < reg_id
            assert reg_id < self.num_pickable_regs
            if not force:
                if self.regs[reg_id].fsm_state == IntRegIndivState.FREE:
                    assert new_state in (IntRegIndivState.FREE, IntRegIndivState.PRODUCED0, IntRegIndivState.CONSUMED)
                elif self.regs[reg_id].fsm_state == IntRegIndivState.PRODUCED0:
                    assert new_state == IntRegIndivState.PRODUCED1
                elif self.regs[reg_id].fsm_state == IntRegIndivState.PRODUCED1:
                    assert new_state in (IntRegIndivState.CONSUMED, IntRegIndivState.UNRELIABLE)
                elif self.regs[reg_id].fsm_state == IntRegIndivState.CONSUMED:
                    assert new_state == IntRegIndivState.FREE
                if DO_EXPENSIVE_ASSERT:
                    # Check that the register is registered in exactly one state
                    for s in IntRegIndivState:
                        assert self.__regs_in_state_onehot[s][reg_id] == int(s == self.regs[reg_id].fsm_state)
                else:
                    assert self.__regs_in_state_onehot[self.regs[reg_id].fsm_state][reg_id]
        self.__regs_in_state_onehot[self.regs[reg_id].fsm_state][reg_id] = 0
        self.__regs_in_state_onehot[new_state][reg_id] = 1
        self.regs[reg_id].fsm_state = new_state
    # Brings iteratively a register to the requested state, as fast as possible
    # @return nothing, but guarantees that a register will be in the target state
    def bring_some_reg_to_state(self, req_state: int, fuzzerstate):
        if DO_ASSERT:
            assert req_state == IntRegIndivState.CONSUMED
        if req_state == IntRegIndivState.CONSUMED:
            if self.exists_reg_in_state(IntRegIndivState.CONSUMED):
                return # self.pick_int_reg_in_state(IntRegIndivState.CONSUMED)
            if self.exists_reg_in_state(IntRegIndivState.PRODUCED1):
                fuzzerstate.append_and_execute_instr(create_targeted_consumer_instrobj(fuzzerstate), False)
                return # self.pick_int_reg_in_state(IntRegIndivState.CONSUMED)
            if self.exists_reg_in_state(IntRegIndivState.PRODUCED0):
                fuzzerstate.append_and_execute_instr(create_targeted_producer1_instrobj(fuzzerstate), False)
                # Consumer also includes preconsumer
                fuzzerstate.append_and_execute_isntr(create_targeted_consumer_instrobj(fuzzerstate), False)
                return # self.pick_int_reg_in_state(IntRegIndivState.CONSUMED)
            if self.exists_reg_in_state(IntRegIndivState.FREE):
                fuzzerstate.append_and_execute(create_targeted_producer0_instrobj(fuzzerstate), False)
                fuzzerstate.append_and_execute(create_targeted_producer1_instrobj(fuzzerstate), False)
                # Consumer also includes preconsumer
                fuzzerstate.append_and_execute(create_targeted_consumer_instrobj(fuzzerstate), False)
                return # self.pick_int_reg_in_state(IntRegIndivState.CONSUMED)
            raise ValueError('Unexpected state.')

    # Save at the end of basic blocks, and restore if popping basic blocks from the end.
    def save_curr_state(self):
        return copy(self.__reg_weights), copy([reg.fsm_state for _,reg in self.regs.items()]), copy(self.__last_producer_ids), deepcopy(self.__last_producer_coords), deepcopy(self.regs)
    
    # Rarely called.
    def restore_state(self, saved_state: tuple):
        if DO_ASSERT:
            assert len(saved_state) == 5
        # Restore the reg weights (this is not so important)
        self.__reg_weights = copy(saved_state[0])
        # Restore the reg states. Be careful to also restore the internal matrix. Therefore, use the API function.
        for reg_id in range(1, self.num_pickable_regs):
            self.set_regstate(reg_id, saved_state[1][reg_id], force=True)
        self.__last_producer_ids = copy(saved_state[2])
        self.__last_producer_coords = deepcopy(saved_state[3])
        self.regs = copy(saved_state[4])

    # Getters and setters for producer ids 
    def get_producer_id(self, reg_id: int):
        return self.__last_producer_ids[reg_id]
    def set_producer_id(self, reg_id: int, producer_id: int):
        self.__last_producer_ids[reg_id] = producer_id
    def set_producer0_location(self, reg_id: int, bb_id: int, instr_id_in_bb: int):
        self.__last_producer_coords[reg_id][0] = (bb_id, instr_id_in_bb)
    def set_producer1_location(self, reg_id: int, bb_id: int, instr_id_in_bb: int):
        self.__last_producer_coords[reg_id][1] = (bb_id, instr_id_in_bb)

    # Getters for registers in a certain state
    def exists_reg_in_state(self, req_state: IntRegIndivState) -> bool:
        return np.any(self.__regs_in_state_onehot[req_state])
    def exists_untainted_reg_in_state(self, req_state: IntRegIndivState) -> bool:
        regs_in_state = self.__regs_in_state_onehot[req_state]
        untainted_regs = [int(reg.get_val_t0() == 0) for reg in self.regs.values()]
        untainted_regs_in_state = [int(i&j) for i,j in zip(regs_in_state,untainted_regs)]
        return np.any(untainted_regs_in_state)
    def get_num_regs_in_state(self, req_state: IntRegIndivState) -> bool:
        return np.sum(self.__regs_in_state_onehot[req_state])
    def pick_int_reg_in_state(self, req_state: IntRegIndivState):
        if DO_ASSERT:
            assert self.exists_reg_in_state(req_state), f"No reg in state `{req_state}`"
        ret = None
        while ret is None or not self.__regs_in_state_onehot[req_state][ret]:
            ret = random.choices(range(self.num_pickable_regs), self.__regs_in_state_onehot[req_state], k=1)[0]
        return ret
        
    # If available, returns an untainted register in requested state if force is disabled. If all are tainted, returns a tainted one  or throws an exception if no regs are in the state.
    def pick_untainted_int_reg_in_state(self, req_state: IntRegIndivState, force: bool = False):
        if DO_ASSERT:
            if force:
                assert self.exists_untainted_reg_in_state(req_state), f"No untainted reg in state `{req_state.name}`."
            else:
                assert self.exists_reg_in_state(req_state), f"No reg in state `{req_state.name}`."
        regs_in_state = self.__regs_in_state_onehot[req_state]
        regs_in_state = regs_in_state * self.get_effective_weights_t0(regs_in_state, True, force)

        ret = None
        while ret is None or not regs_in_state[ret]:
            ret = random.choices(range(self.num_pickable_regs), regs_in_state, k=1)[0]
        assert regs_in_state[ret]
        if force:
            # self.print()
            assert self.regs[ret].get_val_t0() == 0, f"Chosen register {ABI_INAMES[ret]} is tainted! {regs_in_state}"
        return ret
    
    def display(self):
        print('pickreg', self.__regs_in_state_onehot)

    def print(self):
        row = ["ID","VALUE","VALUE_T0", "STATE"]
        print("{: >20} {: >20} {: >20} {: >20}".format(*row))
        row = ["*"*20,"*"*20,"*"*20, "*"*20]
        print("{: >20} {: >20} {: >20} {: >20}".format(*row))

        for _,reg in self.regs.items():
            reg.print()

# Float registers are never forbidden, therefore this is simpler than integer registers.
class FloatRegPickState:
    def __init__(self, num_pickable_floating_regs: int):
        self.num_pickable_floating_regs = num_pickable_floating_regs
        self.__reg_weights = np.ones(self.num_pickable_floating_regs)
        self.__reg_weights /= sum(self.__reg_weights)
    # Consuming a register does not update the float pick state.
    def pick_float_inputreg(self):
        return random.choices(range(self.num_pickable_floating_regs), self.__reg_weights)[0]
    # Consuming multiple input registers in one go.
    def pick_float_inputregs(self, n: int):
        if DO_ASSERT:
            assert n > 1, "The function pick_float_inputregs should not be used for n < 2. For n = 1, please use pick_float_inputreg."
        return random.choices(range(self.num_pickable_floating_regs), self.__reg_weights, k=n)
    # This updates the floatregstate.
    def pick_float_outputreg(self):
        rd = random.choices(range(self.num_pickable_floating_regs), self.__reg_weights)[0]
        self._update_floatregstate(rd)
        return rd
    # @param outreg the produced register.
    def _update_floatregstate(self, outreg: int):
        if DO_ASSERT:
            assert 0 <= outreg
            assert outreg < self.num_pickable_floating_regs
            assert math.isclose(sum(self.__reg_weights), 1, abs_tol=0.001), f"{sum(self.__reg_weights)} {str(self.__reg_weights)}"
        # The lines here below are a heuristic algorithm to favor more recently produced registers
        if self.num_pickable_floating_regs > 1: # If there is a single one, we do not want to zero its weight
            sum_of_others = np.sum(self.__reg_weights) - self.__reg_weights[outreg]
            for reg_id in range(self.num_pickable_floating_regs):
                # We also do it (for performance) for outreg and we overwrite it later
                self.__reg_weights[reg_id] = self.__reg_weights[reg_id] * (1-REGPICK_PROTUBERANCE_RATIO) / sum_of_others
            self.__reg_weights[outreg] = REGPICK_PROTUBERANCE_RATIO
