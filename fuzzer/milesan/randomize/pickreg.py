# Copyright 2024 Tobias Kovats, Flavien Solt, ETH Zurich.
# Licensed under the General Public License, Version 3.0, see LICENSE for details.
# SPDX-License-Identifier: GPL-3.0-only

from params.runparams import DO_ASSERT, DO_EXPENSIVE_ASSERT, PRINT_FSM_TRANSITIONS, PRINT_WRITEBACK_T0
from params.fuzzparams import REGPICK_PROTUBERANCE_RATIO,  REGPICK_PROTUBERANCE_RATIO_T0_POS, REGPICK_PROTUBERANCE_RATIO_T0_NEG, NUM_MIN_FREE_INTREGS,  MAX_NUM_PICKABLE_REGS, NUM_MIN_UNTAINTED_INTREGS, MIN_WEIGHT_T0, MAX_WEIGHT_T0, P_TAINT_REG, NUM_MIN_TAINTED_REGS, DISABLE_COMPUTATION_ON_TAINT
from params.fuzzparams import RDEP_MASK_REGISTER_ID, RELOCATOR_REGISTER_ID, FPU_ENDIS_REGISTER_ID, MPP_BOTH_ENDIS_REGISTER_ID, MPP_TOP_ENDIS_REGISTER_ID, SPP_ENDIS_REGISTER_ID, REGDUMP_REGISTER_ID
from params.fuzzparams import USE_TAINT_HW, USE_TAINT_TANH, USE_TAINT_BIN, NONPICKABLE_REGISTERS, TAINT_EN
from milesan.randomize.createcfinstr import create_targeted_producer0_instrobj, create_targeted_producer1_instrobj, create_targeted_consumer_instrobj
from milesan.util import IntRegIndivState
from milesan.registers import IntRegister, ABI_INAMES
from common.spike import SPIKE_STARTADDR, SPIKE_BOOTVAL_A1
from milesan.registers import ABI_INAMES,MAX_32b, MAX_64b
from copy import copy, deepcopy
import math
import numpy as np
import random

class IntRegPickState:
    def __init__(self, fuzzerstate):
        self.fuzzerstate = fuzzerstate
        self.num_pickable_regs = fuzzerstate.num_pickable_regs
        self.__reg_weights  = np.ones(self.num_pickable_regs)
        self.__reg_weights /= np.sum(self.__reg_weights)

        self.__reg_weights_t0  = np.ones(self.num_pickable_regs)
        self.__reg_weights_t0 /= np.sum(self.__reg_weights_t0)

        self.setup_registers()
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


    def setup_registers(self):
        self.regs = {id:IntRegister(id,self.fuzzerstate.is_design_64bit,pickable=True) for id in range(self.num_pickable_regs)} # pickable registers
        # Below are non-pickable registers.
        for reg_id in NONPICKABLE_REGISTERS:
            self.regs[reg_id] = IntRegister(reg_id,self.fuzzerstate.is_design_64bit)
        self.set_spike_boot_values()

    def set_initial_values(self, fuzzerstate): # Reset seed to starting value to ensure random values match if this function is called twice.
        raise NotImplementedError("Depricated.")
        random.seed(fuzzerstate.randseed)
        for i,reg_data_content in enumerate(fuzzerstate.initial_reg_data_content):
            self.regs[i+1].set_val(reg_data_content) # skip reg 0
            if random.random() < P_TAINT_REG:
                self.regs[i+1].set_val_t0(random.randint(1,MAX_64b if self.fuzzerstate.is_design_64bit else MAX_32b))
            else:
                self.regs[i+1].set_val_t0(0x0)
        self.regs[RELOCATOR_REGISTER_ID].set_val(SPIKE_STARTADDR)
        self.regs[RELOCATOR_REGISTER_ID].set_val_t0(0x0)
        self.regs[RDEP_MASK_REGISTER_ID].set_val(MAX_32b)
        self.regs[RDEP_MASK_REGISTER_ID].set_val_t0(0x0)

    def set_spike_boot_values(self): # Spike implicitly executes a couple of boot instructions that change the register values.
        if ABI_INAMES.index("t0") in range(self.num_pickable_regs): # We only modify them if they are considered during the register checks.
            self.regs[ABI_INAMES.index("t0")].set_val(SPIKE_STARTADDR) # The provided SPIKE_STARTADDR is loaded into t0 during boot.
        if ABI_INAMES.index("a1") in range(self.num_pickable_regs):
            self.regs[ABI_INAMES.index("a1")].set_val(SPIKE_BOOTVAL_A1)

    def reset(self):
        for reg in self.regs.values():
            reg.reset()

    def get_free_regs_onehot(self):
        ret = [int(self.regs[reg_id].fsm_state == IntRegIndivState.FREE) for reg_id in range(self.num_pickable_regs)]
        if DO_ASSERT:
            if sum(ret) < NUM_MIN_FREE_INTREGS:
                self.print()
                # assert False, f"There are less than {NUM_MIN_FREE_INTREGS} free integer registers available. ({ret})"
            assert sum(ret) >= NUM_MIN_FREE_INTREGS, f"There are less than {NUM_MIN_FREE_INTREGS} free integer registers available."
        return np.asarray(ret)

    def get_relocused_regs_onehot(self):
        ret = [int(self.regs[reg_id].fsm_state == IntRegIndivState.RELOCUSED) for reg_id in range(self.num_pickable_regs)]
        return np.asarray(ret)

    def get_untainted_regs_onehot(self):
        ret = [int(self.regs[reg_id].get_val_t0() == 0) for reg_id in range(self.num_pickable_regs)]
        # if DO_ASSERT:
            # if sum(ret) < NUM_MIN_UNTAINTED_INTREGS:
            #     # self.print()
            #     assert False,f"There are less than {NUM_MIN_UNTAINTED_INTREGS} untainted integer registers available."
            # assert sum(ret) >= NUM_MIN_UNTAINTED_INTREGS, f"There are less than {NUM_MIN_UNTAINTED_INTREGS} untainted integer registers available."
        return np.asarray(ret)

    def get_tainted_regs_onehot(self):
        ret = [int(self.regs[reg_id].get_val_t0() != 0) for reg_id in range(self.num_pickable_regs)]
        # if DO_ASSERT:
        #     assert sum(ret) >= NUM_MIN_TAINTED_REGS
        return np.asarray(ret)

    # If there are relocused regs, prioritize those as output. This way they return to the free state and can be used in the dataflow asap.
    # WARNING: Use those only for outputs, not for inputs, as the relocused registers change values between in-situ simulation and spike/final.
    def get_free_or_relocused_regs_onehot(self,min: int = 1): 
        ret = self.get_relocused_regs_onehot()
        if sum(ret) >= min: # if theres more than min relocused register, prioritize it to be used as output register.
            return ret
        return ret + self.get_free_regs_onehot()

    # Weights after deducting the forbidden registers
    def get_effective_weights(self, authorized_regs_onehot):
        if DO_ASSERT:
            assert np.any(authorized_regs_onehot)
        return self.__reg_weights * authorized_regs_onehot

    def _get_rel_taint_hw(self): 
        return np.asarray([self.regs[reg_id].get_val_t0().bit_count()/self.regs[reg_id].n_bits for reg_id in range(self.num_pickable_regs)])

    def _get_taint_bin(self): 
        return np.asarray([self.regs[reg_id].get_val_t0().bit_count()>0 for reg_id in range(self.num_pickable_regs)])

    def _get_rel_taint_tanh(self): # this is nice because it saturates and thus we prefer more taint but dont overfit on fully tainted regs
        return np.asarray([np.tanh(self.regs[reg_id].get_val_t0().bit_count()*np.pi/self.regs[reg_id].n_bits) for reg_id in range(self.num_pickable_regs)])

    def _get_taint_ps(self, inverse: bool):
        if USE_TAINT_TANH:
            taint_ps = self._get_rel_taint_tanh()
        elif USE_TAINT_HW:
            taint_ps = self._get_rel_taint_hw()
        elif USE_TAINT_BIN:
            taint_ps = self._get_taint_bin()
        if not inverse: # taint makes them more likely
            taint_ps = self.__reg_weights + taint_ps*REGPICK_PROTUBERANCE_RATIO_T0_POS # Add pertubation to drive probability up for registers with higher taint hamming weight.
            taint_ps = np.asarray([i if i<MAX_WEIGHT_T0 else MAX_WEIGHT_T0 for i in taint_ps]) # upper bound with MAX_WEIGHT_T0
        else: # taint makes them less likely
            taint_ps = self.__reg_weights - taint_ps*REGPICK_PROTUBERANCE_RATIO_T0_NEG # Substract to do the opposite.            
            taint_ps = np.asarray([i if i>MIN_WEIGHT_T0 else MIN_WEIGHT_T0 for i in taint_ps]) # lower bound with MIN_WEIGHT_T0
        return taint_ps

    # Weights after deducting the forbidden registers
    def get_effective_weights_t0(self, authorized_regs_onehot, inverse = False, force = False):
        if not force:
            taint_ps = self._get_taint_ps(inverse)
        else:
            if inverse:
                taint_ps = self.get_untainted_regs_onehot()
            else:
                taint_ps = self.get_tainted_regs_onehot()
            
            # If we force the register to be tainted or untainted, prefer the most recently used one that fulfulls the criteria.
            taint_ps = taint_ps * self.__reg_weights

        if DO_ASSERT:
            if not force:
                states = {ABI_INAMES[i]:[j,k,l] for i,(j,k,l) in enumerate(zip(self.__reg_weights,taint_ps,authorized_regs_onehot))}
            else:
                states = {ABI_INAMES[i]:[j,k] for i,(j,k) in enumerate(zip(taint_ps,authorized_regs_onehot))}
            assert np.sum(taint_ps * authorized_regs_onehot) > 0, f"No register fulfills requested requirements! {states}"


        taint_ps_sum = np.sum(taint_ps)
        taint_ps /= taint_ps_sum if taint_ps_sum else 1

        if DO_ASSERT:
            assert math.isclose(sum(taint_ps), 1, abs_tol=0.001), f"{sum(taint_ps)} {str(taint_ps)}"
        # print({ABI_INAMES[i]:[j,k,l] for i,(j,k,l) in enumerate(zip(self.__reg_weights,taint_ps,authorized_regs_onehot))})
        return  taint_ps * authorized_regs_onehot

    # Returns a free inputreg.
    def pick_int_inputreg(self, authorize_sideeffects: bool = True):
        return random.choices(range(self.num_pickable_regs), self.get_effective_weights(self.get_free_regs_onehot()))[0]
    
    # Returns a free and likely tainted inputreg.
    def pick_tainted_int_inputreg(self, authorize_sideeffects: bool = True, force: bool = False, allow_zero: bool = True):
        authorized_regs_onehot = self.get_free_regs_onehot()
        zero_allowed = authorized_regs_onehot[0]
        if zero_allowed and not allow_zero:
            authorized_regs_onehot[0] = 0
        id = random.choices(range(self.num_pickable_regs), self.get_effective_weights_t0(authorized_regs_onehot, False, force))[0]
        if DO_ASSERT:
            assert self.regs[id].fsm_state == IntRegIndivState.FREE
        authorized_regs_onehot[0] = zero_allowed
        return id

    # Excludes the zero register
    def pick_int_inputreg_nonzero(self, authorize_sideeffects: bool = True):
        authorized_regs_onehot = self.get_free_regs_onehot()
        was_zero_authorized = authorized_regs_onehot[0]
        authorized_regs_onehot[0] = 0
        id = random.choices(range(self.num_pickable_regs), self.get_effective_weights(authorized_regs_onehot))[0]
        authorized_regs_onehot[0] = was_zero_authorized
        if DO_ASSERT:
            assert self.regs[id].fsm_state == IntRegIndivState.FREE
        return id


    # Pick 2 different nonzero free registers. Used for li_doubleword
    def pick_int_inputregs_nonzero(self, n: int):
        ret = []
        authorized_regs_onehot = self.get_free_regs_onehot()
        was_zero_authorized = authorized_regs_onehot[0]
        authorized_regs_onehot[0] = 0
        if DO_ASSERT:
            assert n > 1, "The function pick_int_inputregs should not be used for n < 2. For n = 1, please use pick_int_inputreg."
            assert sum(authorized_regs_onehot) >= 2, f"There is less than 2 free regs that are not zero"
        #ret = random.sample(range(self.num_pickable_regs+1), k=n)
        r1 = random.choices(range(self.num_pickable_regs), self.get_effective_weights(authorized_regs_onehot))[0]
        ret.append(r1)
        authorized_regs_onehot[r1] = 0
        r2 = random.choices(range(self.num_pickable_regs), self.get_effective_weights(authorized_regs_onehot))[0]
        ret.append(r2)
        return ret


    # Excludes the zero register
    def pick_tainted_int_inputreg_nonzero(self, force: bool = False):
        authorized_regs_onehot = self.get_free_regs_onehot()
        was_zero_authorized = authorized_regs_onehot[0]
        authorized_regs_onehot[0] = 0
        id = random.choices(range(self.num_pickable_regs), self.get_effective_weights_t0(authorized_regs_onehot, False, force))[0]
        authorized_regs_onehot[0] = was_zero_authorized
        if DO_ASSERT:
            assert self.regs[id].fsm_state == IntRegIndivState.FREE
        return id

    # Excludes the zero register. When force is enabled, will either throw an exception or return an untainted register.
    def pick_untainted_int_inputreg_nonzero(self, force: bool = False, val_range: tuple = None, val_t0_range: tuple = None):
        authorized_regs_onehot = self.get_free_regs_onehot()
        was_zero_authorized = authorized_regs_onehot[0]
        authorized_regs_onehot[0] = 0
        regs_in_range_onehot = [1 for _ in range(len(authorized_regs_onehot))]
        if val_range is not None:
            regs_in_range_onehot &= [reg.get_val() in val_range for reg in self.regs[:self.num_pickable_regs]]
        if val_t0_range is not None:
            assert TAINT_EN
            regs_in_range_onehot &= [reg.get_val_t0() in val_t0_range for reg in self.regs[:self.num_pickable_regs]]
        if DO_ASSERT:
            # if self.get_num_untainted_regs_in_state(IntRegIndivState.FREE) < NUM_MIN_UNTAINTED_INTREGS:
                # self.print()
            assert self.get_num_untainted_regs_in_state(IntRegIndivState.FREE) >= NUM_MIN_UNTAINTED_INTREGS, f"There are less than {NUM_MIN_UNTAINTED_INTREGS} untainted integer registers available."
        id = random.choices(range(self.num_pickable_regs), self.get_effective_weights_t0([i&j for i,j in zip(authorized_regs_onehot,regs_in_range_onehot)], True, force))[0]
        authorized_regs_onehot[0] = was_zero_authorized
        if DO_ASSERT:
            assert self.regs[id].fsm_state == IntRegIndivState.FREE
        return id

    def exists_free_intreg_in_range(self, val_range: tuple = None, val_t0_range: tuple = None, allow_zero: bool = False):
        regs_in_range_onehot = self.get_free_regs_onehot()
        if not allow_zero:
            regs_in_range_onehot[0] = 0
        if val_range is not None:
            regs_in_range_onehot &= [reg.get_val() in val_range for reg in self.regs[:self.num_pickable_regs]]
        if val_t0_range is not None:
            assert TAINT_EN
            regs_in_range_onehot &= [reg.get_val_t0() in val_t0_range for reg in self.regs[:self.num_pickable_regs]]

        return sum(regs_in_range_onehot) > 0

    # Includes the zero register. When force is enabled, will either throw an exception or return an untainted register.
    def pick_untainted_int_inputreg(self, force: bool = False):
        authorized_regs_onehot = self.get_free_regs_onehot()
        id = random.choices(range(self.num_pickable_regs), self.get_effective_weights_t0(authorized_regs_onehot, True, force))[0]
        if DO_ASSERT:
            assert self.regs[id].fsm_state == IntRegIndivState.FREE
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

    # This updates the IntRegister.
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

    def pick_tainted_int_outputreg(self, authorize_sideeffects: bool = True, force: bool = False, allow_zero: bool = True):
        authorized_regs_onehot = self.get_free_or_relocused_regs_onehot() # We could use any, but let's not waste the generated ones
        zero_allowed = authorized_regs_onehot[0]
        if zero_allowed and not allow_zero:
            authorized_regs_onehot[0] = 0
        if DO_ASSERT:
            assert np.max(authorized_regs_onehot) == 1, "Unexpectedly, some register was registered in two states at a time."
        rd = random.choices(range(self.num_pickable_regs), self.get_effective_weights_t0(authorized_regs_onehot, False, force))[0]
        if authorize_sideeffects:
            self._update_probaweights(rd)
            if rd:
                self.set_regstate(rd, IntRegIndivState.FREE)
        authorized_regs_onehot[0] = zero_allowed
        return rd

    def pick_untainted_int_outputregs_nonzero(self, n:int, authorize_sideeffects: bool = True, force: bool = False):
        authorized_regs_onehot = self.get_free_or_relocused_regs_onehot(n) # We could use any, but let's not waste the generated ones
        was_zero_authorized = authorized_regs_onehot[0]
        authorized_regs_onehot[0] = 0
        if DO_ASSERT:
            assert np.max(authorized_regs_onehot) == 1, "Unexpectedly, some register was registered in two states at a time."
        regs = None
        assert sum(authorized_regs_onehot) >= n
        while regs is None or len(set(regs)) != n:
            regs = random.choices(range(self.num_pickable_regs), self.get_effective_weights_t0(authorized_regs_onehot, True, force), k=n)
        if authorize_sideeffects:
            for rd in regs:
                self._update_probaweights(rd)
                if rd:
                    self.set_regstate(rd, IntRegIndivState.FREE)
        authorized_regs_onehot[0] = was_zero_authorized
        return regs

  
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
                    assert new_state == IntRegIndivState.CONSUMED
                elif self.regs[reg_id].fsm_state == IntRegIndivState.CONSUMED:
                    assert new_state == IntRegIndivState.RELOCUSED
                elif self.regs[reg_id].fsm_state == IntRegIndivState.RELOCUSED:
                    assert new_state in (IntRegIndivState.FREE, IntRegIndivState.PRODUCED0, IntRegIndivState.CONSUMED)

                if DO_EXPENSIVE_ASSERT:
                    # Check that the register is registered in exactly one state
                    for s in IntRegIndivState:
                        assert self.__regs_in_state_onehot[s][reg_id] == int(s == self.regs[reg_id].fsm_state)
                else:
                    assert self.__regs_in_state_onehot[self.regs[reg_id].fsm_state][reg_id]
        self.__regs_in_state_onehot[self.regs[reg_id].fsm_state][reg_id] = 0
        self.__regs_in_state_onehot[new_state][reg_id] = 1
        if PRINT_FSM_TRANSITIONS:
            print(f"Setting {ABI_INAMES[reg_id]}: {self.regs[reg_id].fsm_state.name} -> {new_state.name}")
        self.regs[reg_id].fsm_state = new_state
    # Brings iteratively a register to the requested state, as fast as possible
    # @return nothing, but guarantees that a register will be in the target state
    def bring_some_reg_to_state(self, req_state: int, fuzzerstate):
        if DO_ASSERT:
            assert req_state == IntRegIndivState.CONSUMED
        if req_state == IntRegIndivState.CONSUMED:
            if self.exists_reg_in_state(IntRegIndivState.CONSUMED):
                return # self.pick_int_reg_in_state(IntRegIndivState.CONSUMED)
            elif self.exists_reg_in_state(IntRegIndivState.PRODUCED1):
                for instr in create_targeted_consumer_instrobj(fuzzerstate):
                    fuzzerstate.append_and_execute_instr(instr)
            elif self.exists_reg_in_state(IntRegIndivState.PRODUCED0):
                for instr in create_targeted_producer1_instrobj(fuzzerstate):
                    fuzzerstate.append_and_execute_instr(instr)
                for instr in create_targeted_consumer_instrobj(fuzzerstate):
                    fuzzerstate.append_and_execute_instr(instr)
            elif self.exists_reg_in_state(IntRegIndivState.FREE):
                for instr in create_targeted_producer0_instrobj(fuzzerstate):
                    fuzzerstate.append_and_execute_instr(instr)
                for instr in create_targeted_producer1_instrobj(fuzzerstate): 
                    fuzzerstate.append_and_execute_instr(instr)
                for instr in create_targeted_consumer_instrobj(fuzzerstate):
                    fuzzerstate.append_and_execute_instr(instr)

            else: 
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
    
    def exists_tainted_reg(self):
        return any([r.get_val_t0() for r in self.regs.values()])

    def get_tainted_free_regs(self):
        return [reg_id for reg_id in range(self.num_pickable_regs) if self.regs[reg_id].get_val_t0() and self.regs[reg_id].fsm_state == IntRegIndivState.FREE] 

    def get_untainted_free_regs(self):
        return [reg_id for reg_id in range(self.num_pickable_regs) if self.regs[reg_id].get_val_t0() == 0 and self.regs[reg_id].fsm_state == IntRegIndivState.FREE] 

    def exists_untainted_reg_in_state(self, req_state: IntRegIndivState, allow_zero = False) -> bool:
        untainted_regs_oneshot = self.get_untainted_regs_onehot()
        if not allow_zero: 
            untainted_regs_oneshot[0] = 0
        regs_ins_state_oneshot = self.__regs_in_state_onehot[req_state]
        return np.any(untainted_regs_oneshot * regs_ins_state_oneshot)

    def get_num_regs_in_state(self, req_state: IntRegIndivState) -> bool:
        return np.sum(self.__regs_in_state_onehot[req_state])

    def get_num_untainted_regs_in_state(self, req_state: IntRegIndivState) -> bool:
        return np.sum(self.__regs_in_state_onehot[req_state] * self.get_untainted_regs_onehot())

    def get_num_tainted_regs_in_state(self, req_state: IntRegIndivState) -> bool:
        return np.sum(self.__regs_in_state_onehot[req_state] * self.get_tainted_regs_onehot())

    def pick_int_reg_in_state(self, req_state: IntRegIndivState):
        if DO_ASSERT:
            assert self.exists_reg_in_state(req_state), f"No reg in state `{req_state.name}`"
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

        untainted_regs_in_state = self.get_effective_weights_t0(self.__regs_in_state_onehot[req_state], True, force)

        ret = None
        while ret is None or not untainted_regs_in_state[ret]:
            ret = random.choices(range(self.num_pickable_regs), untainted_regs_in_state, k=1)[0]
        if DO_ASSERT:
            assert untainted_regs_in_state[ret]
            if force:
                assert self.regs[ret].get_val_t0() == 0, f"Chosen register {ABI_INAMES[ret]} is tainted! {untainted_regs_in_state}"
        # if self.regs[ret].get_val_t0() == 0:
        #     print(f"WANT UNTAINTED: Got untainted reg.")
        # else:
        #     print(f"WANT UNTAINTED: Got tainted reg.")
        return ret
    
    def display(self):
        print('pickreg', self.__regs_in_state_onehot)

    def print(self):
        row = ["ID","VALUE","VALUE_T0","STATE","PICKABLE"]
        print("{: >20} {: >20} {: >20} {: >20} {: >20}".format(*row))
        row = ["*"*20,"*"*20,"*"*20, "*"*20, "*"*20]
        print("{: >20} {: >20} {: >20} {: >20} {: >20}".format(*row))

        for _,reg in self.regs.items():
            reg.print()

    def print_and_compare(self,regdumps_rtl):
        row = ["ID","VALUE (sim/rtl)","VALUE_T0 (sim/rtl)"]
        print("{: >30} {: >30} {: >30}".format(*row))
        row = ["*"*30,"*"*30,"*"*30]
        print("{: >30} {: >30} {: >30}".format(*row))

        for reg_id in range(1,self.num_pickable_regs):
            self.regs[reg_id].print_and_compare(regdumps_rtl[0][reg_id],regdumps_rtl[1][reg_id])

    # def add_writeback_trace(self, instr, reg, val_t0, is_spike_resolution):
    #     if PRINT_WRITEBACK_T0: 
    #         row = [instr.get_str(is_spike_resolution), ABI_INAMES[reg], val_t0]
    #         print("WRITEBACK_T0: {: <75}: {: >5} <- 0x{:016x}".format(*row))
    #     if is_spike_resolution:
    #         self.writeback_trace_in_situ[instr.paddr] = (reg, val_t0)
    #     else:
    #         self.writeback_trace_final[instr.paddr] = (reg,val_t0)

    # def verify_writeback_t0(self,final_addr: int = None, print_trace: bool = False):
    #     for (addr_insitu,trace_insitu),(addr_final, trace_final) in zip(self.writeback_trace_in_situ.items(),self.writeback_trace_final.items()):
    #         assert addr_insitu == addr_final, f"Address mismatch between insitu and final taint simulation {hex(addr_insitu)} != {hex(addr_final)}"
    #         assert trace_insitu[0] == trace_final[0], f"Register mismatch between insitu and final simulation {ABI_INAMES[trace_insitu[0]]} != {ABI_INAMES[trace_final[0]]}"
    #         assert trace_insitu[1] == trace_final[1], f"Mismatch in taint trace between in-situ simulation and final elf: {hex(addr_final)}: {ABI_INAMES[trace_insitu[0]]} <- {hex(trace_insitu[1])}/{hex(trace_final[1])} (in-situ/final)."
    #         if print_trace:
    #             row = [hex(addr_insitu),ABI_INAMES[trace_insitu[0]],hex(trace_insitu[1])]
    #             print("{: >20}: {: >20} <- {: >20}".format(*row))
    #         if final_addr is not None and final_addr == addr_insitu:
    #             return
    #     if DO_ASSERT:
    #         assert final_addr is None, f"Final address not reached {hex(final_addr)}."

    # def print_writebacks_t0(self, final_addr: int = None):
    #     if DO_ASSERT:
    #         len_in_situ =  len(self.writeback_trace_in_situ.items())
    #         len_final = len(self.writeback_trace_final.items())
    #         assert len_in_situ != 0
    #         assert len_final != 0
    #         assert len_in_situ == len_final
    #     for (addr_insitu,trace_insitu),(addr_final, trace_final) in zip(self.writeback_trace_in_situ.items(),self.writeback_trace_final.items()):
    #         row = [hex(addr_insitu),ABI_INAMES[trace_insitu[0]],hex(trace_insitu[1])]
    #         print("{: >20}: {: >20} <- {: >20}".format(*row))
    #         if final_addr is not None and final_addr == addr_insitu:
    #             return
    #     if DO_ASSERT:
    #         assert final_addr is None, f"Final address not reached {hex(final_addr)}."

    def analyze_writeback_trace(self, use_final: bool = True):
        n_tainted_bits = 0
        n_untainted_bits = 0
        n_tainted_writes = 0
        traces = self.writeback_trace_final if use_final else self.writeback_trace_in_situ
        for trace in traces.values():
            n_tainted_bits += trace[1].bit_count()
            n_untainted_bits += (64 if self.fuzzerstate.is_design_64bit else 32) - trace[1].bit_count()
            n_tainted_writes += int(trace[1].bit_count() > 0)
        # print(f"{n_tainted_bits}/{n_untainted_bits}/{len(traces)} (n_tainted_bits/n_untainted_bits/len(traces))")
        return n_tainted_bits, n_untainted_bits, n_tainted_writes, len(traces)

    # NOT TESTED, DO NOT USE
    def pick_two_free_regs_with_property(self, property_func):
        raise NotImplementedError("This is not tested and should not be used.")
        free_regs = self.get_free_regs_onehot()
        for reg0_id in range(self.num_pickable_regs):
            if not free_regs[reg0_id]:
                continue
            reg0_val = self.regs[reg0_id].get_val()
            for reg1_id in range(self.num_pickable_regs):
                if not free_regs[reg1_id]:
                    continue
                reg1_val = self.regs[reg1_id].get_val()
                if property_func(reg0_val,reg1_val):
                    return reg0_id, reg1_id

    def free_pageregs(self):
        while self.exists_reg_in_state(IntRegIndivState.PAGE_ADDR):
            reg_id = self.pick_int_reg_in_state(IntRegIndivState.PAGE_ADDR)
            self.set_regstate(reg_id, IntRegIndivState.FREE, force=True)
        while self.exists_reg_in_state(IntRegIndivState.PAGE_T0_ADDR):
            reg_id = self.pick_int_reg_in_state(IntRegIndivState.PAGE_T0_ADDR)
            self.set_regstate(reg_id, IntRegIndivState.FREE, force=True)


    def free_relocusedregs(self):
        while self.exists_reg_in_state(IntRegIndivState.RELOCUSED):
            reg_id = self.pick_int_reg_in_state(IntRegIndivState.RELOCUSED)
            self.set_regstate(reg_id, IntRegIndivState.FREE, force=True)
            
# Float registers are never forbidden, therefore this is simpler than integer registers.
class FloatRegPickState:
    def __init__(self, fuzzerstate):
        self.fuzzerstate = fuzzerstate
        self.num_pickable_floating_regs = fuzzerstate.num_pickable_floating_regs
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


