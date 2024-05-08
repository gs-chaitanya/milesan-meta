# Copyright 2023 Flavien Solt, ETH Zurich.
# Licensed under the General Public License, Version 3.0, see LICENSE for details.
# SPDX-License-Identifier: GPL-3.0-only

from params.runparams import DO_ASSERT, PRINT_INSTRUCTION_EXECUTION_IN_SITU, PRINT_INSTRUCTION_EXECUTION_REGDUMP_REQS, PATH_TO_TMP, INSERT_REGDUMPS, INSERT_FENCE, PRINT_ENVIRONMENT
from params.fuzzparams import RELOCATOR_REGISTER_ID, RDEP_MASK_REGISTER_ID, REGDUMP_REGISTER_ID, FPU_ENDIS_REGISTER_ID, MIN_NUM_PICKABLE_REGS, MAX_NUM_PICKABLE_REGS, MIN_NUM_PICKABLE_FLOATING_REGS, MAX_NUM_PICKABLE_FLOATING_REGS, MPP_BOTH_ENDIS_REGISTER_ID, MPP_TOP_ENDIS_REGISTER_ID, SPP_ENDIS_REGISTER_ID, MAX_NUM_STORE_LOCATIONS
from params.fuzzparams import TAINT_EN, MAX_CYCLES_PER_INSTR, SETUP_CYCLES, USE_SPIKE_INTERM_ELF
from common.designcfgs import is_design_32bit, design_has_float_support, design_has_double_support, design_has_muldiv_support, design_has_atop_support, design_has_misaligned_data_support, get_design_boot_addr, design_has_supervisor_mode, design_has_user_mode, design_has_compressed_support, design_has_pmp
from common.spike import SPIKE_STARTADDR, FPREG_ABINAMES

from cascade.util import ISAInstrClass, ExceptionCauseVal
from cascade.memview import MemoryView
from cascade.csrfile import CSRFile
from cascade.contextreplay import get_context_setter_max_size
from cascade.privilegestate import PrivilegeState
from cascade.randomize.pickstoreaddr import MemStoreState
from cascade.randomize.pickreg import IntRegPickState, FloatRegPickState
from cascade.randomize.pickisainstrclass import ISAINSTRCLASS_INITIAL_BOOSTERS
from cascade.randomize.pickexceptionop import EXCEPTION_OP_TYPE_INITIAL_BOOSTERS
from cascade.cfinstructionclasses_t0 import RegdumpInstruction_t0, SpecialInstruction_t0, has_taint_trace
from rv.csrids import CSR_IDS, CSR_ABI_NAMES

import random
import os
import itertools
import shutil

class FuzzerState:
    # @param randseed for identification purposes only.
    def __init__(self, design_base_addr: int, design_name: str, memsize: int, randseed: int, nmax_bbs: int, authorize_privileges: bool, taint_en: bool = TAINT_EN):
        # For identification
        self.randseed = randseed
        self.nmax_bbs = nmax_bbs
        self.memsize  = memsize
        self.authorize_privileges = authorize_privileges

        self.design_name = design_name
        self.design_base_addr = design_base_addr
        self.is_design_64bit = not is_design_32bit(design_name)
        self.design_has_compressed_support     : bool = design_has_compressed_support(design_name)
        self.design_has_fpu                    : bool = design_has_float_support(design_name)
        self.design_has_fpud                   : bool = design_has_double_support(design_name)
        self.design_has_muldiv                 : bool = design_has_muldiv_support(design_name)
        self.design_has_amo                    : bool = design_has_atop_support(design_name)
        self.design_has_misaligned_data_support: bool = design_has_misaligned_data_support(design_name)
        self.design_has_supervisor_mode        : bool = design_has_supervisor_mode(design_name)
        self.design_has_user_mode              : bool = design_has_user_mode(design_name)
        self.design_has_pmp                    : bool = design_has_pmp(design_name)

        self.gen_pick_weights()
        self.reset()
        self.init_design_state()

        self.inject_taint_addr = None
        self.taint_en = taint_en
        self.expected_regvals = None
        self.interm_elfpath = None
        self.rtl_elfpath = None
        
        self.tmp_dir = os.path.join(PATH_TO_TMP, self.design_name, self.instance_to_str())
        os.makedirs(self.tmp_dir,exist_ok=True)
       

    # @brief cleans up the fuzzerstate. Used in case of failed input generation.
    def reset(self):
        self.initial_block_data_start, self.initial_block_data_end = None, None
        self.random_block_content4by4bytes = []

        self.next_bb_addr = 0
        self.memview = MemoryView(self)
        self.memview_blacklist = MemoryView(self) # For load blacklist

        self.num_store_locations = random.randint(1, MAX_NUM_STORE_LOCATIONS)
        self.ctxsv_size_upperbound: int = get_context_setter_max_size(self) # Can be called once is_design_64bit, design_has_fpu and design_has_fpud are set, and the number of store locations is known.

        self.memstorestate = MemStoreState()
        self.csrfile = CSRFile()
        self.intregpickstate = IntRegPickState(self)
        self.floatregpickstate = FloatRegPickState(self)
        self.privilegestate = PrivilegeState()

        # self.instr_objs_seq does NEVER contain the final basic block.
        self.instr_objs_seq = [] # List (queue) of (for each basic block) lists of instruction objects
        self.bb_start_addr_seq = [] # List (queue) of bb start addresses. Self-managed through init_new_bb.
        self.saved_reg_states = [] # List (queue) of register save objects, as saved by pickreg.py

        # Strictly increasing when we create new producer0, to ensure uniqueness
        self.next_producer_id = 0
        # As a second phase, we will populate the producers with addresses before the spike resolution
        self.producer_id_to_tgtaddr = None
        self.producer_id_to_noreloc_spike = None
        # Register initial data address and content
        self.initial_reg_data_addr = -1
        self.initial_reg_data_content = []
        # Register final data address and content. The final bb is responsible for dumping the the final integer and floating registers.
        self.final_bb = []
        self.final_bb_base_addr = -1
        # Context setter
        self.ctxsv_bb = []
        self.ctxsv_bb_base_addr = -1
        self.ctxsv_bb_jal_instr_id = -1 # Useful because the last elements in ctxsv_bb are data.
        self.ctxdmp_bb = []
        self.ctxdmp_bb_base_addr = -1
        self.ctxdmp_bb_jal_instr_id = -1 # Useful because the last elements in ctxdmp_bb are data.

        # Instructions after the basic blocks, called block tails
        self.block_tail_instrs = [] # List of pairs (instr_obj, instr_addr)

        # Rocket has some inaccuracy in minstret because of ebreak and ecall. Hence, we don't read instret after these 2 instructions.
        self.is_minstret_inaccurate_because_ecall_ebreak = False
        # To avoid having too many fences
        self.special_instrs_count = 0
        # Coordinates of the FPU enable/disable instructions. Only used in program reduction.
        self.fpuendis_coords = []

        self.curr_addr = -1 # keep track of current address during program generation
        self.curr_pc = -1 # to validate correctness of simulated control flow
        self.inject_taint_addr = None # Has taint been injected yet? TODO: remove this

    def init_new_bb(self):
        self.instr_objs_seq.append([])

        self.curr_bb_start_addr = self.next_bb_addr
        self.next_bb_addr = None
        self.bb_start_addr_seq.append(self.curr_bb_start_addr)

    def gen_pick_weights(self):
        self.fpuweight = random.random() # Can decrease the overall FPU load to favor other types of instructions
        self.isapickweights = {
            ISAInstrClass.REGFSM:      (random.random() + 0.05) * ISAINSTRCLASS_INITIAL_BOOSTERS[ISAInstrClass.REGFSM],
            ISAInstrClass.FPUFSM:      (random.random() + 0.05) * ISAINSTRCLASS_INITIAL_BOOSTERS[ISAInstrClass.FPUFSM],
            ISAInstrClass.ALU:         (random.random() + 0.05) * ISAINSTRCLASS_INITIAL_BOOSTERS[ISAInstrClass.ALU],
            ISAInstrClass.ALU64:       (random.random() + 0.05) * ISAINSTRCLASS_INITIAL_BOOSTERS[ISAInstrClass.ALU64],
            ISAInstrClass.MULDIV:      (random.random() + 0.05) * ISAINSTRCLASS_INITIAL_BOOSTERS[ISAInstrClass.MULDIV],
            ISAInstrClass.MULDIV64:    (random.random() + 0.05) * ISAINSTRCLASS_INITIAL_BOOSTERS[ISAInstrClass.MULDIV64],
            ISAInstrClass.AMO:         (random.random() + 0.05) * ISAINSTRCLASS_INITIAL_BOOSTERS[ISAInstrClass.AMO],
            ISAInstrClass.AMO64:       (random.random() + 0.05) * ISAINSTRCLASS_INITIAL_BOOSTERS[ISAInstrClass.AMO64],
            ISAInstrClass.JAL :        (random.random() + 0.05) * ISAINSTRCLASS_INITIAL_BOOSTERS[ISAInstrClass.JAL],
            ISAInstrClass.JALR:        (random.random() + 0.05) * ISAINSTRCLASS_INITIAL_BOOSTERS[ISAInstrClass.JALR],
            ISAInstrClass.BRANCH:      (random.random() + 0.05) * ISAINSTRCLASS_INITIAL_BOOSTERS[ISAInstrClass.BRANCH],
            ISAInstrClass.MEM:         (random.random() + 0.05) * ISAINSTRCLASS_INITIAL_BOOSTERS[ISAInstrClass.MEM],
            ISAInstrClass.MEM64:       (random.random() + 0.05) * ISAINSTRCLASS_INITIAL_BOOSTERS[ISAInstrClass.MEM64],
            ISAInstrClass.MEMFPU:      (random.random() + 0.05) * ISAINSTRCLASS_INITIAL_BOOSTERS[ISAInstrClass.MEMFPU]  * self.fpuweight,
            ISAInstrClass.FPU:         (random.random() + 0.05) * ISAINSTRCLASS_INITIAL_BOOSTERS[ISAInstrClass.FPU]     * self.fpuweight,
            ISAInstrClass.FPU64:       (random.random() + 0.05) * ISAINSTRCLASS_INITIAL_BOOSTERS[ISAInstrClass.FPU64]   * self.fpuweight,
            ISAInstrClass.MEMFPUD:     (random.random() + 0.05) * ISAINSTRCLASS_INITIAL_BOOSTERS[ISAInstrClass.MEMFPUD] * self.fpuweight,
            ISAInstrClass.FPUD:        (random.random() + 0.05) * ISAINSTRCLASS_INITIAL_BOOSTERS[ISAInstrClass.FPUD]    * self.fpuweight,
            ISAInstrClass.FPUD64:      (random.random() + 0.05) * ISAINSTRCLASS_INITIAL_BOOSTERS[ISAInstrClass.FPUD64]  * self.fpuweight,
            ISAInstrClass.MEDELEG:     (random.random() + 0.05) * ISAINSTRCLASS_INITIAL_BOOSTERS[ISAInstrClass.MEDELEG],
            ISAInstrClass.TVECFSM:     (random.random() + 0.05) * ISAINSTRCLASS_INITIAL_BOOSTERS[ISAInstrClass.TVECFSM],
            ISAInstrClass.PPFSM:       (random.random() + 0.05) * ISAINSTRCLASS_INITIAL_BOOSTERS[ISAInstrClass.PPFSM],
            ISAInstrClass.EPCFSM:      (random.random() + 0.05) * ISAINSTRCLASS_INITIAL_BOOSTERS[ISAInstrClass.EPCFSM],
            ISAInstrClass.EXCEPTION:   (random.random() + 0.05) * ISAINSTRCLASS_INITIAL_BOOSTERS[ISAInstrClass.EXCEPTION],
            ISAInstrClass.RANDOM_CSR:  (random.random() + 0.05) * ISAINSTRCLASS_INITIAL_BOOSTERS[ISAInstrClass.RANDOM_CSR],
            ISAInstrClass.DESCEND_PRV: (random.random() + 0.05) * ISAINSTRCLASS_INITIAL_BOOSTERS[ISAInstrClass.DESCEND_PRV],
            ISAInstrClass.SPECIAL:     (random.random() + 0.05) * ISAINSTRCLASS_INITIAL_BOOSTERS[ISAInstrClass.SPECIAL],
        }
        self.exceptionoppickweights = {
            ExceptionCauseVal.ID_INSTR_ADDR_MISALIGNED:        (random.random() + 0.05) * EXCEPTION_OP_TYPE_INITIAL_BOOSTERS[ExceptionCauseVal.ID_INSTR_ADDR_MISALIGNED],
            ExceptionCauseVal.ID_INSTR_ACCESS_FAULT:           (random.random() + 0.05) * EXCEPTION_OP_TYPE_INITIAL_BOOSTERS[ExceptionCauseVal.ID_INSTR_ACCESS_FAULT],
            ExceptionCauseVal.ID_ILLEGAL_INSTRUCTION:          (random.random() + 0.05) * EXCEPTION_OP_TYPE_INITIAL_BOOSTERS[ExceptionCauseVal.ID_ILLEGAL_INSTRUCTION],
            ExceptionCauseVal.ID_BREAKPOINT:                   (random.random() + 0.05) * EXCEPTION_OP_TYPE_INITIAL_BOOSTERS[ExceptionCauseVal.ID_BREAKPOINT],
            ExceptionCauseVal.ID_LOAD_ADDR_MISALIGNED:         (random.random() + 0.05) * EXCEPTION_OP_TYPE_INITIAL_BOOSTERS[ExceptionCauseVal.ID_LOAD_ADDR_MISALIGNED],
            ExceptionCauseVal.ID_LOAD_ACCESS_FAULT:            (random.random() + 0.05) * EXCEPTION_OP_TYPE_INITIAL_BOOSTERS[ExceptionCauseVal.ID_LOAD_ACCESS_FAULT],
            ExceptionCauseVal.ID_STORE_AMO_ADDR_MISALIGNED:    (random.random() + 0.05) * EXCEPTION_OP_TYPE_INITIAL_BOOSTERS[ExceptionCauseVal.ID_STORE_AMO_ADDR_MISALIGNED],
            ExceptionCauseVal.ID_STORE_AMO_ACCESS_FAULT:       (random.random() + 0.05) * EXCEPTION_OP_TYPE_INITIAL_BOOSTERS[ExceptionCauseVal.ID_STORE_AMO_ACCESS_FAULT],
            ExceptionCauseVal.ID_ENVIRONMENT_CALL_FROM_U_MODE: (random.random() + 0.05) * EXCEPTION_OP_TYPE_INITIAL_BOOSTERS[ExceptionCauseVal.ID_ENVIRONMENT_CALL_FROM_U_MODE],
            ExceptionCauseVal.ID_ENVIRONMENT_CALL_FROM_S_MODE: (random.random() + 0.05) * EXCEPTION_OP_TYPE_INITIAL_BOOSTERS[ExceptionCauseVal.ID_ENVIRONMENT_CALL_FROM_S_MODE],
            ExceptionCauseVal.ID_ENVIRONMENT_CALL_FROM_M_MODE: (random.random() + 0.05) * EXCEPTION_OP_TYPE_INITIAL_BOOSTERS[ExceptionCauseVal.ID_ENVIRONMENT_CALL_FROM_M_MODE],
            ExceptionCauseVal.ID_INSTRUCTION_PAGE_FAULT:       (random.random() + 0.05) * EXCEPTION_OP_TYPE_INITIAL_BOOSTERS[ExceptionCauseVal.ID_INSTRUCTION_PAGE_FAULT],
            ExceptionCauseVal.ID_LOAD_PAGE_FAULT:              (random.random() + 0.05) * EXCEPTION_OP_TYPE_INITIAL_BOOSTERS[ExceptionCauseVal.ID_LOAD_PAGE_FAULT],
            ExceptionCauseVal.ID_STORE_AMO_PAGE_FAULT:         (random.random() + 0.05) * EXCEPTION_OP_TYPE_INITIAL_BOOSTERS[ExceptionCauseVal.ID_STORE_AMO_PAGE_FAULT]
        }

        if self.design_has_fpu:
            # Probability to change rounding mode instead of turning the FPU off
            self.proba_change_rm = random.random()
        self.proba_ebreak_instead_of_ecall = random.random()

        # Numbers of pickable registers
        self.num_pickable_regs = random.randint(MIN_NUM_PICKABLE_REGS, MAX_NUM_PICKABLE_REGS)
        if DO_ASSERT:
            assert self.num_pickable_regs < RELOCATOR_REGISTER_ID, f"Required self.num_pickable_regs ({self.num_pickable_regs}) < RELOCATOR_REGISTER_ID ({RELOCATOR_REGISTER_ID})"
            assert self.num_pickable_regs < RDEP_MASK_REGISTER_ID, f"Required self.num_pickable_regs ({self.num_pickable_regs}) < RDEP_MASK_REGISTER_ID ({RDEP_MASK_REGISTER_ID})"
            assert self.num_pickable_regs < FPU_ENDIS_REGISTER_ID, f"Required self.num_pickable_regs ({self.num_pickable_regs}) < FPU_ENDIS_REGISTER_ID ({FPU_ENDIS_REGISTER_ID})"
            assert self.num_pickable_regs < MPP_BOTH_ENDIS_REGISTER_ID, f"Required self.num_pickable_regs ({self.num_pickable_regs}) < MPP_BOTH_ENDIS_REGISTER_ID ({MPP_BOTH_ENDIS_REGISTER_ID})"
            assert self.num_pickable_regs < MPP_TOP_ENDIS_REGISTER_ID, f"Required self.num_pickable_regs ({self.num_pickable_regs}) < MPP_TOP_ENDIS_REGISTER_ID ({MPP_TOP_ENDIS_REGISTER_ID})"
            assert self.num_pickable_regs < SPP_ENDIS_REGISTER_ID, f"Required self.num_pickable_regs ({self.num_pickable_regs}) < SPP_ENDIS_REGISTER_ID ({SPP_ENDIS_REGISTER_ID})"
        if self.design_has_fpu:
            # We impose self.num_pickable_floating_regs <= self.num_pickable_regs just because initialblock is easier to write. It also has no impact on the fuzzing quality overall.
            self.num_pickable_floating_regs = random.randint(MIN_NUM_PICKABLE_FLOATING_REGS, min(MAX_NUM_PICKABLE_FLOATING_REGS, self.num_pickable_regs))
        else:
            self.num_pickable_floating_regs = 0 # Just for compatibility. This variable is not used if self.design_has_fpu is False.

        # Registers' initial values
        self.proba_reg_starts_with_zero = random.random() / 10
        if DO_ASSERT:
            assert self.proba_reg_starts_with_zero >= 0.0
            assert self.proba_reg_starts_with_zero <= 1.0

    def init_design_state(self):
        if self.design_has_fpu:
            self.is_fpu_activated = True
            self.proba_turn_on_off_fpu_again = random.random()*0.1 # Proba that we re-turn the FPU into the mode it is already in (on or off)

    def instance_to_str(self):
        return f"{self.memview.memsize}_{self.design_name}_{self.randseed}_{self.nmax_bbs}"
        
    def advance_minstret(self):
        curr_val = self.csrfile.regs[CSR_IDS.MINSTRET].get_val()
        self.csrfile.regs[CSR_IDS.MINSTRET].set_val(curr_val+1)

    def append_and_execute_instr(self, instr, execute: bool= False, insert_regdump: bool = INSERT_REGDUMPS):
        instr.execute(taint_en=self.taint_en, is_spike_resolution = True)
        if PRINT_INSTRUCTION_EXECUTION_IN_SITU: 
            instr.print(is_spike_resolution=True)
        self.instr_objs_seq[-1].append(instr)
        if insert_regdump:
            if has_taint_trace(instr) and instr.rd < MAX_NUM_PICKABLE_REGS:
                # fence_instr = SpecialInstruction_t0(self,"fence")
                store_instr = RegdumpInstruction_t0(self,"sd" if self.is_design_64bit else "sw", REGDUMP_REGISTER_ID, instr.rd,0,-1)
                store_instr.execute(taint_en=self.taint_en, is_spike_resolution=True)
                if PRINT_INSTRUCTION_EXECUTION_IN_SITU: 
                    store_instr.print(is_spike_resolution=True)
                self.instr_objs_seq[-1].append(store_instr)
                if INSERT_FENCE:
                    fence_instr = SpecialInstruction_t0(self,"fence")
                    fence_instr.execute(taint_en=False, is_spike_resolution=True)
                    if PRINT_INSTRUCTION_EXECUTION_IN_SITU: 
                        fence_instr.print(is_spike_resolution=True)
                    self.instr_objs_seq[-1].append(fence_instr)
                    return 12
                return 8
        return 4


    def dump_instructions_t0(self):
        insts = {}
        for bb_id ,bb_instrs in enumerate(self.instr_objs_seq): # skip first and last bb
            insts[bb_id] = []
            for instr_obj in bb_instrs:
                if instr_obj.injectable:
                    insts[bb_id] += [{"bytecode": instr_obj.gen_bytecode_int(is_spike_resolution=True),
                                    "bytecode_t0": instr_obj.gen_bytecode_int_t0(is_spike_resolution=True),
                                    "addr": instr_obj.addr,
                                    "type": instr_obj.instr_type.name, 
                                    "str": instr_obj.instr_str,
                                    "bb_id": bb_id}]
    
    def dump_memview_t0(self, path: str = None):
        path = self.env["SIMSRAMTAINT"]
        self.memview.dump_taint(path)

    def setup_env(self, rtl_elfpath, seed):
        ## temp dirs below
        os.makedirs(self.tmp_dir,exist_ok=True)
        env_path = os.path.join(self.tmp_dir,f'env.sh')
        regdump_path = os.path.join(self.tmp_dir, f"regump.json")
        sramdump_path = os.path.join(self.tmp_dir, f"sramdump.json")
        regstream_path = os.path.join(self.tmp_dir, f"regstream.json")
        simsramtaint_path = os.path.join(self.tmp_dir, f"{rtl_elfpath.split('/')[-1].split('.')[0]}.simsramtaint.txt")
        tracefile_path = os.path.join(self.tmp_dir, f"{self.instance_to_str()}.trace.vcd")
        num_instrs = len(list(itertools.chain.from_iterable(self.instr_objs_seq)))
        simlen = str(num_instrs*MAX_CYCLES_PER_INSTR + SETUP_CYCLES)
        env = os.environ.copy()
        env["SIMLEN"] = simlen
        env["SIMSRAMELF"] = rtl_elfpath
        env["ID"] = str(self.instance_to_str())
        env["DESIGN"] = self.design_name
        env["SEED"] = str(seed)
        env["REGDUMP_PATH"] = regdump_path
        env["REGSTREAM_PATH"] = regstream_path
        env["SRAMDUMP_PATH"] = sramdump_path
        env["SIMSRAMTAINT"] = simsramtaint_path
        env["TRACEFILE"] = tracefile_path

        with open(env_path, "w") as f:
            f.write(f"export SIMSRAMELF={env['SIMSRAMELF']}\n")
            f.write(f"export SIMSRAMELF_DUMP={env['SIMSRAMELF']}.dump\n")
            f.write(f"export SIMSRAMTAINT={simsramtaint_path}\n")
            f.write(f"export SEED={env['SEED']}\n")
            f.write(f"export ID={env['ID']}\n")
            f.write(f"export SIMLEN={simlen}\n")
            f.write(f"export REGSTREAM_PATH={regstream_path}\n")
            f.write(f"export REGDUMP_PATH={regdump_path}\n")
            f.write(f"export SRAMDUMP_PATH={sramdump_path}\n")
            f.write(f"export TRACEFILE={tracefile_path}\n")

        if PRINT_ENVIRONMENT:
            print("*** ENVIRONMENT ***")
            print(f"source {env_path}")

        self.env = env

        return env

    def remove_tmp_files(self):
        shutil.rmtree(self.tmp_dir)


    def load_init_regvals_from_memview(self):
        self.initial_reg_data_content.clear()
        for val,addr in self.memview.data.items():
            self.initial_reg_data_content.append(val)

    # Returns the register values and taints for the given spike requests.
    # The register values are obtained from the in-situ simulation instead of spike 
    # to also obtain the (upper-bound) taint values.
    def get_regdumps_from_reqs(self, regdump_reqs, is_spike_resolution, final_address, dump_final_reg_vals):
        regdump_idx = 0
        regdumps = []
        regdumps_t0 = []
        reached_end = False
        # Retrieve the register values from the requests
        for bb_instrs in self.instr_objs_seq:
            for next_instr in bb_instrs:
                if PRINT_INSTRUCTION_EXECUTION_REGDUMP_REQS:
                    next_instr.print(is_spike_resolution)
                next_instr.execute(self.taint_en, is_spike_resolution=is_spike_resolution)
                while regdump_idx < len(regdump_reqs) and next_instr.addr == regdump_reqs[regdump_idx][0] + SPIKE_STARTADDR: # there could be multiple dumps for this address
                    is_floatdump = regdump_reqs[regdump_idx][1]
                    reg_id = regdump_reqs[regdump_idx][2]
                    regdump_idx += 1
                    if is_floatdump:
                        raise NotImplementedError("Float extension not implemented yet.")
                    else:
                        if DO_ASSERT:
                            if not USE_SPIKE_INTERM_ELF:
                                assert reg_id in CSR_ABI_NAMES + ["priv"] or reg_id < self.num_pickable_regs, f"Invalid register id {reg_id}"
                        if reg_id in CSR_ABI_NAMES + ["priv"]: # We dont dump CSR values here for now
                            regdumps += [None]
                            regdumps_t0 += [0]
                        elif reg_id in FPREG_ABINAMES:
                            raise NotImplementedError("fp not implemented yet.")
                        else:
                            regdumps += [self.intregpickstate.regs[reg_id].get_val()]
                            regdumps_t0 += [self.intregpickstate.regs[reg_id].get_val_t0()]
                if final_address is not None and next_instr.addr == final_address:
                    reached_end = True
                    break
            if reached_end:
                break

        
        if DO_ASSERT:
            assert reached_end or final_address is None
            assert regdump_idx == len(regdump_reqs), f"Number of processed dumps does not match number of requests! {regdump_idx} != {len(regdump_reqs)-1}: requests at {[(hex(i[0]+SPIKE_STARTADDR),i[-1]) for i in regdump_reqs]}"
        if not dump_final_reg_vals:
            return (regdumps, regdumps_t0)
        # Retrieve the final register values
        final_intreg_vals = []
        final_intreg_vals_t0 = []
        for reg_id in range(self.num_pickable_regs):
            final_intreg_vals += [self.intregpickstate.regs[reg_id].get_val()]
            final_intreg_vals_t0 += [self.intregpickstate.regs[reg_id].get_val_t0()]

        return (regdumps, regdumps_t0),((final_intreg_vals, final_intreg_vals_t0), (None, None))

