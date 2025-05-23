# Copyright 2024 Tobias Kovats, Flavien Solt, ETH Zurich.
# Licensed under the General Public License, Version 3.0, see LICENSE for details.
# SPDX-License-Identifier: GPL-3.0-only

from params.runparams import DO_ASSERT, PRINT_INSTRUCTION_EXECUTION_IN_SITU, PRINT_INSTRUCTION_EXECUTION_REGDUMP_REQS, PATH_TO_TMP,PATH_TO_MNT, PATH_TO_MNT_ENV_VAR, INSERT_REGDUMPS, INSERT_FENCE, PRINT_ENVIRONMENT, GET_DATA, DEBUG_PRINT, PRINT_PRIV_STATS, TRACE_FST, USE_MODELSIM, DEBUG_RVC, MODELSIM_TIMEOUT, PRINT_TRANSIENT_INSTRUCTIONS, PRINT_RESTORED_TRANSIENT_STATE
from params.fuzzparams import RELOCATOR_REGISTER_ID, RDEP_MASK_REGISTER_ID, REGDUMP_REGISTER_ID, FPU_ENDIS_REGISTER_ID, MIN_NUM_PICKABLE_REGS, MAX_NUM_PICKABLE_REGS, MIN_NUM_PICKABLE_FLOATING_REGS, MAX_NUM_PICKABLE_FLOATING_REGS, MPP_BOTH_ENDIS_REGISTER_ID, MPP_TOP_ENDIS_REGISTER_ID, SPP_ENDIS_REGISTER_ID, MAX_NUM_STORE_LOCATIONS, NONPICKABLE_REGISTERS, FENCE_CF_INSTR
from params.fuzzparams import TAINT_EN, MAX_CYCLES_PER_INSTR, SETUP_CYCLES, USE_SPIKE_INTERM_ELF, USE_MMU, MAX_NUM_LAYOUTS, TAINT_SOURCE_PRIVS, TAINT_SINK_PRIVS, P_TWO_TAINT_SOURCE_PRIVS, P_TWO_TAINT_SINK_PRIVS
from params.fuzzparams import MAX_N_TAINT_SOURCE_LAYOUTS, MIN_N_TAINT_SOURCE_LAYOUTS, MAX_GADGET_N_INSTR, DEAD_CODE_ONLY_IN_CODE_PAGES, STOP_AT_PC_TAINT
from params.fuzzparams import reset_reg_settings
from common.designcfgs import is_design_32bit, design_has_float_support, design_has_double_support, design_has_muldiv_support, design_has_atop_support, design_has_misaligned_data_support, get_design_milesan_path, design_has_supervisor_mode, design_has_user_mode, design_has_compressed_support, design_has_pmp, design_has_only_bare, design_has_sv32, design_has_sv39, design_has_sv48, get_design_boot_addr
from common.spike import SPIKE_STARTADDR, FPREG_ABINAMES
from milesan.util import INSTRUCTIONS_BY_ISA_CLASS
from milesan.util import ISAInstrClass, ExceptionCauseVal, MmuState, SimulatorEnum
from milesan.cfinstructionclasses import is_placeholder
from milesan.memview import MemoryView
from milesan.csrfile import CSRFile
from milesan.contextreplay import get_context_setter_max_size
from milesan.privilegestate import PrivilegeState, PrivilegeStateEnum
from milesan.randomize.pickstoreaddr import MemStoreState
from milesan.randomize.pickreg import IntRegPickState, FloatRegPickState
from milesan.randomize.pickisainstrclass import ISAINSTRCLASS_INITIAL_BOOSTERS
from milesan.randomize.pickexceptionop import EXCEPTION_OP_TYPE_INITIAL_BOOSTERS
from milesan.cfinstructionclasses_t0 import *
from milesan.mmu_utils import MODES_PARAM_RV32, MODES_PARAMS_RV64, PageTablesGen,PAGE_ALIGNMENT_MASK, PHYSICAL_PAGE_SIZE
from rv.csrids import CSR_IDS, CSR_ABI_NAMES
from milesan.registers import ABI_INAMES
from milesan.perfmonitor import PerformanceMonitor
import random
import os
import itertools
import shutil
import glob
from milesan.randomize.createspecinstr import create_speculative_instrs
import pickle
class FuzzerState:
    # @param randseed for identification purposes only.
    def __init__(self, design_base_addr: int, design_name: str, memsize: int, randseed: int, nmax_bbs: int, authorize_privileges: bool):
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
        self.design_has_no_mmu                 : bool = design_has_only_bare(design_name)
        self.design_has_misaligned_data_support: bool = design_has_misaligned_data_support(design_name)
        self.design_has_supervisor_mode        : bool = design_has_supervisor_mode(design_name)
        self.design_has_user_mode              : bool = design_has_user_mode(design_name)
        self.design_has_pmp                    : bool = design_has_pmp(design_name)
        self.random_block_contents4by4bytes = []
        self.random_data_block_ranges = []

        self.taint_source_transient_addrs_regs = {} # physical addresses of possibly speculatively executed code in taint source privileges and the register taints.
        # The page domains of the code blocks. va_layout is only determined during program generation, thus
        # we collect them in the BaseInstruction
        self.page_domains = {} # dict of paddr : {'va_layouts': {va_layouts}, 'priv_level': priv_level}

        if TAINT_EN:
            self.random_data_block_has_taint = {} # Is true if the random data block at that page can have taint.
            if USE_MMU:
                if TAINT_SOURCE_PRIVS is None:
                    # We either choose a single or multiple taint source privs
                    self.taint_source_privs = set(random.choices(list({PrivilegeStateEnum.MACHINE, PrivilegeStateEnum.SUPERVISOR, PrivilegeStateEnum.USER}),k=1+int(random.random()<P_TWO_TAINT_SOURCE_PRIVS))) # Subset of priveleges has access to tainted data
                else:
                    self.taint_source_privs = set()
                    if "M" in TAINT_SOURCE_PRIVS:
                        self.taint_source_privs.add(PrivilegeStateEnum.MACHINE)
                    if "S" in TAINT_SOURCE_PRIVS:
                        self.taint_source_privs.add(PrivilegeStateEnum.SUPERVISOR)
                    if "U" in TAINT_SOURCE_PRIVS:
                        self.taint_source_privs.add(PrivilegeStateEnum.USER)
                
                if TAINT_SINK_PRIVS is None:
                    possible_taint_sink_privs = {PrivilegeStateEnum.MACHINE, PrivilegeStateEnum.SUPERVISOR, PrivilegeStateEnum.USER} - self.taint_source_privs
                    # If we could have more than one taint sink privilege, we either chose multiple or only a single one
                    self.taint_sink_privs = set(random.choices(list(possible_taint_sink_privs),k=1+int(len(possible_taint_sink_privs)>1)*int(random.random()<P_TWO_TAINT_SINK_PRIVS))) if len(possible_taint_sink_privs) > 0 else set()
                else:
                    self.taint_sink_privs = set()
                    if "M" in TAINT_SINK_PRIVS:
                        self.taint_sink_privs.add(PrivilegeStateEnum.MACHINE)
                    if "S" in TAINT_SINK_PRIVS:
                        self.taint_sink_privs.add(PrivilegeStateEnum.SUPERVISOR)
                    if "U" in TAINT_SINK_PRIVS:
                        self.taint_sink_privs.add(PrivilegeStateEnum.USER)
                # If the MMU is disabled, all privileges can acccess tainted data.
                if DO_ASSERT:
                    assert self.taint_sink_privs & self.taint_source_privs == set(), f"Privilege can't be both taint source and sink! {self.taint_source_privs}/{self.taint_sink_privs}"
                    assert len(self.taint_sink_privs), f"At least one privilige must be a taint sink when TAINT_EN and USE_MMU are enabled."
                    assert len(self.taint_source_privs), f"At least one privilige must be a taint source when TAINT_EN and USE_MMU are enabled."

                # print(f"Taint source privileges: {self.taint_source_privs}")
                # print(f"Taint sink privileges: {self.taint_sink_privs}")

                self.n_instr_in_priv = {
                    PrivilegeStateEnum.USER: 0,
                    PrivilegeStateEnum.SUPERVISOR: 0,
                    PrivilegeStateEnum.MACHINE: 0
                    }
            # If MMU is disabled, all privileges can compute on and access taint.
            else:
                self.taint_source_privs = {PrivilegeStateEnum.MACHINE, PrivilegeStateEnum.SUPERVISOR, PrivilegeStateEnum.USER}
                self.taint_sink_privs = set()

        # For benchmarks
        if GET_DATA:
            self.num_hardcoded_instr_mmufsm = 0
            self.num_hardcoded_instr_regfsm = 0
            self.num_mprv_memop = 0
            self.num_virt_pc = 0
            self.jump_to_new_layout = 0
            self.machine_only_rprod = 0
            self.satp_write_machine = 0
            self.satp_write_supervisor = 0

        if USE_MMU and not self.design_has_no_mmu:
            if self.is_design_64bit:
                reset_reg_settings()
            self.mmu_capabilities = []
            self.prog_mmu_params =  []
            if self.is_design_64bit: 
                self.ptesize = 8
            else:
                self.ptesize = 4
            self.get_design_mmu(design_name)
            self.select_prog_mmu_params()
        else:
            self.taint_source_layouts = range(-1,0) # effective layout is always -1
        if not USE_MODELSIM:
            self.simulator = SimulatorEnum.VERILATOR
        else:
            self.simulator = SimulatorEnum.MODELSIM

        self.gen_pick_weights()
        self.reset()
        self.init_design_state()

        self.expected_regvals = None
        self.interm_elfpath = None
        self.rtl_elfpath = None

        self.tmp_dir = os.path.join(PATH_TO_TMP, self.design_name, self.instance_to_str()) 
        # Same directory but relative from native env i.e. points to SSH mount from outside of the container
        os.makedirs(self.tmp_dir,exist_ok=True)

        self.pmonitor = PerformanceMonitor(os.path.join(self.tmp_dir,'perf_stats.json'))

    # @brief return the MMU capabilities of the design 
    # @return [bool] : [sv32, sv39, sv48]
    def get_design_mmu(self, design_name):
        if self.is_design_64bit:
            self.mmu_capabilities.append(design_has_sv39(design_name))
            self.mmu_capabilities.append(design_has_sv48(design_name))
            # self.mmu_capabilities.append(False)
        else:
            self.mmu_capabilities.append(design_has_sv32(design_name))

    # @brief return the MODE and page sizes we will support in the current program
    # @return [(MODE, #level_used)]
    def select_prog_mmu_params(self):
        self.num_layouts = random.randint(1, MAX_NUM_LAYOUTS)
        num_taint_source_layouts = random.randint(max(MIN_N_TAINT_SOURCE_LAYOUTS,0), min(self.num_layouts, MAX_N_TAINT_SOURCE_LAYOUTS)) if MAX_N_TAINT_SOURCE_LAYOUTS!=-1 else self.num_layouts
        # -1 is always a taint_source_layout
        self.taint_source_layouts = range(-1,num_taint_source_layouts)
        # self.taint_sink_layouts = range(num_taint_source_layouts,num_taint_source_layouts+num_taint_sink_layouts)
        if self.is_design_64bit:
            allowed_params = MODES_PARAMS_RV64
        else:
            allowed_params = MODES_PARAM_RV32
        for _ in range(self.num_layouts):
            mode = random.choices(list(allowed_params.keys()), self.mmu_capabilities)[0]
            # n_level = random.randint(1, allowed_params[mode][2])
            n_level = allowed_params[mode][2]
            self.prog_mmu_params.append((mode, n_level))
        if DEBUG_PRINT: print(f"generated parameters: {self.prog_mmu_params}: taint source layouts: {self.taint_source_layouts} ({num_taint_source_layouts}/{self.num_layouts})")

        self.n_instr_in_layout = {
            i:0 for i in range(-1,self.num_layouts) # -1 is special case for M-mode bare translation
        }

    # @brief cleans up the fuzzerstate. Used in case of failed input generation.
    def reset(self):
        self.initial_block_data_start, self.initial_block_data_end = None, None
        self.random_block_contents4by4bytes = []
        self.random_data_block_ranges = []
        if TAINT_EN:
            self.random_data_block_has_taint = {} # Is true if the random data block at that page can have taint.
        self.next_bb_addr = 0
        self.memview = MemoryView(self)
        self.memview_blacklist = MemoryView(self) # For load blacklis

        self.max_num_store_locations = random.randint(1, MAX_NUM_STORE_LOCATIONS)
        self.num_store_locations = 0
        self.ctxsv_size_upperbound: int = get_context_setter_max_size(self) # Can be called once is_design_64bit, design_has_fpu and design_has_fpud are set, and the number of store locations is known.

        self.memstorestate = MemStoreState()
        self.csrfile = CSRFile(self)
        self.intregpickstate = IntRegPickState(self)
        self.floatregpickstate = FloatRegPickState(self)
        self.privilegestate = PrivilegeState()

        # self.instr_objs_seq does NEVER contain the final basic block.
        self.instr_objs_seq = [] # List (queue) of (for each basic block) lists of instruction objects
        self.bb_start_addr_seq = [] # List (queue) of bb start addresses. Self-managed through init_new_bb.
        self.saved_reg_states = [] # List (queue) of register save objects, as saved by pickreg.py
        self.saved_csr_states = [] # List (queue) of register save objects, as saved by csrflile.py
        self.saved_mem_states = [] # List (queue) of mem save objects, as saved by mem
        self.saved_mmu_state  = []

        self.spec_instr_objs_seq = [] # Speculative instructions. Not executed in spike, only transiently on RTL.

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
        self.last_bb_id_before_ctx_saver = 0
        self.first_bb_id_after_ctx_saver = None

        # Context dump, not used i think
        # self.ctxdmp_bb = []
        # self.ctxdmp_bb_base_addr = -1
        # self.ctxdmp_bb_jal_instr_id = -1 # Useful because the last elements in ctxdmp_bb are data.

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

        ##
        # MMU
        ##

        self.pagetablestate = PageTablesGen(self.is_design_64bit, self.design_name)

        # Layout trackers, updated during generation
        self.effective_curr_layout = -1 # The effective layout id, -1 is bare (is -1 if the current mode is machine)
        self.effective_prev_layout = None
        self.real_curr_layout = -1 # The true layout id
        self.target_layout = None # The next layout
        
        # list to transmit the effective layout id to producers once the program is generated
        self.consumer_inst_va_layout = None

        # MMU FSM helper, we do not change layouts before he last on is used
        self.satp_set_not_used = False

        # When traps are raised in supervisor mode, we need one extra r 1 to dump all PCs
        self.n_missing_r_cmds = 0

        # Instruction coordinates tracker
        self.stvec_satp_op_coordinates = (None, None)
        self.satp_op_coordinates = ((None, None), None) # Used to set the RPROD_MASK value, as we do not know the future priv level when creating RPROD
        self.last_medeleg_coordinates = (None, None) # Saves the coordinate of the last medeleg operation, disables delegation for U/S transitions if pages are too large

        # Keeps the current state of mstatus for SUM/MPRV
        self.status_sum_mprv = (False, False)
        self.curr_asid = 0
        self.curr_satp_no_asid = 0
        self.num_instr_to_stay_in_prv = 0
        self.num_instr_to_stay_in_layout = 0

        self.curr_mmu_state = MmuState.IDLE

        if not USE_MODELSIM:
            self.simulator = SimulatorEnum.VERILATOR
        else:
            self.simulator = SimulatorEnum.MODELSIM

        if USE_MMU:
            self.n_instr_in_priv = {
                PrivilegeStateEnum.USER: 0,
                PrivilegeStateEnum.SUPERVISOR: 0,
                PrivilegeStateEnum.MACHINE: 0
                }


    def init_new_bb(self):
        self.instr_objs_seq.append([])

        self.curr_bb_start_addr = self.next_bb_addr
        self.next_bb_addr = None
        self.bb_start_addr_seq.append(self.curr_bb_start_addr)

    def save_states(self):
        self.saved_reg_states.append(self.intregpickstate.save_curr_state())
        self.saved_csr_states.append(self.csrfile.save_curr_state())
        self.memview.store_state() # special case since also used for reduction

    def restore_states(self, bb_id: int = -1):
        self.intregpickstate.restore_state(self.saved_reg_states[bb_id])
        self.csrfile.restore_state(self.saved_csr_states[bb_id])
        self.memview.restore(bb_id)

    def pop_states(self):
        self.saved_reg_states.pop()
        self.saved_csr_states.pop()
        self.memview.states.pop()

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
            ISAInstrClass.MMU:         (random.random() + 0.05) * ISAINSTRCLASS_INITIAL_BOOSTERS[ISAInstrClass.MMU],
            ISAInstrClass.MSTATUS:     (random.random() + 0.05) * ISAINSTRCLASS_INITIAL_BOOSTERS[ISAInstrClass.MSTATUS],
            ISAInstrClass.MEMFSM:     (random.random() + 0.05) * ISAINSTRCLASS_INITIAL_BOOSTERS[ISAInstrClass.MEMFSM],
        }
        self.exceptionoppickweights = {
            ExceptionCauseVal.ID_INSTR_ADDR_MISALIGNED:        (random.random() + 0.05) * EXCEPTION_OP_TYPE_INITIAL_BOOSTERS[ExceptionCauseVal.ID_INSTR_ADDR_MISALIGNED],
            ExceptionCauseVal.ID_INSTR_ACCESS_FAULT:           (random.random() + 0.05) * EXCEPTION_OP_TYPE_INITIAL_BOOSTERS[ExceptionCauseVal.ID_INSTR_ACCESS_FAULT],
            ExceptionCauseVal.ID_ILLEGAL_INSTRUCTION:          (random.random() + 0.05) * EXCEPTION_OP_TYPE_INITIAL_BOOSTERS[ExceptionCauseVal.ID_ILLEGAL_INSTRUCTION],
            ExceptionCauseVal.ID_BREAKPOINT:                   (random.random() + 0.05) * EXCEPTION_OP_TYPE_INITIAL_BOOSTERS[ExceptionCauseVal.ID_BREAKPOINT],
            ExceptionCauseVal.ID_LOAD_ADDR_MISALIGNED:         (random.random() + 0.05) * EXCEPTION_OP_TYPE_INITIAL_BOOSTERS[ExceptionCauseVal.ID_LOAD_ADDR_MISALIGNED] if self.design_has_misaligned_data_support else 0,
            ExceptionCauseVal.ID_LOAD_ACCESS_FAULT:            (random.random() + 0.05) * EXCEPTION_OP_TYPE_INITIAL_BOOSTERS[ExceptionCauseVal.ID_LOAD_ACCESS_FAULT],
            ExceptionCauseVal.ID_STORE_AMO_ADDR_MISALIGNED:    (random.random() + 0.05) * EXCEPTION_OP_TYPE_INITIAL_BOOSTERS[ExceptionCauseVal.ID_STORE_AMO_ADDR_MISALIGNED] if self.design_has_misaligned_data_support else 0,
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

    def append_and_execute_instr(self, instr, insert_regdump: bool = INSERT_REGDUMPS):            
        instr.reset_addr()
        assert not (SPIKE_STARTADDR != self.design_base_addr and "auipc" in instr.instr_str and self.intregpickstate.regs[instr.rd].fsm_state == IntRegIndivState.FREE), f"SPIKE_STARTADDR: {hex(SPIKE_STARTADDR)}, design_base_addr: {hex(self.design_base_addr)}, instr: {instr.get_str()}, rd: {self.intregpickstate.regs[instr.rd].fsm_state.name}"
        if PRINT_INSTRUCTION_EXECUTION_IN_SITU: 
            instr.print(is_spike_resolution=True)
        if DEBUG_RVC and instr.iscompressed:
            print(f"RVC: {instr.get_str()}")
        if instr.iscompressed:
            n_bytes = 2
        else:
            n_bytes = 4
        curr_paddr = self.get_curr_paddr(add_spike_offset=False)
        if len(self.instr_objs_seq)>1:
            self.memview.alloc_mem_range(curr_paddr, curr_paddr+(2 if instr.iscompressed else 4))
        self.instr_objs_seq[-1].append(instr)
        instr.execute(is_spike_resolution = True)
        if USE_MMU and not self.design_has_no_mmu:
            self.n_instr_in_priv[instr.priv_level] += 1
            self.n_instr_in_layout[instr.va_layout] += 1
        if insert_regdump:
            if 'cva6' in self.design_name or "openc910" in self.design_name:
                assert INSERT_FENCE, f"{self.design_name} needs INSERT_FENCE enabled when using register dumps!"
            if has_taint_trace(instr) and instr.rd < MAX_NUM_PICKABLE_REGS and self.intregpickstate.regs[instr.rd].fsm_state == IntRegIndivState.FREE:
                store_instr = RegdumpInstruction_t0(self,"sd" if self.is_design_64bit else "sw", REGDUMP_REGISTER_ID, instr.rd,0,-1)
                store_instr.reset_addr()
                if PRINT_INSTRUCTION_EXECUTION_IN_SITU: 
                    store_instr.print(is_spike_resolution=True)
                store_instr.execute(is_spike_resolution=True)
                curr_paddr = self.get_curr_paddr(add_spike_offset=False)
                if len(self.instr_objs_seq)>1:
                    self.memview.alloc_mem_range(curr_paddr, curr_paddr+4)
                self.instr_objs_seq[-1].append(store_instr)
                n_bytes += 4
                if INSERT_FENCE:
                    fence_instr = SpecialInstruction_t0(self,"fence")
                    fence_instr.reset_addr()
                    if PRINT_INSTRUCTION_EXECUTION_IN_SITU: 
                        fence_instr.print(is_spike_resolution=True)
                    fence_instr.execute(is_spike_resolution=True)
                    curr_paddr = self.get_curr_paddr(add_spike_offset=False)
                    if len(self.instr_objs_seq)>1:
                        self.memview.alloc_mem_range(curr_paddr, curr_paddr+4)
                    self.instr_objs_seq[-1].append(fence_instr)
                    n_bytes += 4
        return n_bytes


    def write_imm_t0_to_mem(self):
        for bb_instrs in self.instr_objs_seq:
            for next_instr in bb_instrs:
                if TAINT_EN and isinstance(next_instr, (ImmRdInstruction_t0, RegImmInstruction_t0, BranchInstruction_t0)):
                    next_instr.write_t0() # Write tainted bytecode to instruction memory if taint is enabled.

        for next_instr in self.ctxsv_bb:
            if TAINT_EN and isinstance(next_instr, (ImmRdInstruction_t0, RegImmInstruction_t0, BranchInstruction_t0)):
                next_instr.write_t0() # Write tainted bytecode to instruction memory if taint is enabled.


    def dump_instructions_t0(self):
        insts = {}
        for bb_id ,bb_instrs in enumerate(self.instr_objs_seq): # skip first and last bb
            insts[bb_id] = []
            for instr_obj in bb_instrs:
                if instr_obj.injectable:
                    insts[bb_id] += [{"bytecode": instr_obj.gen_bytecode_int(is_spike_resolution=True),
                                    "bytecode_t0": instr_obj.gen_bytecode_int_t0(is_spike_resolution=True),
                                    "addr": instr_obj.paddr,
                                    "type": instr_obj.instr_type.name, 
                                    "str": instr_obj.instr_str,
                                    "bb_id": bb_id}]
    
    def dump_memview_t0(self, path: str = None):
        path = self.env["SIMSRAMTAINT"]
        self.memview.dump_taint(path)

    def gen_tmp_dir(self):
        os.makedirs(self.tmp_dir,exist_ok=True)
        
    def setup_env(self, rtl_elfpath, seed):
        ## temp dirs below
        preamble = rtl_elfpath.split('/')[-1].split('.')[0]
        os.makedirs(self.tmp_dir,exist_ok=True)
        env_path = os.path.join(self.tmp_dir,f'{preamble}.env.sh')
        regdump_path = os.path.join(self.tmp_dir, f"{preamble}.regdump.json")
        pcdump_path = os.path.join(self.tmp_dir, f"{preamble}.pcdump.txt")
        sramdump_path = os.path.join(self.tmp_dir, f"{preamble}.sramdump.json")
        regstream_path = os.path.join(self.tmp_dir, f"{preamble}.regstream.json")
        writeback_path = os.path.join(self.tmp_dir, f"{preamble}.writeback.txt")
        simsramtaint_path = os.path.join(self.tmp_dir, f"{preamble}.simsramtaint.txt")
        cov_path = os.path.join(self.tmp_dir, f"{preamble}.cov")
        timestamp_path = os.path.join(self.tmp_dir, f"{preamble}.timestamp.txt")
        tracefile_path = os.path.join(self.tmp_dir, f"{preamble}.trace{'.fst' if TRACE_FST else '.vcd'}")
        num_instrs = len(list(itertools.chain.from_iterable(self.instr_objs_seq)))
        simlen = str(num_instrs*MAX_CYCLES_PER_INSTR + SETUP_CYCLES)
        env = {}
        env["SIMLEN"] = simlen
        env["MODELSIM_TIMEOUT"] = str(MODELSIM_TIMEOUT)
        env["SIMSRAMELF"] = rtl_elfpath
        env["ID"] = str(self.instance_to_str())
        env["DESIGN"] = self.design_name
        env["SEED"] = str(seed)
        env["REGDUMP_PATH"] = regdump_path
        env["REGSTREAM_PATH"] = regstream_path
        env["SRAMDUMP_PATH"] = sramdump_path
        env["PCDUMP_PATH"] = pcdump_path
        env["STOP_AT_PC_TAINT"] = "1" if STOP_AT_PC_TAINT else "0"
        env["SIMSRAMTAINT"] = simsramtaint_path
        env["TRACEFILE"] = tracefile_path
        env["WRITEBACK_PATH"] = writeback_path
        env["DESIGN_DIR"] = os.path.abspath(get_design_milesan_path(self.design_name))
        env["COV_PATH"] = cov_path
        env["TIMESTAMP_PATH"] = timestamp_path

        with open(env_path, "w") as f:
            f.write(f"export SIMSRAMELF={env['SIMSRAMELF'].replace(PATH_TO_MNT, f'${PATH_TO_MNT_ENV_VAR}')}\n")
            f.write(f"export SIMSRAMELF_DUMP={env['SIMSRAMELF'].replace(PATH_TO_MNT, f'${PATH_TO_MNT_ENV_VAR}')}.dump\n")
            f.write(f"export SIMSRAMTAINT={simsramtaint_path.replace(PATH_TO_MNT, f'${PATH_TO_MNT_ENV_VAR}')}\n")
            f.write(f"export SEED={env['SEED']}\n")
            f.write(f"export ID={env['ID']}\n")
            f.write(f"export SIMLEN={simlen}\n")
            f.write(f"export REGSTREAM_PATH={regstream_path.replace(PATH_TO_MNT, f'${PATH_TO_MNT_ENV_VAR}')}\n")
            f.write(f"export REGDUMP_PATH={regdump_path.replace(PATH_TO_MNT, f'${PATH_TO_MNT_ENV_VAR}')}\n")
            f.write(f"export SRAMDUMP_PATH={sramdump_path.replace(PATH_TO_MNT, f'${PATH_TO_MNT_ENV_VAR}')}\n")
            f.write(f"export TRACEFILE={tracefile_path.replace(PATH_TO_MNT, f'${PATH_TO_MNT_ENV_VAR}')}\n")
            f.write(f"export WRITEBACK_PATH={writeback_path.replace(PATH_TO_MNT, f'${PATH_TO_MNT_ENV_VAR}')}\n")
            f.write(f"export COV_PATH={cov_path.replace(PATH_TO_MNT, f'${PATH_TO_MNT_ENV_VAR}')}\n")
            f.write(f"export PCDUMP_PATH={pcdump_path.replace(PATH_TO_MNT, f'${PATH_TO_MNT_ENV_VAR}')}\n")
            f.write(f"export STOP_AT_PC_TAINT={env['STOP_AT_PC_TAINT']}\n")
        if PRINT_ENVIRONMENT:
            print("*** ENVIRONMENT ***")
            print(f"source {env_path}")

        self.env = env

        return env

    ## remove the whole temporary directory
    def remove_tmp_dir(self):
        if os.path.isdir(self.tmp_dir):
            shutil.rmtree(self.tmp_dir)

    ## only remove tmp files
    def remove_tmp_files(self):
        if os.path.isdir(self.tmp_dir):
            for file in glob.glob(f"{self.tmp_dir}/*"):
                if not ("log" in file or "perfstats" in file):
                    os.remove(file)      

    def load_init_regvals_from_memview(self):
        self.initial_reg_data_content.clear()
        for val,addr in self.memview.data.items():
            self.initial_reg_data_content.append(val)

    # Returns the register values and taints for the given spike requests.
    # The register values are obtained from the in-situ simulation instead of spike 
    # to also obtain the (upper-bound) taint values.
    # NOT TESTED WITH MMU ENABLED
    def get_regdumps_from_reqs(self, regdump_reqs, is_spike_resolution, final_address, dump_final_reg_vals, skip_placeholder):
        regdump_idx = 0
        regdumps = []
        regdumps_t0 = []
        reached_end = False
        # Retrieve the register values from the requests
        self.curr_pc = SPIKE_STARTADDR if is_spike_resolution else self.design_base_addr
        for bb_id, bb_instrs in enumerate(self.instr_objs_seq):
            for next_instr in bb_instrs:
                if PRINT_INSTRUCTION_EXECUTION_REGDUMP_REQS:
                    next_instr.print(is_spike_resolution)
                while regdump_idx < len(regdump_reqs) and  (next_instr.vaddr if USE_MMU else next_instr.paddr) == regdump_reqs[regdump_idx][0]: # there could be multiple dumps for this address
                    is_floatdump = regdump_reqs[regdump_idx][1]
                    reg_id = regdump_reqs[regdump_idx][2]
                    regdump_idx += 1
                    if is_floatdump:
                        raise NotImplementedError("Float extension not implemented yet.")
                    else:
                        if DO_ASSERT:
                            if not USE_SPIKE_INTERM_ELF:
                                assert reg_id in CSR_ABI_NAMES + ["priv"] or reg_id < self.num_pickable_regs or reg_id in NONPICKABLE_REGISTERS, f"Invalid register id {reg_id}"
                        if reg_id in CSR_ABI_NAMES + ["priv"]: # We dont dump CSR values or privileges here since we don't allow them to be tainted for now.
                            regdumps += [None]
                            regdumps_t0 += [0]
                        elif reg_id in FPREG_ABINAMES:
                            raise NotImplementedError("fp not implemented yet.")
                        elif is_placeholder(next_instr) and skip_placeholder:
                            regdumps += [None]
                            regdumps_t0 += [0]
                        else:
                            regdumps += [self.intregpickstate.regs[reg_id].get_val()]
                            regdumps_t0 += [self.intregpickstate.regs[reg_id].get_val_t0()]
                next_instr.execute(is_spike_resolution=is_spike_resolution)
                if final_address is not None and (next_instr.vaddr if USE_MMU else next_instr.paddr) == final_address:
                    reached_end = True
                    break
            # if this bb is followed by a context saver block, execute it
            if bb_id == self.last_bb_id_before_ctx_saver:
                for next_instr in self.ctxsv_bb:
                    next_instr.execute(is_spike_resolution=is_spike_resolution)

            if reached_end:
                break


        if DO_ASSERT:
            assert reached_end or final_address is None
            assert regdump_idx == len(regdump_reqs), f"Number of processed dumps does not match number of requests! {regdump_idx} != {len(regdump_reqs)-1}: requests at {[(hex(i[0]),i[-1]) for i in regdump_reqs]}"
        if not dump_final_reg_vals:
            self.reset_states()
            return (regdumps, regdumps_t0)
        # Retrieve the final register values
        final_intreg_vals = []
        final_intreg_vals_t0 = []
        for reg_id in range(self.num_pickable_regs):
            final_intreg_vals += [self.intregpickstate.regs[reg_id].get_val()]
            final_intreg_vals_t0 += [self.intregpickstate.regs[reg_id].get_val_t0()]

        self.reset_states()
        return (regdumps, regdumps_t0),((final_intreg_vals, final_intreg_vals_t0), (None, None))

    
    def simulate_execution(self, is_spike_resolution: bool = True, final_addr: int = None, print_execution: bool = False, reset_after_execution: bool = False):
        # Retrieve the register values from the requests
        self.curr_pc = SPIKE_STARTADDR
        for bb_id, bb_instrs in enumerate(self.instr_objs_seq):
            for next_instr in bb_instrs:
                next_instr.execute(is_spike_resolution=is_spike_resolution)
                if print_execution:
                    next_instr.print(is_spike_resolution)
                
            # if this bb is followed by a context saver block, execute it
            if bb_id == self.last_bb_id_before_ctx_saver:
                for next_instr in self.ctxsv_bb:
                    next_instr.execute(is_spike_resolution=is_spike_resolution)
                    if print_execution:
                        print(f"{next_instr.get_str(is_spike_resolution)} (ctx)")
                if final_addr is not None and (next_instr.vaddr if USE_MMU else next_instr.paddr) == final_addr:
                    if reset_after_execution:
                        self.reset_states()
                    return
        if DO_ASSERT:
            assert final_addr is None, f"Final address not reached {hex(final_addr)}."
        if reset_after_execution:
            self.reset_states()

    def reset_states(self, mem_state_id = 0):
        self.intregpickstate.setup_registers() # Restore registers to before anything was executed.
        self.memview.restore(mem_state_id) # Restore contents before anything was executed.
        self.csrfile.reset() # Reset all CSRs to zero.

    def verify_program(self, reset_before_execution: bool = True, print_execution: bool = False, print_trace:bool = False):
        if reset_before_execution:
            self.reset_states()
        self.simulate_execution(True,print_execution=print_execution, reset_after_execution=True)
        self.simulate_execution(False,print_execution=print_execution, reset_after_execution=True)

    def compute_context_stats(self, print_stats: bool = PRINT_PRIV_STATS):
        n_taints_in_priv = {
            PrivilegeStateEnum.USER: 0,
            PrivilegeStateEnum.SUPERVISOR: 0,
            PrivilegeStateEnum.MACHINE: 0
        }
        for bb_instrs in self.instr_objs_seq:
            for next_instr in bb_instrs:
                if isinstance(next_instr, RDInstruction_t0) and next_instr.writeback_trace["in-situ"]:
                    n_taints_in_priv[next_instr.priv_level] += 1
        if print_stats:
                print({p.name:v for p,v in self.n_instr_in_priv.items()})

        return n_taints_in_priv


    def compute_taint_stats(self):
        # Retrieve the register values from the requests
        stats_per_cycle = []
        self.curr_pc = SPIKE_STARTADDR
        for bb_id, bb_instrs in enumerate(self.instr_objs_seq):
            for next_instr in bb_instrs:
                isa_class = None
                for isac ,instrs in INSTRUCTIONS_BY_ISA_CLASS.items():
                    if next_instr.instr_str in instrs:
                        isa_class = isac
                        break

                stats = {
                    "n_tainted_regs_ratio": sum([self.intregpickstate.regs[i].get_val_t0() != 0 for i in range(self.num_pickable_regs)])/self.num_pickable_regs,
                    "all_reg_taints": [self.intregpickstate.regs[i].get_val_t0() for i in range(self.num_pickable_regs)],
                    "priv": next_instr.priv_level,
                    "instr_str": next_instr.instr_str,
                    "rs1": None if not hasattr(next_instr, "rs1") else next_instr.rs1,
                    "rs2": None if not hasattr(next_instr, "rs2") else next_instr.rs2,
                    "rd": None if not hasattr(next_instr, "rd") else next_instr.rd,
                    "rdep": None if not hasattr(next_instr, "rdep") else next_instr.rdep,
                    "rdep_value":  None if not hasattr(next_instr, "rdep") else self.intregpickstate.regs[next_instr.rdep].get_val(),
                    "rprod": None if not hasattr(next_instr, "rprod") else next_instr.rprod,
                    "rprod_value":  None if not hasattr(next_instr, "rprod") else self.intregpickstate.regs[next_instr.rprod].get_val(),
                    "rs1_value": None if not hasattr(next_instr, "rs1") else self.intregpickstate.regs[next_instr.rs1].get_val(),
                    "rs2_value": None if not hasattr(next_instr, "rs2") else self.intregpickstate.regs[next_instr.rs2].get_val(),
                    "rs1_value_t0": None if not hasattr(next_instr, "rs1") else self.intregpickstate.regs[next_instr.rs1].get_val_t0(),
                    "rs2_value_t0": None if not hasattr(next_instr, "rs2") else self.intregpickstate.regs[next_instr.rs2].get_val_t0(),
                    "imm_value": None if not hasattr(next_instr, "imm") else next_instr.imm,
                    "imm_value_t0": None if not hasattr(next_instr, "imm_t0") else next_instr.imm_t0,
                    "rd_value_before_exec": None if not hasattr(next_instr, "rd") else self.intregpickstate.regs[next_instr.rd].get_val(),
                    "rd_value_t0_before_exec": None if not hasattr(next_instr, "rd") else self.intregpickstate.regs[next_instr.rd].get_val_t0(),
                    "isa_class" : None if isa_class is None else isa_class.name,
                    "instr_class": next_instr.__class__.__name__,
                    "taint_source_privs": [i for i in self.taint_source_privs],
                    "taint_sink_privs": [i for i in self.taint_sink_privs]
                }
                next_instr.execute(is_spike_resolution=False)
                stats["rd_value_after_exec"] =  None if not hasattr(next_instr, "rd") else self.intregpickstate.regs[next_instr.rd].get_val()
                stats["rd_value_t0_after_exec"] =  None if not hasattr(next_instr, "rd") else self.intregpickstate.regs[next_instr.rd].get_val_t0()
                stats_per_cycle += [stats]
            # if this bb is followed by a context saver block, execute it
            # if bb_id == self.last_bb_id_before_ctx_saver:
            #     assert False, f"Don't use this with ctxsaver"


        self.reset_states()
        return stats_per_cycle

    def comp_instr_dist(self):
        dist = {}
        for instrs in self.instr_objs_seq[1:]: # skip initial block
            for instr in instrs:
                if instr.instr_str in dist:
                    dist[instr.instr_str] += 1
                else:
                    dist[instr.instr_str] = 1
        return dist

    def log(self, log_msg):
        os.makedirs(self.tmp_dir,exist_ok=True)
        with open(f"{self.tmp_dir}/log.txt", "a") as f:
            f.write(log_msg)


    def get_curr_paddr(self, add_spike_offset: bool = True):
        return self.curr_bb_start_addr + sum([int(not i.iscompressed)*2+2 for i in self.instr_objs_seq[-1]]) + SPIKE_STARTADDR*int(add_spike_offset)

    def add_page_domain(self, addr, va_layout, priv):
        if addr&PAGE_ALIGNMENT_MASK  ==  self.final_bb_base_addr&PAGE_ALIGNMENT_MASK+SPIKE_STARTADDR:

            return
        if addr&PAGE_ALIGNMENT_MASK not in self.page_domains:
            self.page_domains[addr&PAGE_ALIGNMENT_MASK] = {'va_layouts' : {va_layout}, 'priv' : priv}
        else:
            assert self.page_domains[addr&PAGE_ALIGNMENT_MASK]['priv'] == priv, f"Privilege mismatch at {hex(addr)}: {self.page_domains[addr&PAGE_ALIGNMENT_MASK]['priv']} != {priv}. final bb at {hex(self.final_bb_base_addr+SPIKE_STARTADDR)}"
            self.page_domains[addr&PAGE_ALIGNMENT_MASK]['va_layouts'] |= {va_layout}

    # Save register states for locations that could be executed transiently to triage gadgets executed from taint-source domain
    def blacklist_gadget_addr(self, addr, va_layout, priv):
        assert va_layout is not None
        assert priv is not None

        # Don't restrict transient execution in taint sink privileges
        if priv in self.taint_sink_privs:
            return
        # print(f"Blacklisting {hex(addr)}")
        # We allow blacklisting one instruction beyond last addr
        assert addr > SPIKE_STARTADDR and addr <= SPIKE_STARTADDR+self.memsize, f"{hex(addr)} not in valid range [{hex(SPIKE_STARTADDR)},{hex(SPIKE_STARTADDR+self.memsize)}]."
        
        # records the domain of the arch. executed code in the page. Might execute from several layouts in a single page, but always only one privilege
        self.add_page_domain(addr, va_layout, priv)
        
        # print(f"Blacklisting {hex(addr)} with domain {self.page_domains[addr&PAGE_ALIGNMENT_MASK]}")
        # checkpoint of arch state
        if addr not in self.taint_source_transient_addrs_regs:
            self.taint_source_transient_addrs_regs[addr] = self.intregpickstate.save_curr_state()
        # if there's already a checkpoint, merge them by ORing taints of existing
        # and new checkpoint, and taint derived from XOR of concrete values to 
        # account for superposition 
        else:
            curr_state = self.intregpickstate.save_curr_state()
            for reg_id in range(self.intregpickstate.num_pickable_regs):
                reg_taint = curr_state[-1][reg_id].get_val_t0() | self.taint_source_transient_addrs_regs[addr][-1][reg_id].get_val_t0()
                # if the actual values differ, add the respective taint pattern to do superpositional simulation
                reg_taint |= curr_state[-1][reg_id].get_val() ^ self.taint_source_transient_addrs_regs[addr][-1][reg_id].get_val()
                self.taint_source_transient_addrs_regs[addr][-1][reg_id].set_val_t0(reg_taint) # or both taints


    def fill_mem_with_dead_code(self):
        for bb_instrs in enumerate(self.instr_objs_seq):
            for instr in bb_instrs:
                if isinstance(instr,(BranchInstruction,PrivilegeDescentInstruction,JALInstruction,JALRInstruction,SimpleExceptionEncapsulator)) and not is_tolerate_transient_window(self, instr) and not instr.priv_level in self.taint_sink_privs:
                    instr.blacklist_transient_window()

        # Iterate over all allocated (physical) pages
        for page_addr, page_privs in self.pagetablestate.ppn_leaf_to_priv_dict.items():
            if DEAD_CODE_ONLY_IN_CODE_PAGES:
                has_data_or_code = False
                for bb_start_addr in self.bb_start_addr_seq:
                    if (bb_start_addr+SPIKE_STARTADDR)&PAGE_ALIGNMENT_MASK == page_addr:
                        has_data_or_code = True
                    elif (bb_start_addr+SPIKE_STARTADDR +sum([2 if i.iscompressed else 4 for i in self.instr_objs_seq[self.bb_start_addr_seq.index(bb_start_addr)]]))&PAGE_ALIGNMENT_MASK == page_addr:
                        has_data_or_code = True
                if not has_data_or_code:
                    continue
            if page_privs == {}:
                # No data or code allowed here. E.g. page tables page or inital BB.
                continue
            # If we blacklisted this region, we obtain the domain from the dict.
            assert page_addr in self.page_domains, f"Page {hex(page_addr)} not in page_domains."
            domain = self.page_domains[page_addr]
            if domain['priv'] in self.taint_sink_privs:
                assert page_addr not in self.taint_source_transient_addrs_regs
                domain = (random.choice(list(self.page_domains[page_addr]['va_layouts'])), self.page_domains[page_addr]['priv'])
                
            # Otherwise we choose it randomly.
            else:
                priv = random.choice(list(page_privs))
                domain = (random.choice(range(0,self.num_layouts)) if  priv != PrivilegeStateEnum.MACHINE else -1, priv)

            # Iterate over addresses in page.
            addr = page_addr
            n_restricted_instrs = 0
            n_free_instrs = 0
            while addr < page_addr + PHYSICAL_PAGE_SIZE:
                if not self.memview.is_mem_range_free(addr-SPIKE_STARTADDR,addr-SPIKE_STARTADDR+4):
                    # If a BB starts here, skip until end of BB
                    if addr in self.bb_start_addr_seq:
                        addr += sum([2 if i.iscompressed else 4 for i in self.instr_objs_seq[self.bb_start_addr_seq.index(addr)]])
                        if addr >= page_addr + PHYSICAL_PAGE_SIZE:
                            break
                    else:
                        addr += 4
                    continue
                elif addr-SPIKE_STARTADDR>self.memsize:
                    break
                # Addr in page is free
                if addr in self.taint_source_transient_addrs_regs:
                    # print(f"{hex(addr)} in dict, restoring state")
                    self.intregpickstate.restore_state(self.taint_source_transient_addrs_regs[addr])
                    if PRINT_RESTORED_TRANSIENT_STATE:
                        print(f"Transient state at {hex(addr)}")
                        self.intregpickstate.print()
                    assert not None in domain, f"None in domain: {domain}"
                    spec_instrs= create_speculative_instrs(self, addr, domain)
                    for instr in spec_instrs:
                        assert instr.paddr == addr, f"Addr mismatch: {instr.get_str()} at {hex(addr)}"
                        if PRINT_TRANSIENT_INSTRUCTIONS:
                            instr.print() 
                        # The execution of a cf-instruction will blacklist some region as well, thus triaging second-order speculation (i.e. blacklist the target of a transiently executed branch), which however is not complete since we do not know which regions are blacklisted by this mechanism a-prioi, thus there might already be some code there    
                        instr.execute(is_spike_resolution=True)
                        self.memview.alloc_mem_range(addr-SPIKE_STARTADDR,addr-SPIKE_STARTADDR+(2 if instr.iscompressed else 4))
                        self.spec_instr_objs_seq += [instr]
                        n_restricted_instrs += 1


                        addr += (2 if instr.iscompressed else 4)
                        if addr&PAGE_ALIGNMENT_MASK != page_addr or not self.memview.is_mem_range_free(addr-SPIKE_STARTADDR, addr-SPIKE_STARTADDR+4) or addr-SPIKE_STARTADDR>self.memsize:
                            # print(f"Reached page boundary at {hex(addr)}")
                            break
                        # TODO don't do this for every single instruction, just after a block of instructions
                        self.blacklist_gadget_addr(addr, domain[0],domain[1]) # blacklist and checkpoint next address
                else:
                    spec_instrs= create_speculative_instrs(self, addr, domain)
                    for instr in spec_instrs:
                        assert instr.paddr == addr, f"Addr mismatch: {instr.get_str()} at {hex(addr)}"
                        if PRINT_TRANSIENT_INSTRUCTIONS:
                            instr.print()  
                        self.memview.alloc_mem_range(addr-SPIKE_STARTADDR,addr-SPIKE_STARTADDR+(2 if instr.iscompressed else 4))
                        self.spec_instr_objs_seq += [instr]
                        n_free_instrs += 1
                        addr += (2 if instr.iscompressed else 4)
                        if addr&PAGE_ALIGNMENT_MASK != page_addr or not self.memview.is_mem_range_free(addr-SPIKE_STARTADDR, addr-SPIKE_STARTADDR+4) or addr-SPIKE_STARTADDR>self.memsize:
                            # print(f"Reached page boundary at {hex(addr)}")
                            break

            # print(f"Page at {hex(page_addr)}, added {n_free_instrs} free and {n_restricted_instrs} restricted transient instructions.")
        


    def pickle(self, prefixname, test_identifier):
        pickle_path = os.path.join(self.tmp_dir, f"{prefixname}{test_identifier}.fuzzerstate.pickle")
        with open(pickle_path,"wb") as f:
            pickle.dump(self, f)


