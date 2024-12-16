from common.spike import SPIKE_STARTADDR
# from milesan.cfinstructionclasses import R12DInstruction, ImmRdInstruction, RegImmInstruction
from rv.asmutil import li_into_reg
from params.fuzzparams import RDEP_MASK_REGISTER_ID, PROBA_ENTANGLE_LAYOUT, PROBA_SAME_BASE_PT, TAINT_EN, ALLOC_PAGE_PER_PT
from params.runparams import DEBUG_PRINT, DO_ASSERT
from milesan.privilegestate import PrivilegeStateEnum
from common.designcfgs import get_design_stop_sig_addr, get_design_reg_dump_addr, get_design_reg_stream_addr
import random
from math import ceil, floor

#DEBUG_PRINT = True

MODES_PARAM_RV32 = {
    "sv32": [1, 32, 2]
}

# [mode id, #bits_va, #PPN]
MODES_PARAMS_RV64 = {
    "sv39": [8, 39, 3],
    "sv48": [9, 48, 4]
}

# MMU constants
PHYSICAL_PAGE_SIZE = 0x1000 #4KiB
PAGE_ALIGNMENT_MASK = (~0xfff)
PAGE_ALIGNMENT_BITS = 0xfff
PAGE_ALIGNMENT_SHIFT = 12
VPN_WIDTH = 9
PHYSICAL_ADDRESS_WIDTH = 64

R_PTE_BIT = 1
W_PTE_BIT = 2
X_PTE_BIT = 3
U_PTE_BIT = 4 

# @brief compute the virtual address
# TODO we can now randomly choose between layouts with the same base page
def phys2virt(paddr, priv_level, va_layout, fuzzerstate, absolute_addr = True):
    #bare
    if va_layout == -1: 
        return paddr
    else:
        if absolute_addr:
            vaddr = paddr + fuzzerstate.pagetablestate.vmem_base_list[va_layout][priv_level]
        else:
            vaddr = paddr - (SPIKE_STARTADDR - fuzzerstate.pagetablestate.vmem_base_list[va_layout][priv_level])
        return vaddr

# @brief reciprocal of above.
def virt2phys(vaddr, priv_level, va_layout, fuzzerstate, absolute_addr = True):
    #bare
    if va_layout == -1: 
        return vaddr
    else:
        if absolute_addr:
            paddr = vaddr - fuzzerstate.pagetablestate.vmem_base_list[va_layout][priv_level]
        else:
            paddr = vaddr + (SPIKE_STARTADDR - fuzzerstate.pagetablestate.vmem_base_list[va_layout][priv_level])
        return paddr

# @brief Stores a 64 bit value into a 64 bit register. 
def li_doubleword(value, rd, tmp, fuzzerstate, is_rd_nonpickable_ok: bool = False):
    from milesan.cfinstructionclasses_t0 import R12DInstruction_t0, ImmRdInstruction_t0, RegImmInstruction_t0

    instrs = []
    imm_0_to_31 = value & 0xffffffff
    imm_63_to_31 = value >> 32

    assert rd != tmp
    #load the first 32 bits 
    lui_imm, addi_imm = li_into_reg(imm_0_to_31, False)
    instrs.append(ImmRdInstruction_t0(fuzzerstate, "lui", tmp, lui_imm, is_rd_nonpickable_ok=is_rd_nonpickable_ok))
    instrs.append(RegImmInstruction_t0(fuzzerstate, "addi", tmp, tmp, addi_imm, is_rd_nonpickable_ok=is_rd_nonpickable_ok))
    #clear the top 32 bits
    instrs.append(R12DInstruction_t0(fuzzerstate, "and", tmp, tmp, RDEP_MASK_REGISTER_ID))
    #load the next 32 bits
    lui_imm_2, addi_imm_2 = li_into_reg(imm_63_to_31, False)
    instrs.append(ImmRdInstruction_t0(fuzzerstate, "lui", rd, lui_imm_2, is_rd_nonpickable_ok=is_rd_nonpickable_ok))
    instrs.append(RegImmInstruction_t0(fuzzerstate, "addi", rd, rd, addi_imm_2, is_rd_nonpickable_ok=is_rd_nonpickable_ok))
    instrs.append(RegImmInstruction_t0(fuzzerstate, "slli", rd, rd, 32, is_rd_nonpickable_ok=is_rd_nonpickable_ok))
    #coalesce the result
    instrs.append(R12DInstruction_t0(fuzzerstate, "or", rd, rd, tmp, is_rd_nonpickable_ok=is_rd_nonpickable_ok))
        
    return instrs

class PageTablesGen:
    def __init__(self, is_design_64bit, design_name):
        # Constants
        self.flags_leaf_pte_user         = 0b00011011111 #:=RSW DAGUXWRV
        self.flags_leaf_pte_supervisor   = 0b00011001111 #:=RSW DAGUXWRV
        self.flags_node_pte              = 0b00000000001 #:=RSW DAGUXWRV

        # Tracking accross functions
        self.entangled_layouts = [] # (None) or (entangled layout id, entanlged with, first common level)
        self.global_from_level = []

        # Output
        self.finalblock_sig_vaddr = [] # Saves the virtual addresses of regdump and stopsig for all layouts
        self.n_entries_per_level = [] # Number of PTE per level for each layouts
        self.vmem_base_list = [] # The virtual address mapping to SPIKE_STARTADDR for each layout
        self.ptr_pt_base_list_per_layout = [] # The physical address of the page base for each PT lavel and layouts, [[l0, l1, l2], [...], ...]
        self.ppn_leaves = [] # The value of the PTE for the leaf at offset 0 for all layout (SPIKE_START or 0x0 depending on allignment)
        self.ppn_leaf_to_priv_dict = {} # The privilege mode for that ppn_leave
        self.page_size_per_layout = [] # The page size for all layout
        self.all_pt_entries = [] # DATA BLOCK, saves all of the PTEs for all layouts, [[[ptel0], [ptel1], ...] ...]
        self.layout_is_global = [] # If the layout has global mappings, TLB entries need to be flushed even if ASID changes
        self.common_base_page = None #dict of layout with a common base page

        if not is_design_64bit:
            global VPN_WIDTH
            VPN_WIDTH = 10
            global PHYSICAL_ADDRESS_WIDTH
            PHYSICAL_ADDRESS_WIDTH = 32

        # Get the address for the final block
        try:
            self.stopsig_addr = get_design_stop_sig_addr(design_name)
        except:
            raise ValueError(f"Design `{design_name}` does not have the `stopsigaddr` attribute.")
        try:
            self.regdump_addr = get_design_reg_dump_addr(design_name)
        except:
            raise ValueError(f"Design `{design_name}` does not have the `regdumpaddr` attribute.")

    # @brief return the worst case required number of pages on each level
    def get_n_leaf_pte(self, page_size, mem_start, memsize, pte_size, n_levels):
        pte_per_page = PHYSICAL_PAGE_SIZE/pte_size
        # Get the first physical address mapped
        if mem_start == SPIKE_STARTADDR:
            mem_end = mem_start + memsize
        else:
            mem_end = mem_start + SPIKE_STARTADDR + memsize
        memsize_absolute = mem_end - mem_start
        n_leaf_pte = ceil(memsize_absolute / page_size)
        return n_leaf_pte

    # @brief gets node PTE for a given number of levels
    def get_node_pte_addr(self, fuzzerstate, n_node_levels, n_entries_per_level, leaf_base):
        ret             = []
        prev_level_base = leaf_base
        pte_per_page    = PHYSICAL_PAGE_SIZE/fuzzerstate.ptesize
        pte_locs = []
        # Get all the node page table addresses
        for level in range(n_node_levels-1, -1, -1):
            # Calculate the number of PTE required on the current level, based on the allignment of the previous level
            page_offset_start       = (prev_level_base & PAGE_ALIGNMENT_BITS)/fuzzerstate.ptesize
            n_pte_prev_level        = n_entries_per_level[level+1]
            # Get the page span
            start_page_id = floor(page_offset_start / pte_per_page)
            end_page_id = ceil((page_offset_start + n_pte_prev_level) / pte_per_page)
            n_entries_required = end_page_id - start_page_id
            n_entries_per_level[level] = n_entries_required # Update traking

            # With a certain probability, we generate base PTE in the same base page
            same_base_page = False
            if level == 0 and self.ptr_pt_base_list_per_layout != [] and random.random() < PROBA_SAME_BASE_PT:
                base_page = (self.ptr_pt_base_list_per_layout[0][0] & PAGE_ALIGNMENT_MASK) - SPIKE_STARTADDR
                addr = fuzzerstate.memview.gen_random_free_addr(fuzzerstate.ptesize, fuzzerstate.ptesize * n_entries_per_level[level], base_page, base_page + PAGE_ALIGNMENT_BITS)
                if addr != None: 
                    same_base_page = True
            elif same_base_page == False:
                addr = fuzzerstate.memview.gen_random_free_addr(fuzzerstate.ptesize, fuzzerstate.ptesize * n_entries_per_level[level], 0, fuzzerstate.memsize)
            # In case all allocations fail
            if addr is None:
                return False
            
            # Allocate the right ammount of memory
            fuzzerstate.memview.alloc_mem_range(addr, addr + fuzzerstate.ptesize * n_entries_required)
            pte_locs += [pte_loc for pte_loc in range(addr, addr + fuzzerstate.ptesize * n_entries_required, fuzzerstate.ptesize)]
            # Update 
            ret.append(addr + SPIKE_STARTADDR)
            prev_level_base = addr # Save previous base
        return ret, pte_locs
    
    # @brief makes a page table entry
    def gen_page_table_entry(self, ppn, is_global, is_user: bool = False, is_node: bool = False, is_executable: bool = True):
        if not is_node:
            if is_user:
                flags = self.flags_leaf_pte_user
            else:
                flags = self.flags_leaf_pte_supervisor
            if not is_executable:
                flags &= ~(1<<X_PTE_BIT) # clear executable bit.
                # print(f"{hex(ppn)} not executable.")
                
        else:
            flags = self.flags_node_pte
        return ((ppn >> PAGE_ALIGNMENT_SHIFT) << 10) | (flags | (is_global << 5))

    # @brief allocates space for all level of the page table
    def gen_mmu_dependencies(self, fuzzerstate):
        all_pte_locs = []
        for layout_id, (mode, n_level) in enumerate(fuzzerstate.prog_mmu_params):
            if DEBUG_PRINT:
                print(f"\n======= allocating pages for layout {layout_id} ===========================")
                print(VPN_WIDTH)
            
            # Initialize variables
            pte_addr                            = []
            leaf_pt_addr                        = []
            if fuzzerstate.is_design_64bit:
                n_virt_addr_bits, max_n_levels  = MODES_PARAMS_RV64[mode][1], MODES_PARAMS_RV64[mode][2]
            else:
                n_virt_addr_bits, max_n_levels  = MODES_PARAM_RV32[mode][1], MODES_PARAM_RV32[mode][2]
            n_allignment_bits                   = PAGE_ALIGNMENT_SHIFT + VPN_WIDTH * (max_n_levels - n_level)
            page_size                           = (1 << n_allignment_bits)
            mem_start                           = SPIKE_STARTADDR & (~(page_size - 1)) # Holds the first address mapped using the current page size, either 0x80000000 or 0x0
            start_vmem                          = {PrivilegeStateEnum.USER: 0, PrivilegeStateEnum.SUPERVISOR: 0, PrivilegeStateEnum.MACHINE: 0}
            layout_entangled                    = False
            
            # Update the entangled list
            self.entangled_layouts.append(None)

            # Entangle the pages, we generate new PTEs for the upper levels, we randomly choose the level at which the PTEs will be identical to a randomly selected previous mapping
            if self.ptr_pt_base_list_per_layout != [] and random.random() < PROBA_ENTANGLE_LAYOUT and n_level > 1:
                raise NotImplementedError("Entangled layouts not implemented.")
                # We can only entangle with layouts that have the same levels and page size
                possible_layouts = []
                for layout_id, (mode_entagle, n_level_entangle) in enumerate(fuzzerstate.prog_mmu_params):
                    if layout_id >= len(self.ptr_pt_base_list_per_layout): break
                    if mode_entagle == mode and n_level_entangle == n_level:
                        possible_layouts.append(layout_id)

                # If we can entangle, we randomly select the target
                if possible_layouts != []:
                    layout_entangled = True
                    layout_entangle = random.choice(possible_layouts)
                    if len(self.ptr_pt_base_list_per_layout[layout_entangle]) - 1 == 1:
                        first_common_level = 1
                    else:
                        first_common_level = random.randrange(1, len(self.ptr_pt_base_list_per_layout[layout_entangle])-1) #We must generate at least one new level and at most all except the leaf
                    if DEBUG_PRINT: print(f"We entagle layout {layout_id} with layout {layout_entangle}, at level: {first_common_level}")
                    self.entangled_layouts[layout_id] = ((layout_id, layout_entangle, first_common_level))
                    
                    # Copy the values from the other layout
                    pte_addr = self.ptr_pt_base_list_per_layout[layout_entangle].copy()
                    n_entries_per_level = self.n_entries_per_level[layout_entangle].copy()

                    # Get node PTEs
                    addrs = self.get_node_pte_addr(fuzzerstate, first_common_level, n_entries_per_level, pte_addr[first_common_level])
                    if addrs == False:
                        return False
                    level = 0
                    for addr in addrs:
                        pte_addr[level] = addr
                        level + 1
                    if DEBUG_PRINT: 
                        print(f"pte are at addr: {[hex(x) for x in pte_addr]}")
                        print(f"Will use {n_entries_per_level}")

            # If we generate a fresh new layout
            if not layout_entangled:
                # Calculate number of leaf page table entries needed
                n_entries_per_level = [0] * n_level
                n_leaf_pte = self.get_n_leaf_pte(page_size, mem_start, fuzzerstate.memsize, fuzzerstate.ptesize, n_level)
                n_leaves_with_duplicate = n_leaf_pte * 2 + 2 # Duplicate for S mode, + 2 for signal mappings
                n_entries_per_level[-1] = n_leaves_with_duplicate

                # Get leaf page table address
                addr = fuzzerstate.memview.gen_random_free_addr(fuzzerstate.ptesize, n_leaves_with_duplicate * fuzzerstate.ptesize, 0, fuzzerstate.memsize) # + (2*fuzzerstate.ptesize) to map sig addr
                if addr is None:
                    return False
                fuzzerstate.memview.alloc_mem_range(addr, addr + n_leaves_with_duplicate * fuzzerstate.ptesize) #+ (2*fuzzerstate.ptesize) to map sig addr
                all_pte_locs += [pte_loc for pte_loc in range(addr, addr + n_leaves_with_duplicate * fuzzerstate.ptesize, fuzzerstate.ptesize)] # collect leaf ptes
                leaf_pt_addr.append(addr + SPIKE_STARTADDR)

                # Get all the node page table addresses, and the number of pte accross levels
                addrs, pte_locs = self.get_node_pte_addr(fuzzerstate, n_level - 1, n_entries_per_level, leaf_pt_addr[-1])
                if addrs == False:
                    return False
                for addr in addrs:
                    pte_addr.append(addr)

                all_pte_locs += pte_locs 


                # reset the number of leave PTE
                n_entries_per_level[-1] = n_leaf_pte

                # Append leaf pt address at the end
                pte_addr += leaf_pt_addr
                if DEBUG_PRINT: print(f"pte are at addr: {[hex(x) for x in pte_addr]}, and use: {n_entries_per_level[-1]} leaves")
                
                if DEBUG_PRINT:
                    print(f"Will use: {n_entries_per_level}")

            # Compute the VA address equivalent to 0x80000000 to later translate from phys to virt
            n_unused_level = max_n_levels - n_level
            vpn_shift_amt = PAGE_ALIGNMENT_SHIFT + VPN_WIDTH * n_unused_level
            for level in range(n_level):
                curr_pte_addr = pte_addr[n_level - level - 1]
                offset = (curr_pte_addr & PAGE_ALIGNMENT_BITS) // fuzzerstate.ptesize
                start_vmem[PrivilegeStateEnum.USER] |= offset << vpn_shift_amt
                vpn_shift_amt += VPN_WIDTH

            # Set remaining bits in VA mode
            if start_vmem[PrivilegeStateEnum.USER] >> (n_virt_addr_bits - 1):
                same_bit = ((1 << (PHYSICAL_ADDRESS_WIDTH - n_virt_addr_bits)) - 1) << n_virt_addr_bits
                start_vmem[PrivilegeStateEnum.USER] |= same_bit

            # Compute the regdump and stopsig virtual addresses before adding the start address offset
            regdump_vaddr                               = start_vmem[PrivilegeStateEnum.USER] + (n_entries_per_level[-1] * 2) * page_size + (self.regdump_addr & (page_size - 1))
            stopsig_vaddr                               = start_vmem[PrivilegeStateEnum.USER] + ((n_entries_per_level[-1] * 2) + 1) * page_size + (self.stopsig_addr & (page_size - 1))

            start_vmem[PrivilegeStateEnum.USER]         += (SPIKE_STARTADDR - mem_start) # Add offset if the pages start at address 0
            # Add the offset to get the base for the supervisor mappings
            start_vmem[PrivilegeStateEnum.SUPERVISOR]   = start_vmem[PrivilegeStateEnum.USER] + n_entries_per_level[-1] * page_size
            start_vmem[PrivilegeStateEnum.MACHINE]      = start_vmem[PrivilegeStateEnum.USER]

            if DEBUG_PRINT: 
                print(f"base vmem: {[hex(x) for x in start_vmem.values()]}")
                print(f"USER: {hex(start_vmem[PrivilegeStateEnum.USER])}")
                print(f"SUPERVISOR: {hex(start_vmem[PrivilegeStateEnum.SUPERVISOR])}")
                print(f"regdump_vaddr: {hex(regdump_vaddr)}")
                print(f"stopsig_vaddr: {hex(stopsig_vaddr)}")


            # Set variables for bookeeping

            self.finalblock_sig_vaddr.append((regdump_vaddr, stopsig_vaddr))
            self.n_entries_per_level.append(n_entries_per_level)
            self.vmem_base_list.append(start_vmem)
            self.ptr_pt_base_list_per_layout.append(pte_addr)
            self.ppn_leaves.append(mem_start)
            self.page_size_per_layout.append(page_size)

        # Make a dictionary of layouts with the same base page
        self.common_base_page = {i: [] for i in range(len(self.ptr_pt_base_list_per_layout))}
        # Iterate over each pair of objects
        for i in range(len(self.ptr_pt_base_list_per_layout)):
            for j in range(len(self.ptr_pt_base_list_per_layout)):
                if i != j:
                    # Check if the first elements of self.ptr_pt_base_list_per_layout[i] and self.ptr_pt_base_list_per_layout[j] are the same
                    if (self.ptr_pt_base_list_per_layout[i][0] & PAGE_ALIGNMENT_MASK) == (self.ptr_pt_base_list_per_layout[j][0] & PAGE_ALIGNMENT_MASK):
                        self.common_base_page[i].append(j)

                
        all_pte_locs.sort()
        pages_holding_ptes = set([pte&PAGE_ALIGNMENT_MASK for pte in all_pte_locs])
        page_base_addr_to_ptes_dict = {page_addr: [] for page_addr in list(pages_holding_ptes)}
        for pte in all_pte_locs:
            page_base_addr_to_ptes_dict[pte&PAGE_ALIGNMENT_MASK] += [pte]
        
        # for page_addr, ptes in page_base_addr_to_ptes_dict.items():
        #     print(f"{hex(page_addr)}: {[hex(addr) for addr in ptes]}")
        for page_addr, ptes_in_page in page_base_addr_to_ptes_dict.items():
            space_until_first_pte = fuzzerstate.memview.get_available_contig_space(page_addr)
            pte_addr = page_addr + space_until_first_pte
            assert pte_addr == ptes_in_page[0], f"{hex(pte_addr)} does not match expected addr of first PTE in page {hex(page_addr)} at {hex(ptes_in_page[0])}. {hex(space_until_first_pte)}"
            if DEBUG_PRINT:
                print(f"Allocating until first pte {hex(page_addr)} - {hex(pte_addr)}")
            if pte_addr>page_addr:
                fuzzerstate.memview.alloc_mem_range(page_addr, pte_addr)
            while pte_addr < page_addr+PHYSICAL_PAGE_SIZE:
                space_until_next_pte = fuzzerstate.memview.get_available_contig_space(pte_addr+fuzzerstate.ptesize)
                if space_until_next_pte==0:
                    pte_addr+=fuzzerstate.ptesize
                    continue
                if pte_addr+fuzzerstate.ptesize+space_until_next_pte > page_addr+PHYSICAL_PAGE_SIZE: # last pte in this page
                    if DEBUG_PRINT:
                        print(f"Allocating until end of page {hex(pte_addr+fuzzerstate.ptesize)} - {hex(page_addr+PHYSICAL_PAGE_SIZE)}")
                    if pte_addr+fuzzerstate.ptesize<page_addr+PHYSICAL_PAGE_SIZE:
                        fuzzerstate.memview.alloc_mem_range(pte_addr+fuzzerstate.ptesize, page_addr+PHYSICAL_PAGE_SIZE)
                    break
                else:
                    if DEBUG_PRINT:
                        print(f"Allocating until next base pte {hex(pte_addr+fuzzerstate.ptesize)} - {hex(pte_addr+fuzzerstate.ptesize+space_until_next_pte)}")
                    fuzzerstate.memview.alloc_mem_range(pte_addr+fuzzerstate.ptesize, pte_addr + fuzzerstate.ptesize + space_until_next_pte)
                    pte_addr += fuzzerstate.ptesize + space_until_next_pte



        if DEBUG_PRINT: 
            print("common base page dict")
            print(self.common_base_page)
            print("============ Page tables are created, will now populate ===============\n")

        return True
        
    # @brief populate the mmu pte list with the value of the PTE for all layouts to write them already initialized in memory
    # the program can later modify these lists to trigger page faults, etc 
    def gen_pt_in_mem(self, fuzzerstate):
        from milesan.finalblock import get_finalblock_max_size
        curr_layout_pt_content      = []
        ppn_leaf                    = 0


        # For non-leaf PTEs, the global setting implies that all mappings in the subsequent levels of the page table are global
        # We thus randomize all levels, as every scenario is interesting. We must then handle entagled layouts

        ##
        # We initialize the upper level of the page tables here
        ##
        for layout_id, va_layout in enumerate(self.ptr_pt_base_list_per_layout):
            self.global_from_level.append(None)
            if DEBUG_PRINT: print(f"\n======== Filling top level pages for layout {layout_id} ============")
            curr_layout_pt_content = []
            is_curr_layout_global = 0
            for level in range(0, len(va_layout)-1):
                entries = []
                pte_ppn = va_layout[level+1] #points to the next PT

                # Check if the layout is entangled from this level on
                if self.entangled_layouts[layout_id] != None:
                    if self.entangled_layouts[layout_id][2] == level:
                        if DEBUG_PRINT: print("Entry is part of an entangled layout, skipping")
                        break
                # Make all required entries
                for i in range(self.n_entries_per_level[layout_id][level]):
                    global_bit = random.randint(0, 1)
                    is_curr_layout_global |= global_bit
                    if is_curr_layout_global:
                        self.global_from_level[layout_id] = level
                    imm = self.gen_page_table_entry(pte_ppn, global_bit, is_node=True)
                    entries.extend([imm])
                    if DEBUG_PRINT: 
                        print(f"setting layout {layout_id}, level {level} pte @addr: {hex((va_layout[level]+PHYSICAL_PAGE_SIZE*i))} with val: {hex(imm)} ({hex(pte_ppn)})")
                    pte_ppn += PHYSICAL_PAGE_SIZE
                curr_layout_pt_content.append(entries)

            self.all_pt_entries.append(curr_layout_pt_content)
            self.layout_is_global.append(is_curr_layout_global)

        if DEBUG_PRINT: print("\n###\nLEAF MAPPINGS\n###\n")
        
        ##
        # Initialize the leaves of page tables, duplicated for supervisor mode support
        ##
        for layout_id, va_layout in enumerate(self.ptr_pt_base_list_per_layout):
            if DEBUG_PRINT: print(f"======== Filling leaf page for layout {layout_id} ============\n")
            # Check if we didn't already writ something in the PTE, otherwise, we add it to the written list
            if self.entangled_layouts[layout_id] != None:
                if DEBUG_PRINT: print("Entry is part of an entangled layout, skipping")
                continue
            is_curr_layout_global = random.randint(0, 1)
            if is_curr_layout_global:
                self.global_from_level[layout_id] = len(va_layout)-1
            ppn_leaf = self.ppn_leaves[layout_id]
            if DEBUG_PRINT: 
                print(f"curent layout is {[hex(x) for x in va_layout]}, with the base ppn of the page: {hex(ppn_leaf)}")
            curr_layout_pt_content, curr_layout_pt_content_supervisor = [], []
            if DEBUG_PRINT:
                print(f"Generating {self.n_entries_per_level[layout_id][-1]} leaves for layout {layout_id}")
            
            mapped_initial_block = False
            mapped_final_block = False
            mapped_ctx_block = False
            # priv = PrivilegeStateEnum.MACHINE
            for _ in range(self.n_entries_per_level[layout_id][-1]):
                assert (ppn_leaf^self.stopsig_addr)&PAGE_ALIGNMENT_MASK != 0, f"Page table allocated in same frame as stopsig addr. This should not happen."
                assert (ppn_leaf^self.regdump_addr)&PAGE_ALIGNMENT_MASK != 0, f"Page table allocated in same frame as stopsig addr. This should not happen."
                # Make user and supervisor
                is_pt = ppn_leaf in [i&PAGE_ALIGNMENT_MASK for j in self.ptr_pt_base_list_per_layout for i in j]
                if is_pt:
                    if DEBUG_PRINT:
                        print(f"{hex(ppn_leaf)} points to page table. Skipping mapping.")
                    self.ppn_leaf_to_priv_dict[ppn_leaf] = {} # Empty set. No privilige can allocate code here.
                    curr_layout_pt_content.append(0)
                    curr_layout_pt_content_supervisor.append(0)
                    ppn_leaf += self.page_size_per_layout[layout_id]
                    continue
                is_random_data_block = ppn_leaf-SPIKE_STARTADDR in [addr[0] for addr in fuzzerstate.random_data_block_ranges]
                if TAINT_EN and is_random_data_block and fuzzerstate.random_data_block_has_taint[ppn_leaf-SPIKE_STARTADDR]:
                    if layout_id in fuzzerstate.taint_source_layouts:
                        # If this is a random data block with taint and we only allow taint in one privilege, we map it accordingly s.t. only that privelege has access.
                        # We then need to ensure that tainted data is also only written to pages that were tainted initially.
                        curr_pte            = self.gen_page_table_entry(ppn_leaf, is_curr_layout_global, is_user=PrivilegeStateEnum.USER in fuzzerstate.taint_source_privs, is_executable=False)
                        # When M-mode is the only taint source privilege, we map a PTE for S-mode with the U bit set we can trigger page faults with it.
                        curr_pte_supervisor = self.gen_page_table_entry(ppn_leaf, is_curr_layout_global, is_user=PrivilegeStateEnum.USER in fuzzerstate.taint_source_privs or fuzzerstate.taint_source_privs == {PrivilegeStateEnum.MACHINE}, is_executable=False)
                        self.ppn_leaf_to_priv_dict[ppn_leaf] = set(fuzzerstate.taint_source_privs) # need a copy here, so create new set
                        if DEBUG_PRINT:
                            print(f"{hex(ppn_leaf)} maps data page with taints: U-PTE: {hex(curr_pte)}, S-PTE: {hex(curr_pte_supervisor)}")
                    else:
                        curr_pte = 0
                        curr_pte_supervisor = 0
                        if ppn_leaf not in self.ppn_leaf_to_priv_dict: # might be mapped from another privilege, don't overwrite in this case
                            self.ppn_leaf_to_priv_dict[ppn_leaf] = {PrivilegeStateEnum.MACHINE}
                        else:
                            self.ppn_leaf_to_priv_dict[ppn_leaf] |= {PrivilegeStateEnum.MACHINE}
                        if DEBUG_PRINT:
                            print(f"{hex(ppn_leaf)} maps data page with taints, skipping in taint-sink-layout {layout_id}")

                elif is_random_data_block:
                    # If it is a random data block without taint, map it to both privileges. It will be a shared memory, where only untainted data can be written to.
                    curr_pte            = self.gen_page_table_entry(ppn_leaf, is_curr_layout_global, is_user=True, is_executable=False)
                    curr_pte_supervisor = self.gen_page_table_entry(ppn_leaf, is_curr_layout_global, is_user=False, is_executable=False)
                    self.ppn_leaf_to_priv_dict[ppn_leaf] = {PrivilegeStateEnum.USER, PrivilegeStateEnum.SUPERVISOR, PrivilegeStateEnum.MACHINE}
                    if DEBUG_PRINT:
                        print(f"{hex(ppn_leaf)} maps data page without taints: U-PTE: {hex(curr_pte)}, S-PTE: {hex(curr_pte_supervisor)}")
                elif ppn_leaf - SPIKE_STARTADDR == fuzzerstate.final_bb_base_addr&PAGE_ALIGNMENT_MASK or ppn_leaf - SPIKE_STARTADDR == ((fuzzerstate.final_bb_base_addr+get_finalblock_max_size())&PAGE_ALIGNMENT_MASK):
                    mapped_final_block = True
                    # print("Mapping final block")
                    # If the page belongs to the final block, also map it for both priveleges.
                    curr_pte            = self.gen_page_table_entry(ppn_leaf, is_curr_layout_global, is_user=True, is_executable=True)
                    curr_pte_supervisor = self.gen_page_table_entry(ppn_leaf, is_curr_layout_global, is_user=False, is_executable=True)
                    self.ppn_leaf_to_priv_dict[ppn_leaf] = {PrivilegeStateEnum.USER, PrivilegeStateEnum.SUPERVISOR, PrivilegeStateEnum.MACHINE}
                    if DEBUG_PRINT:
                        print(f"{hex(ppn_leaf)} maps the final BB: U-PTE: {hex(curr_pte)}, S-PTE: {hex(curr_pte_supervisor)}")
                elif ppn_leaf - SPIKE_STARTADDR == fuzzerstate.bb_start_addr_seq[0]&PAGE_ALIGNMENT_MASK:
                    mapped_initial_block = True
                    if DEBUG_PRINT:
                        print(f"{hex(ppn_leaf)} maps the initial BB.")
                    # If it is the first basic block, don't map it as it will only be used in machine mode.
                    curr_pte            = 0
                    curr_pte_supervisor = 0
                    self.ppn_leaf_to_priv_dict[ppn_leaf] = {PrivilegeStateEnum.MACHINE}
                elif ppn_leaf - SPIKE_STARTADDR == fuzzerstate.ctxsv_bb_base_addr&PAGE_ALIGNMENT_MASK:
                    mapped_ctx_block = True
                    # Map the context saver to all privileges
                    curr_pte            = self.gen_page_table_entry(ppn_leaf, is_curr_layout_global, is_user=True, is_executable=True)
                    curr_pte_supervisor = self.gen_page_table_entry(ppn_leaf, is_curr_layout_global, is_user=False, is_executable=True)
                    self.ppn_leaf_to_priv_dict[ppn_leaf] = {PrivilegeStateEnum.USER, PrivilegeStateEnum.SUPERVISOR, PrivilegeStateEnum.MACHINE}
                    if DEBUG_PRINT:
                        print(f"{hex(ppn_leaf)} maps the initial BB: U-PTE: {hex(curr_pte)}, S-PTE: {hex(curr_pte_supervisor)}")
                else:
                    if ppn_leaf not in self.ppn_leaf_to_priv_dict:
                        priv = {random.choice([PrivilegeStateEnum.USER, PrivilegeStateEnum.SUPERVISOR, PrivilegeStateEnum.MACHINE])} # Dont map any hypervisor
                        if DEBUG_PRINT:
                            print(f"{hex(ppn_leaf)} assigned to {[p.name for p in priv]}.")
                        self.ppn_leaf_to_priv_dict[ppn_leaf] = priv
                    else:
                        priv = self.ppn_leaf_to_priv_dict[ppn_leaf]
                    if priv == {PrivilegeStateEnum.MACHINE}:
                        curr_pte = 0 # If this page is an executable page for machine mode, don't map it
                        curr_pte_supervisor = 0
                    else:
                        # Otherwise, map it for both user and supervisor with the right privileges.
                        curr_pte            = self.gen_page_table_entry(ppn_leaf, is_curr_layout_global, is_user = PrivilegeStateEnum.USER in priv, is_executable=True)
                        curr_pte_supervisor = self.gen_page_table_entry(ppn_leaf, is_curr_layout_global, is_user = PrivilegeStateEnum.USER in priv, is_executable=True)
                curr_layout_pt_content.append(curr_pte)
                curr_layout_pt_content_supervisor.append(curr_pte_supervisor)
                ppn_leaf += self.page_size_per_layout[layout_id]
            assert mapped_initial_block
            assert mapped_final_block
            assert mapped_ctx_block

            # Coalesce the results and store bookeeping data
            curr_layout_pt_content += curr_layout_pt_content_supervisor
            self.all_pt_entries[layout_id].append(curr_layout_pt_content)
            self.layout_is_global[layout_id] |= is_curr_layout_global

        if DEBUG_PRINT: print("\n")

        ##
        # Handle global mappings for entangled layouts
        ##

        for cur_entry in self.entangled_layouts:
            if cur_entry != None:
                entangled_layout_id, entanlged_with, first_common_level = cur_entry
                if DEBUG_PRINT: print(f"entangled with: {entanlged_with}, is_glb:{self.layout_is_global[entanlged_with]}, from lvl:{self.global_from_level[entanlged_with]}")
                # If an entry in the reused layout is global, which is below the last unentangled pte, the current layout is gloabal as well
                if self.layout_is_global[entanlged_with] and first_common_level >= self.global_from_level[entanlged_with]:
                    self.layout_is_global[entangled_layout_id] |= 1
                    self.global_from_level[entangled_layout_id] = self.global_from_level[entanlged_with]

        if DEBUG_PRINT:
            print("\nLIST OF GLOABL LAYOUTS")
            for id, i in enumerate(self.layout_is_global):
                if i:
                    print(f"layout {id} is global")
            print("\n")

        ##
        # Map the regdump and stopsig addr
        ##
        
        for layout_id, va_layout in enumerate(self.ptr_pt_base_list_per_layout):
            if self.entangled_layouts[layout_id] != None: continue
            final_block_addr_ptes = []

            # Get the PPN for the leaf PTEs
            ppn_leaf_regdump = self.regdump_addr & (~(self.page_size_per_layout[layout_id] - 1))
            ppn_leaf_stopsig = self.stopsig_addr & (~(self.page_size_per_layout[layout_id] - 1))
            assert ppn_leaf_regdump + self.page_size_per_layout[layout_id] > self.regdump_addr
            assert ppn_leaf_stopsig + self.page_size_per_layout[layout_id] > self.stopsig_addr

            # Make supervisor regdump and stopsig
            curr_pte_supervisor = self.gen_page_table_entry(ppn_leaf_stopsig, True, is_user=False)
            if DEBUG_PRINT:
                print(f"stopsig pte: {hex(curr_pte_supervisor)}: {hex(ppn_leaf_stopsig)} at {hex(self.stopsig_addr)}")
            final_block_addr_ptes.append(curr_pte_supervisor)
            curr_pte_supervisor = self.gen_page_table_entry(ppn_leaf_regdump, True, is_user=False)
            if DEBUG_PRINT:
                print(f"regdump pte: {hex(curr_pte_supervisor)}: {hex(ppn_leaf_regdump)} at {hex(self.regdump_addr)}")
            final_block_addr_ptes.append(curr_pte_supervisor)
            self.all_pt_entries[layout_id][-1] += final_block_addr_ptes



    

    

