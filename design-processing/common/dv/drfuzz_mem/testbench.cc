
#include "testbench.h"
#include "macros.h"
#include "dtypes.h"
#include "update_req.h"
#include "def_tb.h"
#include "instructions.h"
#include <iomanip>

void Testbench::reset(){
    this->got_stop_req = false;
    this->module_->rst_ni = 1;
    #ifdef DISABLE_PC_TAINT
    this->module_->meta_reset_pc_t0 = 1;
    #endif
    this->module_->meta_rst_ni = 1;
    this->module_->meta_rst_ni_t0 = 1;
    this->tick(1);
    this->module_->rst_ni = 0;
    this->tick(N_RESET_TICKS);
    this->module_->rst_ni = 1;
}


void Testbench::meta_reset(){
    this->module_->meta_rst_ni = 1;
    this->module_->rst_ni = 1; // deassert normal reset while meta reset is running
    this->tick(1);
    this->module_->meta_rst_ni = 0;
    this->module_->meta_rst_ni_t0 = 0;
    this->tick(N_META_RESET_TICKS);
    this->module_->meta_rst_ni = 1;
    this->module_->meta_rst_ni_t0 = 1;
}

void Testbench::meta_reset_t0(){
    this->module_->meta_rst_ni_t0 = 0;
    this->tick(N_META_RESET_TICKS);
    this->module_->meta_rst_ni_t0 = 1;
}

void Testbench::meta_reset_pc_t0(){
    this->module_->meta_reset_pc_t0 = 1;
    this->tick(N_META_RESET_TICKS);
    this->module_->meta_reset_pc_t0 = 0;
}

void Testbench::clear_outputs(){
    this->outputs.clear();
    assert(this->outputs.size() == 0);
}

void Testbench::reset_memory(){
    #ifdef SINGLE_MEM
    svScope scope = svGetScopeFromName(VSCOPE_MEM);
    assert(scope);  // Check for nullptr if scope not found
    svSetScope(scope);
    _reset_memory();
    #endif
    #ifdef DUAL_MEM // also reset inst rom because of taints
    svScope scope = svGetScopeFromName(VSCOPE_DMEM);
    assert(scope);  // Check for nullptr if scope not found
    svSetScope(scope);
    _reset_memory();
    scope = svGetScopeFromName(VSCOPE_IMEM);
    assert(scope);  // Check for nullptr if scope not found
    svSetScope(scope);
    _reset_memory();
    #endif
}

void Testbench::reset_memory_t(){
    #ifdef SINGLE_MEM // TODO test
    svScope scope = svGetScopeFromName(VSCOPE_MEM);
    assert(scope);  // Check for nullptr if scope not found
    svSetScope(scope);
    _reset_memory_t();
    // this->module_->mem_req_t0 = 0x0ULL;
    #endif

    #ifdef DUAL_MEM
    svScope scope = svGetScopeFromName(VSCOPE_DMEM);
    assert(scope);  // Check for nullptr if scope not found
    svSetScope(scope);
    _reset_memory_t();
    // this->module_->data_mem_req_t0 = 0x0ULL;
    // this->module_->data_mem_addr_t0 = 0x0ULL;
    
    scope = svGetScopeFromName(VSCOPE_IMEM);
    assert(scope);  // Check for nullptr if scope not found
    svSetScope(scope);
    _reset_memory_t();
    // this->module_->instr_mem_req_t0 = 0x0ULL;
    // this->module_->instr_mem_addr_t0 = 0x0ULL;
    #endif

}

void Testbench::dump_mem(){
    #ifdef SINGLE_MEM // TODO test
    std::cout << "MEM:\n";
    svScope scope = svGetScopeFromName(VSCOPE_MEM);
    assert(scope);  // Check for nullptr if scope not found
    svSetScope(scope);
    _dump_mem();
    #endif

    #ifdef DUAL_MEM
    svScope scope = svGetScopeFromName(VSCOPE_DMEM);
    assert(scope);  // Check for nullptr if scope not found
    svSetScope(scope);
    std::cout << "DMEM:\n";
    _dump_mem();
    scope = svGetScopeFromName(VSCOPE_IMEM);
    assert(scope);  // Check for nullptr if scope not found
    svSetScope(scope);
    std::cout << "IMEM:\n";
    _dump_mem();
    #endif
}

void Testbench::close_trace(void) {
	#if VM_TRACE  
	trace_->close();
	#endif // VM_TRACE
  }

tick_req_t Testbench::tick(int num_ticks, bool false_tick) {
    static Instruction *intercept = nullptr;
	tick_req_t ret;
	ret.type = REQ_NONE;

	for (size_t i = 0; i < num_ticks || num_ticks == -1; i++) {
        this->tick_count_++;

  
        module_->clk_i = 0;
        module_->eval();

        #if VM_TRACE
        trace_->dump(5 * this->tick_count_ - 1);
        #endif // VM_TRACE

        module_->clk_i = !false_tick;

        if(intercept != nullptr){
            #ifdef DUAL_MEM
            module_->intercept_instr_mem_en = 1;
            module_->intercept_instr_mem_rdata = intercept->inject_inst ? intercept->get_binary() : module_->instr_mem_rdata;
            module_->instr_mem_rdata_t0 = intercept->inject_taint ? intercept->get_binary_t0() : 0x0;
            #ifdef PRINT_INTERCEPT
            // std::cout << "Intercepting setting module->instr_mem_rdata: " << std::hex <<  module_->intercept_instr_mem_rdata << "(" << std::hex << module_->instr_mem_rdata << ")\n";
            // std::cout <<  "\tand module->instr_mem_rdata_t0 " << std::hex <<module_->instr_mem_rdata_t0 << std::endl;
            intercept->print_intercept(module_->instr_mem_rdata,0x0);
            #endif // PRINT_INTERCEPT
            #else
            module_->intercept_mem_en = 1;
            #if DATA_WIDTH_BYTES == 4
            module_->intercept_mem_rdata = intercept->inject_inst ?   module_->mem_rdata_o | intercept->get_binary() : module_->mem_rdata_o;
            module_->mem_rdata_o_t0 = intercept->inject_taint ? intercept->get_binary_t0() : 0x0;
            #else // DATA_WIDTH_BYTES == 8
            assert(DATA_WIDTH_BYTES==8);
            if(intercept->alignment == 0){
                module_->intercept_mem_rdata = intercept->inject_inst ?  (module_->mem_rdata_o&(0xFFFFFFFFULL<<32) | intercept->get_binary()) : module_->mem_rdata_o;
                module_->mem_rdata_o_t0 = intercept->inject_taint ? intercept->get_binary_t0() : 0x0;
                #ifdef PRINT_INTERCEPT
                intercept->print_intercept(module_->mem_rdata_o&0xFFFFFFFFULL,0x0);
                #endif // PRINT_INTERCEPT


            }
            else{
                assert(intercept->alignment == 4);
                module_->intercept_mem_rdata = intercept->inject_inst ?  (module_->mem_rdata_o & (0xFFFFFFFFULL) | ((uint64_t) intercept->get_binary())<<32) : module_->mem_rdata_o;
                module_->mem_rdata_o_t0 = intercept->inject_taint ? ((uint64_t) intercept->get_binary_t0())<<32 : 0x0;
                #ifdef PRINT_INTERCEPT
                intercept->print_intercept((module_->mem_rdata_o&(0xFFFFFFFFULL<<32))>>32,0x0);
                #endif // PRINT_INTERCEPT
            }
            #endif // DATA_WIDTH_BYTES
            #endif // DUAL_MEM
        }
        module_->eval();


        #if VM_TRACE
        trace_->dump(5 * this->tick_count_);
        #endif // VM_TRACE

        _update_req(module_, &ret); // design specific function
        this->read_new_output();

        module_->clk_i = 0;
        module_->eval();

        if(intercept){
            intercept->retired = true;
            intercept = nullptr;
            #ifdef DUAL_MEM
            module_->instr_mem_rdata_t0 = 0x0;
            module_->intercept_instr_mem_en = 0;
            #else
            module_->mem_rdata_o_t0 = 0x0;
            module_->intercept_mem_en = 0;
            #endif
        }
        #ifdef DUAL_MEM
        if(this->intercept_instructions.count((module_->instr_mem_addr>>DATA_WIDTH_BYTES_LOG2)-1)){ // instr_mem returns instruction in subsequent cycle
            intercept = this->intercept_instructions[(module_->instr_mem_addr>>DATA_WIDTH_BYTES_LOG2)-1];
            if(!intercept->retired){
                // #ifdef PRINT_INTERCEPT
                // std::cout << "Intercepting instruction found for address " << std::hex << intercept->get_address() <<  ", intercepting next cycle" << std::endl; 
                // #endif // PRINT_INTERCEPT
            }
            else{
                intercept = nullptr;
            }
            }
        #else // single memory for data and instructions 
        if(this->intercept_instructions.count((module_->mem_addr_o>>DATA_WIDTH_BYTES_LOG2)-1)){ // instr_mem returns instruction in subsequent cycle
            intercept = this->intercept_instructions[(module_->mem_addr_o>>DATA_WIDTH_BYTES_LOG2)-1];
            if(!intercept->retired){
                // #ifdef PRINT_INTERCEPT
                // std::cout << "Intercepting instruction found for address " << std::hex << intercept->get_address() <<  ", intercepting next cycle" << std::endl; 
                // #endif // PRINT_INTERCEPT
            }
            else{
                intercept = nullptr;
            }
        }
        #endif
        // if(module_->mem_addr_o) std::cout << std::hex << (module_->mem_addr_o>>3) << ":" << module_->mem_rdata_o << std::endl;
        #if VM_TRACE
            trace_->dump(5 * tick_count_ + 2);
            trace_->flush();
        #endif // VM_TRACE
    }
    return ret;
}

#ifdef TAINT_EN
void Testbench::read_vtaints(uint32_t* taints){
     for(int i=0; i<N_TAINT_OUTPUTS_b32; i++){
        taints[i] = this->module_->auto_cover_out_t0[i];
    }
}
#endif // TAINT_EN

void Testbench::read_vcoverage(uint32_t* cov){
    for(int i=0; i<N_COV_POINTS_b32; i++){
        cov[i] = this->module_->auto_cover_out[i];
    }
    cov[N_COV_POINTS_b32-1] &= COV_MASK;
}

void Testbench::read_vasserts(uint32_t* asserts){
    #ifdef CHECK_ASSERTS
    #if N_ASSERTS_b32>1
    for(int i=0; i<N_ASSERTS_b32; i++){
        asserts[i] = this->module_->assert_out[i];
    }
    #else
    asserts[0] = this->module_->assert_out;
    #endif // N_ASSERTS_b32>1
    asserts[N_ASSERTS_b32-1] &= ASSERTS_MASK;
    #endif // CHECK_ASSERTS
}

void Testbench::read_new_output(){
    doutput_t *new_output = (doutput_t *) malloc(sizeof(doutput_t));
    this->read_vcoverage(new_output->coverage);
    #ifdef TAINT_EN
    this->read_vtaints(new_output->taints);
    #endif
    this->read_vasserts(new_output->asserts);
    new_output->check_failed();
    new_output->check(); // sanity check
    this->outputs.push_back(new_output);
}  

void Testbench::print_last_output(){
    assert(this->outputs.size());
    this->outputs.back()->print();
}
#ifdef TAINT_EN
bool Testbench::is_output_tainted(){
    return  this->outputs.back()->is_tainted();
}
#endif //TAINT_EN

std::deque<doutput_t *> *Testbench::pop_outputs(){
    return &this->outputs;
}

void Testbench::push_instruction(Instruction *instruction){
    instruction->retired = false;
    this->intercept_instructions[instruction->addr] = instruction;
}

void Testbench::push_instructions(std::deque<Instruction *> *instructions){
    assert(instructions->size() != 0);
    for(auto &inst: *instructions) this->push_instruction(inst);
    instructions->clear();
}

//  only pops retired instructions
std::deque<Instruction *> *Testbench::pop_instructions(){
    std::deque<Instruction *> *q = new std::deque<Instruction *>();
    for(auto &inst: this->intercept_instructions){
        if(inst.second->retired) q->push_back(inst.second);
    }
    return q;
}

int Testbench::check_all_inst_retired(){
    for(auto &inst: this->intercept_instructions){
        if(!inst.second->retired) {
            std::cout << "Instruction not retired: ";
            inst.second->print();
            return 0;
        }
    }
    return 1;
}

void Testbench::clear_instructions(){
    this->intercept_instructions.clear();
}

void Testbench::print_outputs(){
    for(auto &out: this->outputs) out->print();
}




