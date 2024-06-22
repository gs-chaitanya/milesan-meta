
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
    #ifdef META_RESTET_EN
    this->module_->meta_rst_ni = 1;
    #ifdef TAINT_EN
    this->module_->meta_rst_ni_t0 = 1;
    #endif // TAINT_EN
    #endif // META_RESET_EN

    #ifdef BLOCK_TAINT
    this->module_->block_signal_t0 = 1;
    #endif // BLOCK_TAINT
    this->tick(1);
    this->module_->rst_ni = 0;
    this->tick(N_RESET_TICKS);
    this->module_->rst_ni = 1;
}


#ifdef META_RESTET_EN
void Testbench::meta_reset(){
    this->module_->meta_rst_ni = 1;
    this->module_->rst_ni = 1; // deassert normal reset while meta reset is running
    this->tick(1);
    this->module_->meta_rst_ni = 0;
    #ifdef TAINT_EN
    this->module_->meta_rst_ni_t0 = 0;
    #endif
    this->tick(N_META_RESET_TICKS);
    this->module_->meta_rst_ni = 1;
    #ifdef TAINT_EN
    this->module_->meta_rst_ni_t0 = 1;
    #endif
}
#endif

#ifdef TAINT_EN
#ifdef META_RESTET_EN
void Testbench::meta_reset_t0(){
    this->module_->meta_rst_ni_t0 = 0;
    this->tick(N_META_RESET_TICKS);
    this->module_->meta_rst_ni_t0 = 1;
}
#endif
#endif


void Testbench::clear_outputs(){
    this->outputs.clear();
    assert(this->outputs.size() == 0);
}

#ifdef RESET_MEM_EN
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

#ifdef TAINT_EN
void Testbench::reset_memory_t(){
    #ifdef SINGLE_MEM // TODO test
    svScope scope = svGetScopeFromName(VSCOPE_MEM);
    assert(scope);  // Check for nullptr if scope not found
    svSetScope(scope);
    _reset_memory_t();
    #endif

    #ifdef DUAL_MEM
    svScope scope = svGetScopeFromName(VSCOPE_DMEM);
    assert(scope);  // Check for nullptr if scope not found
    svSetScope(scope);
    _reset_memory_t();
    
    scope = svGetScopeFromName(VSCOPE_IMEM);
    assert(scope);  // Check for nullptr if scope not found
    svSetScope(scope);
    _reset_memory_t();
    #endif
}
#endif
#endif

#ifdef DUMP_FINAL_MEM
void Testbench::dump_memory(){
    #ifdef SINGLE_MEM // TODO test
    // std::cout << "MEM:\n";
    svScope scope = svGetScopeFromName(VSCOPE_MEM);
    assert(scope);  // Check for nullptr if scope not found
    svSetScope(scope);
    _dump_memory();
    #endif

    #ifdef DUAL_MEM
    svScope scope = svGetScopeFromName(VSCOPE_DMEM);
    assert(scope);  // Check for nullptr if scope not found
    svSetScope(scope);
    std::cout << "DMEM:\n";
    _dump_memory();
    #endif
}
#endif

void Testbench::close_trace(void) {
	#if VM_TRACE  
	trace_->close();
	#endif // VM_TRACE
  }

tick_req_t *Testbench::tick(int num_ticks, bool false_tick) {
    static Instruction *intercept = nullptr;
	tick_req_t *ret = (tick_req_t *) malloc(sizeof(tick_req_t));
	ret->type = REQ_NONE;

	for (size_t i = 0; i < num_ticks || num_ticks == -1; i++) {
        this->tick_count_++;

        module_->clk_i = 0;
        module_->eval();

        #if VM_TRACE
        trace_->dump(5 * this->tick_count_ - 1);
        #endif // VM_TRACE

        module_->clk_i = !false_tick;


        #ifdef INJECT_INSTR_EN
        if(intercept != nullptr){
            if(intercept->retired){
                intercept = nullptr;
                #ifdef DUAL_MEM
                #ifdef TAINT_EN
                module_->instr_mem_rdata_t0 = 0x0;
                #endif // TAINT_EN
                module_->intercept_instr_mem_rdata = 0x0;
                module_->intercept_instr_mem_en = 0;
                #else // DUAL_MEM
                #ifdef TAINT_EN
                module_->mem_rdata_o_t0 = 0x0;
                #endif // TAINT_EN
                module_->intercept_mem_rdata = 0x0;
                module_->intercept_mem_en = 0;
                #endif // DUAL_MEM
            }
            else{
                #ifdef DUAL_MEM
                module_->intercept_instr_mem_en = 1;
                module_->intercept_instr_mem_rdata = intercept->inject_inst ? intercept->get_binary() : module_->instr_mem_rdata;
                module_->instr_mem_rdata_t0 = intercept->inject_taint ? intercept->get_binary_t0() : 0x0;
                #ifdef PRINT_INTERCEPT
                intercept->print_intercept(module_->instr_mem_rdata,0x0);
                #endif // PRINT_INTERCEPT
                #else // DUAL_MEM
                module_->intercept_mem_en = 1;
                #if DATA_WIDTH_BYTES == 4
                module_->intercept_mem_rdata = intercept->inject_inst ?   module_->mem_rdata_o | intercept->get_binary() : module_->mem_rdata_o;
                module_->mem_rdata_o_t0 = intercept->inject_taint ? intercept->get_binary_t0() : 0x0;
                #else // DATA_WIDTH_BYTES == 8
                assert(DATA_WIDTH_BYTES==8);
                if(intercept->alignment == 0){
                    module_->intercept_mem_rdata = intercept->inject_inst ?  (module_->mem_rdata_o&(0xFFFFFFFFULL<<32) | intercept->get_binary()) : module_->mem_rdata_o;
                    #ifdef TAINT_EN
                    module_->mem_rdata_o_t0 = intercept->inject_taint ? intercept->get_binary_t0() : 0x0;
                    #endif // TAINT_EN
                    #ifdef PRINT_INTERCEPT
                    intercept->print_intercept(module_->mem_rdata_o&0xFFFFFFFFULL,0x0);
                    #endif // PRINT_INTERCEPT
                }
                else{
                    assert(intercept->alignment == 4);
                    module_->intercept_mem_rdata = intercept->inject_inst ?  (module_->mem_rdata_o & (0xFFFFFFFFULL) | ((uint64_t) intercept->get_binary())<<32) : module_->mem_rdata_o;
                    #ifdef TAINT_EN
                    module_->mem_rdata_o_t0 = intercept->inject_taint ? ((uint64_t) intercept->get_binary_t0())<<32 : 0x0;
                    #endif // TAINT_EN
                    #ifdef PRINT_INTERCEPT
                    intercept->print_intercept((module_->mem_rdata_o&(0xFFFFFFFFULL<<32))>>32,0x0);
                    #endif // PRINT_INTERCEPT
                }
                #endif // DATA_WIDTH_BYTES
                #endif // DUAL_MEM
                intercept->retired = true;
                this->intercepted = true;
            }
        }
        #endif
        module_->eval();


        #if VM_TRACE
        trace_->dump(5 * this->tick_count_);
        #endif // VM_TRACE

        _update_req(module_, ret); // design specific function
        this->read_new_output();

        module_->clk_i = 0;
        module_->eval();
        #ifdef INJECT_INSTR_EN
        if(intercept==nullptr){
            #ifdef DUAL_MEM
            if(this->intercept_instructions.count((module_->instr_mem_addr>>DATA_WIDTH_BYTES_LOG2))){ // instr_mem returns instruction in subsequent cycle
                intercept = this->intercept_instructions[(module_->instr_mem_addr>>DATA_WIDTH_BYTES_LOG2)];
                }
            #else // single memory for data and instructions 
            if(this->intercept_instructions.count((module_->mem_addr_o>>DATA_WIDTH_BYTES_LOG2))){ // instr_mem returns instruction in subsequent cycle
                intercept = this->intercept_instructions[(module_->mem_addr_o>>DATA_WIDTH_BYTES_LOG2)];
            }
            #endif
        }
        if(module_->mem_addr_o) std::cout << std::hex << (module_->mem_addr_o>>3) << ":" << module_->mem_rdata_o << std::endl;
        #endif
        #if VM_TRACE
            trace_->dump(5 * tick_count_ + 2);
            trace_->flush();
        #endif // VM_TRACE
    }
    return ret;
}

#ifdef TAINT_EN
#ifdef MUXCOV_EN
void Testbench::read_vtaints(uint32_t* taints){
     for(int i=0; i<N_TAINT_OUTPUTS_b32; i++){
        #ifdef READ_UNTIL_PC_TAINTED
        if(this->module_->pc_probe_t0) taints[i] = 0;
        else taints[i] = this->module_->auto_cover_out_t0[i];
        #else
        taints[i] = this->module_->auto_cover_out_t0[i];
        #endif
    }
}
#endif
#endif // TAINT_EN

#ifdef MUXCOV_EN
void Testbench::read_vcoverage(uint32_t* cov){
    for(int i=0; i<N_COV_POINTS_b32; i++){
        cov[i] = this->module_->auto_cover_out[i];
    }
    cov[N_COV_POINTS_b32-1] &= COV_MASK;
}
#endif
#ifdef ASSERTCOV_EN
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
#endif

void Testbench::read_new_output(){
    doutput_t *new_output = (doutput_t *) malloc(sizeof(doutput_t));
    #ifdef MUXCOV_EN
    this->read_vcoverage(new_output->coverage);
    #ifdef TAINT_EN
    this->read_vtaints(new_output->taints);
    #endif
    #endif
    #ifdef ASSERTCOV_EN
    this->read_vasserts(new_output->asserts);
    #endif
    new_output->check_failed();
    new_output->check(); // sanity check
    this->outputs.push_back(new_output);
}  

#ifdef MUXCOV_EN
void Testbench::print_last_output(){
    assert(this->outputs.size());
    this->outputs.back()->print();
}
#endif
#ifdef TAINT_EN
bool Testbench::is_output_tainted(){
    return  this->outputs.back()->is_tainted();
}
#endif //TAINT_EN

std::deque<doutput_t *> *Testbench::pop_outputs(){
    return &this->outputs;
}

std::deque<tick_req_t *> *Testbench::pop_tick_reqs(){
    return &this->tick_reqs;
}

std::deque<tick_req_t *> *Testbench::pop_reg_stream(){
    return &this->reg_stream;
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
    int all_retired = 1;
    for(auto &inst: this->intercept_instructions){
        if(!inst.second->retired) {
            std::cout << "Instruction not retired: ";
            inst.second->print();
            all_retired = 0;
        }
    }
    return all_retired;
}

void Testbench::clear_instructions(){
    this->intercept_instructions.clear();
}

void Testbench::print_outputs(){
    for(auto &out: this->outputs) out->print();
}

void Testbench::check_got_stop_req(){
    if(!this->got_stop_req){
    	std::cout << "Invalid seed with ID " << get_id() <<  ": did not receive stop request!\n";
		exit(-1);
    }
}




