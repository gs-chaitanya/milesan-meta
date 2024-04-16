#include <cassert>
#include <iostream>
#include <cstring>
#include <fstream>
#include <cassert>
#include <map>
#include <sstream>  
#include <sys/file.h>

#include "queue.h"
#include "dtypes.h"
#include "macros.h"
#include "testbench.h"
#include "helperfuncs.h"
#include "instructions.h"
#include <jsoncpp/json/json.h>


// Use this to have relationships betweem queues or load the instructions from MUT_INST_PATH.
Queue* new_queue(Queue *parent_q, bool load_instructions){
    static size_t id = 0;
    Queue *new_q = new Queue();
    new_q->ID = ++id;
    if(parent_q != nullptr) new_q->parent_ID = parent_q->ID;
    else new_q->parent_ID = 0;
    if(load_instructions) new_q->load_instructions();
    return new_q;
}



void Queue::load_instructions(){    
    static const std::string mut_inst_path = get_mut_inst_path();
    std::ifstream mut_inst_stream(mut_inst_path, std::ifstream::binary);
    Json::Value mut_insts;
    mut_inst_stream >> mut_insts;
    for(auto &inst_i: mut_insts){
        if(!inst_i["load"].asBool()) continue;
        std::string address_str = inst_i["addr"].asString();
        std::string bytecode_str = inst_i["bytecode"].asString();
        std::string bytecode_t0_str = inst_i["bytecode_t0"].asString();
        std::string i_str = inst_i["str"].asString();
        std::string type= inst_i["type"].asString();
        uint32_t addr = std::stoul(address_str, nullptr, 16);
        uint32_t bytecode = std::stoul(bytecode_str, nullptr, 16);
        uint32_t bytecode_t0 = std::stoul(bytecode_t0_str, nullptr, 16);
        Instruction *new_inst;
        if(type=="R12D") new_inst = new R12DInstruction(addr,bytecode,bytecode_t0,i_str);
        else if(type=="REGIMM") new_inst = new RegImmInstruction(addr,bytecode,bytecode_t0,i_str);
        else if(type=="IMMRD") new_inst = new ImmRdInstruction(addr,bytecode,bytecode_t0,i_str);
        else if(type=="F2I") new_inst = new FloatToIntInstruction(addr,bytecode,bytecode_t0,i_str);
        else if(type=="I2F") new_inst = new IntToFloatInstruction(addr,bytecode,bytecode_t0,i_str);
        else if(type=="F4") new_inst = new Float4Instruction(addr,bytecode,bytecode_t0,i_str);
        else if(type=="F3") new_inst = new Float3Instruction(addr,bytecode,bytecode_t0,i_str);
        else if(type=="F3NORM") new_inst = new Float3NoRmInstruction(addr,bytecode,bytecode_t0,i_str);
        else if(type=="FIRD2") new_inst = new FloatIntRd2Instruction(addr,bytecode,bytecode_t0,i_str);
        else if(type=="FIRD1") new_inst = new FloatIntRd1Instruction(addr,bytecode,bytecode_t0,i_str);
        else if(type=="F2") new_inst = new Float2Instruction(addr,bytecode,bytecode_t0,i_str);
        else if(type=="FIRS1") new_inst = new FloatIntRs1Instruction(addr,bytecode,bytecode_t0,i_str);
        else assert(0); // not implemented instruction type
        // new_inst->inject_inst=false;
        // new_inst->inject_taint=false;
        this->instructions.push_back(new_inst);
    }
    if(this->instructions.size()){
        std::cout << "Loaded instructions: \n";
        this->print_instructions();
    }
    else{
        std::cout << "Did not load any instructions from MUT_INST_PATH \"" << mut_inst_path << "\"" << std::endl;
    }

}

void Queue::decode_instructions(){
    for(int i=0; i<this->instructions.size(); i++) this->instructions[i]->decode();
}

void Queue::print_instructions(){
    for(int i=0; i<this->instructions.size(); i++) this->instructions[i]->print();
}

void Queue::print_instructions_binary(){
    for(int i=0; i<this->instructions.size(); i++) this->instructions[i]->print_binary();
}

std::string Queue::get_instructions_json_str(){
    std::string instructions_str = "[";
    size_t n_instructions = this->instructions.size();
    for(int i=0; i<n_instructions; i++){
        std::string c = i==n_instructions-1 ? "" : ",";
        instructions_str += this->instructions[i]->get_json_str() + c;
    }
    instructions_str += "]";
    return instructions_str;
}

#ifdef TAINT_EN
void Queue::taint_all(){
    for(int i=0; i<this->instructions.size(); i++) this->instructions[i]->taint_all();
}

void Queue::rand_taints(){
    for(int i=0; i<this->instructions.size(); i++) this->instructions[i]->rand_taint();
}

void Queue::untaint(){
    for(int i=0; i<this->instructions.size(); i++) this->instructions[i]->untaint();
}
#endif //TAINT_EN

void Queue::seed(){
    #ifdef TAINT_EN
    this->taint_all();
    #endif // TAINT_EN
    this->recompute_inst_taint_hw();
}

void Queue::clear_instructions(){
    this->instructions.clear();
}
void Queue::accumulate_output(doutput_t *output){
    if(this->ini_output == nullptr){
        assert(this->acc_output == nullptr);
        this->acc_output = (doutput_t *) malloc(sizeof(doutput_t));
        this->acc_output->init();
        this->acc_output->check();

        this->ini_output = (doutput_t *) malloc(sizeof(doutput_t));
        this->ini_output->init();
        this->ini_output->check();
        memcpy(this->ini_output, output, sizeof(doutput_t));
    }
    else{
        for(int i=0; i<N_COV_POINTS_b32; i++){
            this->acc_output->coverage[i] |= this->ini_output->coverage[i] ^ output->coverage[i];
        }
        #ifdef TAINT_EN
        for(int i=0; i<N_TAINT_OUTPUTS_b32; i++){
            this->acc_output->taints[i] |= output->taints[i];
        }
        #endif // TAINT_EN

        for(int i=0; i<N_ASSERTS_b32; i++){
            this->acc_output->asserts[i] |= output->asserts[i];
        }
        this->acc_output->check();
    }
}


void Queue::push_tb_instruction(Instruction *instruction){
    instruction->retired = false;
    this->instructions.push_back(instruction);
    this->recompute_inst_taint_hw();
}

void Queue::push_tb_instructions(std::deque<Instruction *> *instructions){
    assert(instructions->size()!=0);
    while(instructions->size()){
        this->push_tb_instruction(instructions->front());
        instructions->pop_front();
    }
    assert(this->instructions.size());
    assert(instructions->size()==0);
}

std::deque<Instruction *> *Queue::pop_tb_instructions(){
    return &this->instructions;
}

void Queue::push_tb_output(doutput_t *output){
    output->check();
    this->accumulate_output(output);
    this->outputs.push_back(output);
}

void Queue::push_tb_outputs(std::deque<doutput_t *> *outputs){
    while(outputs->size()){
        this->push_tb_output(outputs->front());
        outputs->pop_front();
    }
    assert(outputs->size()==0);
}

void Queue::push_tb_tick_req(tick_req_t *tick_req){
    this->tick_reqs.push_back(tick_req);
}

void Queue::push_tb_tick_reqs(std::deque<tick_req_t *> *tick_reqs){
    while(tick_reqs->size()){
        this->push_tb_tick_req(tick_reqs->front());
        tick_reqs->pop_front();
    }
    assert(tick_reqs->size() == 0);
}

void Queue::check_tick_reqs_taint(){
    bool all_regs_fully_tainted = true;
    for(auto &tick_req: this->tick_reqs){
        #ifdef ARCH_32b
        all_regs_fully_tainted &= tick_req->content_t0 == 0xFFFFFFFFULL;
        #else
        all_regs_fully_tainted &= tick_req->content_t0 == 0xFFFFFFFFFFFFFFFFULL;
        #endif
    }
    if(all_regs_fully_tainted){
        std::cout << "Taint explosion with ID " << get_id() <<  ": all registers fully tainted!\n";
		exit(-1);
    }
}

void Queue::check_reg_reqs(){
    #ifdef CHECK_REG_REQ
    if(this->tick_reqs.size() == 0){
    	std::cout << "Invalid seed with ID " << get_id() <<  ": did not any receive register requests!\n";
		exit(-1);
    }
    #endif
}
void Queue::print_outputs(){
    for(auto &out: this->outputs) out->print();
}

doutput_t *Queue::get_accumulated_output(){
    return this->acc_output;
}

void Queue::clear_accumulated_output(){
    free(this->ini_output);
    this->ini_output = nullptr;
    free(this->acc_output);
    this->acc_output = nullptr;
}

void Queue::print_accumulated_output(){
    if(this->acc_output != nullptr) this->acc_output->print();
}

bool Queue::failed(){
    for(auto &out: this->outputs){
        if(out->failed()) return true;
    }
    return false;
}

int Queue::get_coverage_amount(){
    assert(this->acc_output != nullptr);
    assert((this->acc_output->coverage[N_COV_POINTS_b32-1] & ~COV_MASK) == 0);
    // Count the bits equal to 1.
    int ret = 0;
    for (int i = 0; i < N_COV_POINTS_b32; i++) {
        ret += __builtin_popcount(this->acc_output->coverage[i]);
    }
    assert(ret >= 0);
    assert(ret <= N_COV_POINTS);
    return ret;
}

void Queue::clear_tb_outputs(){
    while(this->outputs.size()){
        free(this->outputs.front());
        this->outputs.pop_front();
    }
    assert(this->outputs.size() == 0);
    this->clear_accumulated_output();
}

void Queue::print_diff(Queue *other){
    assert(this->size() == other->size());
    assert(this->outputs.size() == other->outputs.size());
    std::cout << "OUTPUT DIFF\n";
    for(int i=0; i<this->outputs.size(); i++){
        this->outputs[i]->check();
        other->outputs[i]->check();
        this->outputs[i]->print_diff(other->outputs[i]);
    }
    #ifdef TAINT_EN
    std::cout << "OUTPUT TAINT DIFF\n";
    for(int i=0; i<this->outputs.size(); i++){
        this->outputs[i]->check();
        other->outputs[i]->check();
        this->outputs[i]->print_taint_diff(other->outputs[i]);
    }
    #endif // TAINT_EN
}

void Queue::print_increase(Queue *other){
    this->acc_output->print_increase(other->get_accumulated_output());
}

std::deque<size_t> Queue::get_new_toggles(Queue *other){
    doutput_t *new_output = other->get_accumulated_output();
    std::deque<size_t> new_toggles_idx;;
    for(int i=0; i<N_COV_POINTS_b32; i++){ // TODO: modifiy this to include taints
        uint32_t check = (~this->acc_output->coverage[i]) & new_output->coverage[i];
        if(check != 0){
            for(int j=0; j<32; j++){
                if(check & (1<<j)){
                    new_toggles_idx.push_back(j+i*32); // maybe need the indices sometime later
                }
            }
        } 
    }
    return new_toggles_idx;
}

std::deque<size_t> Queue::get_toggles(){
    std::deque<size_t> toggles_idx;
    for(int i=0; i<N_COV_POINTS_b32; i++){ // TODO: modifiy this to include taints
        if(this->acc_output->coverage[i]){
            for(int j=0; j<32; j++){
                if(this->acc_output->coverage[i] & (1<<j)){
                    toggles_idx.push_back(j+i*32); // maybe need the indices sometime later
                }
            }
        } 
    }
    return toggles_idx;
}

size_t Queue::size(){
    return this->outputs.size();
}

size_t Queue::compute_inst_taint_hw(){
    size_t weight = 0;
    for(auto &inst: this->instructions){
        weight += __builtin_popcount(inst->get_binary_t0());
    }
    return weight;
}

void Queue::recompute_inst_taint_hw(){
    this->inst_taint_hw = this->compute_inst_taint_hw();
}

#ifdef TAINT_EN
void Queue::reduce_instruction_taints(Queue *in_q){
    assert(this->instructions.size() >= in_q->instructions.size()); // allow that in_q has less instructions
    for(int i=0; i<in_q->instructions.size(); i++){
        for(int j=0; j<this->instructions.size(); j++){
            if(this->instructions[j]->addr == in_q->instructions[i]->addr)
                this->instructions[j]->set_binary_t0(this->instructions[j]->bytecode_t0 & in_q->instructions[i]->bytecode_t0);
        }
    }
    this->recompute_inst_taint_hw();
}
#endif // TAINT_EN

Queue *Queue::copy(){ // deep cpy
    Queue *cpy = new Queue();
    cpy->ID = this->ID;
    cpy->parent_ID = this->parent_ID;
    cpy->mutator = this->mutator;

    for(auto &inst: this->instructions){
        cpy->instructions.push_back(inst->copy());
    }
    cpy->recompute_inst_taint_hw();

    for(auto &out: this->outputs){
        doutput_t *cpy_out = (doutput_t *) malloc(sizeof(doutput_t));
        memcpy(cpy_out->coverage, out->coverage, N_COV_POINTS_b32 * sizeof(uint32_t));
        #ifdef TAINT_EN
        memcpy(cpy_out->taints, out->taints, N_TAINT_OUTPUTS_b32 * sizeof(uint32_t));
        #endif // TAINT_EN
        memcpy(cpy_out->asserts, out->asserts, N_ASSERTS_b32 * sizeof(uint32_t));
        cpy_out->check();
        cpy->push_tb_output(cpy_out);
    }
    assert(cpy->get_accumulated_output() != nullptr);
    return cpy;
}
#ifdef TAINT_EN
size_t Queue::compute_min_simlen(){
    doutput_t *acc = (doutput_t *) malloc(sizeof(doutput_t));
    acc->init();
    int i = 0;
    for(auto &out: this->outputs){
        i++;
        acc->add_or(out);
        if(acc->compare_taints(this->acc_output)){
            return i;
        }
    }
    std::cerr << "Minimal simlen computation failed!\n";
    return -1;
}

void Queue::revert_taints(Queue *other){
    assert(other != nullptr);
    assert(this->instructions.size() == other->instructions.size());
    for(int i=0; i<this->instructions.size(); i++){
        this->instructions[i]->set_binary_t0(other->instructions[i]->get_binary_t0());
    }
    this->recompute_inst_taint_hw();
}
#endif

void Queue::dump(Testbench *tb){
    std::string q_dir = get_q_dir();
    std::string q_path = q_dir + "/" + std::to_string(this->ID) + ".queue.json";
    std::cout << "Dumping queue to " << q_path << std::endl;
    std::string instruction_str = this->get_instructions_json_str();
    std::ofstream ofstream;
    ofstream.open(q_path);
    ofstream << "[\n\t{\n";
    ofstream << "\n\t\t" << "\"mut_inst_path\":\"" << get_mut_inst_path() << "\",";
    ofstream << "\n\t\t" << "\"got_stop_request\":" << tb->got_stop_req << ",";
    ofstream << "\n\t\t" << "\"instructions\":" << instruction_str << ",";
    ofstream << "\n\t\t" << "\"id\": " << "\"" << get_id() << "\",";
    ofstream << "\n\t\t" << "\"seed\": " << get_seed() << ",";
    ofstream << "\n\t\t" << "\"inst\": " << "\"" << INST << "\",";
    ofstream << "\n\t\t" << "\"dut\": " <<  "\"" << DUT << "\",";
    ofstream << "\n\t\t" << "\"elf\": " <<  "\"" << get_sramelf() << "\",";
    ofstream << "\n\t\t" << "\"cov\":" << this->get_accumulated_output()->get_cov_str() << ",";
    #ifdef TAINT_EN
    ofstream << "\n\t\t" << "\"cov_t0\":" << this->get_accumulated_output()->get_cov_t0_str() << ",";
    #endif
    ofstream << "\n\t\t" << "\"ticks\":" << tb->tick_count_ << ",";
    #ifdef DUAL_MEM
    ofstream << "\n\t\t" << "\"pc\":" << tb->module_->instr_mem_addr << ",";
    #else
    ofstream << "\n\t\t" << "\"pc\":" << tb->module_->mem_addr_o << ",";
    #endif
    ofstream << "\n\t\t" << "\"injected_taint\":" << tb->intercepted;
    ofstream << "\n\t}\n]"; 
    ofstream.close();
}


void Queue::dump_acc(Testbench *tb){
    static int q_it = 0;
    std::string q_dir = get_cov_dir();
    std::string q_path = q_dir + "/" + std::to_string(q_it++) + ".queue.json";
    // std::cout << "Dumping accumulated queue to " << q_path << std::endl;
    std::string instruction_str = this->get_instructions_json_str();
    std::ofstream ofstream;
    ofstream.open(q_path);
    ofstream << "[\n\t{\n";
    ofstream << "\n\t\t" << "\"mut_inst_path\":\"" << get_mut_inst_path() << "\",";
    ofstream << "\n\t\t" << "\"got_stop_request\":" << tb->got_stop_req << ",";
    ofstream << "\n\t\t" << "\"instructions\":" << instruction_str << ",";
    ofstream << "\n\t\t" << "\"id\": " << "\"" << get_id() << "\",";
    ofstream << "\n\t\t" << "\"seed\": " << get_seed() << ",";
    ofstream << "\n\t\t" << "\"inst\": " << "\"" << INST << "\",";
    ofstream << "\n\t\t" << "\"dut\": " <<  "\"" << DUT << "\",";
    ofstream << "\n\t\t" << "\"elf\": " <<  "\"" << get_sramelf() << "\",";
    ofstream << "\n\t\t" << "\"cov\":" << this->get_accumulated_output()->get_cov_str() << ",";
    #ifdef TAINT_EN
    ofstream << "\n\t\t" << "\"cov_t0\":" << this->get_accumulated_output()->get_cov_t0_str() << ",";
    #endif
    ofstream << "\n\t\t" << "\"ticks\":" << tb->tick_count_ << ",";
    #ifdef DUAL_MEM
    ofstream << "\n\t\t" << "\"pc\":" << tb->module_->instr_mem_addr << ",";
    #else
    ofstream << "\n\t\t" << "\"pc\":" << tb->module_->mem_addr_o << ",";
    #endif
    ofstream << "\n\t\t" << "\"injected_taint\":" << tb->intercepted;
    ofstream << "\n\t}\n]"; 
    ofstream.close();
}

void Queue::dump_tick_reqs(){
    std::string path = get_regdump_path();
    std::ofstream ofstream;
    ofstream.open(path);
    ofstream << "[\n";
    for(auto &req: this->tick_reqs){
        ofstream << "\t" << req->get_json();
        if(req != this->tick_reqs.back()) ofstream << ",\n";
        else  ofstream << "\n";
    }
    ofstream << "]";
}

void Queue::dump_reg_stream(){
    std::string path = get_regstream_path();
    std::cout << "dumping to " << path << std::endl;
    std::ofstream ofstream;
    ofstream.open(path);
    ofstream << "[\n";
    for(auto &req: this->tick_reqs){
        ofstream << "\t" << req->get_json();
        if(req != this->tick_reqs.back()) ofstream << ",\n";
        else  ofstream << "\n";
    }
    ofstream << "]";
}


void Queue::accumulate(Queue *other){
    this->acc_output->add_or(other->get_accumulated_output());
    for(auto &inst: other->instructions){
        this->push_tb_instruction(inst->copy());
    }
}
#ifdef TAINT_EN
bool Queue::taints_all_untoggled_mux(Queue *other){
    if(this->acc_output==nullptr) return true;
    doutput_t *new_output = other->get_accumulated_output();
    assert(N_COV_POINTS_b32 == N_TAINT_OUTPUTS_b32);

    for(int i=0; i<N_COV_POINTS_b32; i++){ // TODO: modifiy this to include taints
        int trail = 32;
        if(i == N_COV_POINTS_b32-1) trail = N_COV_TRAIL_BITS;
        for(int j=0; j<trail; j++){
            if(((this->acc_output->coverage[i] & (1<<j)) == 0) && ((this->acc_output->taints[i] & (1<<j)))){ // untoggled but tainted coverage points
                if(!(new_output->taints[i] & (1<<j))){ // is not tainted by queue
                    return false;
                } 

            }
        }
    }
    return true;

}

bool Queue::taints_any_untoggled_mux(Queue *q){
    if(this->acc_output==nullptr) return true;
    doutput_t *new_output = q->get_accumulated_output();
    assert(N_COV_POINTS_b32 == N_TAINT_OUTPUTS_b32);

    for(int i=0; i<N_COV_POINTS_b32; i++){ // TODO: modifiy this to include taints
        int trail = 32;
        if(i == N_COV_POINTS_b32-1) trail = N_COV_TRAIL_BITS;
        for(int j=0; j<trail; j++){
            if(~this->acc_output->coverage[i] & new_output->taints[i] & (1<<j)){ // untoggled but tainted coverage points
                return true; // is tainted by queue
            }
        }
    }
    return false;
}

size_t Queue::get_n_untoggled_and_untainted_mux(Queue *other){
    if(this->acc_output==nullptr) return 0;
    doutput_t *new_output = other->get_accumulated_output();
    assert(N_COV_POINTS_b32 == N_TAINT_OUTPUTS_b32);
    assert(COV_MASK == TAINT_OUPUT_MASK);
    size_t count = 0;
    uint32_t mask;
    for(int i=0; i<N_COV_POINTS_b32; i++){
        mask = (i == N_COV_POINTS_b32 -1) ? COV_MASK : FULLMASK_b32;
        count += __builtin_popcount(~this->acc_output->coverage[i] & this->acc_output->taints[i] & ~new_output->taints[i] & mask);
    }
    return count;
}
#endif
