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


// use this to have relationships betweem queues
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
        // uint32_t bytecode_t0 = 0;
        // for(auto &i_bytecode_t0: inst_i["bytecode_t0"]){
        //     std::string mask_str = i_bytecode_t0["mask"].asString();
        //     uint32_t mask = std::stoul(mask_str,nullptr,16); 
        //     bytecode_t0 |= mask << i_bytecode_t0["offset"].asUInt();
        // }
        std::string type= inst_i["type"].asString();
        uint32_t addr = std::stoul(address_str, nullptr, 16);
        uint32_t bytecode = std::stoul(bytecode_str, nullptr, 16);
        uint32_t bytecode_t0 = std::stoul(bytecode_t0_str, nullptr, 16);
        Instruction *new_inst;
        if(type=="R") new_inst = new R_Instruction(addr,bytecode,bytecode_t0);
        else if(type=="I") new_inst = new I_Instruction(addr,bytecode,bytecode_t0);
        else assert(0); // not supported
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
    assert(this->instructions.size() == in_q->instructions.size());
    for(int i=0; i<in_q->instructions.size(); i++){
        this->instructions[i]->set_binary_t0(this->instructions[i]->bytecode_t0 & in_q->instructions[i]->bytecode_t0);
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

void Queue::dump(Testbench *tb){
    std::string q_dir = get_q_dir();
    std::string q_path = q_dir + "/" + std::to_string(this->ID) + ".queue.json";
    std::cout << "dumping to " << q_path << std::endl;
    std::string coverage_str = this->get_accumulated_output()->get_str(tb);
    std::string instruction_str = this->get_instructions_json_str();
    std::ofstream ofstream;
    ofstream.open(q_path);
    ofstream << "[\n\t{\n";
    ofstream << "\n\t\t" << "\"simsramelf\":\"" << get_sramelf() << "\",";
    ofstream << "\n\t\t" << "\"mut_inst_path\":\"" << get_mut_inst_path() << "\",";
    ofstream << "\n\t\t" << "\"got_stop_request\":" << tb->got_stop_req << ",";
    ofstream << "\t\t" << "\"instructions\":" << instruction_str << ",";
    ofstream << "\n\t\t" << "\"output\":" << coverage_str;
    ofstream << "\n\t}\n]"; 
    ofstream.close();
}
#endif
