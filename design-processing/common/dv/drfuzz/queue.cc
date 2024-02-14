#include <cassert>
#include <iostream>
#include <cstring>
#include <fstream>
#include <cassert>
#include <map>
#include <sstream>  

#include "queue.h"
#include "dtypes.h"
#include "macros.h"
#include "testbench.h"


Queue* new_queue(Queue *q){
    static size_t id = 0;
    Queue *new_q = new Queue();
    new_q->ID = ++id;
    if(q != nullptr) new_q->parent_ID = q->ID;
    else new_q->parent_ID = 0;
    new_q->mutator = std::string("Root"); // if not root, will be overwritten
    return new_q;
}

void Queue::generate_inputs(bool taint, int n_inputs){ // will move this to mutation engine
    for(size_t i = 0; i<n_inputs; i++){
        dinput_t *new_input = (dinput_t *) malloc(sizeof(dinput_t)); // allocates memory for inputs -> do this in mutator?
        for(size_t j = 0; j<N_FUZZ_INPUTS_b32; j++){
            new_input->inputs[j] = rand()%MAX_b32_VAL;
        }
        new_input->inputs[N_FUZZ_INPUTS_b32-1] &= FUZZ_INPUT_MASK;
        #ifdef TAINT_EN
        for(size_t j = 0; j<N_TAINT_INPUTS_b32; j++){
            new_input->taints[j] = 0; // random taints
            for(size_t k=0; k<32; k++){
                if(rand()%P_TAINT == 0){
                    new_input->taints[j] |= ((uint32_t) 1<<k); // with probability 1/P_TAINT we taint a bit
                }
            }
        }
        new_input->taints[N_TAINT_INPUTS_b32-1] &= TAINT_INPUT_MASK;
        #endif // TAINT_EN

        this->inputs.push_back(new_input);
    }
    #ifdef TAINT_EN
    this->recompute_input_hw();
    #endif // TAINT_EN
}

void Queue::seed(){
    for(int i=0; i<N_ZEROS_SEED; i++){
        dinput_t *new_input = (dinput_t *) malloc(sizeof(dinput_t));
        for(size_t j = 0; j<N_FUZZ_INPUTS_b32; j++){
            new_input->inputs[j] = 0;
        }
        new_input->inputs[N_FUZZ_INPUTS_b32-1] &= FUZZ_INPUT_MASK;
        #ifdef TAINT_EN
        for(size_t j = 0; j<N_TAINT_INPUTS_b32; j++){
            new_input->taints[j] = 0; // random taints
            for(size_t k=0; k<32; k++){
                if(rand()%P_TAINT == 0){
                    new_input->taints[j] |= ((uint32_t) 1<<k); // with probability 1/P_TAINT we taint a bit
                }
            }
        }
        new_input->taints[N_TAINT_INPUTS_b32-1] &= TAINT_INPUT_MASK;
        #endif // TAINT_EN

        this->inputs.push_back(new_input);
    }
    #ifdef TAINT_EN
    this->recompute_input_hw();
    #endif // TAINT_EN

}

bool Queue::has_another_input(){
    return this->inputs.size() != 0;
}

dinput_t *Queue::pop_tb_input(){
    assert(this->inputs.size());
    this->last_input = this->inputs.front();
    this->inputs.pop_front();
    return this->last_input;
}

std::deque<dinput_t *> *Queue::pop_tb_inputs(){
    return &this->inputs;
}

#ifdef TAINT_EN
void Queue::check_taint_progess(){
    if(this->inputs.size() != this->outputs.size()){
        std::cout << "input queue has " << this->inputs.size() << "elements\n";
        std::cout << "output queue has " << this->outputs.size() << "elements\n";
        assert(0);

    }
    bool tainted = false;
    for(int i=0; i<this->size(); i++){
        for(int j=0; j<N_TAINT_INPUTS_b32; j++){
            if(this->inputs[i]->taints[j]) tainted = true;
        }
        if(!tainted){
            for(int j=0; j<N_TAINT_OUTPUTS_b32; j++){
                if(this->outputs[i]->taints[j]){// we cant have a tainted output before a tainted input was applied
                    std::cout << "ERROR TAINT PROGESS\n";
                    std::cout << "INPUTS\n";
                    this->print_inputs();
                    std::cout << "OUTPUTS\n";
                    this->print_outputs();
                    assert(false);
                } 
            }
        }
    }
}
#endif // TAINT_EN

void Queue::accumulate_output(doutput_t *output){
    if(this->ini_output == nullptr){
        this->acc_output = (doutput_t *) malloc(sizeof(doutput_t));
        for(int i=0; i<N_COV_POINTS_b32; i++){
            this->acc_output->coverage[i] = 0; 
        }
        #ifdef TAINT_EN
        for(int i=0; i<N_TAINT_OUTPUTS_b32; i++){
            this->acc_output->taints[i] = 0;
        }
        #endif // TAINT_EN

        for(int i=0; i<N_ASSERTS_b32; i++){
            this->acc_output->asserts[i] = 0;
        }
        this->acc_output->check();

        this->ini_output = (doutput_t *) malloc(sizeof(doutput_t));
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
#ifdef TAINT_EN
size_t Queue::compute_input_hw(){
    size_t weight = 0;
    for(auto &inp: this->inputs){
        for(int i=0; i<N_TAINT_INPUTS_b32; i++){
            weight += __builtin_popcount(inp->taints[i]);
        }
    }
    return weight;
}

void Queue::recompute_input_hw(){
    this->input_hw = this->compute_input_hw();
}

void Queue::reduce_input_taints(Queue *in_q){
    assert(this->inputs.size() == in_q->inputs.size());
    for(int i=0; i<in_q->inputs.size(); i++){
        for(int j=0; j<N_TAINT_INPUTS_b32; j++){
            this->inputs[i]->taints[j] &= in_q->inputs[i]->taints[j];
        }
    }
    this->recompute_input_hw();
}
#endif


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
    assert(this->outputs.size());
    assert(outputs->size()==0);
}

void Queue::push_tb_input(dinput_t *input){
    input->check();
    this->inputs.push_back(input);
}

void Queue::push_tb_inputs(std::deque<dinput_t *> *inputs){
    while(inputs->size()){
        this->push_tb_input(inputs->front());
        inputs->pop_front();
    }
    assert(this->inputs.size());
    assert(inputs->size()==0);
}

void Queue::print_inputs(){
    for(auto &inp: this->inputs) inp->print();
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
    this->acc_output->print();
}

#ifdef TAINT_EN
void Queue::invert_tainted_bits(){
    assert(N_FUZZ_INPUTS_b32==N_TAINT_INPUTS_b32);
    assert(N_FUZZ_TRAIL_BITS==N_TAINT_INPUT_TRAIL_BITS);
    for(auto &inp: this->inputs){
        for(int i=0; i<N_FUZZ_INPUTS_b32; i++){
            inp->inputs[i] ^= inp->taints[i];
        }
        inp->check();
    }
    this->recompute_input_hw();
}
#endif // TAINT_EN

Queue *Queue::copy(){ // deep cpy
    Queue *cpy = new Queue();
    cpy->ID = this->ID;
    cpy->parent_ID = this->parent_ID;
    cpy->mutator = this->mutator;

    for(auto &inp: this->inputs){
        dinput_t *cpy_inp = (dinput_t *) malloc(sizeof(dinput_t));
        memcpy(cpy_inp->inputs, inp->inputs, N_FUZZ_INPUTS_b32 * sizeof(uint32_t));
        #ifdef TAINT_EN
        memcpy(cpy_inp->taints, inp->taints, N_TAINT_INPUTS_b32 * sizeof(uint32_t));
        #endif // TAINT_EN
        cpy_inp->check();
        cpy->inputs.push_back(cpy_inp);
    }
    for(auto &out: this->outputs){
        doutput_t *cpy_out = (doutput_t *) malloc(sizeof(doutput_t));
        memcpy(cpy_out->coverage, out->coverage, N_COV_POINTS_b32 * sizeof(uint32_t));
        #ifdef TAINT_EN
        memcpy(cpy_out->taints, out->taints, N_TAINT_OUTPUTS_b32 * sizeof(uint32_t));
        #endif // TAINT_EN
        memcpy(cpy_out->asserts, out->asserts, N_ASSERTS_b32 * sizeof(uint32_t));
        cpy_out->check();
        cpy->outputs.push_back(cpy_out);
    }
    return cpy;
}

bool Queue::failed(){
    for(auto &out: this->outputs){
        if(out->failed()) return true;
    }
    return false;
}


size_t Queue::size(){
    return this->inputs.size();
}

int Queue::get_coverage_amount(){
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
}

void Queue::clear_tb_inputs(){
    while(this->inputs.size()){
        free(this->inputs.front());
        this->inputs.pop_front();
    }
}

bool Queue::is_equal(Queue* other){
    if(this->size() != other->size()) return false;
    if(this->outputs.size() != other->outputs.size()) return false;
    for(int i=0; i<this->inputs.size(); i++){
        this->inputs[i]->check();
        other->inputs[i]->check();
        for(int j=0; j<N_FUZZ_INPUTS_b32; j++){
            if(this->inputs[i]->inputs[j] != other->inputs[i]->inputs[j]) return false;
        }
        #ifdef TAINT_EN
        for(int j=0; j<N_TAINT_INPUTS_b32; j++){
            if(this->inputs[i]->taints[j] != other->inputs[i]->taints[j]) return false;
        }
        #endif // TAINT_EN
    }
    for(int i=0; i<this->outputs.size(); i++){
        this->outputs[i]->check();
        other->outputs[i]->check();
        for(int j=0; j<N_COV_POINTS_b32; j++){
            if(this->outputs[i]->coverage[j] != other->outputs[i]->coverage[j]) return false;
        }

        #ifdef TAINT_EN
        for(int j=0; j<N_TAINT_OUTPUTS_b32; j++){
            if(this->outputs[i]->taints[j] != other->outputs[i]->taints[j]) return false;
        }
        #endif // TAINT_EN

        for(int j=0; j<N_ASSERTS_b32; j++){
            if(this->outputs[i]->asserts[j] != other->outputs[i]->asserts[j]) return false;
        }
    }
    return true;
}

void Queue::print_diff(Queue *other){
    assert(this->size() == other->size());
    assert(this->outputs.size() == other->outputs.size());

    std::cout << "INPUT DIFF\n";
    for(int i=0; i<this->inputs.size(); i++){
        this->inputs[i]->check();
        other->inputs[i]->check();
        this->inputs[i]->print_diff(other->inputs[i]);
    }
    #ifdef TAINT_EN
    std::cout << "INPUT TAINT DIFF\n";
    for(int i=0; i<this->inputs.size(); i++){
        this->inputs[i]->check();
        other->inputs[i]->check();
        this->inputs[i]->print_taint_diff(other->inputs[i]);
    }
    #endif // TAINT_EN
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
#ifdef WRITE_QUEUES
void Queue::dump(Testbench *tb){
    long timestamp = std::chrono::duration_cast<std::chrono::seconds>(std::chrono::steady_clock::now() - tb->start_time).count();
    std::vector<std::map<std::string,std::stringstream>> inputs, outputs;
    for(auto &inp: this->inputs) inputs.push_back(inp->dump_buf());
    for(auto &out: this->outputs) outputs.push_back(out->dump_buf());
    std::string path = std::string(Q_DIR) + std::to_string(this->ID) + std::string(".in.json");
    std::ofstream cov_ofstream;    
    cov_ofstream.open(path);

    cov_ofstream << "{\"inputs\":[";
    for(int i=0; i<inputs.size(); i++){
        cov_ofstream << inputs[i]["inputs"].str();
        if(i < inputs.size()-1) cov_ofstream << ",";
    }
    cov_ofstream << "],";
    cov_ofstream << std::endl;
    #ifdef TAINT_EN
    cov_ofstream << "\"taints\":[";
    for(int i=0; i<inputs.size(); i++){
        cov_ofstream << inputs[i]["taints"].str();
        if(i < inputs.size()-1) cov_ofstream << ",";
    }
    cov_ofstream << "],";
    #endif // TAINT_EN
    cov_ofstream << "\"timestamp\": " << timestamp << ",";
    cov_ofstream << "\"ticks\": " << tb->tick_count_ << ",";
    cov_ofstream << "\"ID\": " << this->ID << ",";
    cov_ofstream << "\"mutator\": " << "\"" << this->mutator << "\"" << ",";
    cov_ofstream << "\"parent\": " << this->parent_ID;
    cov_ofstream << "}";
    cov_ofstream.close();

    path = std::string(Q_DIR) + std::to_string(this->ID) + std::string(".out.json");
    cov_ofstream.open(path);

    cov_ofstream << "{\"coverage\":[";
    for(int i=0; i<outputs.size(); i++){
        cov_ofstream << outputs[i]["coverage"].str();
        if(i < outputs.size()-1) cov_ofstream << ",";
    }
    cov_ofstream << "],";
    cov_ofstream << std::endl;
    #ifdef TAINT_EN
    cov_ofstream << "\"taints\":[";
    for(int i=0; i<outputs.size(); i++){
        cov_ofstream << outputs[i]["taints"].str();
        if(i < outputs.size()-1) cov_ofstream << ",";
    }    
    cov_ofstream << "],";
    #endif // TAINT_EN
    cov_ofstream << "\"timestamp\": " << timestamp << ",";
    cov_ofstream << "\"ticks\": " << tb->tick_count_ << ",";
    cov_ofstream << "\"ID\": " << this->ID << ",";
    cov_ofstream << "\"mutator\": " << "\"" << this->mutator << "\"" << ",";
    cov_ofstream << "\"parent\": " << this->parent_ID;
    cov_ofstream << "}";
    cov_ofstream.close();
}

#endif